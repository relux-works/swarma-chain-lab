//go:build linux

package service

import (
	"bytes"
	"context"
	"crypto/subtle"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/model-proxy/service/internal/wire"
)

const Placeholder = "ssh-placeholder"
const upstreamOrigin = "https://api.anthropic.com"
const MaxIntakeBody = 128 << 20

type GatewaySource interface {
	GatewayBinding() (Caller, string)
	CredentialValue(context.Context) (string, []byte, string, error)
	CredentialContext(context.Context, string) (context.Context, context.CancelFunc)
	ReserveGeneration([]byte) error
}

type Gateway struct {
	source      GatewaySource
	mapping     Mapping
	transport   http.RoundTripper
	authority   context.Context
	cancel      context.CancelFunc
	mu          sync.Mutex
	values      [][]byte
	blocked     bool
	idleTimeout time.Duration
}

func (*Gateway) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("<credential-intake>"))
}

func NewGateway(source GatewaySource, mapping Mapping) (*Gateway, error) {
	if source == nil || !validCaller(mapping.Caller) || !generationName.MatchString(mapping.ServiceGeneration) || !valid(mapping.Listener) || !valid(mapping.Policy) || mapping.Placeholder != Placeholder {
		return nil, ErrInput
	}
	caller, generation := source.GatewayBinding()
	if caller != mapping.Caller || generation != mapping.ServiceGeneration {
		return nil, ErrRole
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DisableCompression = true
	transport.ResponseHeaderTimeout = 30 * time.Second
	authority, cancel := context.WithCancel(context.Background())
	return &Gateway{source: source, mapping: mapping, transport: transport, authority: authority, cancel: cancel, idleTimeout: time.Minute}, nil
}

func (g *Gateway) Close() {
	g.cancel()
	if transport, ok := g.transport.(interface{ CloseIdleConnections() }); ok {
		transport.CloseIdleConnections()
	}
}

type gatewayPeerKey struct{}
type gatewayPeer struct{ uid uint32 }

func (g *Gateway) ConnContext(ctx context.Context, conn net.Conn) context.Context {
	if unixConn, ok := conn.(*net.UnixConn); ok {
		if uid, err := peerUID(unixConn); err == nil {
			return context.WithValue(ctx, gatewayPeerKey{}, gatewayPeer{uid: uid})
		}
	}
	return ctx
}

func credentialHeader(key string) bool {
	switch strings.ToLower(key) {
	case "authorization", "x-api-key", "proxy-authorization", "cookie", "x-auth-token", "anthropic-auth-token", "x-access-token":
		return true
	}
	return false
}

func intakeShape(request *http.Request) bool {
	if request.URL == nil || request.ProtoMajor != 1 || request.ProtoMinor != 1 || request.URL.IsAbs() || request.URL.User != nil || request.URL.Fragment != "" || request.URL.Opaque != "" {
		return false
	}
	authorization := []string{}
	for key, values := range request.Header {
		if strings.EqualFold(key, "Authorization") {
			authorization = append(authorization, values...)
			if len(values) == 0 {
				return false
			}
		} else if credentialHeader(key) {
			return false
		}
	}
	switch {
	case request.Method == http.MethodPost && request.URL.EscapedPath() == "/v1/messages":
		return len(authorization) == 1 && subtle.ConstantTimeCompare([]byte(authorization[0]), []byte("Bearer "+Placeholder)) == 1
	case request.Method == http.MethodGet && request.URL.EscapedPath() == "/api/claude_code/policy_limits" && request.URL.RawQuery == "" && !request.URL.ForceQuery:
		return len(authorization) == 0
	}
	return false
}

func (g *Gateway) remember(material []byte) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.blocked {
		return false
	}
	for _, value := range g.values {
		if bytes.Equal(value, material) {
			return true
		}
	}
	if len(g.values) >= 256 {
		g.blocked = true
		g.cancel()
		return false
	}
	g.values = append(g.values, bytes.Clone(material))
	return true
}

func (g *Gateway) needles() [][]byte {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([][]byte(nil), g.values...)
}

func containsMaterial(raw []byte, values [][]byte) bool {
	for _, value := range values {
		if bytes.Contains(raw, value) {
			return true
		}
	}
	return false
}

func (g *Gateway) scan(request *http.Request, body []byte) bool {
	values := g.needles()
	leak := containsMaterial(body, values) || containsMaterial([]byte(request.RequestURI+request.URL.String()+request.Host), values)
	for key, entries := range request.Header {
		leak = leak || containsMaterial([]byte(key), values)
		for _, entry := range entries {
			leak = leak || containsMaterial([]byte(entry), values)
		}
	}
	if leak {
		g.mu.Lock()
		g.blocked = true
		g.cancel()
		g.mu.Unlock()
	}
	return !leak
}

func (g *Gateway) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	refuse := func(status int) { http.Error(writer, "GATEWAY_REFUSED", status) }
	peer, ok := request.Context().Value(gatewayPeerKey{}).(gatewayPeer)
	if !ok || peer.uid != g.mapping.Caller.UID {
		refuse(http.StatusForbidden)
		return
	}
	if !intakeShape(request) {
		refuse(http.StatusBadRequest)
		return
	}
	g.mu.Lock()
	blocked := g.blocked || g.authority.Err() != nil
	g.mu.Unlock()
	if blocked {
		refuse(http.StatusServiceUnavailable)
		return
	}
	var body []byte
	var err error
	if request.Body != nil {
		body, err = io.ReadAll(io.LimitReader(request.Body, MaxIntakeBody+1))
	}
	if err != nil || len(body) > MaxIntakeBody || len(request.Trailer) != 0 || request.Method == http.MethodGet && len(body) != 0 {
		refuse(http.StatusBadRequest)
		return
	}
	if !g.scan(request, body) {
		refuse(http.StatusForbidden)
		return
	}
	if request.Method == http.MethodPost {
		if g.source.ReserveGeneration(body) != nil {
			refuse(http.StatusForbidden)
			return
		}
	}
	scheme, material, version, err := g.source.CredentialValue(context.WithoutCancel(request.Context()))
	defer clear(material)
	if err != nil || scheme != "oauth-bearer" || !validMaterial(material) || !wire.ASCII(version, 128) || !g.remember(material) {
		refuse(http.StatusServiceUnavailable)
		return
	}
	if !g.scan(request, body) {
		refuse(http.StatusForbidden)
		return
	}
	call, cancel := g.source.CredentialContext(request.Context(), version)
	defer cancel()
	stop := context.AfterFunc(g.authority, cancel)
	defer stop()
	if g.authority.Err() != nil {
		cancel()
	}
	if call.Err() != nil {
		refuse(http.StatusServiceUnavailable)
		return
	}
	target := upstreamOrigin + request.URL.EscapedPath()
	if request.URL.RawQuery != "" || request.URL.ForceQuery {
		target += "?" + request.URL.RawQuery
	}
	out, err := http.NewRequestWithContext(call, request.Method, target, bytes.NewReader(body))
	if err != nil {
		refuse(http.StatusBadRequest)
		return
	}
	copyProtocolHeaders(out.Header, request.Header)
	out.Header.Set("Authorization", "Bearer "+string(material))
	defer Drop(out)
	client := http.Client{Transport: g.transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(out)
	if err != nil {
		refuse(http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	if response.Header.Get("Content-Encoding") != "" {
		refuse(http.StatusBadGateway)
		return
	}
	stopBody := context.AfterFunc(call, func() { _ = response.Body.Close() })
	defer stopBody()
	idle := time.AfterFunc(g.idleTimeout, cancel)
	defer idle.Stop()
	copyProtocolHeaders(writer.Header(), response.Header)
	for key, values := range writer.Header() {
		if containsMaterial([]byte(key+strings.Join(values, "")), g.needles()) {
			writer.Header().Del(key)
		}
	}
	writer.WriteHeader(response.StatusCode)
	if streamFiltered(call, writer, response.Body, g.needles, g.idleTimeout, func() { idle.Reset(g.idleTimeout) }) != nil {
		panic(http.ErrAbortHandler)
	}
}

func validMaterial(material []byte) bool {
	if len(material) == 0 || len(material) > 4096 {
		return false
	}
	for _, character := range material {
		if character < 33 || character > 126 {
			return false
		}
	}
	return true
}

func copyProtocolHeaders(destination, source http.Header) {
	for key, values := range source {
		lower := strings.ToLower(key)
		if lower == "content-type" || lower == "accept" || lower == "user-agent" || lower == "cache-control" || lower == "retry-after" || lower == "x-should-retry" || lower == "request-id" || lower == "x-request-id" || lower == "anthropic-version" || lower == "anthropic-beta" || strings.HasPrefix(lower, "anthropic-ratelimit-") || strings.HasPrefix(lower, "x-stainless-") {
			destination[key] = append([]string(nil), values...)
		}
	}
}

func streamFiltered(ctx context.Context, writer http.ResponseWriter, reader io.Reader, needles func() [][]byte, idleTimeout time.Duration, progress func()) error {
	buffer := make([]byte, 8192)
	var pending []byte
	for {
		count, err := reader.Read(buffer)
		if count > 0 {
			progress()
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		pending = append(pending, buffer[:count]...)
		values := needles()
		for _, value := range values {
			pending = bytes.ReplaceAll(pending, value, []byte("[redacted]"))
		}
		keep := 0
		if err == nil {
			for _, value := range values {
				for length := 1; length < len(value) && length <= len(pending); length++ {
					if bytes.Equal(pending[len(pending)-length:], value[:length]) && length > keep {
						keep = length
					}
				}
			}
		}
		if ready := len(pending) - keep; ready > 0 {
			if deadlineErr := http.NewResponseController(writer).SetWriteDeadline(time.Now().Add(idleTimeout)); deadlineErr != nil && deadlineErr != http.ErrNotSupported {
				return deadlineErr
			}
			if _, writeErr := writer.Write(pending[:ready]); writeErr != nil {
				return writeErr
			}
			if flushErr := http.NewResponseController(writer).Flush(); flushErr != nil {
				return flushErr
			}
			pending = bytes.Clone(pending[ready:])
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}
