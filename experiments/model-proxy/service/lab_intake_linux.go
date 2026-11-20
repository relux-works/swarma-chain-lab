//go:build linux && gateway_lab

package service

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type LabGatewaySource interface {
	GatewayBinding() (Caller, string)
	CredentialValue(context.Context) (string, []byte, string, error)
	CredentialContext(context.Context, string) (context.Context, context.CancelFunc)
	Inventory() [][]byte
	ReportLeak()
}
type labGatewayAdapter struct {
	LabGatewaySource
	reserve func([]byte) error
}

func (adapter labGatewayAdapter) ReserveGeneration(body []byte) error { return adapter.reserve(body) }

type LabGatewayIO struct {
	Transport http.RoundTripper
	PeerUID   func(net.Conn) (uint32, error)
	Attempts  *LabAttemptGate
}

type LabGateway struct {
	*Gateway
	labSource LabGatewaySource
	peerUID   func(net.Conn) (uint32, error)
	attempts  *LabAttemptGate
}

func NewLabGateway(source LabGatewaySource, reserve func([]byte) error, collaborators ...LabGatewayIO) (*LabGateway, error) {
	if len(collaborators) != 1 || collaborators[0].Attempts == nil || collaborators[0].Attempts.admission == nil {
		return nil, ErrInput
	}
	bound, ok := source.(*LabSource)
	if !ok || bound != collaborators[0].Attempts.admission.source {
		return nil, ErrIdentity
	}
	gateway, err := newLabIntake(source, reserve, collaborators...)
	if err != nil {
		return nil, err
	}
	gateway.attempts = collaborators[0].Attempts
	if transport, ok := gateway.transport.(*http.Transport); ok {
		transport.Protocols = new(http.Protocols)
		transport.Protocols.SetHTTP1(true)
		transport.ForceAttemptHTTP2 = false
		transport.DisableKeepAlives = true
	}
	return gateway, nil
}

func newLabIntake(source LabGatewaySource, reserve func([]byte) error, collaborators ...LabGatewayIO) (*LabGateway, error) {
	if source == nil || reserve == nil || len(collaborators) > 1 {
		return nil, ErrInput
	}
	caller, generation := source.GatewayBinding()
	gateway, err := NewGateway(labGatewayAdapter{source, reserve}, Mapping{Caller: caller, ServiceGeneration: generation, Listener: generation, Policy: "lab-v0", Placeholder: Placeholder})
	if err != nil {
		return nil, err
	}
	lab := &LabGateway{Gateway: gateway, labSource: source}
	if len(collaborators) == 1 {
		lab.peerUID = collaborators[0].PeerUID
		if collaborators[0].Transport != nil {
			gateway.transport = collaborators[0].Transport
		}
	}
	return lab, nil
}

func (gateway *LabGateway) ConnContext(ctx context.Context, conn net.Conn) context.Context {
	if gateway.peerUID == nil {
		return gateway.Gateway.ConnContext(ctx, conn)
	}
	if uid, err := gateway.peerUID(conn); err == nil {
		return context.WithValue(ctx, gatewayPeerKey{}, gatewayPeer{uid: uid})
	}
	return ctx
}

func labShapeValid(request *http.Request) bool {
	if request.URL == nil || request.ProtoMajor != 1 || request.ProtoMinor != 1 || request.URL.IsAbs() || request.URL.User != nil || request.URL.Fragment != "" || request.URL.Opaque != "" || len(request.Trailer) != 0 || len(request.TransferEncoding) != 0 {
		return false
	}
	headers := map[string]string{}
	seen := map[string]bool{}
	for name, values := range request.Header {
		lower, valid := labHeaderName(name)
		if !valid || len(values) != 1 {
			return false
		}
		if seen[lower] {
			return false
		}
		seen[lower] = true
		if lower == "content-length" {
			length, err := strconv.ParseInt(values[0], 10, 64)
			if err != nil || length != request.ContentLength || strconv.FormatInt(length, 10) != values[0] {
				return false
			}
			continue
		}
		if lower == "content-type" || lower == "accept" || lower == "accept-encoding" || strings.HasPrefix(lower, "x-stainless-") {
			continue
		}
		switch lower {
		case "x-api-key", "anthropic-beta", "anthropic-version", "user-agent":
		default:
			return false
		}
		headers[lower] = values[0]
	}
	if request.Method == http.MethodGet {
		return request.URL.EscapedPath() == "/api/claude_code/policy_limits" && request.URL.RawQuery == "" && !request.URL.ForceQuery && len(headers) == 1 && headers["user-agent"] == "claude-code/2.1.328"
	}
	return request.Method == http.MethodPost && request.URL.EscapedPath() == "/v1/messages" && request.URL.RawQuery == "beta=true" && len(headers) == 4 && headers["x-api-key"] == Placeholder && headers["anthropic-version"] == "2023-06-01" && headers["user-agent"] == "claude-cli/2.1.328 (external, sdk-cli)" && labBetaValid(headers["anthropic-beta"])
}

func (gateway *LabGateway) scanLab(request *http.Request, body []byte) bool {
	inventory := gateway.labSource.Inventory()
	defer func() {
		for _, value := range inventory {
			clear(value)
		}
	}()
	leak := containsMaterial(body, inventory) || containsMaterial([]byte(request.RequestURI+request.URL.String()+request.Host), inventory)
	for name, values := range request.Header {
		leak = leak || containsMaterial([]byte(name+strings.Join(values, "")), inventory)
	}
	if leak {
		gateway.labSource.ReportLeak()
	}
	return !leak
}

func (gateway *LabGateway) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	refuse := func(status int) { http.Error(writer, "GATEWAY_REFUSED", status) }
	peer, ok := request.Context().Value(gatewayPeerKey{}).(gatewayPeer)
	if !ok || peer.uid != gateway.mapping.Caller.UID {
		refuse(http.StatusForbidden)
		return
	}
	if request.URL != nil && !gateway.scanLab(request, nil) {
		refuse(http.StatusForbidden)
		return
	}
	if !labShapeValid(request) {
		refuse(http.StatusBadRequest)
		return
	}
	if gateway.authority.Err() != nil {
		refuse(http.StatusServiceUnavailable)
		return
	}
	capacity := int64(MaxIntakeBody + 1)
	if request.ContentLength >= 0 && request.ContentLength <= MaxIntakeBody {
		capacity = request.ContentLength + 1
	}
	gateway.mu.Lock()
	if gateway.bodyBytes+capacity > MaxIntakeMemory || gateway.bodyCalls >= 8 {
		gateway.mu.Unlock()
		refuse(http.StatusServiceUnavailable)
		return
	}
	gateway.bodyBytes += capacity
	gateway.bodyCalls++
	gateway.mu.Unlock()
	defer func() { gateway.mu.Lock(); gateway.bodyBytes -= capacity; gateway.bodyCalls--; gateway.mu.Unlock() }()
	controller := http.NewResponseController(writer)
	if err := controller.SetReadDeadline(time.Now().Add(gateway.readTimeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		refuse(http.StatusBadRequest)
		return
	}
	body := make([]byte, capacity)
	count, err := io.ReadFull(io.LimitReader(request.Body, MaxIntakeBody+1), body)
	body = body[:count]
	defer clear(body)
	if err != io.EOF && err != io.ErrUnexpectedEOF && err != nil || request.ContentLength >= 0 && int64(count) != request.ContentLength || len(body) > MaxIntakeBody || len(request.Trailer) != 0 {
		refuse(http.StatusBadRequest)
		return
	}
	_ = controller.SetReadDeadline(time.Time{})
	if request.Method == http.MethodGet && len(body) != 0 || request.Method == http.MethodPost && !labBodyValid(body) {
		refuse(http.StatusBadRequest)
		return
	}
	if !gateway.scanLab(request, body) {
		refuse(http.StatusForbidden)
		return
	}
	if request.Method == http.MethodPost && gateway.source.ReserveGeneration(body) != nil {
		refuse(http.StatusForbidden)
		return
	}
	scheme, material, version, err := gateway.labSource.CredentialValue(request.Context())
	defer clear(material)
	if err != nil || !validMaterial(material) {
		refuse(http.StatusServiceUnavailable)
		return
	}
	if scheme != "api-key" || !gateway.scanLab(request, body) {
		refuse(http.StatusForbidden)
		return
	}
	call, cancel := gateway.labSource.CredentialContext(request.Context(), version)
	defer cancel()
	stop := context.AfterFunc(gateway.authority, cancel)
	defer stop()
	if call.Err() != nil {
		refuse(http.StatusServiceUnavailable)
		return
	}
	target := upstreamOrigin + request.URL.EscapedPath()
	if request.URL.RawQuery != "" {
		target += "?" + request.URL.RawQuery
	}
	out, err := http.NewRequestWithContext(call, request.Method, target, bytes.NewReader(body))
	if err != nil {
		refuse(http.StatusBadRequest)
		return
	}
	defer func() { out.Header.Del("Authorization"); out.Header.Del("X-Api-Key") }()
	copyProtocolHeaders(out.Header, request.Header)
	out.Header.Del("Authorization")
	out.Header.Del("X-Api-Key")
	if request.Method == http.MethodPost {
		out.Header.Set("X-Api-Key", string(material))
		out.Header.Set("Anthropic-Beta", labBeta)
	}
	var attempt *labAttempt
	if request.Method == http.MethodPost && gateway.attempts != nil {
		attempt, err = gateway.attempts.begin(call)
		if err != nil {
			refuse(http.StatusForbidden)
			return
		}
		defer attempt.finish(nil, "not-observed", false)
		out = out.WithContext(attempt.ctx)
		call = attempt.ctx
	}
	out.GetBody = nil
	out.Close = true
	client := http.Client{Transport: gateway.transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	headers := time.AfterFunc(gateway.headerTimeout, cancel)
	response, err := client.Do(out)
	headers.Stop()
	if err != nil {
		refuse(http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	if response.Header.Get("Content-Encoding") != "" {
		refuse(http.StatusBadGateway)
		return
	}
	inventory := gateway.labSource.Inventory()
	defer func() {
		for _, value := range inventory {
			clear(value)
		}
	}()
	for name, values := range response.Header {
		if containsMaterial([]byte(name+strings.Join(values, "")), inventory) {
			gateway.labSource.ReportLeak()
			refuse(http.StatusBadGateway)
			return
		}
	}
	copyProtocolHeaders(writer.Header(), response.Header)
	stopBody := context.AfterFunc(call, func() { _ = controller.SetWriteDeadline(time.Now()); _ = response.Body.Close() })
	defer stopBody()
	writer.WriteHeader(response.StatusCode)
	idle := time.AfterFunc(gateway.idleTimeout, cancel)
	defer idle.Stop()
	progress := func() { idle.Reset(gateway.idleTimeout) }
	var reader io.Reader = response.Body
	var usage *labAttemptUsage
	if attempt != nil {
		usage = newLabAttemptUsage(response.Body, response, attempt)
		reader = usage
	}
	streamErr := labStream(call, labProgressWriter{writer, progress}, labProgressReader{reader, progress}, inventory, gateway.labSource.ReportLeak)
	stopBody()
	if usage != nil {
		_ = usage.finish(streamErr == nil)
	}
	if streamErr != nil {
		panic(http.ErrAbortHandler)
	}
}

func labStream(ctx context.Context, writer http.ResponseWriter, reader io.Reader, needles [][]byte, hold func()) error {
	longest := 0
	for _, value := range needles {
		if len(value) > longest {
			longest = len(value)
		}
	}
	if longest == 0 {
		return ErrInactive
	}
	pending := []byte{}
	defer func() { clear(pending) }()
	buffer := make([]byte, 32<<10)
	defer clear(buffer)
	for {
		if ctx.Err() != nil {
			return ErrInactive
		}
		count, err := reader.Read(buffer)
		pending = append(pending, buffer[:count]...)
		if containsMaterial(pending, needles) {
			hold()
			return ErrInactive
		}
		retained := 0
		for _, needle := range needles {
			limit := len(needle) - 1
			if limit > len(pending) {
				limit = len(pending)
			}
			for length := limit; length > retained; length-- {
				if bytes.Equal(pending[len(pending)-length:], needle[:length]) {
					retained = length
					break
				}
			}
		}
		safe := len(pending) - retained
		if err == io.EOF {
			safe = len(pending)
		}
		if safe > 0 {
			if _, writeErr := writer.Write(pending[:safe]); writeErr != nil {
				return writeErr
			}
			if flushErr := http.NewResponseController(writer).Flush(); flushErr != nil && !errors.Is(flushErr, http.ErrNotSupported) {
				return flushErr
			}
			copy(pending, pending[safe:])
			pending = pending[:len(pending)-safe]
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

type labProgressReader struct {
	io.Reader
	progress func()
}

func (reader labProgressReader) Read(buffer []byte) (int, error) {
	count, err := reader.Reader.Read(buffer)
	if count > 0 {
		reader.progress()
	}
	return count, err
}

type labProgressWriter struct {
	http.ResponseWriter
	progress func()
}

func (writer labProgressWriter) Write(buffer []byte) (int, error) {
	count, err := writer.ResponseWriter.Write(buffer)
	if count > 0 {
		writer.progress()
	}
	return count, err
}
func (writer labProgressWriter) Unwrap() http.ResponseWriter { return writer.ResponseWriter }
