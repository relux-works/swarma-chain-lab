// Package payload is a scripted station fixture, not a general agent runtime.
package payload

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	proxy "relux.works/swarma-chain-lab/experiments/model-proxy"
	"relux.works/swarma-chain-lab/experiments/station-lifecycle/gatewaybind"
)

// Code is safe for public status; no lower-level errors or remote text escape.
type Code string

func (c Code) Error() string { return string(c) }

const (
	ErrBootstrap Code = "PAYLOAD_BOOTSTRAP"
	ErrConfig    Code = "PAYLOAD_CONFIG"
	ErrRequest   Code = "PAYLOAD_REQUEST"
	ErrTransport Code = "MODEL_TRANSPORT"
	ErrResponse  Code = "MODEL_RESPONSE"
	ErrChannel   Code = "PAYLOAD_CHANNEL"
)

const MaxText = 32768

// Options are operator inputs, independent of the private bootstrap. No default
// production model or output budget is inferred. V1 does not use model options.
type Options struct {
	Model     string
	MaxTokens uint64
	Roots     *x509.CertPool
}

type Client struct {
	mu        sync.Mutex
	bootstrap gatewaybind.PayloadBootstrap
	model     string
	maxTokens uint64
	http      *http.Client
	terminal  error
}

func (*Client) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, "[private payload client]") }

// New decodes the landed canonical v1/v2 codec before constructing any client.
// Only the bootstrap origin/slot route can receive the model bearer.
func New(raw []byte, options Options) (*Client, error) {
	b, err := gatewaybind.DecodeBootstrap(raw)
	if err != nil {
		return nil, ErrBootstrap
	}
	c := &Client{bootstrap: b, model: options.Model, maxTokens: options.MaxTokens}
	if b.V == 1 {
		return c, nil
	}
	if len(options.Model) == 0 || len(options.Model) > 128 || !utf8.ValidString(options.Model) || options.MaxTokens == 0 {
		return nil, ErrConfig
	}
	for _, r := range options.Model {
		if r < 33 || r > 126 {
			return nil, ErrConfig
		}
	}
	var roots *x509.CertPool
	if options.Roots != nil {
		roots = options.Roots.Clone()
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, VerifyConnection: func(s tls.ConnectionState) error {
		if len(s.VerifiedChains) == 0 || len(s.PeerCertificates) == 0 {
			return ErrTransport
		}
		sum := sha256.Sum256(s.PeerCertificates[0].Raw)
		if hex.EncodeToString(sum[:]) != b.ModelCertSHA256 {
			return ErrTransport
		}
		return nil
	}}
	// No reusable connection or replayable/idempotent request: the transport must
	// not silently retry a generation after an ambiguous connection failure.
	tr := &http.Transport{TLSClientConfig: tlsConfig, Proxy: nil, DisableKeepAlives: true, DisableCompression: true,
		DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext, TLSHandshakeTimeout: 3 * time.Second,
		ResponseHeaderTimeout: 25 * time.Second, MaxResponseHeaderBytes: 8192, MaxConnsPerHost: 1}
	c.http = &http.Client{Transport: tr, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrTransport }}
	return c, nil
}

func (c *Client) Close() {
	if c.http != nil {
		c.http.CloseIdleConnections()
	}
}

// Respond sends one text-only, non-streaming request, or preserves the v1 echo.
// Only fixed proxy CAP/AUTH refusals latch (AUTH includes expiry/revocation).
// Other failures refuse this call; a later delivery makes a new accounted request.
// No call automatically retries or changes budgets/credentials.
func (c *Client) Respond(ctx context.Context, text string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.terminal != nil {
		return "", c.terminal
	}
	if c.bootstrap.V == 1 {
		return "echo: " + text, nil
	}
	if len(text) > MaxText || !utf8.ValidString(text) {
		return "", ErrRequest
	}
	answer, err := c.generate(ctx, text)
	if err == Code("MODEL_CAP") || err == Code("MODEL_AUTH") {
		c.terminal = err
	}
	return answer, err
}

func (c *Client) generate(ctx context.Context, text string) (string, error) {
	q := struct {
		Model     string `json:"model"`
		MaxTokens uint64 `json:"max_tokens"`
		Stream    bool   `json:"stream"`
		Messages  []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}{Model: c.model, MaxTokens: c.maxTokens}
	q.Messages = append(q.Messages, struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}{"user", text})
	raw, _ := json.Marshal(q)
	prepared, err := (proxy.Messages{}).Parse(raw)
	if err != nil {
		return "", ErrRequest
	}
	url := c.bootstrap.ModelEndpoint + "/slots/" + c.bootstrap.BookingID + "/v1/messages"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return "", ErrRequest
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+string(c.bootstrap.ModelBearer))
	res, err := c.http.Do(req)
	if err != nil {
		return "", ErrTransport
	}
	defer res.Body.Close()
	if res.Header.Get("Content-Encoding") != "" {
		return "", ErrResponse
	}
	limit := int64(proxy.MaxResponse)
	if res.StatusCode != http.StatusOK {
		limit = 256
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err != nil || int64(len(body)) > limit {
		return "", ErrResponse
	}
	if res.StatusCode != http.StatusOK {
		return "", refusal(res.StatusCode, body)
	}
	if _, err = (proxy.Messages{}).Complete(body, prepared); err != nil {
		return "", ErrResponse
	}
	var response struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if json.Unmarshal(body, &response) != nil {
		return "", ErrResponse
	}
	var out strings.Builder
	for _, b := range response.Content {
		if out.Len()+len(b.Text) > MaxText {
			return "", ErrResponse
		}
		out.WriteString(b.Text)
	}
	return out.String(), nil
}

func refusal(status int, raw []byte) error {
	// Compare the entire fixed body, including status. Never echo arbitrary
	// upstream errors, credentials, prompts or URL diagnostics into a reply.
	codes := map[int][]string{400: {"REQUEST"}, 401: {"AUTH"}, 403: {"AUTH", "BUSY", "MODEL", "CAP"}, 404: {"ROUTE"}, 413: {"BODY"}, 502: {"UPSTREAM", "USAGE", "STREAM"}}
	for _, code := range codes[status] {
		if string(raw) == `{"error":"`+code+`"}` {
			return Code("MODEL_" + code)
		}
	}
	return ErrResponse
}
