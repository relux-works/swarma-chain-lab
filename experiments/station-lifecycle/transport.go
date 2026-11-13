package lifecycle

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

const PollPath = "/v1/station-manager/poll"

// Handler requires an already verified mTLS chain and the exact configured leaf.
// This check remains mandatory even if a caller misconfigures the TLS listener.
func (b *Broker) Handler(peerSHA256 string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		reject := func(code int, reason string) {
			w.WriteHeader(code)
			_, _ = w.Write(privateCanonical(struct {
				Error string `json:"error"`
			}{reason}))
		}
		if !digest(peerSHA256) || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 || hash(r.TLS.PeerCertificates[0].Raw) != peerSHA256 {
			reject(http.StatusUnauthorized, "POLL_AUTH")
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != PollPath || r.URL.RawQuery != "" {
			reject(http.StatusNotFound, "POLL_ROUTE")
			return
		}
		raw, e := io.ReadAll(io.LimitReader(r.Body, MaxBody+1))
		if e != nil || len(raw) > MaxBody {
			reject(http.StatusBadRequest, "POLL_REQUEST")
			return
		}
		var p PollRequest
		if strict(raw, &p) != nil {
			reject(http.StatusBadRequest, "POLL_REQUEST")
			return
		}
		out, e := b.Poll(p)
		if e != nil {
			reject(http.StatusConflict, "POLL_REFUSED")
			return
		}
		raw = privateCanonical(out)
		if len(raw) > MaxBody {
			reject(http.StatusInternalServerError, "POLL_CAPACITY")
			return
		}
		_, _ = w.Write(raw)
	})
}
func pinnedTLS(roots *x509.CertPool, serverName, pin string) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: serverName, VerifyConnection: func(s tls.ConnectionState) error {
		if len(s.VerifiedChains) == 0 || len(s.PeerCertificates) == 0 || hash(s.PeerCertificates[0].Raw) != pin {
			return fail("TLS_PIN")
		}
		return nil
	}}
}

// DialPayload authenticates the server and pins its certificate. It carries no
// manager mTLS credential; the payload must then use its per-slot HMAC handshake.
func DialPayload(ctx context.Context, address, pin string, roots *x509.CertPool) (net.Conn, error) {
	host, port, e := net.SplitHostPort(address)
	if e != nil || net.ParseIP(host) == nil || port == "" || !digest(pin) {
		return nil, fail("PAYLOAD_TLS_CONFIG")
	}
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 2 * time.Second}, Config: pinnedTLS(roots, host, pin)}
	conn, e := d.DialContext(ctx, "tcp", address)
	if e != nil {
		return nil, fail("PAYLOAD_TLS")
	}
	return conn, nil
}

type PollClient struct {
	endpoint string
	http     *http.Client
}

func NewPollClient(endpoint string, certificate tls.Certificate, roots *x509.CertPool, serverPin string) (*PollClient, error) {
	u, e := url.Parse(endpoint)
	if e != nil || u.Scheme != "https" || u.User != nil || u.Path != PollPath || u.RawQuery != "" || u.Fragment != "" || net.ParseIP(u.Hostname()) == nil || !digest(serverPin) || len(certificate.Certificate) == 0 || certificate.PrivateKey == nil {
		return nil, fail("POLL_CONFIG")
	}
	cfg := pinnedTLS(roots, u.Hostname(), serverPin)
	cfg.Certificates = []tls.Certificate{certificate}
	tr := &http.Transport{TLSClientConfig: cfg, Proxy: nil, DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext, TLSHandshakeTimeout: 2 * time.Second, ResponseHeaderTimeout: 2 * time.Second, MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1}
	c := &http.Client{Transport: tr, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return fail("POLL_REDIRECT") }}
	return &PollClient{endpoint: endpoint, http: c}, nil
}
func (c *PollClient) Poll(ctx context.Context, results []Status) (PollResponse, error) {
	out := PollResponse{}
	if len(results) > MaxRetained {
		return out, fail("POLL_REQUEST")
	}
	raw := privateCanonical(PollRequest{Version: 1, Results: results})
	if len(raw) > MaxBody {
		return out, fail("POLL_REQUEST")
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(raw))
	if e != nil {
		return out, fail("POLL_REQUEST")
	}
	req.Header.Set("Content-Type", "application/json")
	response, e := c.http.Do(req)
	if e != nil {
		return out, fail("POLL_UNAVAILABLE")
	}
	defer response.Body.Close()
	raw, e = io.ReadAll(io.LimitReader(response.Body, MaxBody+1))
	if e != nil || response.StatusCode != http.StatusOK || strict(raw, &out) != nil || out.Version != 1 || len(out.Commands) > MaxLive {
		return PollResponse{}, fail("POLL_RESPONSE")
	}
	seen := map[string]bool{}
	for _, v := range out.Commands {
		if seen[v.Slot.ID] || (v.Op != "start" && v.Op != "stop") || !digest(v.Binding) {
			return PollResponse{}, fail("POLL_RESPONSE")
		}
		seen[v.Slot.ID] = true
	}
	return out, nil
}
func (c *PollClient) Close() { c.http.CloseIdleConnections() }

// Run keeps the expiry worker separate from network polling. Each host step and
// each poll has its own deadline; no socket wait holds the manager lock.
func (c *PollClient) Run(ctx context.Context, m *Manager) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- m.Run(ctx) }()
	defer func() { cancel(); <-done }()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case e := <-done:
			done <- e
			return e
		case <-ticker.C:
		}
		p, e := c.Poll(ctx, m.Results())
		if e != nil {
			continue
		}
		for _, cmd := range p.Commands {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			_, _ = m.Apply(ctx, cmd)
		}
	}
}
