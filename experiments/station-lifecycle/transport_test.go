package lifecycle

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testCertificates(t *testing.T) (tls.Certificate, tls.Certificate, tls.Certificate, *x509.CertPool) {
	t.Helper()
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if e != nil {
		t.Fatal(e)
	}
	parsed, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	leaf := func(n int64, client bool) tls.Certificate {
		p, k, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		usage := x509.ExtKeyUsageServerAuth
		if client {
			usage = x509.ExtKeyUsageClientAuth
		}
		c := &x509.Certificate{SerialNumber: big.NewInt(n), Subject: pkix.Name{CommonName: "fixture"}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
		b, e := x509.CreateCertificate(rand.Reader, c, parsed, p, key)
		if e != nil {
			t.Fatal(e)
		}
		return tls.Certificate{Certificate: [][]byte{b, der}, PrivateKey: k}
	}
	return leaf(2, false), leaf(3, true), leaf(4, true), pool
}
func tlsBroker(t *testing.T, b *Broker, server, client tls.Certificate, roots *x509.CertPool) *httptest.Server {
	t.Helper()
	s := httptest.NewUnstartedServer(b.Handler(hash(client.Certificate[0])))
	s.TLS = &tls.Config{Certificates: []tls.Certificate{server}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, MinVersion: tls.VersionTLS13}
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}

// Real loopback mTLS exercises both chain verification and an independent peer
// leaf pin. A valid request returns the durable command; foreign clients and
// wrong server pins cannot read it or mutate broker records.
func TestPollAuthentication(t *testing.T) {
	_, _, _, now, _ := managerFixture(t)
	b, _ := brokerFixture(t, now)
	key := hash([]byte("booking"))
	if _, e := b.Allocate(key, hash([]byte("grant")), 90, 200); e != nil {
		t.Fatal(e)
	}
	if e := b.SetStart(key); e != nil {
		t.Fatal(e)
	}
	server, client, foreign, roots := testCertificates(t)
	s := tlsBroker(t, b, server, client, roots)
	good, e := NewPollClient(s.URL+PollPath, client, roots, hash(server.Certificate[0]))
	if e != nil {
		t.Fatal(e)
	}
	defer good.Close()
	p, e := good.Poll(context.Background(), []Status{})
	if e != nil || len(p.Commands) != 1 || p.Commands[0].Op != "start" {
		t.Fatal("authenticated neighbor", p, e)
	}
	before := string(canonical(b.state.Records))
	for _, tc := range []struct {
		name string
		cert tls.Certificate
		pin  string
	}{{"wrong-client", foreign, hash(server.Certificate[0])}, {"wrong-server", client, strings.Repeat("f", 64)}} {
		t.Run(tc.name, func(t *testing.T) {
			c, e := NewPollClient(s.URL+PollPath, tc.cert, roots, tc.pin)
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			if _, e = c.Poll(context.Background(), []Status{}); e == nil {
				t.Fatal("unauthenticated poll accepted")
			}
			if string(canonical(b.state.Records)) != before {
				t.Fatal("foreign TLS changed authority")
			}
		})
	}
	plain := httptest.NewRecorder()
	b.Handler(hash(client.Certificate[0])).ServeHTTP(plain, httptest.NewRequest(http.MethodPost, PollPath, strings.NewReader(`{"version":1,"results":[]}`)))
	if plain.Code != http.StatusUnauthorized || plain.Body.String() != `{"error":"POLL_AUTH"}` {
		t.Fatal("plaintext handler bypass", plain.Code)
	}
	// A caller cannot manufacture verified chains by presenting a leaf alone.
	req := httptest.NewRequest(http.MethodPost, PollPath, nil)
	cert, _ := x509.ParseCertificate(client.Certificate[0])
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	w := httptest.NewRecorder()
	b.Handler(hash(client.Certificate[0])).ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatal("unverified peer accepted")
	}
}

// The real polling loop loses its network while a fake owned slot is running.
// Its independent expiry worker still invokes cleanup; no helper OS effects are
// claimed, and no manager TLS credential is passed through the slot payload.
func TestPollDisconnectExpiry(t *testing.T) {
	m, _, h, now, _ := managerFixture(t)
	var clock atomic.Int64
	clock.Store(*now)
	m.cfg.Now = func() time.Time { return time.Unix(clock.Load(), 0) }
	b, c := brokerFixture(t, now)
	b.cfg.Now = m.cfg.Now
	_ = c
	key := hash([]byte("booking"))
	if _, e := b.Allocate(key, hash([]byte("grant")), 90, 200); e != nil {
		t.Fatal(e)
	}
	if e := b.SetStart(key); e != nil {
		t.Fatal(e)
	}
	server, client, _, roots := testCertificates(t)
	s := tlsBroker(t, b, server, client, roots)
	poll, e := NewPollClient(s.URL+PollPath, client, roots, hash(server.Certificate[0]))
	if e != nil {
		t.Fatal(e)
	}
	defer poll.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- poll.Run(ctx, m) }()
	defer func() { cancel(); <-done }()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		h.mu.Lock()
		active := h.active["1"]
		h.mu.Unlock()
		if active {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	h.mu.Lock()
	active := h.active["1"]
	h.mu.Unlock()
	if !active {
		t.Fatal("valid network start missing")
	}
	s.Close()
	clock.Store(200)
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		h.mu.Lock()
		active = h.active["1"]
		h.mu.Unlock()
		if !active {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if active {
		t.Fatal("link loss prevented local expiry")
	}
}

// Payload TLS proves only the server identity. No manager client certificate is
// sent; the separate slot challenge-response remains the payload's next step.
func TestPayloadTLS(t *testing.T) {
	server, _, _, roots := testCertificates(t)
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	s.TLS = &tls.Config{Certificates: []tls.Certificate{server}, ClientAuth: tls.NoClientCert, MinVersion: tls.VersionTLS13}
	s.StartTLS()
	defer s.Close()
	address := strings.TrimPrefix(s.URL, "https://")
	conn, e := DialPayload(context.Background(), address, hash(server.Certificate[0]), roots)
	if e != nil {
		t.Fatal("payload TLS valid neighbor", e)
	}
	conn.Close()
	if conn, e = DialPayload(context.Background(), address, strings.Repeat("f", 64), roots); e == nil {
		conn.Close()
		t.Fatal("wrong payload server pin accepted")
	}
}
