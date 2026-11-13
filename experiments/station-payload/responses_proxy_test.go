package payload

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	proxy "github.com/relux-works/swarma-chain-lab/experiments/model-proxy"
	lifecycle "github.com/relux-works/swarma-chain-lab/experiments/station-lifecycle"
	"github.com/relux-works/swarma-chain-lab/experiments/station-lifecycle/gatewaybind"
)

func newResponsesFixture(t *testing.T) (*fixture, proxy.FileConfig) {
	t.Helper()
	f := &fixture{}
	f.now.Store(100)
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.upstream.Add(1)
		if r.URL.Path != "/v1/responses" || r.Header.Get("Authorization") != "Bearer "+apiKey || r.Header.Get("x-api-key") != "" {
			t.Error("Responses upstream credential/route boundary")
		}
		b, _ := io.ReadAll(r.Body)
		var q map[string]json.RawMessage
		if json.Unmarshal(b, &q) != nil || len(q) != 7 || string(q["store"]) != "false" || string(q["background"]) != "false" || string(q["service_tier"]) != `"default"` {
			t.Error("Responses real proxy profile changed")
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, responsesReply)
	}))
	t.Cleanup(up.Close)
	f.front = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+string(f.doc.ModelBearer.Reveal()) {
			t.Error("Responses bootstrap bearer changed")
		}
		f.s.ServeHTTP(w, r)
	}))
	f.front.Config.ErrorLog = log.New(io.Discard, "", 0)
	f.front.StartTLS()
	t.Cleanup(f.front.Close)
	f.roots = x509.NewCertPool()
	f.roots.AddCert(f.front.Certificate())
	cfg := proxy.FileConfig{Endpoint: proxy.Endpoint{URL: f.front.URL, CertSHA256: pin(f.front.Certificate())}, Upstream: up.URL + "/v1/responses", Models: map[string]proxy.Model{modelID: {ContextTokens: 100, InputNanoUSD: 2, OutputNanoUSD: 3, Source: "synthetic fixture prices"}}, ModelProfiles: map[string]proxy.ModelProfile{modelID: {Profile: proxy.OpenAIResponsesProfile, Upstream: up.URL + "/v1/responses"}}}
	var e error
	f.s, e = proxy.New(proxy.Config{StateDir: root(t), Endpoint: cfg.Endpoint, Upstream: cfg.Upstream, Models: cfg.Models, ModelProfiles: cfg.ModelProfiles, APIKey: apiKey, Now: func() time.Time { return time.Unix(f.now.Load(), 0) }, Transport: up.Client().Transport, Timeout: 2 * time.Second})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { f.s.Close() })
	f.b = proxy.Binding{SlotID: strings.Repeat("b", 64), GrantID: strings.Repeat("c", 64), NotBefore: 90, NotAfter: 1000, Caps: proxy.Caps{InputTokens: 1000, OutputTokens: 1000, Requests: 2, MaxTokens: 10, CostNanoUSD: 10000}}
	cred, e := f.s.Prepare(f.b)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.s.Activate(f.b); e != nil {
		t.Fatal(e)
	}
	f.doc = gatewaybind.PayloadBootstrap{V: 2, BookingID: f.b.SlotID, StationName: "id/responses-fixture", ChannelSecret: gatewaybind.NewChannelSecret(lifecycle.Secret(strings.Repeat("x", 32))), ModelBearer: gatewaybind.NewModelBearer(cred.Bearer), ModelEndpoint: cred.Endpoint.URL, ModelCertSHA256: cred.Endpoint.CertSHA256}
	return f, cfg
}

// Real MP2 accounting settles each no-tool delivery. Exhaustion/revocation/expiry
// after successful use produces the exact terminal code, no retry or extra charge.
func TestResponsesRealProxy(t *testing.T) {
	for _, kind := range []string{"cap", "revoked", "expired"} {
		t.Run(kind, func(t *testing.T) {
			f, cfg := newResponsesFixture(t)
			c, e := NewPinned(encoded(t, f.doc), Options{Model: modelID, MaxTokens: 10, Roots: f.roots}, DialectResponses, cfg)
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			count := 1
			if kind == "cap" {
				count = 2
			}
			for i := 0; i < count; i++ {
				if out, e := c.Respond(context.Background(), prompt); e != nil || out != answer {
					t.Fatal("Responses real proxy neighbor refused", e)
				}
			}
			before, e := f.s.Status(f.b.SlotID)
			if e != nil || before.Exposure != (proxy.Counts{Input: uint64(7 * count), Output: uint64(3 * count), Requests: uint64(count), Cost: uint64(23 * count)}) {
				t.Fatal("Responses accounting changed")
			}
			want := Code("MODEL_CAP")
			if kind == "revoked" {
				if e = f.s.Revoke(f.b); e != nil {
					t.Fatal(e)
				}
				want = "MODEL_AUTH"
			}
			if kind == "expired" {
				f.now.Store(f.b.NotAfter)
				want = "MODEL_AUTH"
			}
			for i := 0; i < 2; i++ {
				if out, e := c.Respond(context.Background(), prompt); out != "" || e != want {
					t.Fatal("Responses closure not terminal", e)
				}
			}
			after, e := f.s.Status(f.b.SlotID)
			if e != nil || after.Exposure != before.Exposure || f.upstream.Load() != int32(count) || f.requests.Load() != int32(count+1) {
				t.Fatal("Responses closure retried or charged")
			}
		})
	}
}

// Shared TLS pin enforcement still applies on the Responses route. Alter both
// public copies of the pin so startup pairing passes, then require TLS rejection.
func TestResponsesTransportPin(t *testing.T) {
	f, cfg := newResponsesFixture(t)
	o := Options{Model: modelID, MaxTokens: 10, Roots: f.roots}
	c, e := NewPinned(encoded(t, f.doc), o, DialectResponses, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	if _, e = c.Respond(context.Background(), prompt); e != nil {
		t.Fatal("Responses pin neighbor")
	}
	f.doc.ModelCertSHA256 = strings.Repeat("a", 64)
	cfg.Endpoint.CertSHA256 = f.doc.ModelCertSHA256
	bad, e := NewPinned(encoded(t, f.doc), o, DialectResponses, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer bad.Close()
	if out, e := bad.Respond(context.Background(), prompt); out != "" || e != ErrTransport {
		t.Fatal("Responses TLS pin bypass")
	}
	if f.requests.Load() != 1 || f.upstream.Load() != 1 {
		t.Fatal("Responses TLS failure caused generation")
	}
}
