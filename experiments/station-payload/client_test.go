package payload

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	proxy "github.com/relux-works/swarma-chain-lab/experiments/model-proxy"
	lifecycle "github.com/relux-works/swarma-chain-lab/experiments/station-lifecycle"
	"github.com/relux-works/swarma-chain-lab/experiments/station-lifecycle/gatewaybind"
)

const modelID = "fixture-model-1"
const prompt = "private-prompt-marker"
const apiKey = "private-upstream-key-marker"
const answer = "private-answer-marker"

type fixture struct {
	s                  *proxy.Service
	b                  proxy.Binding
	doc                gatewaybind.PayloadBootstrap
	roots              *x509.CertPool
	upstream, requests atomic.Int32
	now                atomic.Int64
	mu                 sync.Mutex
	audit              []proxy.Audit
	front              *httptest.Server
}

func encoded(t *testing.T, b gatewaybind.PayloadBootstrap) []byte {
	t.Helper()
	raw, e := gatewaybind.EncodeBootstrap(b)
	if e != nil {
		t.Fatal("fixture bootstrap")
	}
	return raw
}
func root(t *testing.T) string {
	t.Helper()
	p, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if os.Chmod(p, 0700) != nil {
		t.Fatal("fixture root mode")
	}
	return p
}
func pin(cert *x509.Certificate) string {
	h := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(h[:])
}
func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{}
	f.now.Store(100)
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.upstream.Add(1)
		if r.URL.Path != "/v1/messages" || r.Header.Get("x-api-key") != apiKey || r.Header.Get("Authorization") != "" {
			t.Error("upstream credential boundary")
		}
		var q map[string]json.RawMessage
		raw, _ := io.ReadAll(r.Body)
		if json.Unmarshal(raw, &q) != nil || string(q["service_tier"]) != `"standard_only"` || string(q["inference_geo"]) != `"global"` || string(q["stream"]) != "false" {
			t.Error("text profile boundary")
		}
		io.WriteString(w, `{"id":"fixture","type":"message","role":"assistant","model":"`+modelID+`","content":[{"type":"text","text":"`+answer+`"}],"stop_reason":"end_turn","usage":{"input_tokens":7,"output_tokens":3}}`)
	}))
	t.Cleanup(up.Close)
	f.front = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		if r.URL.Path != "/slots/"+f.b.SlotID+"/v1/messages" || r.Header.Get("Authorization") != "Bearer "+string(f.doc.ModelBearer) || r.Header.Get("x-api-key") != "" {
			t.Error("payload credential/route boundary")
		}
		f.s.ServeHTTP(w, r)
	}))
	f.front.Config.ErrorLog = log.New(io.Discard, "", 0)
	f.front.StartTLS()
	t.Cleanup(f.front.Close)
	f.roots = x509.NewCertPool()
	f.roots.AddCert(f.front.Certificate())
	var err error
	f.s, err = proxy.New(proxy.Config{StateDir: root(t), Endpoint: proxy.Endpoint{URL: f.front.URL, CertSHA256: pin(f.front.Certificate())}, Upstream: up.URL + "/v1/messages", APIKey: apiKey, Models: map[string]proxy.Model{modelID: {ContextTokens: 100, InputNanoUSD: 2, OutputNanoUSD: 3, Source: "synthetic test pricing"}}, Now: func() time.Time { return time.Unix(f.now.Load(), 0) }, Transport: up.Client().Transport, Timeout: 2 * time.Second, Audit: func(a proxy.Audit) { f.mu.Lock(); defer f.mu.Unlock(); f.audit = append(f.audit, a) }})
	if err != nil {
		t.Fatal("real proxy setup", err)
	}
	t.Cleanup(func() { f.s.Close() })
	f.b = proxy.Binding{SlotID: strings.Repeat("b", 64), GrantID: strings.Repeat("c", 64), NotBefore: 90, NotAfter: 1000, Caps: proxy.Caps{InputTokens: 1000, OutputTokens: 1000, Requests: 2, MaxTokens: 10, CostNanoUSD: 10000}}
	cred, err := f.s.Prepare(f.b)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.s.Activate(f.b); err != nil {
		t.Fatal(err)
	}
	f.doc = gatewaybind.PayloadBootstrap{V: 2, BookingID: f.b.SlotID, StationName: "id/payload-fixture", ChannelSecret: lifecycle.Secret(strings.Repeat("x", 32)), ModelBearer: cred.Bearer, ModelEndpoint: cred.Endpoint.URL, ModelCertSHA256: cred.Endpoint.CertSHA256}
	return f
}
func (f *fixture) client(t *testing.T) *Client {
	t.Helper()
	c, e := New(encoded(t, f.doc), Options{Model: modelID, MaxTokens: 10, Roots: f.roots})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(c.Close)
	return c
}

// Actual TLS payload -> real proxy -> fake HTTPS upstream settles usage. The
// next request after exact cap exhaustion is refused without another generation;
// terminal client state does not retry even if the caller asks again.
func TestModelAccountingAndCap(t *testing.T) {
	f := newFixture(t)
	c := f.client(t)
	for i := 0; i < 2; i++ {
		s, e := c.Respond(context.Background(), prompt)
		if e != nil || s != answer {
			t.Fatal("valid model neighbor refused", e)
		}
	}
	before, e := f.s.Status(f.b.SlotID)
	if e != nil || before.Exposure != (proxy.Counts{Input: 14, Output: 6, Requests: 2, Cost: 46}) || before.Observed != (proxy.Usage{Input: 14, Output: 6}) {
		t.Fatal("model usage not accounted")
	}
	for i := 0; i < 2; i++ {
		s, e := c.Respond(context.Background(), prompt)
		if e != Code("MODEL_CAP") || s != "" {
			t.Fatal("cap not honored")
		}
	}
	after, e := f.s.Status(f.b.SlotID)
	if e != nil || after.Exposure != before.Exposure || f.upstream.Load() != 2 || f.requests.Load() != 3 {
		t.Fatal("refusal retried or changed accounting")
	}
	f.mu.Lock()
	audit, _ := json.Marshal(f.audit)
	f.mu.Unlock()
	public := fmt.Sprintf("%v %+v %#v %s", c, c, c, audit)
	for _, secret := range []string{string(f.doc.ModelBearer), string(f.doc.ChannelSecret), apiKey, prompt, answer} {
		if strings.Contains(public, secret) {
			t.Fatal("private value escaped public formatting/audit")
		}
	}
}

// A valid TLS/pin control precedes each wrong-pin or untrusted-chain attempt.
// Neither failing TLS variant sends HTTP or charges an upstream generation.
func TestTLSBoundaries(t *testing.T) {
	for _, mode := range []string{"wrong-pin", "untrusted"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			if _, e := f.client(t).Respond(context.Background(), prompt); e != nil {
				t.Fatal("TLS neighbor", e)
			}
			b := f.doc
			roots := f.roots
			if mode == "wrong-pin" {
				b.ModelCertSHA256 = strings.Repeat("a", 64)
			} else {
				roots = x509.NewCertPool()
			}
			c, e := New(encoded(t, b), Options{Model: modelID, MaxTokens: 10, Roots: roots})
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			for i := 0; i < 2; i++ {
				s, e := c.Respond(context.Background(), prompt)
				if e != ErrTransport || s != "" {
					t.Fatal("TLS boundary accepted")
				}
			}
			if f.requests.Load() != 1 || f.upstream.Load() != 1 {
				t.Fatal("TLS rejection caused HTTP effects")
			}
		})
	}
}

// Expired and revoked credentials collapse to the real proxy's AUTH
// code. Each terminal attempt has a preceding active, accounted positive control.
func TestExpiredRevoked(t *testing.T) {
	for _, mode := range []string{"expired", "revoked"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			c := f.client(t)
			if _, e := c.Respond(context.Background(), prompt); e != nil {
				t.Fatal("active neighbor", e)
			}
			if mode == "expired" {
				f.now.Store(f.b.NotAfter)
			} else if e := f.s.Revoke(f.b); e != nil {
				t.Fatal(e)
			}
			for i := 0; i < 2; i++ {
				s, e := c.Respond(context.Background(), prompt)
				if e != Code("MODEL_AUTH") || s != "" {
					t.Fatal("terminal credential accepted")
				}
			}
			st, e := f.s.Status(f.b.SlotID)
			if e != nil || st.Exposure.Requests != 1 || f.requests.Load() != 2 || f.upstream.Load() != 1 {
				t.Fatal("terminal credential retried or charged")
			}
		})
	}
}

// The landed closed canonical codec refuses invalid fields/versions/duplicates
// before any HTTP effect; v1 keeps echo behavior and never calls the model.
func TestBootstrapAndV1(t *testing.T) {
	f := newFixture(t)
	raw := encoded(t, f.doc)
	for _, bad := range [][]byte{
		[]byte(strings.Replace(string(raw), `"v":2`, `"v":3`, 1)),
		[]byte(strings.Replace(string(raw), `"v":2`, `"v":2,"unknown":1`, 1)),
		[]byte(strings.Replace(string(raw), `"v":2`, `"v":2,"v":2`, 1)),
		append(append([]byte{}, raw...), '\n'),
	} {
		if c, e := New(bad, Options{}); e != ErrBootstrap || c != nil {
			t.Fatal("invalid bootstrap accepted")
		}
	}
	b := f.doc
	b.V = 1
	b.ModelBearer = ""
	b.ModelEndpoint = ""
	b.ModelCertSHA256 = ""
	c, e := New(encoded(t, b), Options{})
	if e != nil {
		t.Fatal("v1 neighbor", e)
	}
	defer c.Close()
	if got, e := c.Respond(context.Background(), prompt); e != nil || got != "echo: "+prompt {
		t.Fatal("v1 echo changed")
	}
	large := strings.Repeat("x", MaxText+1)
	if got, e := c.Respond(context.Background(), large); e != nil || got != "echo: "+large {
		t.Fatal("v2 text cap changed v1 echo")
	}
	if f.requests.Load() != 0 || f.upstream.Load() != 0 {
		t.Fatal("invalid/v1 bootstrap caused model effects")
	}
}

// Invalid local text/model limits do not send HTTP. A neighboring valid request
// still succeeds: input rejection is not a counterfeit all-rejecting client.
func TestRequestBounds(t *testing.T) {
	f := newFixture(t)
	for _, o := range []Options{{}, {Model: modelID}, {Model: "invalid model", MaxTokens: 10}, {Model: strings.Repeat("m", 129), MaxTokens: 10}} {
		if c, e := New(encoded(t, f.doc), o); e != ErrConfig || c != nil {
			t.Fatal("invalid model config accepted")
		}
	}
	c := f.client(t)
	for _, s := range []string{strings.Repeat("x", MaxText+1), string([]byte{255})} {
		if out, e := c.Respond(context.Background(), s); e != ErrRequest || out != "" {
			t.Fatal("invalid text accepted")
		}
	}
	if f.requests.Load() != 0 {
		t.Fatal("invalid text sent")
	}
	if _, e := c.Respond(context.Background(), prompt); e != nil {
		t.Fatal("valid text neighbor", e)
	}
}

// Local JSON expansion, raw bounds and pre-cancelled calls have no HTTP effect.
// The same client remains usable; subsequent real proxy caps still latch.
func TestLocalFailureRecovery(t *testing.T) {
	for _, mode := range []string{"escaped-control", "escaped-html", "oversize", "utf8", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			c := f.client(t)
			ctx := context.Background()
			text := strings.Repeat("\x01", 20000)
			want := error(ErrRequest)
			switch mode {
			case "escaped-html":
				text = strings.Repeat("<", 20000)
			case "oversize":
				text = strings.Repeat("x", MaxText+1)
			case "utf8":
				text = string([]byte{255})
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				text = prompt
				want = ErrTransport
			}
			for i := 0; i < 2; i++ {
				if out, e := c.Respond(ctx, text); out != "" || e != want {
					t.Fatal("local refusal changed", e)
				}
			}
			st, e := f.s.Status(f.b.SlotID)
			if e != nil || st.Exposure.Requests != 0 || f.requests.Load() != 0 || f.upstream.Load() != 0 {
				t.Fatal("local failure had effects")
			}
			for i := 0; i < 2; i++ {
				if out, e := c.Respond(context.Background(), prompt); e != nil || out != answer {
					t.Fatal("local failure latched", e)
				}
			}
			for i := 0; i < 2; i++ {
				if out, e := c.Respond(context.Background(), prompt); out != "" || e != Code("MODEL_CAP") {
					t.Fatal("recovery bypassed cap", e)
				}
			}
			st, e = f.s.Status(f.b.SlotID)
			if e != nil || st.Exposure.Requests != 2 || f.requests.Load() != 3 || f.upstream.Load() != 2 {
				t.Fatal("recovery changed accounting or terminal retry")
			}
		})
	}
}
