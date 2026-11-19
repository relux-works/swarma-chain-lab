package modelproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Synthetic source values: long enough for the tripwire and spelled so that
// every encoded form differs from the raw bytes.
const sourceMarker = `sk-marker+v1/"<secret-value>"&x`
const sourceMarker2 = `sk-marker+v2/"<renewed-value>"&y`
const sourceVersion = "version-marker-1"

type issuedValue struct {
	value   Secret
	version string
}

// fakeSource is the non-file CredentialSource stand-in for the broker adapter.
// It records every renewal request and can be made unavailable or renewable.
type fakeSource struct {
	mu       sync.Mutex
	scheme   string
	value    UpstreamKey
	version  string
	fail     string
	next     *issuedValue
	renewals []string
}

func newFakeSource(value Secret) *fakeSource {
	return &fakeSource{scheme: SchemeAPIKey, value: NewAPIKey(value), version: sourceVersion}
}
func (f *fakeSource) current() UpstreamCredential {
	return UpstreamCredential{Scheme: f.scheme, Value: f.value, Version: f.version}
}
func (f *fakeSource) Credential(context.Context) (UpstreamCredential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != "" {
		return UpstreamCredential{}, fail(f.fail)
	}
	return f.current(), nil
}
func (f *fakeSource) Renew(_ context.Context, rejected string) (UpstreamCredential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.renewals = append(f.renewals, rejected)
	if f.fail != "" {
		return UpstreamCredential{}, fail(f.fail)
	}
	if f.next != nil {
		f.value, f.version = NewAPIKey(f.next.value), f.next.version
		f.next = nil
	}
	return f.current(), nil
}

// brokerCredentialSource is the unexported, test-only seam into managed mode's
// allow-list; production code outside this package cannot implement it.
func (*fakeSource) brokerCredentialSource() {}
func (f *fakeSource) renewed() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.renewals...)
}

type gatewayHarness struct {
	s        *Service
	c        Config
	b        Binding
	cred     Credential
	calls    atomic.Int32
	now      atomic.Int64
	mu       sync.Mutex
	audits   []Audit
	keys     map[string]bool
	bearer   bool
	upstream func(http.ResponseWriter, *http.Request)
}

func runBinding(slot, account string) Binding {
	return Binding{SlotID: strings.Repeat(slot, 64), GrantID: strings.Repeat("2", 64), NotBefore: 90, NotAfter: 1000, Caps: Caps{1000, 1000, 10, 10, 10000, 0}, Run: RunBinding{Generation: strings.Repeat("3", 64), RunID: strings.Repeat("4", 64), Account: strings.Repeat(account, 64)}}
}
func rentalBinding(slot string) Binding {
	return Binding{SlotID: strings.Repeat(slot, 64), GrantID: strings.Repeat("2", 64), NotBefore: 90, NotAfter: 1000, Caps: Caps{1000, 1000, 10, 10, 10000, 0}}
}

// wrappedSource hides another source behind a plain CredentialSource, the way
// any adapter outside this package would look to the allow-list.
type wrappedSource struct{ inner CredentialSource }

func (w wrappedSource) Credential(ctx context.Context) (UpstreamCredential, error) {
	return w.inner.Credential(ctx)
}
func (w wrappedSource) Renew(ctx context.Context, rejected string) (UpstreamCredential, error) {
	return w.inner.Renew(ctx, rejected)
}

// gatewayFixture serves one binding through a source-backed proxy: a run
// binding in managed mode, a rental binding otherwise. The loopback upstream
// answers 401 to any key it was not told to accept, so a renewal is observable
// without a real provider.
func gatewayFixture(t *testing.T, mode string, src CredentialSource, ceiling ...uint64) *gatewayHarness {
	t.Helper()
	g := &gatewayHarness{keys: map[string]bool{string(sourceMarker): true}}
	g.now.Store(100)
	g.upstream = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, reply(7, 3))
	}
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.calls.Add(1)
		if r.Header.Get("anthropic-beta") != "" || r.Header.Get("anthropic-version") != "2026-10-21" || r.Header.Get("X-Client-Debug") != "" {
			t.Error("client auth/header escaped")
		}
		// Drain the body before handing over, as every other fixture does: the
		// server starts watching for a client disconnect only once the request
		// body has been consumed, so a blocked handler can observe cancellation.
		body, e := io.ReadAll(r.Body)
		var fields map[string]json.RawMessage
		if e != nil || json.Unmarshal(body, &fields) != nil || string(fields["service_tier"]) != `"standard_only"` || string(fields["inference_geo"]) != `"global"` {
			t.Error("priced upstream profile not pinned")
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		g.mu.Lock()
		accepted := false
		if g.bearer {
			accepted = r.Header.Get("x-api-key") == "" && g.keys[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")] && strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ")
		} else {
			accepted = r.Header.Get("Authorization") == "" && g.keys[r.Header.Get("x-api-key")]
		}
		g.mu.Unlock()
		if !accepted {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(401)
			_, _ = io.WriteString(w, `{"type":"error","error":{"type":"authentication_error"}}`)
			return
		}
		g.upstream(w, r)
	}))
	t.Cleanup(up.Close)
	root := t.TempDir()
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	limit := uint64(1000000)
	if len(ceiling) > 0 {
		limit = ceiling[0]
	}
	g.c = Config{DailyCostCeilingNanoUSD: limit, StateDir: root, Endpoint: Endpoint{URL: "https://proxy.example", CertSHA256: strings.Repeat("a", 64)}, Upstream: up.URL + "/v1/messages", Source: src, Mode: mode, RunMaxWindowSeconds: 7200, Models: map[string]Model{modelID: {ContextTokens: 100, InputNanoUSD: 2, OutputNanoUSD: 3, Source: "fixture model bound, not production pricing"}}, Now: func() time.Time { return time.Unix(g.now.Load(), 0) }, Transport: up.Client().Transport, Timeout: time.Second, Audit: func(a Audit) { g.mu.Lock(); defer g.mu.Unlock(); g.audits = append(g.audits, a) }}
	if mode == ModeManaged {
		g.c.Upstream = ManagedUpstream
		transport := up.Client().Transport.(*http.Transport).Clone()
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
		transport.TLSClientConfig.ServerName = up.Certificate().DNSNames[0]
		transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, up.Listener.Addr().String())
		}
		g.c.Transport = transport
		t.Cleanup(transport.CloseIdleConnections)
	}
	if e := InitializeAccounting(g.c); e != nil {
		t.Fatal(e)
	}
	var e error
	g.s, e = New(g.c)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { g.s.Close() })
	g.b = runBinding("1", "a")
	if mode != ModeManaged {
		g.b = rentalBinding("1")
	}
	g.cred, e = g.s.Prepare(g.b)
	if e != nil {
		t.Fatal(e)
	}
	if e = g.s.Activate(g.b); e != nil {
		t.Fatal(e)
	}
	return g
}
func (g *gatewayHarness) accept(keys ...string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.keys = map[string]bool{}
	for _, k := range keys {
		g.keys[k] = true
	}
}
func (g *gatewayHarness) send(body string) *httptest.ResponseRecorder {
	return g.sendAs(body, g.b.SlotID, g.cred.Bearer.Reveal(), nil)
}
func (g *gatewayHarness) sendAs(body, id string, bearer Secret, headers map[string]string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	g.sendTo(w, strings.NewReader(body), id, bearer, headers)
	return w
}
func (g *gatewayHarness) sendTo(w http.ResponseWriter, body io.Reader, id string, bearer Secret, headers map[string]string) {
	r := httptest.NewRequest("POST", "https://proxy.example/slots/"+id+"/v1/messages", body)
	r.Header.Set("Authorization", "Bearer "+string(bearer))
	r.Header.Set("anthropic-beta", "client-beta-marker")
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	g.s.ServeHTTP(w, r)
}
func (g *gatewayHarness) status(t *testing.T) Status {
	t.Helper()
	v, e := g.s.Status(g.b.SlotID)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func (g *gatewayHarness) reopen(t *testing.T) {
	t.Helper()
	g.s.Close()
	s, e := New(g.c)
	if e != nil {
		t.Fatal(e)
	}
	g.s = s
}
func (g *gatewayHarness) auditLog() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return string(privateCanonical(g.audits))
}
func (g *gatewayHarness) lastAudit() Audit {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.audits) == 0 {
		return Audit{}
	}
	return g.audits[len(g.audits)-1]
}

// keyFile writes a synthetic 0400 key under a symlink-free directory.
func keyFile(t *testing.T, value string) string {
	t.Helper()
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(root, "key")
	if e = os.WriteFile(path, []byte(value), 0400); e != nil {
		t.Fatal(e)
	}
	return path
}

// Config admits exactly one credential origin: neither and both are the named
// CONFIG_CREDENTIAL refusal, while a source alone and a static key alone start.
func TestGatewayCredentialOrigin(t *testing.T) {
	g := gatewayFixture(t, ModeManaged, newFakeSource(sourceMarker))
	if w := g.send(request(false)); w.Code != 200 || g.calls.Load() != 1 {
		t.Fatal("source-only neighbor refused", w.Code, w.Body.String())
	}
	g.s.Close()
	for _, kind := range []string{"neither", "both"} {
		c := g.c
		if kind == "neither" {
			c.Source = nil
		} else {
			c.APIKey = NewAPIKey(keyMarker)
		}
		s, e := New(c)
		if e == nil || e.Error() != "CONFIG_CREDENTIAL" || s != nil {
			t.Fatal("credential origin not exactly one", kind, e)
		}
	}
	c := g.c
	c.Source = nil
	c.APIKey = NewAPIKey(keyMarker)
	c.Mode = ModeDevelopment
	s, e := New(c)
	if e != nil {
		t.Fatal("static-only neighbor refused", e)
	}
	s.Close()
}

// Managed mode allow-lists the broker source: the unexported test double
// starts and serves; a FileSource, a wrapper around a FileSource, a wrapper
// around the double itself and any non-broker source refuse
// CONFIG_MODE_NO_BROKER; a static key refuses CONFIG_MODE; a nil source with
// no key is the existing CONFIG_CREDENTIAL; an unknown mode is refused;
// development mode still accepts a FileSource and a static key.
func TestGatewayManagedMode(t *testing.T) {
	g := gatewayFixture(t, ModeManaged, newFakeSource(sourceMarker))
	if w := g.send(request(false)); w.Code != 200 || g.calls.Load() != 1 {
		t.Fatal("managed broker double refused", w.Code, w.Body.String())
	}
	g.s.Close()
	file := NewFileSource(keyFile(t, sourceMarker))
	for _, tc := range []struct {
		name, mode string
		source     CredentialSource
		static     bool
		want       string
	}{
		{"managed-file", ModeManaged, file, false, "CONFIG_MODE_NO_BROKER"},
		{"managed-wrapped-file", ModeManaged, wrappedSource{file}, false, "CONFIG_MODE_NO_BROKER"},
		{"managed-wrapped-double", ModeManaged, wrappedSource{newFakeSource(sourceMarker)}, false, "CONFIG_MODE_NO_BROKER"},
		{"managed-static", ModeManaged, nil, true, "CONFIG_MODE"},
		{"managed-nil", ModeManaged, nil, false, "CONFIG_CREDENTIAL"},
		{"unknown-mode", "staging", newFakeSource(sourceMarker), false, "CONFIG_MODE"},
		{"development-file", ModeDevelopment, file, false, ""},
		{"default-static", "", nil, true, ""},
	} {
		c := g.c
		c.Mode, c.Source = tc.mode, tc.source
		if tc.static {
			c.APIKey = NewAPIKey(keyMarker)
		}
		s, e := New(c)
		code := ""
		if e != nil {
			code = e.Error()
		}
		if code != tc.want || (e == nil) != (s != nil) {
			t.Fatal("mode verdict", tc.name, e)
		}
		if s != nil {
			s.Close()
		}
	}
}

// A missing, expired or unreadable credential refuses CREDENTIAL_UNAVAILABLE
// with no reservation and zero upstream calls; the restored source then serves
// the same binding.
func TestGatewayCredentialUnavailable(t *testing.T) {
	for _, kind := range []string{"missing", "expired", "unreadable"} {
		t.Run(kind, func(t *testing.T) {
			fake := newFakeSource(sourceMarker)
			var src CredentialSource = fake
			path := ""
			switch kind {
			case "missing":
				fake.fail = "CREDENTIAL_MISSING"
			case "expired":
				fake.fail = "CREDENTIAL_EXPIRED"
			case "unreadable":
				root, e := filepath.EvalSymlinks(t.TempDir())
				if e != nil {
					t.Fatal(e)
				}
				path = filepath.Join(root, "absent")
				src = NewFileSource(path)
			}
			// A FileSource exists only in development mode, so that case runs
			// on a rental binding; the broker double runs in managed mode.
			mode := ModeManaged
			if kind == "unreadable" {
				mode = ModeDevelopment
			}
			g := gatewayFixture(t, mode, src)
			w := g.send(request(false))
			if w.Code != 503 || w.Body.String() != `{"error":"CREDENTIAL_UNAVAILABLE"}` || g.calls.Load() != 0 || g.status(t).Exposure != (Counts{}) {
				t.Fatal("unavailable credential forwarded or charged", w.Code, w.Body.String())
			}
			if path != "" {
				if e := os.WriteFile(path, []byte(sourceMarker), 0400); e != nil {
					t.Fatal(e)
				}
			} else {
				fake.mu.Lock()
				fake.fail = ""
				fake.mu.Unlock()
			}
			if w = g.send(request(false)); w.Code != 200 || g.calls.Load() != 1 {
				t.Fatal("restored source neighbor refused", w.Code, w.Body.String())
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// After an explicit upstream 401 the proxy asks the source once, naming the
// rejected version, and retries once with the renewed credential. A renewal
// that returns the same version refuses CREDENTIAL_REJECTED. A stream that
// fails after it began and a transport failure trigger no renewal and no retry.
func TestGatewayRenewal(t *testing.T) {
	t.Run("renewed", func(t *testing.T) {
		src := newFakeSource(sourceMarker)
		src.next = &issuedValue{sourceMarker2, "version-marker-2"}
		g := gatewayFixture(t, ModeManaged, src)
		g.accept(sourceMarker2)
		w := g.send(request(false))
		if w.Code != 200 || g.calls.Load() != 2 || strings.Join(src.renewed(), ",") != sourceVersion {
			t.Fatal("401 renewal did not name the rejected version once", w.Code, w.Body.String(), src.renewed())
		}
		if v := g.status(t); v.Exposure != (Counts{7, 3, 1, 23}) || v.InFlight {
			t.Fatal("renewed request not settled once", v)
		}
	})
	t.Run("same-version", func(t *testing.T) {
		src := newFakeSource(sourceMarker)
		g := gatewayFixture(t, ModeManaged, src)
		g.accept(sourceMarker2)
		w := g.send(request(false))
		if w.Code != 502 || w.Body.String() != `{"error":"CREDENTIAL_REJECTED"}` || g.calls.Load() != 1 || len(src.renewed()) != 1 {
			t.Fatal("unrenewed 401 retried", w.Code, w.Body.String(), g.calls.Load())
		}
		if v := g.status(t); v.Exposure != (Counts{100, 10, 1, 230}) || v.InFlight {
			t.Fatal("rejected call refunded", v)
		}
	})
	t.Run("stream-began", func(t *testing.T) {
		src := newFakeSource(sourceMarker)
		g := gatewayFixture(t, ModeManaged, src)
		g.upstream = func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, strings.Split(sse(7, 3), "event: message_stop")[0])
		}
		w := g.send(request(true))
		if strings.Contains(w.Body.String(), "message_stop") || !strings.Contains(w.Body.String(), "proxy_error") || g.calls.Load() != 1 || len(src.renewed()) != 0 {
			t.Fatal("broken stream renewed or retried", g.calls.Load(), src.renewed())
		}
	})
	t.Run("transport", func(t *testing.T) {
		src := newFakeSource(sourceMarker)
		g := gatewayFixture(t, ModeManaged, src)
		g.s.cfg.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("synthetic transport failure") })
		w := g.send(request(false))
		if w.Code != 502 || w.Body.String() != `{"error":"UPSTREAM"}` || g.calls.Load() != 0 || len(src.renewed()) != 0 {
			t.Fatal("unknown outcome renewed or retried", w.Code, w.Body.String())
		}
	})
}

// No spelling of a source credential or its version enters the ledger file,
// Audit records or Status, and the Service, Config and credential redact every
// fmt, JSON and slog sink.
func TestGatewayCredentialNeverStored(t *testing.T) {
	src := newFakeSource(sourceMarker)
	g := gatewayFixture(t, ModeManaged, src)
	if g.send(request(false)).Code != 200 {
		t.Fatal("stored-credential control refused")
	}
	stored, e := g.s.disk.Read("registry.json", MaxBody)
	if e != nil {
		t.Fatal(e)
	}
	status, e := g.s.Status(g.b.SlotID)
	if e != nil {
		t.Fatal(e)
	}
	statusJSON, _ := json.Marshal(status)
	for _, sink := range [][]byte{stored, []byte(g.auditLog()), statusJSON} {
		for _, form := range spellings(sourceMarker) {
			if bytes.Contains(sink, []byte(form)) {
				t.Fatal("credential entered state, audit or status")
			}
		}
		if bytes.Contains(sink, []byte(sourceVersion)) {
			t.Fatal("credential version entered state, audit or status")
		}
	}
	cred, e := src.Credential(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	// Format a quiesced snapshot: the live loopback transport has goroutines
	// still writing after the request above, and bad-verb diagnostics walk into
	// any pointer at depth zero. The reopened service holds the same source,
	// issued tripwire values and records without that transport.
	g.s.Close()
	quiet := g.c
	quiet.Transport = nil
	s, e := New(quiet)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if _, e := s.upstreamCredential(context.Background()); e != nil {
		t.Fatal(e)
	}
	n1bOutputMatrix(t, []any{quiet, s, cred, &cred, NewFileSource("/synthetic/key")}, sourceMarker)
}

// authenticate is the one place a credential becomes headers: api-key keeps
// x-api-key for Messages and Bearer for Responses; oauth-bearer sends
// Authorization: Bearer for both and leaves no x-api-key or stale value; the
// proxy forwards an oauth-bearer source credential that way end to end.
func TestGatewaySchemeHeaders(t *testing.T) {
	for _, scheme := range []string{SchemeAPIKey, SchemeOAuthBearer} {
		for _, d := range []Dialect{Messages{}, Responses{}} {
			h := http.Header{}
			h.Set("x-api-key", "stale")
			h.Set("Authorization", "stale")
			authenticate(h, d, UpstreamCredential{Scheme: scheme, Value: NewAPIKey("synthetic-value"), Version: "v"})
			_, messages := d.(Messages)
			if scheme == SchemeAPIKey && messages {
				if h.Get("x-api-key") != "synthetic-value" || len(h.Values("Authorization")) != 0 || h.Get("anthropic-version") != "2026-10-21" {
					t.Fatal("api-key Messages headers changed")
				}
				continue
			}
			if h.Get("Authorization") != "Bearer synthetic-value" || len(h.Values("x-api-key")) != 0 || len(h.Values("Authorization")) != 1 {
				t.Fatal("bearer headers wrong", scheme, d.Profile())
			}
		}
	}
	src := newFakeSource(sourceMarker)
	src.scheme = SchemeOAuthBearer
	g := gatewayFixture(t, ModeManaged, src)
	g.bearer = true
	if w := g.send(request(false)); w.Code != 200 || g.calls.Load() != 1 {
		t.Fatal("oauth-bearer Messages request refused", w.Code, w.Body.String())
	}
}

// Run bindings exist only in managed mode: a development proxy backed by a
// static key or by a FileSource refuses Prepare of a run binding with
// RUN_REQUIRES_MANAGED and persists nothing, while the same proxy still
// prepares a rental binding; the managed broker-backed proxy prepares the same
// run binding.
func TestRunRequiresManaged(t *testing.T) {
	run := runBinding("5", "b")
	for _, kind := range []string{"static", "file"} {
		t.Run(kind, func(t *testing.T) {
			var src CredentialSource = NewFileSource(keyFile(t, sourceMarker))
			g := gatewayFixture(t, ModeDevelopment, src)
			if kind == "static" {
				g.s.Close()
				c := g.c
				c.Source, c.APIKey = nil, NewAPIKey(keyMarker)
				s, e := New(c)
				if e != nil {
					t.Fatal(e)
				}
				g.s = s
			}
			if _, e := g.s.Prepare(run); e == nil || e.Error() != "RUN_REQUIRES_MANAGED" {
				t.Fatal("development proxy minted a run binding", e)
			}
			if _, e := g.s.Status(run.SlotID); e == nil {
				t.Fatal("refused run binding persisted")
			}
			if _, e := g.s.Prepare(rentalBinding("6")); e != nil {
				t.Fatal("development rental neighbor refused", e)
			}
		})
	}
	g := gatewayFixture(t, ModeManaged, newFakeSource(sourceMarker))
	if _, e := g.s.Prepare(run); e != nil {
		t.Fatal("managed run binding refused", e)
	}
}

// A run binding is re-checked at every use, not only at Prepare. The same
// managed state dir reopened in development mode with a static key refuses the
// active run bearer with RUN_REQUIRES_MANAGED; a sealed maximum lowered below
// an active run window refuses it with RUN_WINDOW; both make zero upstream
// calls and block no account, while the rental neighbor keeps serving. The
// exact window as the maximum still serves, and the restored configuration
// serves the run bearer again: lowering the cap is a reversible operator action
// that takes effect on the next use, not a fingerprint change.
func TestRunRecheckedAtUse(t *testing.T) {
	g := gatewayFixture(t, ModeManaged, newFakeSource(sourceMarker))
	g.accept(sourceMarker, keyMarker)
	rental := rentalBinding("6")
	rentalCred, e := g.s.Prepare(rental)
	if e != nil {
		t.Fatal(e)
	}
	if e = g.s.Activate(rental); e != nil {
		t.Fatal(e)
	}
	calls := int32(0)
	serve := func(name string, id string, bearer Secret) {
		t.Helper()
		calls++
		if w := g.sendAs(request(false), id, bearer, nil); w.Code != 200 || g.calls.Load() != calls {
			t.Fatal(name, w.Code, w.Body.String(), g.calls.Load())
		}
	}
	serve("run positive neighbor refused", g.b.SlotID, g.cred.Bearer.Reveal())
	window := uint64(g.b.NotAfter - g.b.NotBefore)
	for _, tc := range []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"development-static", func(c *Config) { c.Mode, c.Source, c.APIKey = ModeDevelopment, nil, NewAPIKey(keyMarker) }, "RUN_REQUIRES_MANAGED"},
		{"lowered-cap", func(c *Config) { c.RunMaxWindowSeconds = window - 1 }, "RUN_WINDOW"},
		{"zero-cap", func(c *Config) { c.RunMaxWindowSeconds = 0 }, "RUN_WINDOW"},
		{"exact-cap", func(c *Config) { c.RunMaxWindowSeconds = window }, ""},
	} {
		g.s.Close()
		c := g.c
		tc.mutate(&c)
		s, e := New(c)
		if e != nil {
			t.Fatal(tc.name, "reopen refused", e)
		}
		g.s = s
		if tc.want == "" {
			serve(tc.name+": exact maximum refused the run bearer", g.b.SlotID, g.cred.Bearer.Reveal())
		} else {
			w := g.send(request(false))
			if w.Code != 403 || w.Body.String() != `{"error":"`+tc.want+`"}` || g.calls.Load() != calls {
				t.Fatal(tc.name, "run bearer served or misreported", w.Code, w.Body.String(), g.calls.Load())
			}
			if a := g.lastAudit(); a.Code != tc.want || a.SlotID != g.b.SlotID {
				t.Fatal(tc.name, "re-check not audited", a)
			}
			if len(persistedBlocks(t, g)) != 0 {
				t.Fatal(tc.name, "re-check blocked an account")
			}
			if v := g.status(t); v.Phase != "active" {
				t.Fatal(tc.name, "re-check changed the record", v)
			}
		}
		serve(tc.name+": rental neighbor refused", rental.SlotID, rentalCred.Bearer.Reveal())
		g.s.Close()
		if s, e = New(g.c); e != nil {
			t.Fatal(tc.name, "restore refused", e)
		}
		g.s = s
		serve(tc.name+": restored configuration refused the run bearer", g.b.SlotID, g.cred.Bearer.Reveal())
	}
}

// Activate re-checks the run admission like every use: a run binding prepared
// in managed mode is refused RUN_REQUIRES_MANAGED by the same state dir
// reopened in development with a static key, and RUN_WINDOW by a sealed maximum
// lowered below its window; the record stays prepared and nothing is blocked.
// The restored configuration activates it and the bearer serves, the positive
// control. A rental binding activates in every configuration.
func TestRunActivateRechecked(t *testing.T) {
	g := gatewayFixture(t, ModeManaged, newFakeSource(sourceMarker))
	g.accept(sourceMarker, keyMarker)
	run := runBinding("5", "b")
	runCred, e := g.s.Prepare(run)
	if e != nil {
		t.Fatal(e)
	}
	rental := rentalBinding("6")
	if _, e = g.s.Prepare(rental); e != nil {
		t.Fatal(e)
	}
	window := uint64(run.NotAfter - run.NotBefore)
	for _, tc := range []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"development-static", func(c *Config) { c.Mode, c.Source, c.APIKey = ModeDevelopment, nil, NewAPIKey(keyMarker) }, "RUN_REQUIRES_MANAGED"},
		{"lowered-cap", func(c *Config) { c.RunMaxWindowSeconds = window - 1 }, "RUN_WINDOW"},
	} {
		g.s.Close()
		c := g.c
		tc.mutate(&c)
		s, e := New(c)
		if e != nil {
			t.Fatal(tc.name, "reopen refused", e)
		}
		g.s = s
		if e = g.s.Activate(run); e == nil || e.Error() != tc.want {
			t.Fatal(tc.name, "run binding activated or misreported", e)
		}
		if v, e := g.s.Status(run.SlotID); e != nil || v.Phase != "prepared" {
			t.Fatal(tc.name, "refused Activate changed the record", v, e)
		}
		if len(persistedBlocks(t, g)) != 0 {
			t.Fatal(tc.name, "refused Activate blocked an account")
		}
	}
	// The rental binding is indifferent to both fields; activate it last here so
	// the restored configuration below proves only the run re-check.
	if e = g.s.Activate(rental); e != nil {
		t.Fatal("rental Activate refused under a lowered cap", e)
	}
	g.s.Close()
	s, e := New(g.c)
	if e != nil {
		t.Fatal("restore refused", e)
	}
	g.s = s
	if e = g.s.Activate(run); e != nil {
		t.Fatal("restored configuration refused Activate", e)
	}
	if w := g.sendAs(request(false), run.SlotID, runCred.Bearer.Reveal(), nil); w.Code != 200 || g.calls.Load() != 1 {
		t.Fatal("activated run binding refused", w.Code, w.Body.String(), g.calls.Load())
	}
}

// One live binding per (generation, run_id, account): a second slot for the
// tuple of an active binding refuses CONFLICT and persists nothing; the exact
// retry of the same slot returns the same credential; after Revoke, and after
// expiry without any Revoke, the tuple is TERMINAL for a new slot; a different
// account with the same generation and run is unaffected before and after.
func TestRunTupleUnique(t *testing.T) {
	g := gatewayFixture(t, ModeManaged, newFakeSource(sourceMarker))
	second := runBinding("5", "a")
	if second.Run != g.b.Run || second.SlotID == g.b.SlotID {
		t.Fatal("tuple fixture calibration failed")
	}
	if _, e := g.s.Prepare(second); e == nil || e.Error() != "CONFLICT" {
		t.Fatal("second slot for an active tuple prepared", e)
	}
	if _, e := g.s.Status(second.SlotID); e == nil {
		t.Fatal("refused duplicate persisted")
	}
	retry, e := g.s.Prepare(g.b)
	if e != nil || !retry.Equal(g.cred) {
		t.Fatal("exact retry changed", e)
	}
	other := runBinding("5", "b")
	if _, e = g.s.Prepare(other); e != nil {
		t.Fatal("different account refused", e)
	}
	if e = g.s.Revoke(g.b); e != nil {
		t.Fatal(e)
	}
	if _, e = g.s.Prepare(runBinding("6", "a")); e == nil || e.Error() != "TERMINAL" {
		t.Fatal("revoked tuple re-prepared", e)
	}
	if _, e = g.s.Status(strings.Repeat("6", 64)); e == nil {
		t.Fatal("refused terminal tuple persisted")
	}
	// Slot 5 (account b) expires without any Revoke; the tuple stays terminal.
	g.now.Store(other.NotAfter)
	late := runBinding("7", "b")
	late.NotAfter = other.NotAfter + 3000
	if _, e = g.s.Prepare(late); e == nil || e.Error() != "TERMINAL" {
		t.Fatal("expired tuple re-prepared", e)
	}
	fresh := runBinding("8", "c")
	fresh.NotAfter = other.NotAfter + 3000
	if _, e = g.s.Prepare(fresh); e != nil {
		t.Fatal("unrelated tuple refused after expiry", e)
	}
}

// A run window above the sealed maximum refuses RUN_WINDOW at Prepare without
// persisting; the exact maximum admits; a zero sealed maximum admits no run
// binding; the rental 3600 s cap is unchanged beside a 7200 s run maximum.
func TestRunBindingWindow(t *testing.T) {
	g := gatewayFixture(t, ModeManaged, newFakeSource(sourceMarker))
	over := runBinding("5", "b")
	over.NotAfter = over.NotBefore + 7201
	if _, e := g.s.Prepare(over); e == nil || e.Error() != "RUN_WINDOW" {
		t.Fatal("run window above sealed maximum accepted", e)
	}
	if _, e := g.s.Status(over.SlotID); e == nil {
		t.Fatal("refused run binding persisted")
	}
	exact := over
	exact.NotAfter = exact.NotBefore + 7200
	if _, e := g.s.Prepare(exact); e != nil {
		t.Fatal("exact sealed maximum refused", e)
	}
	rental := Binding{SlotID: strings.Repeat("6", 64), GrantID: strings.Repeat("2", 64), NotBefore: 90, NotAfter: 90 + 3601, Caps: g.b.Caps}
	if _, e := g.s.Prepare(rental); e == nil || e.Error() != "BINDING" {
		t.Fatal("rental cap changed", e)
	}
	rental.NotAfter = 90 + 3600
	if _, e := g.s.Prepare(rental); e != nil {
		t.Fatal("rental exact cap refused", e)
	}
	g.s.cfg.RunMaxWindowSeconds = 0
	if _, e := g.s.Prepare(runBinding("7", "b")); e == nil || e.Error() != "RUN_WINDOW" {
		t.Fatal("zero sealed maximum admitted a run binding", e)
	}
	if _, e := g.s.Prepare(rental); e != nil {
		t.Fatal("rental binding depends on run maximum", e)
	}
}

// Run fields are decoded strictly: all three digests are required together, a
// window above MaxRunWindow is structurally invalid, and a sealed maximum above
// MaxRunWindow is refused by New and by the sealed decoder; the exact maximum
// and legacy bytes without the tail are admitted.
func TestRunBindingStructure(t *testing.T) {
	b := runBinding("1", "a")
	if !b.Valid() || b.Kind() != KindRun {
		t.Fatal("valid run binding refused")
	}
	for _, mutate := range []func(*Binding){
		func(b *Binding) { b.Run.RunID = "" },
		func(b *Binding) { b.Run.Account = strings.ToUpper(strings.Repeat("a", 64)) },
		func(b *Binding) { b.Run.Generation = strings.Repeat("3", 63) },
		func(b *Binding) { b.NotAfter = b.NotBefore + MaxRunWindow + 1 },
	} {
		bad := b
		mutate(&bad)
		if bad.Valid() {
			t.Fatal("malformed run binding accepted")
		}
	}
	wide := b
	wide.NotAfter = wide.NotBefore + MaxRunWindow
	if !wide.Valid() {
		t.Fatal("hard run ceiling refused")
	}
	if (Binding{}).Kind() != KindRental || bytes.Contains(privateCanonical(Binding{}), []byte(`"run"`)) {
		t.Fatal("rental wire bytes changed")
	}
	g := gatewayFixture(t, ModeManaged, newFakeSource(sourceMarker))
	g.s.Close()
	c := g.c
	c.RunMaxWindowSeconds = MaxRunWindow + 1
	if s, e := New(c); e == nil || e.Error() != "CONFIG_RUN_WINDOW" || s != nil {
		t.Fatal("sealed maximum above 12 h accepted by New", e)
	}
	c.RunMaxWindowSeconds = MaxRunWindow
	s, e := New(c)
	if e != nil {
		t.Fatal("exact 12 h maximum refused by New", e)
	}
	s.Close()
	for _, tc := range []struct {
		name, raw, want string
	}{
		{"legacy", string(privateCanonical(FileConfig{DailyCostCeilingNanoUSD: 230})), ""},
		{"tail", string(privateCanonical(GatewayFileConfig{FileConfig: FileConfig{DailyCostCeilingNanoUSD: 230}, Mode: ModeManaged, RunMaxWindowSeconds: MaxRunWindow})), ""},
		{"run-over", string(privateCanonical(GatewayFileConfig{FileConfig: FileConfig{DailyCostCeilingNanoUSD: 230}, Mode: ModeManaged, RunMaxWindowSeconds: MaxRunWindow + 1})), "CONFIG_RUN_WINDOW"},
		{"mode", string(privateCanonical(GatewayFileConfig{FileConfig: FileConfig{DailyCostCeilingNanoUSD: 230}, Mode: "staging"})), "CONFIG_MODE"},
		{"empty-mode", strings.TrimSuffix(string(privateCanonical(FileConfig{DailyCostCeilingNanoUSD: 230})), "}") + `,"mode":""}`, "CONFIG_FILE"},
		{"tail-order", strings.TrimSuffix(string(privateCanonical(FileConfig{DailyCostCeilingNanoUSD: 230})), "}") + `,"run_max_window_seconds":60,"mode":"managed"}`, "CONFIG_FILE"},
	} {
		got, e := ParseGatewayConfig([]byte(tc.raw))
		code := ""
		if e != nil {
			code = e.Error()
		}
		if code != tc.want {
			t.Fatalf("sealed decode %s: %q want %q", tc.name, code, tc.want)
		}
		if e == nil && (got.DailyCostCeilingNanoUSD != 230 || string(privateCanonical(got)) != tc.raw) {
			t.Fatal("sealed decode changed bytes", tc.name)
		}
		if tc.name == "tail" && (got.Mode != ModeManaged || got.RunMaxWindowSeconds != MaxRunWindow) {
			t.Fatal("sealed tail not loaded")
		}
		if tc.name == "legacy" && (got.Mode != "" || got.RunMaxWindowSeconds != 0) {
			t.Fatal("legacy config grew a tail")
		}
	}
	path := filepath.Join(t.TempDir(), "config.json")
	writeInstalled(t, path, privateCanonical(GatewayFileConfig{FileConfig: FileConfig{DailyCostCeilingNanoUSD: 230}, Mode: ModeDevelopment, RunMaxWindowSeconds: 60}))
	if got, e := LoadGatewayConfig(path); e != nil || got.Mode != ModeDevelopment || got.RunMaxWindowSeconds != 60 {
		t.Fatal("installed gateway config not loaded", e)
	}
}

// A run binding past NotAfter is refused with no upstream call even when no
// Revoke arrived; the daily ceiling admits an exact run reservation and refuses
// one nano-unit more before any provider call, exactly as for rental bindings.
func TestRunBindingExpiryAndCeiling(t *testing.T) {
	g := gatewayFixture(t, ModeManaged, newFakeSource(sourceMarker))
	if g.send(request(false)).Code != 200 {
		t.Fatal("run binding positive neighbor refused")
	}
	g.now.Store(g.b.NotAfter)
	if w := g.send(request(false)); w.Code != 401 || g.calls.Load() != 1 {
		t.Fatal("expired run binding forwarded", w.Code)
	}
	for _, ceiling := range []uint64{230, 229} {
		g := gatewayFixture(t, ModeManaged, newFakeSource(sourceMarker), ceiling)
		g.upstream = fullCostReply
		w := g.send(request(false))
		if ceiling == 230 && (w.Code != 200 || g.calls.Load() != 1) {
			t.Fatal("exact run daily ceiling refused", w.Code, w.Body.String())
		}
		if ceiling == 229 && (w.Code != 403 || w.Body.String() != `{"error":"DAILY_COST_CEILING"}` || g.calls.Load() != 0) {
			t.Fatal("run daily ceiling+1 forwarded", w.Code, w.Body.String())
		}
	}
}

// messagesFrameWriter publishes once a complete message_start frame has been
// flushed downstream; only the handler goroutine touches the recorder.
type messagesFrameWriter struct {
	*httptest.ResponseRecorder
	frame chan struct{}
	sent  bool
}

func (w *messagesFrameWriter) Flush() {
	w.ResponseRecorder.Flush()
	if !w.sent && strings.HasPrefix(w.Body.String(), "event: message_start\n") && strings.HasSuffix(w.Body.String(), "\n\n") {
		w.sent = true
		close(w.frame)
	}
}

// Revoke follows the pre-header revocation contract for a run binding: the
// blocked upstream call is cancelled, before upstream headers the client gets
// 502 UPSTREAM, and after a downstream frame was flushed the stream is cut with
// proxy_error and no message_stop. Both retain the full reservation, make no
// retry and refuse the bearer afterwards.
func TestRunRevokeMidStream(t *testing.T) {
	for _, kind := range []string{"pre-header", "established"} {
		t.Run(kind, func(t *testing.T) {
			g := gatewayFixture(t, ModeManaged, newFakeSource(sourceMarker))
			g.s.cfg.Timeout = 20 * time.Second
			entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
			// The handler is released on every exit path so a failed assertion
			// can never leave the loopback server blocked in Close.
			defer close(release)
			g.upstream = func(w http.ResponseWriter, r *http.Request) {
				if kind == "established" {
					w.Header().Set("Content-Type", "text/event-stream")
					frames := strings.SplitAfterN(sse(7, 3), "\n\n", 3)
					_, _ = io.WriteString(w, frames[0]+frames[1])
					w.(http.Flusher).Flush()
				}
				close(entered)
				select {
				case <-r.Context().Done():
					close(cancelled)
				case <-release:
				}
			}
			writer := &messagesFrameWriter{ResponseRecorder: httptest.NewRecorder(), frame: make(chan struct{})}
			done := make(chan struct{})
			go func() {
				g.sendTo(writer, strings.NewReader(request(kind == "established")), g.b.SlotID, g.cred.Bearer.Reveal(), nil)
				close(done)
			}()
			select {
			case <-entered:
			case <-time.After(2 * time.Second):
				t.Fatal("upstream not entered")
			}
			if kind == "established" {
				select {
				case <-writer.frame:
				case <-time.After(2 * time.Second):
					t.Fatal("downstream frame was not flushed")
				}
			}
			if e := g.s.Revoke(g.b); e != nil {
				t.Fatal(e)
			}
			select {
			case <-cancelled:
			case <-time.After(2 * time.Second):
				t.Fatal("revoke did not cancel the in-flight upstream call")
			}
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("revoked run call remained blocked")
			}
			body := writer.Body.String()
			if kind == "established" {
				if strings.Contains(body, "message_stop") || !strings.Contains(body, "proxy_error") {
					t.Fatal("revoked established stream released success", body)
				}
			} else if writer.Code != 502 || body != `{"error":"UPSTREAM"}` {
				t.Fatal("revoked pre-header call did not return 502 UPSTREAM", writer.Code, body)
			}
			if v := g.status(t); v.Phase != "revoked" || v.Exposure != (Counts{100, 10, 1, 230}) || v.Observed != (Usage{}) || v.InFlight {
				t.Fatal("revoked run call refunded or settled", v)
			}
			if w := g.send(request(false)); w.Code != 401 || g.calls.Load() != 1 {
				t.Fatal("revoked run bearer reused or retried", w.Code)
			}
		})
	}
}

// The admin wire carries a run binding through prepare, activate and revoke
// with strict canonical bytes; a binding operation with an account and a clear
// with a binding are refused.
func TestRunBindingAdminWire(t *testing.T) {
	g := gatewayFixture(t, ModeManaged, newFakeSource(sourceMarker))
	b := runBinding("5", "b")
	send := func(raw []byte) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "http://local/v1/registry", bytes.NewReader(raw))
		r = r.WithContext(context.WithValue(r.Context(), peerKey{}, true))
		w := httptest.NewRecorder()
		g.s.adminHandler(w, r)
		return w
	}
	raw := privateCanonical(adminRequest{V: 1, Op: "prepare", Binding: b})
	if !bytes.Contains(raw, []byte(`"run":{"generation":"`)) {
		t.Fatal("run binding wire bytes missing")
	}
	w := send(raw)
	var out adminResponse
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.OK || out.Credential == nil || out.Binding != b {
		t.Fatal("run binding prepare refused", w.Code, w.Body.String())
	}
	for _, bad := range [][]byte{
		privateCanonical(adminRequest{V: 1, Op: "prepare", Binding: b, Account: b.Run.Account}),
		privateCanonical(adminRequest{V: 1, Op: "clear_block", Binding: b, Account: b.Run.Account}),
		privateCanonical(adminRequest{V: 1, Op: "clear_block"}),
		[]byte(strings.Replace(string(raw), `"run":{`, `"run":{"extra":1,`, 1)),
	} {
		if w := send(bad); w.Code != 400 {
			t.Fatal("malformed admin run request accepted", string(bad))
		}
	}
	if w = send(privateCanonical(adminRequest{V: 1, Op: "activate", Binding: b})); !strings.Contains(w.Body.String(), `"ok":true`) {
		t.Fatal("run activation refused")
	}
	if g.sendAs(request(false), b.SlotID, out.Credential.Bearer.Reveal(), nil).Code != 200 {
		t.Fatal("activated run binding refused")
	}
	if w = send(privateCanonical(adminRequest{V: 1, Op: "revoke", Binding: b})); !strings.Contains(w.Body.String(), `"ok":true`) {
		t.Fatal("run revocation refused")
	}
	if g.sendAs(request(false), b.SlotID, out.Credential.Bearer.Reveal(), nil).Code != 401 {
		t.Fatal("revoked run bearer forwarded")
	}
}
