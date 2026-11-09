package relay

import (
	"encoding/json"
	"github.com/gorilla/websocket"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Exhausted connection/frame/IP-table budgets preserve neighboring capacity;
// disconnect does not reset an IP's rate history, but a completed window does.
func TestQuotaBoundaries(t *testing.T) {
	cfg := fixtureConfig(t)
	cfg.MaxConnections = 2
	cfg.MaxConnectionsPerIP = 1
	cfg.MaxIPs = 2
	cfg.FramesPerMinute = 2
	cfg.FramesPerIPMinute = 3
	now := time.Now()
	r, e := New(cfg, func() time.Time { return now })
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	if !r.reserve("192.0.2.1") || r.reserve("192.0.2.1") || !r.reserve("192.0.2.2") || r.reserve("192.0.2.3") {
		t.Fatal("connection caps")
	}
	a, b := &peer{ip: "192.0.2.1"}, &peer{ip: "192.0.2.2"}
	if !r.allow(a) || !r.allow(a) || r.allow(a) || !r.allow(b) {
		t.Fatal("frame quota isolation")
	}
	r.release(a.ip)
	if r.reserve(a.ip) {
		t.Fatal("reconnect reset IP quota")
	}
	if r.reserve("192.0.2.3") {
		t.Fatal("IP table grew")
	}
	r.release(b.ip)
	now = now.Add(time.Minute)
	if !r.reserve("192.0.2.3") {
		t.Fatal("expired IP budget not reclaimed")
	}
	r.release("192.0.2.3")
}

// A full outbound queue closes only that slow peer; enqueue has no socket write
// or wait. An actual healthy connection can still receive a durable ACK.
func TestSlowPeer(t *testing.T) {
	cfg := fixtureConfig(t)
	_, url := serve(t, cfg)
	slow, _ := dial(t, url)
	p := &peer{ws: slow, out: make(chan []byte, 1), done: make(chan struct{})}
	p.send([]any{"NOTICE", "one"})
	done := make(chan struct{})
	go func() { p.send([]any{"NOTICE", "two"}); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("slow peer blocked enqueue")
	}
	select {
	case <-p.done:
	default:
		t.Fatal("full queue remained live")
	}
	healthy, _ := dial(t, url)
	send(t, healthy, []any{"EVENT", event(t, 8182, time.Now().Unix())})
	ack(t, healthy, true, "")
}

// Invalid, over-size and off-window input cannot enter storage; the next valid
// frame on the same connection still succeeds. An oversize frame closes its own
// connection without disabling a different client.
func TestWireRefusals(t *testing.T) {
	cfg := fixtureConfig(t)
	cfg.MaxEventBytes = 64925
	r, url := serve(t, cfg)
	c, _ := dial(t, url)
	for _, change := range []string{"signature", "kind", "past", "future", "size", "duplicate"} {
		v := event(t, 8182, time.Now().Unix())
		raw, _ := json.Marshal(v)
		switch change {
		case "signature":
			v.Content = "tampered"
			raw, _ = json.Marshal(v)
		case "kind":
			raw, _ = json.Marshal(event(t, 13, time.Now().Unix()))
		case "past":
			raw, _ = json.Marshal(event(t, 8182, time.Now().Unix()-cfg.RetentionSeconds-1))
		case "future":
			raw, _ = json.Marshal(event(t, 8182, time.Now().Unix()+cfg.FutureSeconds+2))
		case "size":
			v.Content = strings.Repeat("z", cfg.MaxEventBytes+1)
			if e := key(t).SignEvent(v); e != nil {
				t.Fatal(e)
			}
			raw, _ = json.Marshal(v)
		case "duplicate":
			raw = []byte(strings.Replace(string(raw), `"kind":8182`, `"kind":8182,"kind":8182`, 1))
		}
		send(t, c, []any{"EVENT", json.RawMessage(raw)})
		m := read(t, c)
		if m[0] == "OK" {
			if m[2] != false {
				t.Fatal("invalid ACK")
			}
		} else if m[0] != "NOTICE" {
			t.Fatal("unexpected refusal", m)
		}
	}
	r.mu.Lock()
	n := len(r.store.events)
	r.mu.Unlock()
	if n != 0 {
		t.Fatal("refused event persisted")
	}
	send(t, c, []any{"EVENT", event(t, 8182, time.Now().Unix())})
	ack(t, c, true, "")
	_ = c.WriteMessage(websocket.TextMessage, []byte(strings.Repeat("x", cfg.MaxEventBytes+1025)))
	c.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, e := c.ReadMessage(); e == nil {
		t.Fatal("oversize frame stayed open")
	}
	other, _ := dial(t, url)
	send(t, other, []any{"EVENT", event(t, 8181, time.Now().Unix())})
	ack(t, other, true, "")
}

// Only the configured subset of read routes and subscriptions is exposed.
// Authenticated positive control is separate from anonymous compatibility mode.
func TestReadAuthAndSubscriptionCap(t *testing.T) {
	cfg := fixtureConfig(t)
	cfg.RequireReadAuth = true
	cfg.Subscriptions = 1
	_, url := serve(t, cfg)
	c, ch := dial(t, url)
	send(t, c, []any{"REQ", "a", map[string]any{"kinds": []int{8182}}})
	if m := read(t, c); m[0] != "CLOSED" || !strings.HasPrefix(m[2].(string), "auth-required:") {
		t.Fatal("read auth bypass")
	}
	send(t, c, []any{"AUTH", authEvent(t, key(t), cfg, ch)})
	ack(t, c, true, "")
	send(t, c, []any{"REQ", "a", map[string]any{}})
	if read(t, c)[0] != "EOSE" {
		t.Fatal("read neighbor")
	}
	send(t, c, []any{"REQ", "b", map[string]any{}})
	if m := read(t, c); m[0] != "CLOSED" || !strings.HasPrefix(m[2].(string), "rate-limited:") {
		t.Fatal("subscription cap")
	}
	send(t, c, []any{"CLOSE", "a"})
	send(t, c, []any{"REQ", "b", map[string]any{}})
	if read(t, c)[0] != "EOSE" {
		t.Fatal("capacity not recovered")
	}
}

// Expiry is durably pruned without a new event; a smaller byte cap refuses a
// large snapshot without losing the preceding durable event.
func TestRetentionAndBytes(t *testing.T) {
	cfg := fixtureConfig(t)
	cfg.MaxEventBytes = 1024
	cfg.MaxStoreBytes = 2048
	cfg.RetentionSeconds = 10
	now := time.Now().Unix()
	s, e := openStore(cfg, now)
	if e != nil {
		t.Fatal(e)
	}
	defer s.close()
	a := event(t, 8182, now)
	if _, e = s.put(a, now); e != nil {
		t.Fatal(e)
	}
	before, _ := os.ReadFile(filepath.Join(cfg.StateDir, "events.json"))
	huge := event(t, 8182, now)
	huge.Content = strings.Repeat("x", 2000)
	if _, e = s.put(huge, now); e == nil || e.Error() != "STORE_CAPACITY" {
		t.Fatal("store byte cap", e)
	}
	after, _ := os.ReadFile(filepath.Join(cfg.StateDir, "events.json"))
	if string(before) != string(after) {
		t.Fatal("capacity rewrote durable state")
	}
	if e = s.prune(now + 11); e != nil || len(s.events) != 0 {
		t.Fatal("idle retention", e)
	}
	s.close()
	s, e = openStore(cfg, now)
	if e != nil {
		t.Fatal(e)
	}
	defer s.close()
	if len(s.events) != 0 {
		t.Fatal("pruned event resurrected")
	}
}

// Config/HTTP refusals occur before writable state or a WebSocket capability.
func TestConfigAndHTTP(t *testing.T) {
	cfg := fixtureConfig(t)
	if e := cfg.Validate(); e != nil {
		t.Fatal(e)
	}
	for _, mut := range []func(*Config){func(c *Config) { c.PublicURL = "ws://public.example" }, func(c *Config) { c.MaxConnections = 0 }, func(c *Config) { c.MaxIPs = 0 }, func(c *Config) { c.Backlog = c.Queue }, func(c *Config) { c.TrustedProxyIP = "127.0.0.1,192.0.2.1" }, func(c *Config) { c.UnknownPowBits = 33 }, func(c *Config) { c.KnownPubkeys = []string{"not-key"} }} {
		bad := cfg
		mut(&bad)
		if _, e := New(bad, time.Now); e == nil {
			t.Fatal("invalid config")
		}
		if _, e := os.Stat(cfg.StateDir); !os.IsNotExist(e) {
			t.Fatal("invalid config created state")
		}
	}
	r, _ := serve(t, cfg)
	for _, path := range []string{"/admin", "/?config=1", "/metrics"} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 404 {
			t.Fatal("extra HTTP surface")
		}
	}
}

// The largest compact REQ permits four full 16KiB filters and worst-case JSON
// escaping of a 64-byte ID and "REQ". Exact derived read capacity loads and
// serves it; one byte less refuses before any state directory is created.
// Arbitrary additional envelope whitespace remains transport-bounded.
func TestRequestReadLimit(t *testing.T) {
	const frameBytes = 65949 // 4*16384 + 64*6 + 3*6 + 2+2+2+5
	cfg := fixtureConfig(t)
	cfg.MaxEventBytes = frameBytes - 1024
	raw, _ := json.Marshal(cfg)
	if _, e := ParseConfig(raw); e != nil {
		t.Fatal("REQ boundary refused", e)
	}
	bad := cfg
	bad.MaxEventBytes--
	raw, _ = json.Marshal(bad)
	if _, e := ParseConfig(raw); e == nil || e.Error() != "CONFIG_LIMIT" {
		t.Fatal("short REQ read limit accepted", e)
	}
	if r, e := New(bad, time.Now); e == nil || e.Error() != "CONFIG_LIMIT" {
		if r != nil {
			r.Close()
		}
		t.Fatal("short REQ limit opened state", e)
	}
	if _, e := os.Stat(cfg.StateDir); !os.IsNotExist(e) {
		t.Fatal("rejected REQ limit created state")
	}
	_, url := serve(t, cfg)
	c, _ := dial(t, url)
	filter := "{" + strings.Repeat(" ", 16382) + "}"
	id := strings.Repeat(`\u0001`, 64)
	frame := `["\u0052\u0045\u0051","` + id + `",` + strings.Repeat(filter+",", 3) + filter + "]"
	if len(frame) != frameBytes {
		t.Fatal("REQ fixture boundary size", len(frame))
	}
	if e := c.WriteMessage(websocket.TextMessage, []byte(frame)); e != nil {
		t.Fatal(e)
	}
	var m []any
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if e := c.ReadJSON(&m); e != nil {
		t.Fatal("maximal REQ not served", e)
	}
	if len(m) != 2 || m[0] != "EOSE" || m[1] != strings.Repeat("\x01", 64) {
		t.Fatal("maximal REQ not served")
	}
	send(t, c, []any{"REQ", "neighbor", map[string]any{}})
	if read(t, c)[0] != "EOSE" {
		t.Fatal("REQ connection not reusable")
	}
}
