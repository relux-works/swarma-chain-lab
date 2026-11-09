package relay

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	booking "relux.works/swarma-chain-lab/experiments/rental-booking"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/gateway"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/nostr"
)

func serve(t *testing.T, c Config) (*Relay, string) {
	t.Helper()
	r, e := New(c, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	s := httptest.NewServer(r)
	t.Cleanup(func() { r.Close(); s.Close() })
	return r, "ws" + strings.TrimPrefix(s.URL, "http")
}
func dial(t *testing.T, url string) (*websocket.Conn, string) {
	t.Helper()
	c, _, e := websocket.DefaultDialer.Dial(url, nil)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { c.Close() })
	send(t, c, []any{"CLOSE", "fixture-handshake"})
	m := read(t, c)
	if m[0] != "AUTH" {
		t.Fatal("no challenge", m)
	}
	return c, m[1].(string)
}
func read(t *testing.T, c *websocket.Conn) []any {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	var m []any
	if e := c.ReadJSON(&m); e != nil {
		t.Fatal("read", e)
	}
	return m
}
func send(t *testing.T, c *websocket.Conn, v any) {
	t.Helper()
	c.SetWriteDeadline(time.Now().Add(time.Second))
	if e := c.WriteJSON(v); e != nil {
		t.Fatal(e)
	}
}
func ack(t *testing.T, c *websocket.Conn, accepted bool, prefix string) {
	t.Helper()
	m := read(t, c)
	if len(m) != 4 || m[0] != "OK" || m[2] != accepted || !strings.HasPrefix(m[3].(string), prefix) {
		t.Fatalf("ACK want %v/%s got %v", accepted, prefix, m)
	}
}
func key(t *testing.T) *nostr.PrivKey {
	t.Helper()
	k, e := nostr.GeneratePrivKey()
	if e != nil {
		t.Fatal(e)
	}
	return k
}
func authEvent(t *testing.T, k *nostr.PrivKey, c Config, challenge string) *nostr.Event {
	t.Helper()
	e := &nostr.Event{Kind: 22242, CreatedAt: time.Now().Unix(), Tags: [][]string{{"relay", c.PublicURL}, {"challenge", challenge}}}
	if err := k.SignEvent(e); err != nil {
		t.Fatal(err)
	}
	return e
}

// Actual gateway client sends and unwraps a signed gift wrap through this relay;
// only durable acceptance/duplicate returns success, one subscription delivery.
func TestGatewayRoundTrip(t *testing.T) {
	cfg := fixtureConfig(t)
	r, url := serve(t, cfg)
	a, b := key(t), key(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := &gateway.RelayClient{URL: url}
	defer client.Close()
	got := make(chan *nostr.Event, 2)
	done := make(chan error, 1)
	go func() {
		done <- client.SubscribeGiftWraps(ctx, b.PubKeyHex(), func(_ context.Context, e *nostr.Event) { got <- e })
	}()
	defer func() {
		cancel()
		client.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("subscriber leaked")
		}
	}()
	// Inspect registration, not an arbitrary sleep, before publishing.
	end := time.Now().Add(time.Second)
	for {
		r.mu.Lock()
		ready := false
		for p := range r.peers {
			ready = ready || len(p.subs) > 0
		}
		r.mu.Unlock()
		if ready {
			break
		}
		if time.Now().After(end) {
			t.Fatal("subscription readiness")
		}
		time.Sleep(time.Millisecond)
	}
	sender := &gateway.RelayClient{URL: url}
	defer sender.Close()
	ev, _, e := nostr.WrapDM(a, b.PubKeyHex(), "terms", nil, time.Now().Unix())
	if e != nil {
		t.Fatal(e)
	}
	call, stop := context.WithTimeout(ctx, 3*time.Second)
	defer stop()
	if e = sender.Publish(call, ev); e != nil {
		t.Fatal(e)
	}
	select {
	case v := <-got:
		u, e := nostr.UnwrapDM(v, b)
		if e != nil || u.Rumor.Content != "terms" || u.SenderHex != a.PubKeyHex() {
			t.Fatal("wrong decrypted binding", e)
		}
	case <-call.Done():
		t.Fatal("missing gift wrap")
	}
	if e = sender.Publish(call, ev); e != nil {
		t.Fatal("duplicate ACK", e)
	}
	r.mu.Lock()
	n := len(r.store.events)
	r.mu.Unlock()
	if n != 1 {
		t.Fatal("duplicate durable effects")
	}
	select {
	case <-got:
		t.Fatal("duplicate broadcast")
	case <-time.After(20 * time.Millisecond):
	}
}

// AUTH is connection-bound, URL/time-bound, ephemeral, and cannot authorize
// another recipient. Multiple identities can be authenticated independently.
func TestAuthentication(t *testing.T) {
	cfg := fixtureConfig(t)
	cfg.RequireWriteAuth = true
	cfg.RestrictGiftWrapReads = true
	r, url := serve(t, cfg)
	a, b := key(t), key(t)
	c, ch := dial(t, url)
	ev, _, _ := nostr.WrapDM(a, b.PubKeyHex(), "private", nil, time.Now().Unix())
	send(t, c, []any{"EVENT", ev})
	ack(t, c, false, "auth-required:")
	send(t, c, []any{"REQ", "x", map[string]any{"kinds": []int{1059}}})
	if m := read(t, c); m[0] != "CLOSED" || !strings.HasPrefix(m[2].(string), "auth-required:") {
		t.Fatal("unauthenticated read", m)
	}
	good := authEvent(t, a, cfg, ch)
	for _, change := range []string{"challenge", "url", "time", "kind", "signature", "duplicate-tag"} {
		bad := authEvent(t, a, cfg, ch)
		switch change {
		case "challenge":
			bad.Tags[1][1] = "wrong"
		case "url":
			bad.Tags[0][1] = "wss://other.example/"
		case "time":
			bad.CreatedAt -= 601
		case "kind":
			bad.Kind = 8182
		case "duplicate-tag":
			bad.Tags = append(bad.Tags, bad.Tags[0])
		}
		a.SignEvent(bad)
		if change == "signature" {
			if bad.Sig[0] == '0' {
				bad.Sig = "1" + bad.Sig[1:]
			} else {
				bad.Sig = "0" + bad.Sig[1:]
			}
		}
		send(t, c, []any{"AUTH", bad})
		ack(t, c, false, "restricted:")
	}
	send(t, c, []any{"AUTH", good})
	ack(t, c, true, "")
	send(t, c, []any{"EVENT", ev})
	ack(t, c, true, "")
	send(t, c, []any{"REQ", "x", map[string]any{"kinds": []int{1059}, "#p": []string{b.PubKeyHex()}}})
	if m := read(t, c); m[0] != "EOSE" {
		t.Fatal("foreign recipient leaked", m)
	}
	other, _ := dial(t, url)
	send(t, other, []any{"AUTH", good})
	ack(t, other, false, "restricted:")
	send(t, c, []any{"AUTH", authEvent(t, b, cfg, ch)})
	ack(t, c, true, "")
	send(t, c, []any{"REQ", "x", map[string]any{"kinds": []int{1059}}})
	if m := read(t, c); m[0] != "EVENT" {
		t.Fatal("recipient positive", m)
	}
	if m := read(t, c); m[0] != "EOSE" {
		t.Fatal(m)
	}
	r.mu.Lock()
	n := len(r.store.events)
	r.mu.Unlock()
	if n != 1 {
		t.Fatal("AUTH stored or refused publication persisted")
	}
}

// Backlog is newest-first with per-filter limits, while limit0 remains live.
// A refused replacement closes the old subscription and CLOSE removes it.
func TestSubscriptions(t *testing.T) {
	cfg := fixtureConfig(t)
	r, url := serve(t, cfg)
	c, _ := dial(t, url)
	now := time.Now().Unix()
	events := []*nostr.Event{event(t, 8182, now-2), event(t, 8182, now-1), event(t, 8181, now)}
	for _, e := range events {
		send(t, c, []any{"EVENT", e})
		ack(t, c, true, "")
	}
	send(t, c, []any{"REQ", "x", map[string]any{"kinds": []int{8182}, "limit": 1}})
	m := read(t, c)
	if m[0] != "EVENT" || m[2].(map[string]any)["id"] != events[1].ID {
		t.Fatal("backlog order", m)
	}
	if read(t, c)[0] != "EOSE" {
		t.Fatal("extra backlog")
	}
	send(t, c, []any{"REQ", "x", map[string]any{"kinds": []int{8182}, "limit": 0}})
	if read(t, c)[0] != "EOSE" {
		t.Fatal("zero backlog")
	}
	send(t, c, []any{"EVENT", event(t, 8182, now)})
	ack(t, c, true, "")
	if read(t, c)[0] != "EVENT" {
		t.Fatal("zero limit suppressed live")
	}
	send(t, c, []any{"REQ", "x", map[string]any{"unknown": 1}})
	if read(t, c)[0] != "CLOSED" {
		t.Fatal("bad filter")
	}
	r.mu.Lock()
	for p := range r.peers {
		if len(p.subs) != 0 {
			t.Error("refused replacement left old subscription")
		}
	}
	r.mu.Unlock()
	send(t, c, []any{"REQ", "x", map[string]any{"limit": 0}})
	read(t, c)
	send(t, c, []any{"CLOSE", "x"})
	send(t, c, []any{"REQ", "barrier", map[string]any{"ids": []string{}}})
	if read(t, c)[0] != "EOSE" {
		t.Fatal("empty ids widened")
	}
	r.mu.Lock()
	for p := range r.peers {
		if _, ok := p.subs["x"]; ok {
			t.Error("CLOSE ignored")
		}
	}
	r.mu.Unlock()
}

// Admission fails before ACK/broadcast when the actual persistence boundary
// fails; the same running relay accepted a valid durable neighbor first.
func TestWirePersistenceFailure(t *testing.T) {
	cfg := fixtureConfig(t)
	r, url := serve(t, cfg)
	c, _ := dial(t, url)
	send(t, c, []any{"EVENT", event(t, 8182, time.Now().Unix())})
	ack(t, c, true, "")
	r.mu.Lock()
	r.store.save = func([]byte) error { return fail("fixture") }
	r.mu.Unlock()
	send(t, c, []any{"EVENT", event(t, 8182, time.Now().Unix())})
	ack(t, c, false, "error:")
	r.mu.Lock()
	n := len(r.store.events)
	r.mu.Unlock()
	if n != 1 {
		t.Fatal("failed write added event")
	}
}

// Per-IP admission uses a configured proxy only. Spoofed headers cannot choose
// a budget; one saturated address does not prevent a distinct address's work.
func TestPeerLimits(t *testing.T) {
	cfg := fixtureConfig(t)
	cfg.MaxConnectionsPerIP = 1
	r, url := serve(t, cfg)
	c, _ := dial(t, url)
	_, resp, e := websocket.DefaultDialer.Dial(url, http.Header{"X-Real-IP": []string{"192.0.2.1"}})
	if e == nil || resp.StatusCode != 429 {
		t.Fatal("connection IP bypass")
	}
	c.Close()
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.0.2.1:123"
	req.Header.Set("X-Real-IP", "192.0.2.2")
	if got, e := r.clientIP(req); e != nil || got != "192.0.2.1" {
		t.Fatal("spoofed proxy")
	}
	r.mu.Lock()
	r.cfg.TrustedProxyIP = "192.0.2.1"
	r.mu.Unlock()
	if got, e := r.clientIP(req); e != nil || got != "192.0.2.2" {
		t.Fatal("trusted proxy")
	}
	req.Header.Set("X-Real-IP", "192.0.2.2, 192.0.2.3")
	if _, e := r.clientIP(req); e == nil {
		t.Fatal("proxy chain accepted")
	}
	if !r.reserve("192.0.2.4") {
		t.Fatal("independent IP refused")
	}
	r.release("192.0.2.4")
}

// Outer PoW is independently configured: inner encrypted work is not inspected,
// unknown authors gain no exemption by publishing, and an explicit known key is
// the valid exemption control. Targetless luck never substitutes for a nonce.
func TestOuterWork(t *testing.T) {
	cfg := fixtureConfig(t)
	cfg.UnknownPowBits = 4
	k := key(t)
	cfg.KnownPubkeys = []string{k.PubKeyHex()}
	r, url := serve(t, cfg)
	c, _ := dial(t, url)
	a := event(t, 8182, time.Now().Unix())
	send(t, c, []any{"EVENT", a})
	ack(t, c, false, "pow:")
	known := &nostr.Event{Kind: 8182, CreatedAt: time.Now().Unix(), Tags: [][]string{}}
	k.SignEvent(known)
	send(t, c, []any{"EVENT", known})
	ack(t, c, true, "")
	unknown := key(t)
	mined := &nostr.Event{Kind: 8182, CreatedAt: time.Now().Unix(), Tags: [][]string{{"nonce", "0", "4"}}}
	for n := 0; ; n++ {
		mined.Tags[0][1] = fmtInt(n)
		unknown.SignEvent(mined)
		if strings.HasPrefix(mined.ID, "0") {
			break
		}
	}
	send(t, c, []any{"EVENT", mined})
	ack(t, c, true, "")
	plain := &nostr.Event{Kind: 8182, CreatedAt: time.Now().Unix(), Tags: [][]string{}}
	unknown.SignEvent(plain)
	send(t, c, []any{"EVENT", plain})
	ack(t, c, false, "pow:")
	r.mu.Lock()
	n := len(r.store.events)
	r.mu.Unlock()
	if n != 2 {
		t.Fatal("PoW refusal effects")
	}
}
func fmtInt(n int) string { b, _ := json.Marshal(n); return string(b) }

// The landed booking publisher reads its OK as the first response. Optional
// AUTH must not mask that durable ACK; both accepted and stored-duplicate paths
// use the actual product adapter, not a test-only replacement.
func TestBookingPublisher(t *testing.T) {
	cfg := fixtureConfig(t)
	_, url := serve(t, cfg)
	publisher, e := booking.NewRelayPublisher(url)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(event(t, 8182, time.Now().Unix()))
	var v booking.Event
	if e = json.Unmarshal(raw, &v); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 2; i++ {
		if e = publisher.Publish(context.Background(), v); e != nil {
			t.Fatal("booking first ACK", e)
		}
	}
}
