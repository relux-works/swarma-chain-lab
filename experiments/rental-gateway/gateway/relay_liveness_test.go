package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/gorilla/websocket"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Client-originated pings keep a passive third-party relay alive; its missing
// pongs are detected even without any application traffic. No server pings.
func TestClientHeartbeat(t *testing.T) {
	for _, respond := range []bool{true, false} {
		t.Run(map[bool]string{true: "pong", false: "silent"}[respond], func(t *testing.T) {
			var pings atomic.Int32
			url := authFixture(t, func(c *websocket.Conn, _ string) {
				c.SetPingHandler(func(s string) error {
					pings.Add(1)
					if !respond {
						return nil
					}
					return c.WriteControl(websocket.PongMessage, []byte(s), time.Now().Add(time.Second))
				})
				typ, _ := authRead(c)
				if typ != "REQ" {
					return
				}
				_ = c.WriteJSON([]any{"EOSE", "gw-inbox"})
				for {
					if _, _, e := c.ReadMessage(); e != nil {
						return
					}
				}
			})
			c := &RelayClient{URL: url, ReadTimeout: 300 * time.Millisecond, PingInterval: 60 * time.Millisecond}
			defer c.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- c.RunGiftWraps(ctx, strings.Repeat("a", 64), func(context.Context, *nostr.Event) {}) }()
			select {
			case <-done:
				t.Fatal("heartbeat subscription exited")
			case <-time.After(1200 * time.Millisecond):
			}
			if respond {
				if pings.Load() < 10 || c.Status().Reconnects != 0 {
					t.Error("client heartbeat did not maintain idle connection")
				}
			} else {
				if c.Status().Reconnects == 0 {
					t.Error("silent relay did not trigger reconnect")
				}
			}
			cancel()
			c.Close()
			select {
			case e := <-done:
				if !errors.Is(e, context.Canceled) {
					t.Error("cancel not returned")
				}
			case <-time.After(time.Second):
				t.Fatal("heartbeat loop leaked")
			}
		})
	}
}

// A permanent policy refusal is fatal and is never retried as transport loss.
// Temporary HTTP/transport failures back off within a cap and cancel promptly.
func TestReconnectRefusalAndBackoff(t *testing.T) {
	var calls atomic.Int32
	url := authFixture(t, func(c *websocket.Conn, _ string) {
		calls.Add(1)
		_, _ = authRead(c)
		_ = c.WriteJSON([]any{"CLOSED", "gw-inbox", "restricted: denied"})
	})
	c := &RelayClient{URL: url}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if e := c.RunGiftWraps(ctx, strings.Repeat("a", 64), func(context.Context, *nostr.Event) {}); e != ErrRelayRejected || calls.Load() != 1 || c.Status().Reconnects != 0 {
		t.Fatal("fatal refusal retried")
	}
	calls.Store(0)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); http.Error(w, "down", 503) }))
	defer srv.Close()
	c = &RelayClient{URL: "ws" + strings.TrimPrefix(srv.URL, "http"), ReconnectMin: 20 * time.Millisecond, ReconnectMax: 50 * time.Millisecond}
	defer c.Close()
	ctx, cancel = context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	if e := c.RunGiftWraps(ctx, strings.Repeat("a", 64), func(context.Context, *nostr.Event) {}); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("backoff cancellation")
	}
	if n := calls.Load(); n < 9 || n > 12 {
		t.Fatalf("backoff was not capped and bounded: %d", n)
	}
}

// Persistent reconnect signs a new required-AUTH challenge on each connection;
// the fixture refuses any REQ arriving before that connection's positive ACK.
func TestPersistentAuthReconnect(t *testing.T) {
	key, _ := nostr.GeneratePrivKey()
	var connects, auths, subscriptions atomic.Int32
	url := authFixture(t, func(c *websocket.Conn, relay string) {
		n := connects.Add(1)
		// Delayed challenge exposes any pre-AUTH REQ already buffered on the wire.
		time.Sleep(20 * time.Millisecond)
		challenge := strings.Repeat("d", int(n))
		_ = c.WriteJSON([]any{"AUTH", challenge})
		typ, m := authRead(c)
		if typ != "AUTH" {
			t.Error("persistent REQ preceded AUTH")
			return
		}
		ev, ok := authValid(m[1], relay, challenge)
		if !ok {
			t.Error("persistent auth wrong binding")
			return
		}
		auths.Add(1)
		_ = c.WriteJSON([]any{"OK", ev.ID, true, ""})
		typ, _ = authRead(c)
		if typ != "REQ" {
			t.Error("persistent authenticated REQ missing")
			return
		}
		subscriptions.Add(1)
		_ = c.WriteJSON([]any{"EOSE", "gw-inbox"})
		if n == 1 {
			return
		}
		for {
			if _, _, e := c.ReadMessage(); e != nil {
				return
			}
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &RelayClient{URL: url, Auth: RelayAuthRequired, AgentKey: key, ReconnectMin: 10 * time.Millisecond}
	defer c.Close()
	done := make(chan error, 1)
	go func() { done <- c.RunGiftWraps(ctx, key.PubKeyHex(), func(context.Context, *nostr.Event) {}) }()
	deadline := time.Now().Add(2 * time.Second)
	for auths.Load() < 2 || subscriptions.Load() < 2 {
		select {
		case e := <-done:
			t.Fatal("persistent auth exited", e)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("fresh AUTH not repeated")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	c.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("persistent auth leaked")
	}
}

// Invalid liveness/page bounds refuse before dialing; valid defaults and a short
// adjacent policy are accepted. URL configuration failure is fatal, not retried.
func TestClientLivenessConfig(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); http.Error(w, "unused", 503) }))
	defer srv.Close()
	base := RelayClient{URL: "ws" + strings.TrimPrefix(srv.URL, "http")}
	if base.validateLiveness() != nil {
		t.Fatal("valid client defaults")
	}
	for _, change := range []func(*RelayClient){func(c *RelayClient) { c.URL = "invalid" }, func(c *RelayClient) { c.ReadTimeout = -1 }, func(c *RelayClient) { c.PingInterval = 90 * time.Second }, func(c *RelayClient) { c.ReconnectMin = -1 }, func(c *RelayClient) { c.ReconnectMax = time.Millisecond }, func(c *RelayClient) { c.ReplayLimit = 1 }, func(c *RelayClient) { c.ReplayLimit = 4097 }} {
		c := &RelayClient{URL: base.URL}
		change(c)
		if e := c.RunGiftWraps(context.Background(), strings.Repeat("a", 64), func(context.Context, *nostr.Event) {}); e != ErrRelayConfig || calls.Load() != 0 {
			t.Fatal("invalid client policy caused dial")
		}
	}
	c := &RelayClient{URL: base.URL, ReadTimeout: 300 * time.Millisecond, PingInterval: 60 * time.Millisecond, ReconnectMin: time.Millisecond, ReconnectMax: 10 * time.Millisecond, ReplayLimit: 2}
	if c.validateLiveness() != nil {
		t.Fatal("valid adjacent client policy")
	}
}

// Catchup uses a second subscription: a fresh live event received during the
// historical page is still delivered. These are signed transport fixtures, not
// decrypted rental messages (native application dedup is covered in relay).
func TestReplayKeepsLiveInbox(t *testing.T) {
	key, _ := nostr.GeneratePrivKey()
	mk := func(at int64) *nostr.Event {
		e := &nostr.Event{Kind: nostr.KindGiftWrap, CreatedAt: at, Tags: [][]string{{"p", key.PubKeyHex()}}, Content: "transport fixture"}
		if err := key.SignEvent(e); err != nil {
			t.Fatal(err)
		}
		return e
	}
	now := time.Now().Unix()
	newer, older, live := mk(now-10), mk(now-11), mk(now)
	url := authFixture(t, func(c *websocket.Conn, _ string) {
		typ, _ := authRead(c)
		if typ != "REQ" {
			return
		}
		_ = c.WriteJSON([]any{"EVENT", "gw-inbox", newer})
		_ = c.WriteJSON([]any{"EVENT", "gw-inbox", older})
		_ = c.WriteJSON([]any{"EOSE", "gw-inbox"})
		typ, m := authRead(c)
		var id string
		if len(m) > 1 {
			_ = json.Unmarshal(m[1], &id)
		}
		if typ != "REQ" || id != "gw-catchup" {
			t.Error("catchup replaced live inbox")
			return
		}
		_ = c.WriteJSON([]any{"EVENT", "gw-inbox", live})
		_ = c.WriteJSON([]any{"EVENT", "gw-catchup", older})
		_ = c.WriteJSON([]any{"EOSE", "gw-catchup"})
		for {
			if _, _, e := c.ReadMessage(); e != nil {
				return
			}
		}
	})
	c := &RelayClient{URL: url, ReplayLimit: 2}
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got := make(chan string, 8)
	done := make(chan error, 1)
	go func() {
		done <- c.RunGiftWraps(ctx, key.PubKeyHex(), func(_ context.Context, e *nostr.Event) { got <- e.ID })
	}()
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	found := false
	for !found {
		select {
		case id := <-got:
			found = id == live.ID
		case <-timer.C:
			t.Error("live event lost during catchup")
			found = true
		}
	}
	cancel()
	c.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("live catchup leaked")
	}
}

// A challenge that closes the broad inbox during catchup must restore that
// inbox after AUTH, rather than leaving only an until-bounded historical page.
func TestReplayRechallengeRestoresInbox(t *testing.T) {
	key, _ := nostr.GeneratePrivKey()
	mk := func(at int64) *nostr.Event {
		e := &nostr.Event{Kind: nostr.KindGiftWrap, CreatedAt: at, Tags: [][]string{{"p", key.PubKeyHex()}}, Content: "transport fixture"}
		if err := key.SignEvent(e); err != nil {
			t.Fatal(err)
		}
		return e
	}
	now := time.Now().Unix()
	a, b, live := mk(now-10), mk(now-11), mk(now)
	url := authFixture(t, func(c *websocket.Conn, relay string) {
		auth := func(ch string) bool {
			_ = c.WriteJSON([]any{"AUTH", ch})
			typ, m := authRead(c)
			if typ != "AUTH" {
				t.Error("rechallenge AUTH missing")
				return false
			}
			e, ok := authValid(m[1], relay, ch)
			if !ok {
				t.Error("rechallenge binding")
				return false
			}
			_ = c.WriteJSON([]any{"OK", e.ID, true, ""})
			return true
		}
		if !auth("first") {
			return
		}
		typ, _ := authRead(c)
		if typ != "REQ" {
			return
		}
		_ = c.WriteJSON([]any{"EVENT", "gw-inbox", a})
		_ = c.WriteJSON([]any{"EVENT", "gw-inbox", b})
		_ = c.WriteJSON([]any{"EOSE", "gw-inbox"})
		typ, _ = authRead(c)
		if typ != "REQ" {
			return
		}
		_ = c.WriteJSON([]any{"AUTH", "second"})
		_ = c.WriteJSON([]any{"CLOSED", "gw-inbox", "auth-required: fresh challenge"})
		typ, m := authRead(c)
		if typ != "AUTH" {
			t.Error("rechallenge AUTH missing")
			return
		}
		e, ok := authValid(m[1], relay, "second")
		if !ok {
			t.Error("rechallenge binding")
			return
		}
		_ = c.WriteJSON([]any{"OK", e.ID, true, ""})
		typ, _ = authRead(c)
		if typ != "CLOSE" {
			t.Error("stale catchup not closed")
			return
		}
		typ, m = authRead(c)
		var id string
		if len(m) > 1 {
			_ = json.Unmarshal(m[1], &id)
		}
		if typ != "REQ" || id != "gw-inbox" {
			t.Error("rechallenge did not restore live inbox")
			return
		}
		var filter map[string]json.RawMessage
		_ = json.Unmarshal(m[2], &filter)
		if filter["until"] != nil {
			t.Error("rechallenge left live inbox time-bounded")
			return
		}
		_ = c.WriteJSON([]any{"EOSE", "gw-inbox"})
		_ = c.WriteJSON([]any{"EVENT", "gw-inbox", live})
		for {
			if _, _, e := c.ReadMessage(); e != nil {
				return
			}
		}
	})
	c := &RelayClient{URL: url, Auth: RelayAuthRequired, AgentKey: key, ReplayLimit: 2}
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got := make(chan string, 8)
	done := make(chan error, 1)
	go func() {
		done <- c.RunGiftWraps(ctx, key.PubKeyHex(), func(_ context.Context, e *nostr.Event) { got <- e.ID })
	}()
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	found := false
	for !found {
		select {
		case id := <-got:
			found = id == live.ID
		case <-timer.C:
			t.Error("rechallenge lost live event")
			found = true
		}
	}
	cancel()
	c.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("rechallenge leaked")
	}
}
