package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
)

func authFixture(t *testing.T, handle func(*websocket.Conn, string)) string {
	t.Helper()
	u := websocket.Upgrader{}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, e := u.Upgrade(w, r, nil)
		if e != nil {
			return
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		handle(c, "ws://"+r.Host)
	}))
	t.Cleanup(s.Close)
	return "ws" + strings.TrimPrefix(s.URL, "http")
}
func authRead(c *websocket.Conn) (string, []json.RawMessage) {
	var m []json.RawMessage
	if c.ReadJSON(&m) != nil || len(m) < 2 {
		return "", nil
	}
	var typ string
	_ = json.Unmarshal(m[0], &typ)
	return typ, m
}
func authValid(raw json.RawMessage, relay, challenge string) (*nostr.Event, bool) {
	e, err := nostr.ParseEvent(raw)
	if err != nil {
		return nil, false
	}
	r, _ := e.TagFirst("relay")
	ch, _ := e.TagFirst("challenge")
	return e, e.Kind == 22242 && nostr.VerifySignature(e) == nil && r == relay && ch == challenge && e.Content == "" && e.CreatedAt >= time.Now().Unix()-10 && e.CreatedAt <= time.Now().Unix()+10
}

// A real websocket relay validates the signed binding, requires positive AUTH
// acknowledgement, then delivers the subscribed event. Each reconnect must sign
// the new connection's challenge; a prior accepted session is insufficient.
func TestRelayAuthReconnect(t *testing.T) {
	key, _ := nostr.GeneratePrivKey()
	var connections, auths atomic.Int32
	url := authFixture(t, func(c *websocket.Conn, relay string) {
		n := connections.Add(1)
		challenge := strings.Repeat("c", int(n))
		_ = c.WriteJSON([]any{"AUTH", challenge})
		typ, m := authRead(c)
		if typ != "AUTH" {
			t.Error("AUTH must precede REQ")
			return
		}
		ev, valid := authValid(m[1], relay, challenge)
		if !valid {
			t.Error("auth binding invalid")
			return
		}
		auths.Add(1)
		_ = c.WriteJSON([]any{"OK", ev.ID, true, ""})
		typ, m = authRead(c)
		if typ != "REQ" {
			t.Error("missing authenticated REQ")
			return
		}
		var sub string
		_ = json.Unmarshal(m[1], &sub)
		msg := &nostr.Event{Kind: 1059, CreatedAt: time.Now().Unix(), Tags: [][]string{{"p", key.PubKeyHex()}}, Content: "fixture"}
		_ = key.SignEvent(msg)
		_ = c.WriteJSON([]any{"EVENT", sub, msg})
		_, _ = authRead(c)
	})
	client := &RelayClient{URL: url, Auth: RelayAuthRequired, AgentKey: key}
	defer client.Close()
	for range 2 {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		delivered := false
		err := client.SubscribeGiftWraps(ctx, key.PubKeyHex(), func(context.Context, *nostr.Event) { delivered = true; cancel() })
		cancel()
		if !delivered || !errors.Is(err, context.Canceled) {
			t.Fatal("authenticated delivery", err)
		}
	}
	if connections.Load() != 2 || auths.Load() != 2 {
		t.Fatal("reconnect reused authorization")
	}
}

// AUTH cannot be inferred from a challenge, false OK, or a different event's OK.
// Missing key is rejected before any connection; relay-provided text is private.
func TestRelayAuthRefusals(t *testing.T) {
	key, _ := nostr.GeneratePrivKey()
	for _, tc := range []struct {
		name, mode, reply string
		key               *nostr.PrivKey
		want              error
	}{
		{"missing-key", RelayAuthRequired, "", nil, ErrRelayAuthKey},
		{"rejected", RelayAuthRequired, "reject", key, ErrRelayAuthRejected},
		{"wrong-ok", RelayAuthRequired, "wrong", key, ErrRelayAuthTimeout},
		{"no-challenge", RelayAuthRequired, "none", key, ErrRelayAuthTimeout},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var connected atomic.Int32
			url := authFixture(t, func(c *websocket.Conn, relay string) {
				connected.Add(1)
				if tc.reply != "none" {
					_ = c.WriteJSON([]any{"AUTH", "challenge"})
					typ, m := authRead(c)
					if typ != "AUTH" {
						return
					}
					ev, ok := authValid(m[1], relay, "challenge")
					if !ok {
						t.Error("invalid signed AUTH")
						return
					}
					id := ev.ID
					if tc.reply == "wrong" {
						id = strings.Repeat("0", 64)
					}
					_ = c.WriteJSON([]any{"OK", id, tc.reply != "reject", "restricted: PRIVATE_REASON"})
				}
				typ, _ := authRead(c)
				if typ == "REQ" {
					t.Error("unauthenticated REQ escaped")
				}
			})
			c := &RelayClient{URL: url, Auth: tc.mode, AgentKey: tc.key}
			defer c.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			err := c.SubscribeGiftWraps(ctx, key.PubKeyHex(), func(context.Context, *nostr.Event) { t.Error("unauthenticated event") })
			if !errors.Is(err, tc.want) {
				t.Fatalf("auth refusal: got %v want %v", err, tc.want)
			}
			if tc.key == nil && connected.Load() != 0 {
				t.Fatal("missing key dialed relay")
			}
		})
	}
}

// The test relay independently rejects correctly signed AUTH with wrong bindings,
// with a valid neighbour proving it does not simply reject all authentication.
func TestRelayAuthBindingOracle(t *testing.T) {
	key, _ := nostr.GeneratePrivKey()
	url := authFixture(t, func(c *websocket.Conn, relay string) {
		_ = c.WriteJSON([]any{"AUTH", "expected"})
		typ, m := authRead(c)
		if typ != "AUTH" {
			return
		}
		ev, valid := authValid(m[1], relay, "expected")
		if ev == nil {
			return
		}
		_ = c.WriteJSON([]any{"OK", ev.ID, valid, "restricted: invalid binding"})
	})
	for _, kind := range []string{"valid", "relay", "challenge"} {
		t.Run(kind, func(t *testing.T) {
			c, _, e := websocket.DefaultDialer.Dial(url, nil)
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			_ = c.SetReadDeadline(time.Now().Add(time.Second))
			typ, m := authRead(c)
			if typ != "AUTH" {
				t.Fatal("challenge absent")
			}
			var challenge string
			_ = json.Unmarshal(m[1], &challenge)
			relay := url
			if kind == "relay" {
				relay += "/other"
			}
			if kind == "challenge" {
				challenge = "wrong"
			}
			ev := &nostr.Event{Kind: 22242, CreatedAt: time.Now().Unix(), Tags: [][]string{{"relay", relay}, {"challenge", challenge}}}
			_ = key.SignEvent(ev)
			if e = c.WriteJSON([]any{"AUTH", ev}); e != nil {
				t.Fatal(e)
			}
			typ, m = authRead(c)
			if typ != "OK" || len(m) != 4 {
				t.Fatal("auth verdict absent")
			}
			var accepted bool
			_ = json.Unmarshal(m[2], &accepted)
			if accepted != (kind == "valid") {
				t.Fatal("relay accepted wrong auth binding")
			}
		})
	}
}

// An auth-required rejection is retried once after the new AUTH's positive OK,
// for both subscriptions and publications. Disabled auth and restricted errors
// stay refused; none of the relay's free-form reason text escapes in errors.
func TestRelayAuthRetry(t *testing.T) {
	key, _ := nostr.GeneratePrivKey()
	for _, op := range []string{"REQ", "EVENT"} {
		for _, mode := range []string{RelayAuthWhenChallenged, RelayAuthOff} {
			for _, prefix := range []string{"auth-required:", "restricted:"} {
				t.Run(op+"/"+mode+"/"+prefix, func(t *testing.T) {
					delivered := make(chan struct{}, 1)
					var writes atomic.Int32
					url := authFixture(t, func(c *websocket.Conn, relay string) {
						typ, m := authRead(c)
						if typ != op {
							t.Error("missing initial operation")
							return
						}
						writes.Add(1)
						var id string
						if op == "REQ" {
							_ = json.Unmarshal(m[1], &id)
							_ = c.WriteJSON([]any{"CLOSED", id, prefix + " PRIVATE_REASON"})
						} else {
							ev, e := nostr.ParseEvent(m[1])
							if e != nil {
								return
							}
							id = ev.ID
							_ = c.WriteJSON([]any{"OK", id, false, prefix + " PRIVATE_REASON"})
						}
						if mode == RelayAuthOff || prefix != "auth-required:" {
							_, _ = authRead(c)
							return
						}
						_ = c.WriteJSON([]any{"AUTH", "late-challenge"})
						typ, m = authRead(c)
						if typ != "AUTH" {
							t.Error("missing late AUTH")
							return
						}
						ev, valid := authValid(m[1], relay, "late-challenge")
						if !valid {
							t.Error("late auth binding invalid")
							return
						}
						_ = c.WriteJSON([]any{"OK", ev.ID, true, ""})
						typ, m = authRead(c)
						if typ != op {
							t.Error("operation not retried")
							return
						}
						writes.Add(1)
						if op == "EVENT" {
							e, _ := nostr.ParseEvent(m[1])
							if e.ID != id {
								t.Error("retry changed publication")
							}
							_ = c.WriteJSON([]any{"OK", id, true, ""})
						} else {
							ev = &nostr.Event{Kind: 1059, CreatedAt: time.Now().Unix(), Tags: [][]string{{"p", key.PubKeyHex()}}}
							_ = key.SignEvent(ev)
							_ = c.WriteJSON([]any{"EVENT", id, ev})
						}
						_, _ = authRead(c)
					})
					c := &RelayClient{URL: url, Auth: mode, AgentKey: key}
					defer c.Close()
					ctx, cancel := context.WithTimeout(context.Background(), time.Second)
					defer cancel()
					var err error
					if op == "REQ" {
						err = c.SubscribeGiftWraps(ctx, key.PubKeyHex(), func(context.Context, *nostr.Event) { delivered <- struct{}{}; cancel() })
					} else {
						ev := &nostr.Event{Kind: 8182, CreatedAt: time.Now().Unix()}
						_ = key.SignEvent(ev)
						err = c.Publish(ctx, ev)
					}
					if mode == RelayAuthWhenChallenged && prefix == "auth-required:" {
						if op == "REQ" {
							select {
							case <-delivered:
							default:
								t.Fatal("authenticated retry delivery missing")
							}
							if err != context.Canceled {
								t.Fatal(err)
							}
						} else if err != nil {
							t.Fatal("publish retry", err)
						}
						if writes.Load() != 2 {
							t.Fatal("retry count")
						}
					} else {
						want := ErrRelayAuthRequired
						if prefix == "restricted:" {
							want = ErrRelayRejected
						}
						if !errors.Is(err, want) || writes.Load() != 1 {
							t.Fatal("closed refusal", err, writes.Load())
						}
					}
				})
			}
		}
	}
}

// A retired pump's completion is isolated from the replacement's active waiters.
func TestRelayOldConnectionIsolation(t *testing.T) {
	c := &RelayClient{}
	old := &relaySession{done: make(chan struct{}), changed: make(chan struct{})}
	// A real connection is used for Close, while state isolation is deterministic.
	url := authFixture(t, func(conn *websocket.Conn, _ string) { _, _ = authRead(conn) })
	conn, _, e := websocket.DefaultDialer.Dial(url, nil)
	if e != nil {
		t.Fatal(e)
	}
	old.conn = conn
	fresh := &relaySession{done: make(chan struct{}), changed: make(chan struct{}), waiters: map[string]chan error{"new": make(chan error, 1)}}
	c.session = fresh
	c.stop(old, ErrRelayClosed)
	if c.session != fresh || len(fresh.waiters) != 1 || fresh.err != nil {
		t.Fatal("old pump damaged replacement")
	}
	select {
	case <-fresh.done:
		t.Fatal("replacement closed")
	default:
	}
}

// A replaced challenge invalidates its old ACK. Only the current event ID can
// authorize an operation, even when an earlier signature was valid on this socket.
func TestRelayAuthReplacedChallenge(t *testing.T) {
	key, _ := nostr.GeneratePrivKey()
	url := authFixture(t, func(c *websocket.Conn, relay string) {
		_ = c.WriteJSON([]any{"AUTH", "first"})
		typ, m := authRead(c)
		if typ != "AUTH" {
			t.Error("first AUTH missing")
			return
		}
		old, ok := authValid(m[1], relay, "first")
		if !ok {
			t.Error("first AUTH invalid")
			return
		}
		_ = c.WriteJSON([]any{"AUTH", "second"})
		typ, m = authRead(c)
		if typ != "AUTH" {
			t.Error("second AUTH missing")
			return
		}
		current, ok := authValid(m[1], relay, "second")
		if !ok {
			t.Error("second AUTH invalid")
			return
		}
		_ = c.WriteJSON([]any{"OK", old.ID, true, ""})
		// A publication ACK cannot complete AUTH either.
		_ = c.WriteJSON([]any{"OK", strings.Repeat("f", 64), true, ""})
		_ = c.WriteJSON([]any{"OK", current.ID, false, "restricted: PRIVATE_REASON"})
		typ, _ = authRead(c)
		if typ == "REQ" {
			t.Error("stale challenge authorized REQ")
		}
	})
	c := &RelayClient{URL: url, Auth: RelayAuthRequired, AgentKey: key}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if e := c.SubscribeGiftWraps(ctx, key.PubKeyHex(), func(context.Context, *nostr.Event) {}); e != ErrRelayAuthRejected {
		t.Fatal("replaced challenge accepted", e)
	}
}

// Auth-required is bounded to one retry; a relay cannot force unbounded replay
// of publications or subscriptions with repeated CLOSED/negative OK frames.
func TestRelayAuthRetryBound(t *testing.T) {
	key, _ := nostr.GeneratePrivKey()
	var writes atomic.Int32
	url := authFixture(t, func(c *websocket.Conn, relay string) {
		typ, m := authRead(c)
		if typ != "REQ" {
			return
		}
		writes.Add(1)
		_ = c.WriteJSON([]any{"CLOSED", "gw-inbox", "auth-required: first"})
		_ = c.WriteJSON([]any{"AUTH", "challenge"})
		typ, m = authRead(c)
		if typ != "AUTH" {
			return
		}
		ev, ok := authValid(m[1], relay, "challenge")
		if !ok {
			return
		}
		_ = c.WriteJSON([]any{"OK", ev.ID, true, ""})
		typ, _ = authRead(c)
		if typ != "REQ" {
			return
		}
		writes.Add(1)
		_ = c.WriteJSON([]any{"CLOSED", "gw-inbox", "auth-required: second"})
		typ, _ = authRead(c)
		if typ == "REQ" {
			writes.Add(1)
		}
	})
	c := &RelayClient{URL: url, Auth: RelayAuthWhenChallenged, AgentKey: key}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if e := c.SubscribeGiftWraps(ctx, key.PubKeyHex(), func(context.Context, *nostr.Event) {}); e != ErrRelayAuthRequired || writes.Load() != 2 {
		t.Fatal("auth retry unbounded", e, writes.Load())
	}
}
