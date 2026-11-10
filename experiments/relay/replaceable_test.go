package relay

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
)

func relayList(t *testing.T, k *nostr.PrivKey, kind int, at int64, content string) *nostr.Event {
	t.Helper()
	e := &nostr.Event{Kind: kind, CreatedAt: at, Tags: [][]string{{"relay", "opaque value, not a URL"}}, Content: content}
	if err := k.SignEvent(e); err != nil {
		t.Fatal(err)
	}
	return e
}
func storedIDs(t *testing.T, s *eventStore, want ...*nostr.Event) {
	t.Helper()
	if len(s.events) != len(want) {
		t.Fatalf("replaceable set count: got %d want %d", len(s.events), len(want))
	}
	for _, e := range want {
		if s.events[e.ID] == nil {
			t.Fatalf("replaceable set missing %s", e.ID)
		}
	}
}
func snapshotBytes(t *testing.T, c Config) []byte {
	t.Helper()
	b, e := os.ReadFile(filepath.Join(c.StateDir, "events.json"))
	if e != nil {
		t.Fatal(e)
	}
	return b
}

// Both assigned kinds converge to the newer timestamp and lower-ID tie in
// either arrival order. Ignored and duplicate events cannot write the snapshot.
func TestReplaceableOrder(t *testing.T) {
	for _, kind := range []int{10002, 10050} {
		for _, lowerFirst := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/lower-first-%v", kind, lowerFirst), func(t *testing.T) {
				c := fixtureConfig(t)
				c.MaxEvents = 1
				now := time.Now().Unix()
				k := key(t)
				s, err := openStore(c, now)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { s.close() }()
				old := relayList(t, k, kind, now-3, "old")
				lo, hi := relayList(t, k, kind, now-1, "a"), relayList(t, k, kind, now-1, "b")
				if lo.ID > hi.ID {
					lo, hi = hi, lo
				}
				first, second := hi, lo
				if lowerFirst {
					first, second = lo, hi
				}
				for _, e := range []*nostr.Event{old, first} {
					if dup, err := s.put(e, now); err != nil || dup {
						t.Fatal("newer replacement refused", err)
					}
				}
				if lowerFirst {
					s.save = func([]byte) error { t.Fatal("ignored replacement wrote snapshot"); return nil }
					if dup, err := s.put(second, now); err == nil || err.Error() != "EVENT_SUPERSEDED" || dup {
						t.Fatal("higher tie accepted", err)
					}
				} else {
					if dup, err := s.put(second, now); err != nil || dup {
						t.Fatal("lower tie refused", err)
					}
				}
				storedIDs(t, s, lo)
				before := snapshotBytes(t, c)
				s.save = func([]byte) error { t.Fatal("ignored replacement wrote snapshot"); return nil }
				if dup, err := s.put(old, now); err == nil || err.Error() != "EVENT_SUPERSEDED" || dup {
					t.Fatal("older replacement accepted", err)
				}
				if dup, err := s.put(lo, now); err != nil || !dup {
					t.Fatal("duplicate replacement not acknowledged", err)
				}
				if !bytes.Equal(before, snapshotBytes(t, c)) {
					t.Fatal("ignored snapshot changed")
				}
				s.close()
				s, err = openStore(c, now)
				if err != nil {
					t.Fatal("replaceable restart", err)
				}
				storedIDs(t, s, lo)
			})
		}
	}
}

// Replacement changes only its author/kind slot even at capacity; unrelated
// authors, the other replaceable kind and regular events survive a bounded flood.
func TestReplaceableIsolation(t *testing.T) {
	c := fixtureConfig(t)
	c.MaxEvents = 4
	now := time.Now().Unix()
	a, b := key(t), key(t)
	s, err := openStore(c, now)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	current := relayList(t, a, 10050, now-40, "old")
	other := relayList(t, b, 10050, now-40, "other")
	kind := relayList(t, a, 10002, now-40, "kind")
	regular := relayList(t, a, 8182, now-40, "regular")
	for i, e := range []*nostr.Event{current, other, kind, regular} {
		if _, err := s.put(e, now); err != nil || len(s.events) != i+1 {
			t.Fatal("replaceable key isolation", err)
		}
	}
	for i := 1; i <= 32; i++ {
		current = relayList(t, a, 10050, now-40+int64(i), fmt.Sprint(i))
		if _, err := s.put(current, now); err != nil {
			t.Fatal("replacement at capacity refused", err)
		}
		storedIDs(t, s, current, other, kind, regular)
	}
	before := snapshotBytes(t, c)
	if _, err := s.put(relayList(t, b, 10002, now, "new pair"), now); err == nil || err.Error() != "STORE_CAPACITY" {
		t.Fatal("new pair bypassed capacity", err)
	}
	// Regular events remain independently retained, even with identical author/kind.
	if _, err := s.put(relayList(t, a, 8182, now, "regular2"), now); err == nil || err.Error() != "STORE_CAPACITY" {
		t.Fatal("regular event replaced", err)
	}
	storedIDs(t, s, current, other, kind, regular)
	if !bytes.Equal(before, snapshotBytes(t, c)) {
		t.Fatal("capacity changed snapshot")
	}
}

// Byte limits apply to the resulting snapshot; a refused larger replacement
// preserves the old bytes, and a smaller winner releases those bytes atomically.
func TestReplaceableBytes(t *testing.T) {
	c := fixtureConfig(t)
	now := time.Now().Unix()
	k := key(t)
	s, err := openStore(c, now)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	old := relayList(t, k, 10050, now-2, "old")
	if _, err := s.put(old, now); err != nil {
		t.Fatal(err)
	}
	before := snapshotBytes(t, c)
	s.cfg.MaxStoreBytes = len(before)
	large := relayList(t, k, 10050, now-1, strings.Repeat("x", 100))
	if _, err := s.put(large, now); err == nil || err.Error() != "STORE_CAPACITY" {
		t.Fatal("replaceable byte cap bypassed", err)
	}
	storedIDs(t, s, old)
	if !bytes.Equal(before, snapshotBytes(t, c)) {
		t.Fatal("byte refusal changed snapshot")
	}
	small := relayList(t, k, 10050, now, "")
	if _, err := s.put(small, now); err != nil {
		t.Fatal("smaller replacement refused", err)
	}
	storedIDs(t, s, small)
}

// Failure before persistence preserves the old snapshot and poisons later
// writes. Restart recovers the old durable winner, then accepts a valid retry.
func TestReplaceableWriteFailure(t *testing.T) {
	c := fixtureConfig(t)
	now := time.Now().Unix()
	k := key(t)
	s, err := openStore(c, now)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { s.close() }()
	old, newer := relayList(t, k, 10002, now-1, "old"), relayList(t, k, 10002, now, "new")
	if _, err := s.put(old, now); err != nil {
		t.Fatal(err)
	}
	before := snapshotBytes(t, c)
	s.save = func([]byte) error { return fail("injected before persistence") }
	if dup, err := s.put(newer, now); err == nil || err.Error() != "STORE_WRITE" || dup {
		t.Fatal("replacement write failure accepted", err)
	}
	storedIDs(t, s, old)
	if !bytes.Equal(before, snapshotBytes(t, c)) {
		t.Fatal("failed replacement changed snapshot")
	}
	s.save = s.atomicWrite
	if _, err := s.put(newer, now); err == nil || err.Error() != "STORE_UNAVAILABLE" {
		t.Fatal("replacement poison bypassed", err)
	}
	s.close()
	s, err = openStore(c, now)
	if err != nil {
		t.Fatal(err)
	}
	storedIDs(t, s, old)
	if _, err := s.put(newer, now); err != nil {
		t.Fatal(err)
	}
	storedIDs(t, s, newer)
}

// Recovery refuses a non-canonical multi-record pair without rewriting it,
// regardless of snapshot order, while a unique-pair snapshot is readable.
func TestReplaceableRecovery(t *testing.T) {
	for _, kind := range []int{10002, 10050} {
		for _, reverse := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/%v", kind, reverse), func(t *testing.T) {
				c := fixtureConfig(t)
				now := time.Now().Unix()
				k := key(t)
				s, err := openStore(c, now)
				if err != nil {
					t.Fatal(err)
				}
				s.close()
				a, b := relayList(t, k, kind, now-1, "old"), relayList(t, k, kind, now, "new")
				if reverse {
					a, b = b, a
				}
				raw, _ := json.Marshal(snapshot{1, []*nostr.Event{a, b}})
				path := filepath.Join(c.StateDir, "events.json")
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
				s, err = openStore(c, now)
				if err == nil {
					s.close()
					t.Fatal("duplicate replaceable pair recovered")
				}
				if err.Error() != "STORE_CORRUPT" {
					t.Fatal(err)
				}
				if !bytes.Equal(raw, snapshotBytes(t, c)) {
					t.Fatal("corrupt replacement snapshot rewritten")
				}
				raw, _ = json.Marshal(snapshot{1, []*nostr.Event{a}})
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
				s, err = openStore(c, now)
				if err != nil {
					t.Fatal(err)
				}
				defer s.close()
				storedIDs(t, s, a)
			})
		}
	}
}

// Time-window rejection leaves the valid neighbor intact. Pruning removes the
// retained winner durably; a backwards clock cannot resurrect its predecessor.
func TestReplaceableRetention(t *testing.T) {
	c := fixtureConfig(t)
	c.RetentionSeconds = 10
	now := time.Now().Unix()
	k := key(t)
	s, err := openStore(c, now)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { s.close() }()
	old, newer := relayList(t, k, 10050, now-1, "old"), relayList(t, k, 10050, now, "new")
	for _, e := range []*nostr.Event{old, newer} {
		if _, err := s.put(e, now); err != nil {
			t.Fatal(err)
		}
	}
	before := snapshotBytes(t, c)
	for _, at := range []int64{now - 11, now + c.FutureSeconds + 1} {
		if _, err := s.put(relayList(t, k, 10050, at, "outside"), now); err == nil || err.Error() != "EVENT_TIME" {
			t.Fatal("replaceable time boundary", err)
		}
	}
	storedIDs(t, s, newer)
	if !bytes.Equal(before, snapshotBytes(t, c)) {
		t.Fatal("time refusal changed snapshot")
	}
	if err := s.prune(now + 11); err != nil {
		t.Fatal(err)
	}
	storedIDs(t, s)
	s.close()
	s, err = openStore(c, now)
	if err != nil {
		t.Fatal(err)
	}
	storedIDs(t, s)
}

func queryLists(t *testing.T, c *websocket.Conn, id string, k *nostr.PrivKey, kind int, want ...*nostr.Event) {
	t.Helper()
	send(t, c, []any{"REQ", id, map[string]any{"authors": []string{k.PubKeyHex()}, "kinds": []int{kind}}})
	for _, e := range want {
		m := read(t, c)
		if len(m) != 3 || m[0] != "EVENT" || m[1] != id {
			t.Fatal("replaceable query event", m)
		}
		raw, _ := json.Marshal(m[2])
		v, err := nostr.ParseEvent(raw)
		if err != nil || nostr.VerifySignature(v) != nil || v.ID != e.ID {
			t.Fatal("replaceable query wrong winner", err)
		}
	}
	m := read(t, c)
	if len(m) != 2 || m[0] != "EOSE" || m[1] != id {
		t.Fatal("replaceable query extra event", m)
	}
	send(t, c, []any{"CLOSE", id})
}

// Actual WebSocket publish/REQ and live delivery expose one winner. Refused
// predecessors and exact duplicates produce no extra live broadcast. Restart
// recovers that winner; explicit list queries stay public under gift-wrap ACLs.
func TestReplaceableWire(t *testing.T) {
	for _, kind := range []int{10002, 10050} {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			cfg := fixtureConfig(t)
			cfg.RestrictGiftWrapReads = true
			r, url := serve(t, cfg)
			c, _ := dial(t, url)
			k := key(t)
			now := time.Now().Unix()
			old, newer := relayList(t, k, kind, now-2, "old"), relayList(t, k, kind, now-1, "new")
			send(t, c, []any{"EVENT", old})
			ack(t, c, true, "")
			queryLists(t, c, "first", k, kind, old)
			send(t, c, []any{"REQ", "live", map[string]any{"authors": []string{k.PubKeyHex()}, "kinds": []int{kind}, "limit": 0}})
			if m := read(t, c); m[0] != "EOSE" {
				t.Fatal("live EOSE", m)
			}
			send(t, c, []any{"EVENT", newer})
			ack(t, c, true, "")
			if m := read(t, c); len(m) != 3 || m[0] != "EVENT" || m[1] != "live" || m[2].(map[string]any)["id"] != newer.ID {
				t.Fatal("new replacement not broadcast", m)
			}
			send(t, c, []any{"EVENT", old})
			ack(t, c, false, "blocked:")
			send(t, c, []any{"EVENT", newer})
			ack(t, c, true, "duplicate:")
			// This EOSE barrier catches queued forbidden live events without a sleep.
			queryLists(t, c, "latest", k, kind, newer)
			c.Close()
			r.Close()
			_, url = serve(t, cfg)
			c, _ = dial(t, url)
			queryLists(t, c, "restart", k, kind, newer)
		})
	}
}

// Signed valid neighbors surround signature, kind, size, future-time and count
// refusals on the real wire. Every refusal preserves the durable winner bytes.
func TestReplaceableWireRefusals(t *testing.T) {
	cfg := fixtureConfig(t)
	cfg.MaxEvents = 1
	r, url := serve(t, cfg)
	c, _ := dial(t, url)
	k := key(t)
	now := time.Now().Unix()
	good := relayList(t, k, 10050, now-2, "good")
	send(t, c, []any{"EVENT", good})
	ack(t, c, true, "")
	badsig := relayList(t, k, 10050, now-1, "bad")
	badsig.Content = "tampered"
	huge := relayList(t, k, 10050, now-1, strings.Repeat("x", cfg.MaxEventBytes-100)) // Fits transport slack, exceeds event cap.
	for _, tc := range []struct {
		name   string
		e      *nostr.Event
		prefix string
	}{
		{"signature", badsig, "invalid:"},
		{"kind", relayList(t, k, 10003, now-1, "unsupported"), "invalid:"},
		{"size", huge, "invalid:"},
		{"future", relayList(t, k, 10050, now+cfg.FutureSeconds+10, "future"), "invalid:"},
		{"capacity", relayList(t, key(t), 10050, now-1, "other author"), "rate-limited:"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := snapshotBytes(t, cfg)
			send(t, c, []any{"EVENT", tc.e})
			ack(t, c, false, tc.prefix)
			if !bytes.Equal(before, snapshotBytes(t, cfg)) {
				t.Fatal("wire refusal changed snapshot")
			}
			queryLists(t, c, "unchanged", k, 10050, good)
			send(t, c, []any{"EVENT", good})
			ack(t, c, true, "duplicate:")
		})
	}
	next := relayList(t, k, 10050, now-1, "valid replacement")
	send(t, c, []any{"EVENT", next})
	ack(t, c, true, "")
	queryLists(t, c, "valid", k, 10050, next)
	func() { r.mu.Lock(); defer r.mu.Unlock(); storedIDs(t, r.store, next) }()
}

// Newly admitted kinds do not bypass configured write/read authentication.
func TestReplaceableAuth(t *testing.T) {
	cfg := fixtureConfig(t)
	cfg.RequireWriteAuth = true
	cfg.RequireReadAuth = true
	_, url := serve(t, cfg)
	c, ch := dial(t, url)
	k := key(t)
	e := relayList(t, k, 10002, time.Now().Unix(), "list")
	send(t, c, []any{"EVENT", e})
	ack(t, c, false, "auth-required:")
	send(t, c, []any{"REQ", "denied", map[string]any{"kinds": []int{10002}}})
	if m := read(t, c); m[0] != "CLOSED" || !strings.HasPrefix(m[2].(string), "auth-required:") {
		t.Fatal("replaceable read auth bypass", m)
	}
	send(t, c, []any{"AUTH", authEvent(t, k, cfg, ch)})
	ack(t, c, true, "")
	send(t, c, []any{"EVENT", e})
	ack(t, c, true, "")
	queryLists(t, c, "allowed", k, 10002, e)
}
