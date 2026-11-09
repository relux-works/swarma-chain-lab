package relay

import (
	"encoding/json"
	"os"
	"path/filepath"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/nostr"
	"testing"
	"time"
)

func fixtureConfig(t *testing.T) Config {
	t.Helper()
	p, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	return Defaults(filepath.Join(p, "state"), "ws://127.0.0.1:9999")
}
func event(t *testing.T, kind int, at int64) *nostr.Event {
	t.Helper()
	k, e := nostr.GeneratePrivKey()
	if e != nil {
		t.Fatal(e)
	}
	v := &nostr.Event{PubKey: k.PubKeyHex(), Kind: kind, CreatedAt: at, Tags: [][]string{}, Content: "fixture"}
	if e = k.SignEvent(v); e != nil {
		t.Fatal(e)
	}
	return v
}

// Accepted bytes survive restart; duplicates do not rewrite, capacity does not
// evict live events, and expired slots become reusable without resurrection.
func TestStoreDurability(t *testing.T) {
	c := fixtureConfig(t)
	c.MaxEvents = 1
	c.RetentionSeconds = 10
	now := time.Now().Unix()
	s, e := openStore(c, now)
	if e != nil {
		t.Fatal(e)
	}
	if x, e := openStore(c, now); e == nil {
		x.close()
		t.Fatal("concurrent state writer")
	}
	a := event(t, 8182, now)
	if dup, e := s.put(a, now); e != nil || dup {
		t.Fatal("store", e)
	}
	s.close()
	s, e = openStore(c, now)
	if e != nil {
		t.Fatal(e)
	}
	defer s.close()
	if len(s.events) != 1 {
		t.Fatal("restart lost event")
	}
	s.save = func([]byte) error { t.Fatal("duplicate rewrote store"); return nil }
	if dup, e := s.put(a, now); e != nil || !dup {
		t.Fatal("stored duplicate", e)
	}
	s.save = s.atomicWrite
	b := event(t, 8181, now+1)
	if _, e = s.put(b, now); e == nil || e.Error() != "STORE_CAPACITY" || len(s.events) != 1 {
		t.Fatal("capacity evicted live event", e)
	}
	b = event(t, 8181, now+11)
	if _, e = s.put(b, now+11); e != nil || len(s.events) != 1 || s.events[a.ID] != nil {
		t.Fatal("expiry pruning", e)
	}
}

// A persistence failure yields no in-memory acceptance and poisons later writes,
// including retry of the same event; a fresh normal store is the valid neighbor.
func TestStoreFailure(t *testing.T) {
	c := fixtureConfig(t)
	now := time.Now().Unix()
	s, e := openStore(c, now)
	if e != nil {
		t.Fatal(e)
	}
	defer s.close()
	s.save = func([]byte) error { return fail("injected") }
	a := event(t, 8182, now)
	if dup, e := s.put(a, now); e == nil || e.Error() != "STORE_WRITE" || dup || len(s.events) != 0 {
		t.Fatal("failed persistence accepted", e)
	}
	s.save = s.atomicWrite
	if _, e = s.put(a, now); e == nil || e.Error() != "STORE_UNAVAILABLE" {
		t.Fatal("uncertain store resumed", e)
	}
}

// Invalid signed content, timestamps, kinds, store modes and corrupt snapshots
// are refused without overwriting the evidence. Valid 8182 is the parser control.
func TestStoreRefusals(t *testing.T) {
	c := fixtureConfig(t)
	now := time.Now().Unix()
	a := event(t, 8182, now)
	raw, _ := json.Marshal(a)
	if _, e := validEvent(raw, c); e != nil {
		t.Fatal(e)
	}
	for _, v := range []*nostr.Event{event(t, 13, now), event(t, 22242, now), event(t, 1059, now)} {
		b, _ := json.Marshal(v)
		if _, e := validEvent(b, c); e == nil {
			t.Fatal("forbidden event")
		}
	}
	a.Content = "tampered"
	raw, _ = json.Marshal(a)
	if _, e := validEvent(raw, c); e == nil {
		t.Fatal("bad signature")
	}
	s, e := openStore(c, now)
	if e != nil {
		t.Fatal(e)
	}
	for _, at := range []int64{now - c.RetentionSeconds - 1, now + c.FutureSeconds + 1} {
		if _, e := s.put(event(t, 8182, at), now); e == nil || e.Error() != "EVENT_TIME" {
			t.Fatal("time boundary", e)
		}
	}
	s.close()
	path := filepath.Join(c.StateDir, "events.json")
	if e = os.WriteFile(path, []byte(`{"version":1,"events":[],"events":[]}`), 0600); e != nil {
		t.Fatal(e)
	}
	if s, e = openStore(c, now); e == nil {
		s.close()
		t.Fatal("corrupt snapshot accepted")
	}
	if e = os.WriteFile(path, []byte(`{"version":1,"events":[]}`), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(path, 0644); e != nil {
		t.Fatal(e)
	}
	if s, e = openStore(c, now); e == nil {
		s.close()
		t.Fatal("public store accepted")
	}
}
