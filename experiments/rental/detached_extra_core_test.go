package rental

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"relux.works/swarma-chain-lab/experiments/single-use/durable"
)

// A real name_firstupdate can introduce the exact agent value. A subsequent
// malformed pending value refuses without changing an admitted journal; fixing
// that generation restores live. This does not infer unobserved key history.
func TestCoreDetachedFirstUpdate(t *testing.T) {
	l := newCore(t)
	l.station = "id/detached-first"
	var reservation []string
	if e := json.Unmarshal(l.rpc("issuer", "name_new", l.station), &reservation); e != nil {
		t.Fatal(e)
	}
	l.mine(12)
	_, g := testKey(1)
	_, n := testKey(3)
	value, _ := AgentValue(AgentKeys{Nostr: n, Grant: g})
	l.rpc("issuer", "name_firstupdate", l.station, reservation[1], reservation[0], value)
	l.mine(1)
	p, c, raw := l.detached("first", l.detachedPool(1, true), 2)
	l.checkDetached("first-update-live", p, c, raw, 500, "live", "LIVE", false)
	path := filepath.Join(p.StateDir, "detached-"+Hash(raw)+".json")
	before, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	l.rpc("issuer", "name_update", l.station, "{}")
	l.checkDetached("pending-malformed", p, c, raw, 500, "refused", "PENDING_NAME_VALUE", false)
	after, e := os.ReadFile(path)
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("malformed pending value changed journal")
	}
	l.mine(1)
	l.agentValue(1, 3, true)
	l.checkDetached("restored-live", p, c, raw, 500, "live", "LIVE", false)
}

// Detached journal corruption, lock contention and node failure refuse; a
// restored journal remains live. Expiry during a slow read refuses before an
// unseen certificate becomes admitted, with a valid fresh-clock neighbor.
func TestCoreDetachedState(t *testing.T) {
	l := newCore(t)
	l.agentValue(1, 3, true)
	p, c, raw := l.detached("state", l.detachedPool(1, true), 2)
	l.checkDetached("live", p, c, raw, 500, "live", "LIVE", false)
	path := filepath.Join(p.StateDir, "detached-"+Hash(raw)+".json")
	before, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	r := CheckV2(context.Background(), unavailableNode{}, p, raw, p.AgentName, c.GranteeKey, 500)
	if r.Reason != "NODE_UNAVAILABLE" || r.Closed {
		t.Fatal(r)
	}
	after, e := os.ReadFile(path)
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("read failure changed journal")
	}
	lock, e := durable.Open(p.StateDir, "rental.lock")
	if e != nil {
		t.Fatal(e)
	}
	r = CheckV2(context.Background(), l.observer, p, raw, p.AgentName, c.GranteeKey, 500)
	lock.Close()
	if r.Reason != "STATE_BUSY" || r.Closed {
		t.Fatal(r)
	}
	if e := os.WriteFile(path, []byte(`{"version":2}`), 0600); e != nil {
		t.Fatal(e)
	}
	l.checkDetached("corrupt", p, c, raw, 500, "refused", "JOURNAL_CORRUPT", false)
	if e := os.WriteFile(path, before, 0600); e != nil {
		t.Fatal(e)
	}
	l.checkDetached("restored", p, c, raw, 500, "live", "LIVE", false)
	fresh, fc, fr := l.detached("elapsed", c.Seal, 2)
	r = CheckV2(context.Background(), &delayedNode{base: l.observer}, fresh, fr, fresh.AgentName, fc.GranteeKey, 999)
	if r.Reason != "EXPIRED" || r.Closed {
		t.Fatal(r)
	}
	assertNoIssuerBurn(t, fresh.StateDir)
	l.checkDetached("elapsed-neighbor", fresh, fc, fr, 500, "live", "LIVE", false)
}
