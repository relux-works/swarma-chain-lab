package rental

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/durable"
)

// Genuine pending malformed updates refuse without closure. Dropping each
// update restores live. Rolling back a matching generation to an older key or
// pointer refuses without recording a forward rotation; restoration is live.
func TestCoreGrantNameRecovery(t *testing.T) {
	l := newCore(t)
	l.grantIdentity()
	p, g, raw := l.grantFixture("names", l.detachedPool(1, true), 2)
	proof := l.grantProof(p, raw, true)
	l.checkGrant("initial", p, g, proof, 500, "live", "LIVE", false)
	for _, role := range []string{"agent", "landlord"} {
		name := labLandlord
		if role == "agent" {
			name = l.station
		}
		id := text(t, l.rpc("issuer", "name_update", name, `{}`))
		l.checkGrant(role+"-malformed-pending", p, g, proof, 500, "refused", "PENDING_NAME_VALUE", false)
		l.noWalletBroadcast = true
		l.stop()
		l.start()
		l.checkGrant(role+"-dropped-neighbor", p, g, proof, 500, "live", "LIVE", false)
		l.rpc("", "loadwallet", "issuer")
		l.rpc("issuer", "abandontransaction", id)
		l.noWalletBroadcast = false
		l.stop()
		l.start()
		l.rpc("", "loadwallet", "issuer")
		// Core's ordinary wallet locks are not persistent across restart.
		// Protect the live seal from unrelated wallet name-update coin selection.
		l.rpc("issuer", "lockunspent", false, []Point{g.Seal})
		// Establish a mismatching older generation, then a new matching one.
		if role == "agent" {
			l.agentPointer("id/old-landlord", 3, true)
			l.agentPointer(labLandlord, 3, true)
		} else {
			l.landlordKey(5, true)
			l.landlordKey(1, true)
		}
		l.checkGrant(role+"-new-generation", p, g, proof, 500, "live", "LIVE", false)
		tip := text(t, l.rpc("", "getbestblockhash"))
		l.rpc("", "invalidateblock", tip)
		want := "LANDLORD_KEY_MISMATCH"
		if role == "agent" {
			want = "AGENT_LANDLORD_MISMATCH"
		}
		l.checkGrant(role+"-rollback", p, g, proof, 500, "refused", want, false)
		l.rpc("", "reconsiderblock", tip)
		l.checkGrant(role+"-restored", p, g, proof, 500, "live", "LIVE", false)
	}
	// A dropped mempool spend still closes an observed seal permanently.
	l.revokeDetached(g.Seal, false)
	l.checkGrant("spend-observed", p, g, proof, 500, "refused", "SEAL_SPENT", true)
	l.noWalletBroadcast = true
	l.stop()
	l.start()
	r := l.checkGrant("spend-dropped-closed", p, g, proof, 500, "refused", "SEAL_SPENT", true)
	if r.Calls != 0 {
		t.Fatal("durable closure reread node")
	}
}

// State failures preserve existing records. Elapsed expiry cannot publish live;
// a v2 seal index survives migration and prevents a different v3 grant reuse.
func TestCoreGrantState(t *testing.T) {
	l := newCore(t)
	l.grantIdentity()
	p, g, raw := l.grantFixture("state", l.detachedPool(1, true), 2)
	proof := l.grantProof(p, raw, true)
	l.checkGrant("initial", p, g, proof, 500, "live", "LIVE", false)
	path := filepath.Join(p.StateDir, "grant-"+Hash(raw)+".json")
	before, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	r := Check(context.Background(), unavailableNode{}, p, proof, p.AgentName, g.GranteeKey, 500)
	after, e := os.ReadFile(path)
	if e != nil || r.Reason != "NODE_UNAVAILABLE" || r.Closed || !bytes.Equal(before, after) {
		t.Fatal("failed read changed state", r)
	}
	lock, e := durable.Open(p.StateDir, "rental.lock")
	if e != nil {
		t.Fatal(e)
	}
	l.checkGrant("busy", p, g, proof, 500, "refused", "STATE_BUSY", false)
	lock.Close()
	if e = os.WriteFile(path, []byte(`{"version":3}`), 0600); e != nil {
		t.Fatal(e)
	}
	l.checkGrant("corrupt", p, g, proof, 500, "refused", "JOURNAL_CORRUPT", false)
	if e = os.WriteFile(path, before, 0600); e != nil {
		t.Fatal(e)
	}
	l.checkGrant("restored", p, g, proof, 500, "live", "LIVE", false)
	fresh := p
	fresh.StateDir = l.policy("elapsed").StateDir
	r = Check(context.Background(), &delayedNode{base: l.observer}, fresh, proof, p.AgentName, g.GranteeKey, 999)
	if r.Reason != "EXPIRED" || r.Verdict != "refused" || r.Closed {
		t.Fatal("elapsed expiry", r)
	}
	assertNoIssuerBurn(t, fresh.StateDir)
	l.checkGrant("elapsed-neighbor", fresh, g, proof, 500, "live", "LIVE", false)
	fresh.StateDir = l.policy("v2-index").StateDir
	old := seenSeal{Version: 2, Network: p.Network, Genesis: p.Genesis, Seal: g.Seal, CertificateSHA256: Hash([]byte("previous-v2"))}
	b, _ := json.Marshal(old)
	if e = os.WriteFile(filepath.Join(fresh.StateDir, sealIndexName(p, g.Seal)), b, 0600); e != nil {
		t.Fatal(e)
	}
	l.checkGrant("v2-memory", fresh, g, proof, 500, "refused", "SEAL_ALREADY_SEEN", false)
	_, other, signed := l.grantFixture("neighbor", l.detachedPool(1, true), 2)
	otherProof := l.grantProof(fresh, signed, true)
	l.checkGrant("v2-fresh-seal", fresh, other, otherProof, 500, "live", "LIVE", false)
}

// Cached bytes do not confer authority: wrong locator/id, closure and cache
// corruption refuse beside a live neighbor. The byte-cap fixture contains only
// structurally valid public proofs, not claims that all those grants are live.
func TestCoreGrantPresentation(t *testing.T) {
	l := newCore(t)
	l.grantIdentity()
	p, g, raw := l.grantFixture("cache", l.detachedPool(1, true), 2)
	proof := l.grantProof(p, raw, true)
	id := Hash(raw)
	present := func(pr []byte, grantID, verdict, reason string) {
		t.Helper()
		r := Present(context.Background(), l.observer, p, pr, grantID, p.AgentName, g.GranteeKey, 500)
		if r.Verdict != verdict || r.Reason != reason {
			t.Fatalf("presentation want %s/%s got %+v", verdict, reason, r)
		}
	}
	present(proof, id, "live", "LIVE")
	path := filepath.Join(p.StateDir, grantCacheName(p))
	original, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	present(proof, Hash(proof), "refused", "PRESENTATION_ID")
	bad, _ := PresentIssuedGrant(raw, Hash([]byte("missing")))
	present(bad, id, "refused", "NODE_UNAVAILABLE")
	b, e := os.ReadFile(path)
	if e != nil || !bytes.Equal(b, original) {
		t.Fatal("denial changed cache")
	}
	got, gotID, e := CachedGrant(p, g.GranteeKey)
	if e != nil || gotID != id || !bytes.Equal(got, proof) {
		t.Fatal("cache identity")
	}
	present(proof, id, "live", "LIVE")
	if e = os.WriteFile(path, []byte(`{}`), 0600); e != nil {
		t.Fatal(e)
	}
	present(proof, id, "refused", "PRESENTATION_CACHE_CORRUPT")
	if e = os.WriteFile(path, original, 0600); e != nil {
		t.Fatal(e)
	}
	present(proof, id, "live", "LIVE")
	c := grantCache{Version: 3, Entries: []cachedGrant{}}
	for k := byte(3); k < 100; k++ {
		cg := g
		_, cg.GranteeKey = testKey(k)
		cg.Consent.ConsentEvent = signedEvent(t, cg.Consent.ConsentEvent, k)
		signed := signGrantTest(t, cg, 1)
		pr, _ := PresentIssuedGrant(signed, Hash([]byte("public-cache-fixture")))
		c.Entries = append(c.Entries, cachedGrant{cg.GranteeKey, Hash(signed), pr})
		b, _ = json.Marshal(c)
		if len(b) > PresentationBytes {
			c.Entries = c.Entries[:len(c.Entries)-1]
			break
		}
	}
	b, _ = json.Marshal(c)
	if len(c.Entries) >= PresentationCapacity || len(b) > PresentationBytes {
		t.Fatal("byte bound fixture")
	}
	if e = os.WriteFile(path, b, 0600); e != nil {
		t.Fatal(e)
	}
	present(proof, id, "refused", "PRESENTATION_CACHE_FULL")
	after, e := os.ReadFile(path)
	if e != nil || !bytes.Equal(b, after) {
		t.Fatal("overflow changed cache")
	}
	if e = os.WriteFile(path, original, 0600); e != nil {
		t.Fatal(e)
	}
	present(proof, id, "live", "LIVE")
	l.revokeDetached(g.Seal, false)
	present(proof, id, "refused", "SEAL_SPENT")
	got, gotID, e = CachedGrant(p, g.GranteeKey)
	if e != nil || gotID != id || !bytes.Equal(got, proof) {
		t.Fatal("public proof lost")
	}
	l.save("presentation-result.json", map[string]any{"status": "PASS", "byte_cap": PresentationBytes, "fixture_entries": len(c.Entries), "grant_id": id})
}

// The real committed issuance cannot consume the grant's seal, even if its
// OP_RETURN is otherwise correct. A separate pool seal/issuance remains live.
func TestCoreGrantIssuanceSealInput(t *testing.T) {
	l := newCore(t)
	l.grantIdentity()
	p, g, raw := l.grantFixture("spent-in-issue", l.detachedPool(1, true), 2)
	plan := l.grantPlan(p, raw)
	plan.Inputs[0].Point = su.Point{TxID: g.Seal.TxID, Vout: g.Seal.Vout}
	id := l.sendPlan(plan, true)
	proof, _ := PresentIssuedGrant(raw, id)
	l.checkGrant("seal-input", p, g, proof, 500, "refused", "ISSUANCE_SPENDS_SEAL", false)
	assertNoIssuerBurn(t, p.StateDir)
	_, other, signed := l.grantFixture("neighbor", l.detachedPool(1, true), 2)
	pr := l.grantProof(p, signed, true)
	l.checkGrant("valid-neighbor", p, other, pr, 500, "live", "LIVE", false)
}
