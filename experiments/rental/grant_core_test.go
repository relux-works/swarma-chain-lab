package rental

import (
	"context"
	"encoding/json"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"testing"
)

const labLandlord = "id/swarma-landlord-test"

func (l *coreLab) registerRole(name, value string) {
	l.t.Helper()
	var res []string
	if e := json.Unmarshal(l.rpc("issuer", "name_new", name), &res); e != nil {
		l.t.Fatal(e)
	}
	l.mine(12)
	l.rpc("issuer", "name_firstupdate", name, res[1], res[0], value)
	l.mine(1)
}
func (l *coreLab) grantIdentity() {
	l.t.Helper()
	_, key := testKey(1)
	v, e := LandlordValue(LandlordBinding{key})
	if e != nil {
		l.t.Fatal(e)
	}
	l.registerRole(labLandlord, v)
	l.agentPointer(labLandlord, 3, true)
}
func (l *coreLab) agentPointer(landlord string, nostr byte, mine bool) string {
	l.t.Helper()
	_, key := testKey(nostr)
	v, e := AgentBindingValue(AgentBinding{key, landlord})
	if e != nil {
		l.t.Fatal(e)
	}
	id := text(l.t, l.rpc("issuer", "name_update", l.station, v))
	if mine {
		l.mine(1)
	}
	return id
}
func (l *coreLab) landlordKey(key byte, mine bool) string {
	l.t.Helper()
	_, pub := testKey(key)
	v, e := LandlordValue(LandlordBinding{pub})
	if e != nil {
		l.t.Fatal(e)
	}
	id := text(l.t, l.rpc("issuer", "name_update", labLandlord, v))
	if mine {
		l.mine(1)
	}
	return id
}
func (l *coreLab) grantFixture(label string, seal Point, grantee byte) (Policy, Grant, []byte) {
	l.t.Helper()
	p := l.policy(label)
	p.ConstructionProfile = "W"
	p.AgentName = l.station
	p.LandlordName = labLandlord
	p.SealScript, _ = GrantSealScript(p.IssuerPubkey)
	p.FundingScript = testFundingScript()
	g := testGrant(l.t)
	g.AgentName = p.AgentName
	g.LandlordName = p.LandlordName
	g.Seal = seal
	_, g.GranteeKey = testKey(grantee)
	g.Consent.ConsentEvent = signedEvent(l.t, g.Consent.ConsentEvent, grantee)
	return p, g, signGrantTest(l.t, g, 1)
}
func (l *coreLab) grantPlan(p Policy, raw []byte) Plan {
	l.t.Helper()
	fund := l.witnessPool(7, true)
	s := PlanSpec{Kind: "grant-issue", Inputs: []su.PlanInput{{Point: su.Point{TxID: fund.TxID, Vout: fund.Vout}, ValueSat: 1000000, Script: p.FundingScript, Role: "funding"}}, ChangeScript: p.FundingScript}
	plan, e := MakeGrantIssuancePlan(p, s, raw)
	if e != nil {
		l.t.Fatal(e)
	}
	return plan
}
func (l *coreLab) grantProof(p Policy, raw []byte, mine bool) []byte {
	l.t.Helper()
	id := l.sendPlan(l.grantPlan(p, raw), mine)
	proof, e := PresentIssuedGrant(raw, id)
	if e != nil {
		l.t.Fatal(e)
	}
	return proof
}
func (l *coreLab) checkGrant(label string, p Policy, g Grant, proof []byte, now int64, want, reason string, closed bool) Receipt {
	l.t.Helper()
	r := Check(context.Background(), l.observer, p, proof, p.AgentName, g.GranteeKey, now)
	l.save(label+".json", r)
	if r.Verdict != want || r.Reason != reason || r.Closed != closed {
		l.t.Fatalf("%s: want %s/%s closed=%v got %+v", label, want, reason, closed, r)
	}
	return r
}

// Real Core requires the per-grant commitment confirmed before live, while two
// renters coexist under one landlord. Spending one seal closes only that grant;
// the closure persists through node restart without needing node reads.
func TestCoreGrantLifecycle(t *testing.T) {
	l := newCore(t)
	l.grantIdentity()
	a, b := l.witnessPool(1, true), l.witnessPool(1, true)
	p, g, raw := l.grantFixture("parallel", a, 2)
	proof := l.grantProof(p, raw, false)
	l.checkGrant("issuance-unconfirmed", p, g, proof, 500, "pending", "ISSUANCE_UNCONFIRMED", false)
	l.mine(1)
	l.checkGrant("grant-a-live", p, g, proof, 500, "live", "LIVE", false)
	g2 := g
	g2.Seal = b
	_, g2.GranteeKey = testKey(4)
	g2.Consent.ConsentEvent = signedEvent(t, g2.Consent.ConsentEvent, 4)
	raw2 := signGrantTest(t, g2, 1)
	proof2 := l.grantProof(p, raw2, true)
	l.checkGrant("grant-b-live", p, g2, proof2, 500, "live", "LIVE", false)
	l.revokeDetached(a, false)
	l.checkGrant("grant-a-closed", p, g, proof, 500, "refused", "SEAL_SPENT", true)
	l.checkGrant("grant-b-unaffected", p, g2, proof2, 500, "live", "LIVE", false)
	l.mine(1)
	l.stop()
	l.start()
	r := l.checkGrant("grant-a-restart-closed", p, g, proof, 500, "refused", "SEAL_SPENT", true)
	if r.Calls != 0 {
		t.Fatal("durable closure reread node")
	}
	l.checkGrant("grant-b-restart-live", p, g2, proof2, 500, "live", "LIVE", false)
}

// A confirmed landlord grant-key change closes an observed binding forever;
// pending changes refuse only. Nostr-only updates preserve a valid grant.
func TestCoreGrantLandlordRotation(t *testing.T) {
	l := newCore(t)
	l.grantIdentity()
	p, g, raw := l.grantFixture("rotation", l.witnessPool(1, true), 2)
	proof := l.grantProof(p, raw, true)
	l.checkGrant("initial", p, g, proof, 500, "live", "LIVE", false)
	l.agentPointer(labLandlord, 4, true)
	l.checkGrant("nostr-only", p, g, proof, 500, "live", "LIVE", false)
	id := l.landlordKey(5, false)
	l.checkGrant("pending", p, g, proof, 500, "refused", "PENDING_LANDLORD_ROTATION", false)
	l.mine(1)
	l.checkGrant("rotated", p, g, proof, 500, "refused", "LANDLORD_KEY_ROTATED", true)
	block := text(t, object(t, l.rpc("", "getrawtransaction", id, true))["blockhash"])
	l.rpc("", "invalidateblock", block)
	l.checkGrant("reorg-closed", p, g, proof, 500, "refused", "LANDLORD_KEY_ROTATED", true)
	l.rpc("", "reconsiderblock", block)
	l.landlordKey(1, true)
	l.checkGrant("rotate-back-closed", p, g, proof, 500, "refused", "LANDLORD_KEY_ROTATED", true)
}

// Repointing the agent has its own pending/confirmed closure boundary, even
// when the new landlord target is absent. First observers only refuse; prior
// live observers close, and rotate-back cannot reopen their journal.
func TestCoreGrantPointerRotation(t *testing.T) {
	l := newCore(t)
	l.grantIdentity()
	p, g, raw := l.grantFixture("pointer", l.witnessPool(1, true), 2)
	proof := l.grantProof(p, raw, true)
	l.checkGrant("initial", p, g, proof, 500, "live", "LIVE", false)
	l.agentPointer("id/another-landlord", 3, false)
	l.checkGrant("pending", p, g, proof, 500, "refused", "PENDING_LANDLORD_POINTER", false)
	l.mine(1)
	fresh := p
	fresh.StateDir = l.policy("first-observer").StateDir
	l.checkGrant("first-mismatch", fresh, g, proof, 500, "refused", "AGENT_LANDLORD_MISMATCH", false)
	l.checkGrant("confirmed", p, g, proof, 500, "refused", "AGENT_LANDLORD_CHANGED", true)
	l.agentPointer(labLandlord, 3, true)
	l.checkGrant("rotate-back-closed", p, g, proof, 500, "refused", "AGENT_LANDLORD_CHANGED", true)
	l.checkGrant("unclosed-neighbor", fresh, g, proof, 500, "live", "LIVE", false)
}
