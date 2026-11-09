package rental

import (
	"context"
	"strings"
	"testing"
)

func (l *coreLab) n1Agent(landlord string, key byte, mine bool) string {
	l.t.Helper()
	_, k := testKey(key)
	raw, e := CombinedAgentBindingValue(AgentBinding{k, landlord}, n1Descriptor(k))
	if e != nil {
		l.t.Fatal(e)
	}
	id := text(l.t, l.rpc("issuer", "name_update", l.station, raw))
	if mine {
		l.mine(1)
	}
	return id
}
func (l *coreLab) n1Landlord(grant, social byte, mine bool) string {
	l.t.Helper()
	_, k := testKey(grant)
	_, n := testKey(social)
	raw, e := CombinedLandlordValue(LandlordBinding{k}, n1Descriptor(n))
	if e != nil {
		l.t.Fatal(e)
	}
	id := text(l.t, l.rpc("issuer", "name_update", labLandlord, raw))
	if mine {
		l.mine(1)
	}
	return id
}

// Genuine Core: new metadata works through the actual issuer, checker and key
// resolver. Pending/confirmed social-only updates preserve authority; malformed
// metadata refuses without closure; grant-key rotation still closes durably.
func TestCoreN1Values(t *testing.T) {
	l := newCore(t)
	l.grantIdentity()
	l.n1Agent(labLandlord, 3, true)
	l.n1Landlord(1, 4, true)
	seal := l.detachedPool(1, true)
	p, _, _ := l.grantFixture("n1", seal, 2)
	ip, req, event, key, spec := l.grantIssueInputs(p, "n1-issue", true)
	issued := IssueGrant(context.Background(), l.observer, ip, req, event, seal, spec, key, 500)
	requirePrepared(t, issued)
	signed, e := ParseSignedGrant(issued.SignedGrant)
	if e != nil {
		t.Fatal(e)
	}
	id := l.sendPlan(*issued.Plan, true)
	proof, e := PresentIssuedGrant(issued.SignedGrant, id)
	if e != nil {
		t.Fatal(e)
	}
	g := signed.Grant
	live := func(label string) { l.checkGrant(label, p, g, proof, 500, "live", "LIVE", false) }
	live("n1-issued-live")
	l.n1Agent(labLandlord, 5, false)
	live("n1-agent-social-pending")
	l.mine(1)
	live("n1-agent-social-confirmed")
	l.n1Landlord(1, 6, false)
	live("n1-landlord-social-pending")
	l.mine(1)
	live("n1-landlord-social-confirmed")
	got, _, e := ResolveLandlordGrantKey(context.Background(), l.observer, p, labLandlord)
	_, want := testKey(1)
	if e != nil || got != want {
		t.Fatal("N1 resolver used social key", e)
	}
	_, n := testKey(5)
	badValue, _ := CombinedAgentBindingValue(AgentBinding{n, labLandlord}, n1Descriptor(n))
	badValue = strings.Replace(badValue, `"_":"`+n+`"`, `"_":"`+want+`"`, 1)
	l.rpc("issuer", "name_update", l.station, badValue)
	l.checkGrant("n1-malformed-pending", p, g, proof, 500, "refused", "PENDING_NAME_VALUE", false)
	l.mine(1)
	l.checkGrant("n1-malformed-confirmed", p, g, proof, 500, "refused", "AGENT_NOSTR_MISMATCH", false)
	l.n1Agent(labLandlord, 5, true)
	live("n1-malformed-repaired")
	l.n1Landlord(7, 6, false)
	l.checkGrant("n1-authority-pending", p, g, proof, 500, "refused", "PENDING_LANDLORD_ROTATION", false)
	l.mine(1)
	l.checkGrant("n1-authority-rotated", p, g, proof, 500, "refused", "LANDLORD_KEY_ROTATED", true)
	l.n1Landlord(1, 6, true)
	l.checkGrant("n1-authority-rotate-back", p, g, proof, 500, "refused", "LANDLORD_KEY_ROTATED", true)
}

// Genuine Core: the agent pointer remains authoritative even when both social
// key copies agree; a fresh observer refuses, while an admitted observer closes.
func TestCoreN1Pointer(t *testing.T) {
	l := newCore(t)
	l.grantIdentity()
	l.n1Agent(labLandlord, 3, true)
	l.n1Landlord(1, 4, true)
	p, g, raw := l.grantFixture("n1-pointer", l.detachedPool(1, true), 2)
	proof := l.grantProof(p, raw, true)
	l.checkGrant("n1-pointer-live", p, g, proof, 500, "live", "LIVE", false)
	l.n1Agent("id/other-landlord", 3, false)
	l.checkGrant("n1-pointer-pending", p, g, proof, 500, "refused", "PENDING_LANDLORD_POINTER", false)
	l.mine(1)
	fresh := p
	fresh.StateDir = l.policy("n1-fresh").StateDir
	l.checkGrant("n1-pointer-first", fresh, g, proof, 500, "refused", "AGENT_LANDLORD_MISMATCH", false)
	l.checkGrant("n1-pointer-closed", p, g, proof, 500, "refused", "AGENT_LANDLORD_CHANGED", true)
	l.n1Agent(labLandlord, 3, true)
	l.checkGrant("n1-pointer-repaired-closed", p, g, proof, 500, "refused", "AGENT_LANDLORD_CHANGED", true)
	l.checkGrant("n1-pointer-neighbor", fresh, g, proof, 500, "live", "LIVE", false)
}
