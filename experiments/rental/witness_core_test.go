package rental

import (
	"context"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"reflect"
	"testing"
)

// Actual Core mempool funding is insufficient authority, even if its entire
// transaction is native/ALL. Refusal precedes issuer burns/signatures; the same
// exact output becomes an accepted positive control after confirmation.
func TestCoreWitnessIssuerParentRefusal(t *testing.T) {
	l := newCore(t)
	l.grantIdentity()
	seal := l.witnessPool(1, true)
	p, _, _ := l.grantFixture("w-parent", seal, 2)
	ip, req, event, key, spec := l.grantIssueInputs(p, "w-parent", true)
	q := l.witnessPool(7, false)
	spec.Inputs[0].Point = su.Point{TxID: q.TxID, Vout: q.Vout}
	before := issuerFiles(t, p.StateDir)
	result := IssueGrant(context.Background(), l.observer, ip, req, event, seal, spec, key, 500)
	if result.Verdict != "refused" || result.Reason != "W_UNCONFIRMED_NON_LINKAGE_PARENT" || len(result.SignedGrant) != 0 || result.Plan != nil {
		t.Fatal("W issuer parent refusal", result.Verdict, result.Reason)
	}
	if !reflect.DeepEqual(before, issuerFiles(t, p.StateDir)) {
		t.Fatal("W issuer refusal changed state")
	}
	l.mine(1)
	requirePrepared(t, IssueGrant(context.Background(), l.observer, ip, req, event, seal, spec, key, 500))
	l.save("w-issuer-parent.json", map[string]any{"txid": q.TxID, "refusal": "W_UNCONFIRMED_NON_LINKAGE_PARENT", "state_unchanged": true, "confirmed_neighbor": "prepared", "status": "PASS"})
}
