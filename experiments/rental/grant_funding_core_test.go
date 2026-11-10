package rental

import (
	"context"
	"encoding/hex"
	"encoding/json"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"reflect"
	"testing"
)

// Genuine unreserved and stray seal-script UTXOs are refused without inventory,
// even if the spec claims the separate funding script. No signature, plan or
// reservation escapes; ordinary funding produces a live grant with safe change.
// A v3 refill consumes only funding-key coins, creates only explicit seals at
// the grant key, and returns its change to the funding key.
func TestCoreGrantFundingSeparation(t *testing.T) {
	l := newCore(t)
	l.grantIdentity()
	ctx := context.Background()
	seal := l.witnessPool(1, true)
	p, _, _ := l.grantFixture("funding-separation", seal, 2)
	ip, req, event, key, spec := l.grantIssueInputs(p, "funding-separation", true)
	for _, label := range []string{"unreserved-pool", "stray-seal-address"} {
		point := l.witnessPool(1, true)
		for _, declared := range []string{p.SealScript, p.FundingScript} {
			badSpec := spec
			badSpec.Inputs = append([]su.PlanInput{}, spec.Inputs...)
			badSpec.Inputs[0].Point = su.Point{TxID: point.TxID, Vout: point.Vout}
			badSpec.Inputs[0].Script = declared
			before := issuerFiles(t, p.StateDir)
			got := IssueGrant(ctx, l.observer, ip, req, event, seal, badSpec, key, 500)
			if got.Verdict != "refused" || got.Reason != "FUNDING_SEAL_SCRIPT" || got.Plan != nil || len(got.SignedGrant) != 0 {
				t.Fatalf("seal-script funding accepted: %s/%s", got.Verdict, got.Reason)
			}
			if !reflect.DeepEqual(before, issuerFiles(t, p.StateDir)) {
				t.Fatal("seal-script refusal changed journal")
			}
			suffix := "declared"
			if declared == p.FundingScript {
				suffix = "forged"
			}
			l.save(label+"-"+suffix+".json", got)
		}
	}
	result := IssueGrant(ctx, l.observer, ip, req, event, seal, spec, key, 500)
	requirePrepared(t, result)
	for _, out := range result.Plan.Outputs {
		if out.Role == "change" && out.Script != p.FundingScript {
			t.Fatal("issuance change reached seal script")
		}
	}
	id := l.sendPlan(*result.Plan, true)
	proof, e := PresentIssuedGrant(result.SignedGrant, id)
	if e != nil {
		t.Fatal(e)
	}
	sg, e := ParseSignedGrant(result.SignedGrant)
	if e != nil {
		t.Fatal(e)
	}
	l.checkGrant("separate-funding-live", p, sg.Grant, proof, 500, "live", "LIVE", false)
	fund := l.witnessPool(7, true)
	refill := PlanSpec{Kind: "refill", Inputs: []su.PlanInput{{Point: su.Point{TxID: fund.TxID, Vout: fund.Vout}, ValueSat: 1000000, Script: p.FundingScript, Role: "funding"}}, ChangeScript: p.FundingScript, Count: 2, ValueSat: 100000}
	plan, e := MakePlan(ip, refill, nil, nil, nil, 500)
	if e != nil {
		t.Fatal(e)
	}
	rid := l.sendPlan(plan, true)
	l.save("refill.json", plan)
	var tx su.TransactionView
	if e = json.Unmarshal(l.rpc("", "getrawtransaction", rid, true), &tx); e != nil {
		t.Fatal(e)
	}
	if len(tx.Vout) != 3 || tx.Vout[0].Script.Hex != p.SealScript || tx.Vout[1].Script.Hex != p.SealScript || tx.Vout[2].Script.Hex != p.FundingScript {
		t.Fatal("refill output script isolation")
	}
	for _, in := range plan.Inputs {
		if in.Script == p.SealScript {
			t.Fatal("refill consumes pool seal")
		}
	}
	// Verify actual change script against independently decoded transaction bytes.
	raw := text(t, object(t, l.rpc("", "getrawtransaction", id, true))["hex"])
	b, e := hex.DecodeString(raw)
	if e != nil {
		t.Fatal(e)
	}
	decoded, e := su.DecodePaymentTransaction(b)
	if e != nil {
		t.Fatal(e)
	}
	if hex.EncodeToString(decoded.Outputs[1].Script) != p.FundingScript {
		t.Fatal("actual issuance change script")
	}
}
