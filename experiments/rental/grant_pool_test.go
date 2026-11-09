package rental

import (
	su "relux.works/swarma-chain-lab/experiments/single-use"
	"testing"
)

// V3 refill funding and all change use a distinct pinned script. Revocation
// alone may consume the exact selected seal; invalid plans return no outputs.
// Legacy v2 remains independently covered by TestDetachedPoolPlans.
func TestGrantPoolPlans(t *testing.T) {
	g := testGrant(t)
	sealScript, _ := GrantSealScript(g.IssuerKey)
	p := Policy{Network: g.Network, Genesis: g.Genesis, AgentName: g.AgentName, LandlordName: g.LandlordName, SealScript: sealScript, FundingScript: testFundingScript(), StateDir: t.TempDir()}
	in := su.PlanInput{Point: su.Point{TxID: Hash([]byte("pool-funds")), Vout: 0}, ValueSat: 1000000, Script: p.FundingScript, Role: "funding"}
	s := PlanSpec{Kind: "refill", Inputs: []su.PlanInput{in}, ChangeScript: p.FundingScript, Count: 2, ValueSat: 100000}
	valid := func(spec PlanSpec) {
		t.Helper()
		plan, e := MakePlan(IssuerPolicy{Policy: p}, spec, nil, nil, nil, 500)
		if e != nil || plan.Version != 3 || !plan.Offline {
			t.Fatal("v3 pool neighbor", e)
		}
		total := plan.FeeSat
		for _, out := range plan.Outputs {
			want := p.FundingScript
			if out.Role == "pool-seal" {
				want = p.SealScript
			}
			if out.Script != want || out.ValueSat <= 0 {
				t.Fatal("pool output isolation")
			}
			total += out.ValueSat
		}
		if total != spec.Inputs[0].ValueSat {
			t.Fatal("pool conservation")
		}
	}
	valid(s)
	for _, mode := range []string{"seal-funding", "seal-change", "same-policy", "missing-policy", "wrong-funding", "bad-role", "duplicate", "bounds", "revoke-wrong-seal"} {
		t.Run(mode, func(t *testing.T) {
			q := p
			badSpec := s
			badSpec.Inputs = append([]su.PlanInput{}, s.Inputs...)
			want := ""
			switch mode {
			case "seal-funding":
				badSpec.Inputs[0].Script = p.SealScript
				want = "FUNDING_SEAL_SCRIPT"
			case "seal-change":
				badSpec.ChangeScript = p.SealScript
				want = "CHANGE_PIN"
			case "same-policy":
				q.FundingScript = q.SealScript
				want = "FUNDING_POLICY"
			case "missing-policy":
				q.FundingScript = ""
				want = "FUNDING_POLICY"
			case "wrong-funding":
				badSpec.Inputs[0].Script = "51"
				want = "ISSUANCE_FUNDING"
			case "bad-role":
				badSpec.Inputs[0].Role = "seal"
				want = "ISSUANCE_FUNDING"
			case "duplicate":
				badSpec.Inputs = append(badSpec.Inputs, badSpec.Inputs[0])
				want = "ISSUANCE_FUNDING"
			case "bounds":
				badSpec.Count = 17
				want = "REFILL_TEMPLATE"
			case "revoke-wrong-seal":
				badSpec.Kind = "revoke"
				badSpec.Count = 0
				badSpec.ValueSat = 0
				want = "REVOKE_SEAL_BINDING"
			}
			plan, e := MakePlan(IssuerPolicy{Policy: q}, badSpec, nil, nil, nil, 500)
			if e == nil || e.Error() != want || len(plan.Outputs) != 0 {
				t.Fatalf("pool guard %s: %v", mode, e)
			}
			valid(s)
		})
	}
	revoke := PlanSpec{Kind: "revoke", Inputs: []su.PlanInput{{Point: su.Point{TxID: g.Seal.TxID, Vout: g.Seal.Vout}, ValueSat: 1000000, Script: p.SealScript, Role: "seal"}}, ChangeScript: p.FundingScript, Pool: PoolOutput{Point: g.Seal, ValueSat: 1000000, Script: p.SealScript}}
	valid(revoke)
}
