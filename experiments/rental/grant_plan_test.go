package rental

import (
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"testing"
)

// Offline planning binds the exact signed grant commitment and conserves the
// declared input amount after a bounded fee. Invalid funding cannot produce a
// partial plan; adjacent valid input still works. No chain-state claim is made.
func TestGrantPlans(t *testing.T) {
	g := testGrant(t)
	raw := signGrantTest(t, g, 1)
	script, _ := GrantSealScript(g.IssuerKey)
	p := Policy{ConstructionProfile: "W", Network: g.Network, Genesis: g.Genesis, AgentName: g.AgentName, LandlordName: g.LandlordName, SealScript: script, FundingScript: testFundingScript(), StateDir: t.TempDir()}
	good := PlanSpec{Kind: "grant-issue", Inputs: []su.PlanInput{{Point: su.Point{TxID: Hash([]byte("funding")), Vout: 0}, ValueSat: 1000000, Script: p.FundingScript, Role: "funding"}}, ChangeScript: p.FundingScript}
	for _, mode := range []string{"role", "seal-input", "seal-script", "seal-change", "funding-policy", "missing-funding", "duplicate", "change", "amount", "insufficient", "wrong-landlord", "wrong-kind"} {
		t.Run(mode, func(t *testing.T) {
			s := good
			s.Inputs = append([]su.PlanInput(nil), good.Inputs...)
			policy := p
			want := "ISSUANCE_FUNDING"
			switch mode {
			case "role":
				s.Inputs[0].Role = "seal"
			case "seal-input":
				s.Inputs[0].Point = su.Point{TxID: g.Seal.TxID, Vout: g.Seal.Vout}
				want = "ISSUANCE_SPENDS_SEAL"
			case "seal-script":
				s.Inputs[0].Script = p.SealScript
				want = "FUNDING_SEAL_SCRIPT"
			case "seal-change":
				s.ChangeScript = p.SealScript
				want = "ISSUANCE_TEMPLATE"
			case "funding-policy":
				policy.FundingScript = policy.SealScript
				want = "FUNDING_POLICY"
			case "missing-funding":
				policy.FundingScript = ""
				want = "FUNDING_POLICY"
			case "duplicate":
				s.Inputs = append(s.Inputs, s.Inputs[0])
			case "change":
				s.ChangeScript = ""
				want = "ISSUANCE_TEMPLATE"
			case "amount":
				s.Inputs[0].ValueSat = MaxMoney + 1
			case "insufficient":
				s.Inputs[0].ValueSat = 1
				want = "FUNDING_OR_DUST_RESERVE"
			case "wrong-landlord":
				policy.LandlordName = "id/other"
				want = "GRANT_PLAN_POLICY"
			case "wrong-kind":
				s.Kind = "issue"
				want = "ISSUANCE_TEMPLATE"
			}
			plan, e := MakeGrantIssuancePlan(policy, s, raw)
			if e == nil || e.Error() != want || plan.GrantID != "" || len(plan.Outputs) != 0 {
				t.Fatal("plan guard", want, e)
			}
			plan, e = MakeGrantIssuancePlan(p, good, raw)
			if e != nil {
				t.Fatal("plan neighbor", e)
			}
			signed, _ := ParseSignedGrant(raw)
			commit, _ := IssuanceCommitment(signed)
			if !plan.Offline || plan.Version != 3 || plan.GrantID != Hash(raw) || len(plan.Outputs) != 2 || plan.Outputs[0].ValueSat != 0 || plan.Outputs[0].Script != "6a03534c014201"+commit+"01"+signed.ID() || plan.Outputs[1].Script != p.FundingScript || plan.Outputs[1].ValueSat+plan.FeeSat != good.Inputs[0].ValueSat || plan.FeeSat != 200*int64(plan.MaxSignedVBytes) {
				t.Fatal("plan commitment or conservation")
			}
		})
	}
}

// Inventory is trusted policy, not a hint: malformed/duplicate/oversized lists
// fail closed, while a different vout of the same transaction is not funding.
func TestGrantPoolInventory(t *testing.T) {
	g := testGrant(t)
	raw := signGrantTest(t, g, 1)
	script, _ := GrantSealScript(g.IssuerKey)
	p := Policy{ConstructionProfile: "W", Network: g.Network, Genesis: g.Genesis, AgentName: g.AgentName, LandlordName: g.LandlordName, SealScript: script, FundingScript: testFundingScript(), StateDir: t.TempDir()}
	point := Point{Hash([]byte("ordinary-funding")), 0}
	s := PlanSpec{Kind: "grant-issue", Inputs: []su.PlanInput{{Point: su.Point{TxID: point.TxID, Vout: point.Vout}, ValueSat: 1000000, Script: p.FundingScript, Role: "funding"}}, ChangeScript: p.FundingScript}
	for _, inventory := range [][]Point{{{TxID: "bad"}}, {point, point}, make([]Point, 4097)} {
		p.KnownPoolSeals = inventory
		if plan, e := MakeGrantIssuancePlan(p, s, raw); e == nil || e.Error() != "POOL_INVENTORY" || plan.GrantID != "" || len(plan.Outputs) != 0 {
			t.Fatal("invalid pool inventory accepted", e)
		}
	}
	p.KnownPoolSeals = []Point{{TxID: point.TxID, Vout: 1}, g.Seal}
	if _, e := MakeGrantIssuancePlan(p, s, raw); e != nil {
		t.Fatal("distinct vout inventory neighbor", e)
	}
}

func testFundingScript() string {
	_, key := testKey(7)
	script, e := GrantSealScript(key)
	if e != nil {
		panic(e)
	}
	return "0014" + script[6:46]
}
