package rental

import (
	"path/filepath"
	"testing"

	su "relux.works/swarma-chain-lab/experiments/single-use"
)

// Detached refill/revoke conserve value with a bounded legacy fee and only
// pinned outputs. Invalid input roles, ownership, duplication and template
// bounds refuse; default issuance cannot reach the legacy reservation path.
func TestDetachedPoolPlans(t *testing.T) {
	c := testDetached()
	script, _ := GrantSealScript(c.IssuerKey)
	p := IssuerPolicy{Policy: Policy{Network: c.Network, Genesis: c.Genesis, AgentName: c.AgentName, SealScript: script, StateDir: filepath.Join(t.TempDir(), "state")}}
	input := su.PlanInput{Point: su.Point{TxID: c.Seal.TxID, Vout: 0}, ValueSat: 10000000, Script: script, Role: "funding"}
	base := PlanSpec{Kind: "refill", Inputs: []su.PlanInput{input}, ChangeScript: script, Count: 2, ValueSat: 1000000}
	valid := func(s PlanSpec) {
		t.Helper()
		plan, e := MakePlan(p, s, nil, nil, nil, 500)
		if e != nil || !plan.Offline || plan.Version != 2 || plan.NameValue != "" || plan.Reservation != "" {
			t.Fatal("valid plan", e, plan)
		}
		var total int64
		for _, out := range plan.Outputs {
			if out.Script != script || out.ValueSat <= 0 {
				t.Fatal("unowned/nonpositive output")
			}
			total += out.ValueSat
		}
		if total+plan.FeeSat != input.ValueSat || plan.FeeSat != 200*int64(plan.MaxSignedVBytes) {
			t.Fatal("fee conservation")
		}
	}
	valid(base)
	for _, name := range []string{"script", "role", "duplicate", "change", "count", "zero", "issue", "revoke-binding"} {
		t.Run(name, func(t *testing.T) {
			s := base
			s.Inputs = append([]su.PlanInput(nil), base.Inputs...)
			want := ""
			switch name {
			case "script":
				s.Inputs[0].Script = "51"
				want = "POOL_INPUT"
			case "role":
				s.Inputs[0].Role = "seal"
				want = "INPUT_ROLE"
			case "duplicate":
				s.Inputs = append(s.Inputs, input)
				want = "POOL_INPUT"
			case "change":
				s.ChangeScript = "51"
				want = "PLAN_BOUNDS"
			case "count":
				s.Count = 17
				want = "REFILL_TEMPLATE"
			case "zero":
				s.Inputs[0].ValueSat = 0
				want = "POOL_INPUT"
			case "issue":
				s.Kind = "issue"
				want = "LEGACY_ISSUANCE_DISABLED"
			case "revoke-binding":
				s.Kind = "revoke"
				s.Inputs[0].Role = "seal"
				want = "REVOKE_SEAL_BINDING"
			}
			if _, e := MakePlan(p, s, nil, nil, nil, 500); e == nil || e.Error() != want {
				t.Fatal("plan guard", want, e)
			}
			valid(base)
		})
	}
	revoke := base
	revoke.Kind, revoke.Count = "revoke", 0
	revoke.Inputs = []su.PlanInput{input}
	revoke.Inputs[0].Role = "seal"
	revoke.Pool = PoolOutput{Point: c.Seal, ValueSat: input.ValueSat, Script: script}
	valid(revoke)
}
