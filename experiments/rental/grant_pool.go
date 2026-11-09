package rental

import su "github.com/relux-works/swarma-chain-lab/experiments/single-use"

// V3 refill uses the separate funding key; only explicit pool-seal outputs go
// to the grant key. Revoke deliberately spends one selected seal. Both return
// change to the funding key and remain offline unsigned plans.
func makeGrantPoolPlan(p Policy, s PlanSpec) (Plan, error) {
	if e := p.validateGrantFunding(); e != nil {
		return Plan{}, e
	}
	if s.ChangeScript != p.FundingScript {
		return Plan{}, bad("CHANGE_PIN")
	}
	var tx su.Transaction
	var total int64
	switch s.Kind {
	case "refill":
		if s.Count < 1 || s.Count > 16 || s.ValueSat < 100000 || s.ValueSat > MaxMoney/int64(s.Count) {
			return Plan{}, bad("REFILL_TEMPLATE")
		}
		funding := s
		funding.Kind = "grant-issue"
		funding.Count = 0
		funding.ValueSat = 0
		var e error
		tx, total, e = grantFunding(p, funding, Point{})
		if e != nil {
			return Plan{}, e
		}
		tx.Outputs = nil
	case "revoke":
		if len(s.Inputs) != 1 || s.Count != 0 || s.ValueSat != 0 {
			return Plan{}, bad("REVOKE_TEMPLATE")
		}
		in := s.Inputs[0]
		if in.Role != "seal" || !digest(in.Point.TxID) || in.Point != (su.Point{TxID: s.Pool.Point.TxID, Vout: s.Pool.Point.Vout}) || in.Script != p.SealScript || s.Pool.Script != p.SealScript || in.ValueSat != s.Pool.ValueSat || in.ValueSat < 1 || in.ValueSat > MaxMoney {
			return Plan{}, bad("REVOKE_SEAL_BINDING")
		}
		total = in.ValueSat
		tx = su.Transaction{Version: 2, Inputs: []su.Input{{Point: in.Point, Script: make([]byte, 140), Sequence: 0xfffffffe}}}
	default:
		return Plan{}, bad("PLAN_KIND")
	}
	plan := Plan{Version: 3, Network: p.Network, Genesis: p.Genesis, Kind: s.Kind, Offline: true, TransactionVersion: 2, Inputs: s.Inputs, FeeRate: 200, RequiredReview: "Offline unsigned pool plan. Recheck actual prevouts, separate funding/change script, selected seal, reservations and custody immediately before signing. No broadcast authority."}
	add := func(value int64, script, role string) {
		tx.Outputs = append(tx.Outputs, su.Output{Value: value, Script: mustDecodeKey(script)})
		plan.Outputs = append(plan.Outputs, su.PlanOutput{ValueSat: value, Script: script, Role: role})
	}
	if s.Kind == "refill" {
		for i := 0; i < s.Count; i++ {
			add(s.ValueSat, p.SealScript, "pool-seal")
		}
	}
	add(0, p.FundingScript, "change")
	size, fee, change, e := su.ReserveLegacyFee(tx, total)
	if e != nil {
		return Plan{}, e
	}
	plan.MaxSignedVBytes = size
	plan.FeeSat = fee
	plan.Outputs[len(plan.Outputs)-1].ValueSat = change
	return plan, nil
}
