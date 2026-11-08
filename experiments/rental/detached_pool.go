package rental

import su "relux.works/swarma-chain-lab/experiments/single-use"

func makeDetachedPoolPlan(p Policy, s PlanSpec) (Plan, error) {
	var plan Plan
	if e := p.validateDetached(); e != nil {
		return plan, e
	}
	if s.ChangeScript != p.SealScript || len(s.Inputs) < 1 || len(s.Inputs) > 16 {
		return plan, bad("PLAN_BOUNDS")
	}
	tx := su.Transaction{Version: 2}
	var total int64
	seen := map[su.Point]bool{}
	for _, in := range s.Inputs {
		if !digest(in.Point.TxID) || seen[in.Point] || in.ValueSat < 1 || in.ValueSat > MaxMoney-total || in.Script != p.SealScript {
			return plan, bad("POOL_INPUT")
		}
		seen[in.Point] = true
		total += in.ValueSat
		if s.Kind == "refill" && in.Role != "funding" {
			return plan, bad("INPUT_ROLE")
		}
		if s.Kind == "revoke" && (in.Role != "seal" || in.Point != (su.Point{TxID: s.Pool.Point.TxID, Vout: s.Pool.Point.Vout}) || in.ValueSat != s.Pool.ValueSat || in.Script != s.Pool.Script) {
			return plan, bad("REVOKE_SEAL_BINDING")
		}
		tx.Inputs = append(tx.Inputs, su.Input{Point: in.Point, Script: make([]byte, 140), Sequence: 0xfffffffe})
	}
	plan = Plan{Version: 2, Network: p.Network, Genesis: p.Genesis, Kind: s.Kind, Offline: true, TransactionVersion: 2, Inputs: s.Inputs, FeeRate: 200, RequiredReview: "Offline unsigned pool plan; verify current prevouts, reservations, derived grant-key custody and signing policy before use. No signing or broadcast authority."}
	add := func(value int64, role string) {
		tx.Outputs = append(tx.Outputs, su.Output{Value: value, Script: mustDecodeKey(p.SealScript)})
		plan.Outputs = append(plan.Outputs, su.PlanOutput{ValueSat: value, Script: p.SealScript, Role: role})
	}
	switch s.Kind {
	case "refill":
		if s.Count < 1 || s.Count > 16 || s.ValueSat < 100000 || s.ValueSat > MaxMoney/int64(s.Count) {
			return plan, bad("REFILL_TEMPLATE")
		}
		for i := 0; i < s.Count; i++ {
			add(s.ValueSat, "pool-seal")
		}
	case "revoke":
		if len(s.Inputs) != 1 || s.Count != 0 {
			return plan, bad("REVOKE_TEMPLATE")
		}
	default:
		return plan, bad("PLAN_KIND")
	}
	add(0, "change")
	size, fee, change, e := su.ReserveLegacyFee(tx, total)
	if e != nil {
		return plan, e
	}
	plan.MaxSignedVBytes = size
	plan.FeeSat = fee
	plan.Outputs[len(plan.Outputs)-1].ValueSat = change
	return plan, nil
}
