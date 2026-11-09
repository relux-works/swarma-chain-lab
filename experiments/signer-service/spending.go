package signerservice

import (
	rental "github.com/relux-works/swarma-chain-lab/experiments/rental"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// SpendingCaps bounds transaction movement and enrolled custody exposure in
// integer NMC atoms. It does not discover or bound out-of-band wallet funds.
// Main has no defaults; deployment supplies every value explicitly.
type SpendingCaps struct {
	MovedPerTx  int64 `json:"moved_per_tx"`
	MovedDay    int64 `json:"moved_day"`
	EnrolledHot int64 `json:"enrolled_hot"`
}

func (c SpendingCaps) validate() error {
	if c.MovedPerTx < 1 || c.MovedDay < c.MovedPerTx || c.MovedDay > rental.MaxMoney || c.EnrolledHot < 1 || c.EnrolledHot > rental.MaxMoney {
		return fail("SPENDING_CAP_CONFIG")
	}
	return nil
}

// movement reserves non-change outputs plus the worst-case fee. Issuance has
// only a zero-valued commitment and pinned change, so its movement is its fee.
func (x *Engine) movement(spec rental.PlanSpec) (int64, error) {
	if spec.Kind == "grant-issue" {
		return x.feeProjection(spec)
	}
	plan, err := rental.MakePlan(x.policy(), spec, nil, nil, nil, 0)
	if err != nil {
		return 0, err
	}
	return movedByPlan(plan, x.cfg.Policy.Policy.FundingScript)
}

func movedByPlan(p rental.Plan, fundingScript string) (int64, error) {
	var inputs, outputs, change int64
	changes := 0
	for _, in := range p.Inputs {
		if in.ValueSat < 1 || in.ValueSat > rental.MaxMoney-inputs {
			return 0, fail("MOVEMENT_PLAN")
		}
		inputs += in.ValueSat
	}
	for _, out := range p.Outputs {
		if out.ValueSat < 0 || out.ValueSat > rental.MaxMoney-outputs {
			return 0, fail("MOVEMENT_PLAN")
		}
		outputs += out.ValueSat
		if out.Role == "change" {
			if out.Script != fundingScript || out.ValueSat < 1000 {
				return 0, fail("MOVEMENT_CHANGE")
			}
			changes++
			change = out.ValueSat
		}
	}
	if changes != 1 || p.FeeSat < 1 || p.FeeSat > rental.MaxMoney-outputs || inputs != outputs+p.FeeSat {
		return 0, fail("MOVEMENT_PLAN")
	}
	return inputs - change, nil
}

func terminalSpend(r record) bool { return r.Phase == "broadcast" || r.Phase == "stored" }

func (x *Engine) checkPlanSpending(p rental.Plan, now int64, exclude string) error {
	if x.cfg.Spending == nil {
		return nil
	}
	moved, err := movedByPlan(p, x.cfg.Policy.Policy.FundingScript)
	if err != nil {
		return err
	}
	return x.capSpending(moved, now, exclude)
}

// All pending/uncertain operations remain charged in every UTC day. Completed
// sends use the bucket of their last durable send attempt. Exact-byte retry
// excludes its own reservation, never frees or duplicates another charge.
func (x *Engine) capSpending(moved, now int64, exclude string) error {
	c := x.cfg.Spending
	if c == nil {
		return nil
	}
	if moved < 1 || moved > c.MovedPerTx {
		return fail("MOVED_TX_CAP")
	}
	var used int64
	for _, op := range x.state.Operations {
		if op.ID == exclude {
			continue
		}
		r, err := x.readRecord(op)
		if err != nil {
			return err
		}
		if !terminalSpend(r) || op.SpendAt/86400 == now/86400 {
			if op.MovedAtoms > c.MovedDay-used {
				return fail("MOVED_DAY_CAP")
			}
			used += op.MovedAtoms
		}
	}
	if moved > c.MovedDay-used {
		return fail("MOVED_DAY_CAP")
	}
	return nil
}

func (x *Engine) chargeSpendingAt(j int, now int64) error {
	if x.cfg.Spending == nil {
		return nil
	}
	if err := x.ready(now); err != nil {
		return err
	}
	op := x.state.Operations[j]
	if err := x.capSpending(op.MovedAtoms, now, op.ID); err != nil {
		return err
	}
	if op.SpendAt == now {
		return nil
	}
	s := cloneState(x.state)
	s.Operations[j].SpendAt = now
	s.LastTime = now
	return x.commit(s)
}

// Exposure includes unconsumed enrolled funds and seals. A durable accepted
// transaction replaces its consumed inputs with its custody outputs, even if
// trackOutputs has not completed. Pending sends keep their full input exposure.
// Reserved issuance seals remain counted until a revoke actually consumes them.
func (x *Engine) capExposure(inventory []Inventory) error {
	if x.cfg.Spending == nil {
		return nil
	}
	spent := map[su.Point]bool{}
	owned := map[su.Point]int64{}
	for _, v := range inventory {
		owned[v.Input.Point] = v.Input.ValueSat
	}
	for _, op := range x.state.Operations {
		r, err := x.readRecord(op)
		if err != nil {
			return err
		}
		if !terminalSpend(r) {
			continue
		}
		for _, in := range r.Plan.Inputs {
			spent[in.Point] = true
		}
		for n, out := range r.Plan.Outputs {
			if out.Role == "change" || out.Role == "pool-seal" {
				pt := su.Point{TxID: r.TxID, Vout: uint32(n)}
				if value, ok := owned[pt]; ok && value != out.ValueSat {
					return fail("EXPOSURE_BINDING")
				}
				owned[pt] = out.ValueSat
			}
		}
	}
	var total int64
	for pt, value := range owned {
		if spent[pt] {
			continue
		}
		if value < 1 || value > x.cfg.Spending.EnrolledHot-total {
			return fail("ENROLLED_HOT_CAP")
		}
		total += value
	}
	return nil
}
