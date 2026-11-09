package rental

import su "relux.works/swarma-chain-lab/experiments/single-use"

func (p Policy) validateGrantFunding() error {
	if e := p.validateGrant(); e != nil {
		return e
	}
	if !p2pkh(p.FundingScript) || p.FundingScript == p.SealScript {
		return bad("FUNDING_POLICY")
	}
	return nil
}

// grantFunding validates offline input facts and prepares the bounded fee
// projection. It neither reserves inputs nor asserts their chain state.
func grantFunding(p Policy, s PlanSpec, pool Point) (su.Transaction, int64, error) {
	tx := su.Transaction{Version: 2}
	var total int64
	if e := p.validateGrantFunding(); e != nil {
		return tx, 0, e
	}
	if s.Kind != "grant-issue" || s.ChangeScript != p.FundingScript || len(s.Inputs) < 1 || len(s.Inputs) > 16 || s.Count != 0 || s.ValueSat != 0 {
		return tx, 0, bad("ISSUANCE_TEMPLATE")
	}
	seen := map[su.Point]bool{}
	for _, in := range s.Inputs {
		if in.Point == (su.Point{TxID: pool.TxID, Vout: pool.Vout}) {
			return tx, 0, bad("ISSUANCE_SPENDS_SEAL")
		}
		if in.Script == p.SealScript {
			return tx, 0, bad("FUNDING_SEAL_SCRIPT")
		}
		for _, known := range p.KnownPoolSeals {
			if in.Point == (su.Point{TxID: known.TxID, Vout: known.Vout}) {
				return tx, 0, bad("FUNDING_KNOWN_POOL")
			}
		}
		if in.Role != "funding" || in.Script != p.FundingScript || !digest(in.Point.TxID) || seen[in.Point] || in.ValueSat < 1 || in.ValueSat > MaxMoney-total {
			return tx, 0, bad("ISSUANCE_FUNDING")
		}
		seen[in.Point] = true
		total += in.ValueSat
		tx.Inputs = append(tx.Inputs, su.Input{Point: in.Point, Script: make([]byte, 140), Sequence: 0xfffffffe})
	}
	// The actual commitment is always 34 script bytes. Only its size matters for
	// pre-sign fee validation; these placeholder bytes are never returned as a plan.
	tx.Outputs = []su.Output{{Value: 0, Script: make([]byte, 34)}, {Value: 0, Script: mustDecodeKey(p.FundingScript)}}
	if _, _, _, e := su.ReserveLegacyFee(tx, total); e != nil {
		return tx, 0, e
	}
	return tx, total, nil
}

// MakeGrantIssuancePlan returns an offline unsigned commitment transaction.
// Funding facts confer no authority; a separate signer must recheck prevouts,
// custody and reservations. The referenced seal can never be an input.
func MakeGrantIssuancePlan(p Policy, s PlanSpec, raw []byte) (Plan, error) {
	var result Plan
	if e := p.validateGrantFunding(); e != nil {
		return result, e
	}
	signed, e := ParseSignedGrant(raw)
	if e != nil {
		return result, e
	}
	g := signed.Grant
	script, e := GrantSealScript(g.IssuerKey)
	if e != nil || script != p.SealScript || g.AgentName != p.AgentName || g.LandlordName != p.LandlordName || g.Network != p.Network || g.Genesis != p.Genesis {
		return result, bad("GRANT_PLAN_POLICY")
	}
	tx, total, e := grantFunding(p, s, g.Seal)
	if e != nil {
		return result, e
	}
	commit, e := IssuanceCommitment(signed)
	if e != nil {
		return result, e
	}
	rootScript := "6a20" + commit
	tx.Outputs[0].Script = mustDecodeKey(rootScript)
	size, fee, change, e := su.ReserveLegacyFee(tx, total)
	if e != nil {
		return result, e
	}
	return Plan{Version: 3, Network: p.Network, Genesis: p.Genesis, Kind: "grant-issue", Offline: true, TransactionVersion: 2, Inputs: s.Inputs, Outputs: []su.PlanOutput{{ValueSat: 0, Script: rootScript, Role: "issuance-commitment"}, {ValueSat: change, Script: p.FundingScript, Role: "change"}}, FeeRate: 200, FeeSat: fee, MaxSignedVBytes: size, GrantID: signed.ID(), RequiredReview: "Unsigned issuance plan only. Independently verify current funding prevouts, separate funding/change script, pool reservations, custody and exact transaction before signing; no broadcast authority."}, nil
}
