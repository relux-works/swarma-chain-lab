package signerservice

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"time"

	pc "github.com/relux-works/swarma-chain-lab/experiments/payment-chain"
	rental "github.com/relux-works/swarma-chain-lab/experiments/rental"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

func (x *Engine) Process(ctx context.Context, raw []byte, source SourceClass, now int64) (Result, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.process(ctx, raw, source, now)
}
func (x *Engine) process(ctx context.Context, raw []byte, source SourceClass, now int64) (Result, error) {
	started := time.Now()
	advance := func(j int) (Result, error) { return x.advance(ctx, j, now+int64(time.Since(started)/time.Second)) }

	if e := x.ready(now); e != nil {
		return Result{}, e
	}
	var item Item
	if strict(raw, &item) != nil || !digest(item.ID) || (source != BookingSource && source != OperatorSource) {
		return Result{}, fail("OUTBOX_ITEM")
	}
	for _, op := range x.state.Operations {
		if op.SourceID == item.ID && op.SourceHash != hash(raw) {
			return Result{}, fail("ITEM_CONFLICT")
		}
	}
	for _, sp := range x.state.Suppressed {
		if sp.SourceID == item.ID && sp.SourceHash != hash(raw) {
			return Result{}, fail("ITEM_CONFLICT")
		}
	}
	switch item.Kind {
	case "grant-issue":
		if source != BookingSource || item.Revoke != nil || len(item.Request) == 0 || len(item.Publication) == 0 {
			return Result{}, fail("ISSUE_SOURCE")
		}
		// Unauthenticated booking data is used only for locating an exact existing
		// record. Fresh operations still require Inspect and own-node Check.
		var claimed struct {
			BookingID string `json:"booking_id"`
		}
		if json.Unmarshal([]byte(item.Request), &claimed) != nil || !digest(claimed.BookingID) {
			return Result{}, fail("ISSUE_REQUEST")
		}
		id := hash([]byte("grant-issue/" + claimed.BookingID))
		if j := x.find(id); j >= 0 {
			r, e := x.readRecord(x.state.Operations[j])
			if e != nil {
				return Result{}, e
			}
			if r.Request != item.Request || r.Publication != item.Publication {
				return Result{}, fail("ISSUANCE_CONFLICT")
			}
			return advance(j)
		}
		intent, e := x.issuer.Inspect([]byte(item.Request), []byte(item.Publication), now)
		if e != nil {
			return Result{}, e
		}
		if intent.BookingID != claimed.BookingID || !digest(intent.ContractSHA256) || !digest(intent.PaymentTxID) || !x.paymentProfile(intent.PaymentCoin, intent.PaymentNetwork, intent.PaymentGenesis) {
			return Result{}, fail("ISSUER_INTENT")
		}
		// Budget zero omits the K1 bound, so this capped service refuses it rather
		// than recording unbounded authority as zero value.
		if intent.BudgetSat <= 0 {
			return Result{}, fail("UNBOUNDED_AUTHORITY")
		}
		for _, s := range x.state.Suppressed {
			if s.Booking == intent.BookingID {
				return Result{}, fail("BOOKING_REVOKED")
			}
		}
		if e = x.capIssue(intent, now); e != nil {
			return Result{}, e
		}
		seal, e := x.pick("seal")
		if e != nil {
			return Result{}, e
		}
		fund, e := x.pick("funding")
		if e != nil {
			return Result{}, e
		}
		spec := rental.PlanSpec{Kind: "grant-issue", Inputs: []su.PlanInput{fund}, ChangeScript: x.cfg.Policy.Policy.FundingScript, Pool: rental.PoolOutput{Point: rental.Point{TxID: seal.Point.TxID, Vout: seal.Point.Vout}, ValueSat: seal.ValueSat, Script: seal.Script}}
		fee, e := x.feeProjection(spec)
		if e != nil {
			return Result{}, e
		}
		if fee > x.cfg.Caps.FeePerTx {
			return Result{}, fail("FEE_CAP")
		}
		if e = x.capSpending(fee, now, ""); e != nil {
			return Result{}, e
		}
		if e = x.identity(ctx); e != nil {
			return Result{}, e
		}
		if e = x.issuer.Check(ctx, []byte(item.Request), []byte(item.Publication), now); e != nil {
			return Result{}, e
		}
		if e = x.observe(ctx, []su.PlanInput{seal, fund}); e != nil {
			return Result{}, e
		}
		op := operation{ID: id, Kind: item.Kind, Intent: intent, At: now, SourceID: item.ID, SourceHash: hash(raw)}
		r := record{ID: id, Phase: "reserved", Request: item.Request, Publication: item.Publication, Spec: spec}
		if e = x.reserve(op, r, []su.Point{seal.Point, fund.Point}); e != nil {
			return Result{}, e
		}
		return advance(len(x.state.Operations) - 1)
	case "revoke":
		if len(item.Request) != 0 || len(item.Publication) != 0 || item.Revoke == nil {
			return Result{}, fail("REVOKE_TEMPLATE")
		}
		return x.revoke(ctx, *item.Revoke, source, now, item.ID, hash(raw))
	default:
		return Result{}, fail("TEMPLATE_REFUSED")
	}
}
func (x *Engine) revoke(ctx context.Context, r Revoke, source SourceClass, now int64, sourceID, sourceHash string) (Result, error) {
	if !digest(r.BookingID) || !digest(r.ContractSHA256) {
		return Result{}, fail("REVOKE_BINDING")
	}
	if source == BookingSource {
		if r.Version != 2 || r.Reason != "payment_reorged" || !digest(r.PaymentTxID) || !digest(r.ObservedTipHash) || !x.paymentProfile(r.PaymentCoin, r.PaymentNetwork, r.PaymentGenesis) {
			return Result{}, fail("REVOKE_AUTHORITY")
		}
	} else if r.Reason != "operator" {
		return Result{}, fail("REVOKE_AUTHORITY")
	}
	id := hash([]byte("revoke/" + r.BookingID))
	issuance := x.find(hash([]byte("grant-issue/" + r.BookingID)))
	if issuance < 0 {
		// A trusted revoke arriving first burns the booking, never a guessed seal.
		for _, s := range x.state.Suppressed {
			if s.Booking == r.BookingID {
				if s.Contract != r.ContractSHA256 {
					return Result{}, fail("REVOKE_CONFLICT")
				}
				return Result{ID: id, Phase: "suppressed"}, nil
			}
		}
		if len(x.state.Suppressed) >= MaxRecords {
			return Result{}, fail("SUPPRESSION_BOUND")
		}
		s := cloneState(x.state)
		s.LastTime = now
		s.Suppressed = append(s.Suppressed, suppression{Booking: r.BookingID, Contract: r.ContractSHA256, Payment: hash(encode(r)), SourceID: sourceID, SourceHash: sourceHash})
		if e := x.commit(s); e != nil {
			return Result{}, e
		}
		return Result{ID: id, Phase: "suppressed"}, nil
	}
	op := x.state.Operations[issuance]
	i := op.Intent
	if i.ContractSHA256 != r.ContractSHA256 || (source == BookingSource && (i.PaymentCoin != r.PaymentCoin || i.PaymentNetwork != r.PaymentNetwork || i.PaymentGenesis != r.PaymentGenesis || i.PaymentTxID != r.PaymentTxID || i.PaymentVout != r.PaymentVout)) {
		return Result{}, fail("REVOKE_BINDING")
	}
	if j := x.find(id); j >= 0 {
		return x.advance(ctx, j, now)
	}
	issued, e := x.readRecord(op)
	if e != nil {
		return Result{}, e
	}
	seal := su.PlanInput{Point: su.Point{TxID: issued.Spec.Pool.Point.TxID, Vout: issued.Spec.Pool.Point.Vout}, ValueSat: issued.Spec.Pool.ValueSat, Script: issued.Spec.Pool.Script, Role: "seal"}
	spec := rental.PlanSpec{Kind: "revoke", Inputs: []su.PlanInput{seal}, ChangeScript: x.cfg.Policy.Policy.FundingScript, Pool: issued.Spec.Pool}
	plan, e := rental.MakePlan(x.policy(), spec, nil, nil, nil, now)
	if e != nil {
		return Result{}, e
	}
	if plan.FeeSat > x.cfg.Caps.FeePerTx {
		return Result{}, fail("FEE_CAP")
	}
	if e = x.checkPlanSpending(plan, now, ""); e != nil {
		return Result{}, e
	}
	if e = x.observe(ctx, []su.PlanInput{seal}); e != nil {
		return Result{}, e
	}
	// The seal remains permanently bound to its issuance in the ledger. Revocation
	// consumes that same reserved point; no new operation may treat it as free.
	revokeOp := operation{ID: id, Kind: "revoke", Intent: i, At: now, SourceID: sourceID, SourceHash: sourceHash}
	rec := record{ID: id, Phase: "prepared", Spec: spec, Plan: &plan}
	if e = x.reserve(revokeOp, rec, nil); e != nil {
		return Result{}, e
	}
	return x.advance(ctx, len(x.state.Operations)-1, now)
}

// Refill is selected locally from enrolled funding. An outbox cannot choose
// inputs, outputs, amounts or an arbitrary transaction to sign.
func (x *Engine) Refill(ctx context.Context, now int64) (Result, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if e := x.ready(now); e != nil {
		return Result{}, e
	}
	free := 0
	for _, v := range x.state.Inventory {
		if v.Input.Role == "seal" && v.Reserved == "" {
			free++
		}
	}
	if free >= x.cfg.Caps.LowWater {
		return Result{Phase: "pool_ready"}, nil
	}
	// Resume a pending refill before considering another funding point.
	for j, op := range x.state.Operations {
		if op.Kind == "refill" {
			r, e := x.readRecord(op)
			if e != nil {
				return Result{}, e
			}
			if r.Phase != "broadcast" && r.Phase != "stored" {
				return x.advance(ctx, j, now)
			}
		}
	}
	fund, e := x.pick("funding")
	if e != nil {
		return Result{}, e
	}
	if len(x.state.Inventory)+x.cfg.Caps.RefillCount+1 > MaxRecords {
		return Result{}, fail("INVENTORY_BOUND")
	}
	id := hash(encode(struct {
		Kind  string
		Point su.Point
	}{"refill", fund.Point}))
	if j := x.find(id); j >= 0 {
		return x.advance(ctx, j, now)
	}
	c := x.cfg.Caps
	spec := rental.PlanSpec{Kind: "refill", Inputs: []su.PlanInput{fund}, ChangeScript: x.cfg.Policy.Policy.FundingScript, Count: c.RefillCount, ValueSat: c.SealValue}
	if int64(spec.Count)*spec.ValueSat > c.RefillValue {
		return Result{}, fail("REFILL_CAP")
	}
	plan, e := rental.MakePlan(x.policy(), spec, nil, nil, nil, now)
	if e != nil {
		return Result{}, e
	}
	if plan.FeeSat > c.FeePerTx {
		return Result{}, fail("FEE_CAP")
	}
	if e = x.checkPlanSpending(plan, now, ""); e != nil {
		return Result{}, e
	}
	if e = x.observe(ctx, []su.PlanInput{fund}); e != nil {
		return Result{}, e
	}
	if e = x.reserve(operation{ID: id, Kind: "refill", At: now}, record{ID: id, Phase: "prepared", Spec: spec, Plan: &plan}, []su.Point{fund.Point}); e != nil {
		return Result{}, e
	}
	return x.advance(ctx, len(x.state.Operations)-1, now)
}
func (x *Engine) advance(ctx context.Context, j int, now int64) (Result, error) {
	started := time.Now()
	current := func() int64 { return now + int64(time.Since(started)/time.Second) }

	op := x.state.Operations[j]
	r, e := x.readRecord(op)
	if e != nil {
		return Result{}, e
	}
	result := func() Result {
		v := Result{ID: op.ID, Phase: r.Phase, TxID: r.TxID}
		if len(r.SignedGrant) > 0 {
			v.GrantID = hash(r.SignedGrant)
		}
		return v
	}
	if op.Kind == "grant-issue" && x.find(hash([]byte("revoke/"+op.Intent.BookingID))) >= 0 {
		return result(), fail("BOOKING_REVOKED")
	}
	if !terminalSpend(r) {
		if e = x.chargeSpendingAt(j, current()); e != nil {
			return result(), e
		}
		if e = x.capExposure(x.state.Inventory); e != nil {
			return result(), e
		}
	}
	if r.Phase == "reserved" {
		if op.Kind != "grant-issue" {
			return result(), fail("RECORD_PHASE")
		}
		if e = x.chargeAt(j, current()); e != nil {
			return result(), e
		}
		prepared := x.issuer.Prepare(ctx, []byte(r.Request), []byte(r.Publication), r.Spec.Pool.Point, r.Spec, current())
		x.at("issuer_returned")
		if prepared.Verdict != "prepared" {
			return result(), fail(prepared.Reason)
		}
		signed, e := rental.ParseSignedGrant(prepared.SignedGrant)
		if e != nil {
			return result(), e
		}
		if signed.Grant.Seal != r.Spec.Pool.Point || signed.Grant.ContractSHA256 != op.Intent.ContractSHA256 || signed.Grant.Budget == nil || *signed.Grant.Budget != op.Intent.BudgetSat {
			return result(), fail("PREPARED_BINDING")
		}
		plan, e := rental.MakeGrantIssuancePlan(x.policy().Policy, r.Spec, prepared.SignedGrant)
		if e != nil || prepared.Plan == nil || !bytes.Equal(encode(plan), encode(*prepared.Plan)) {
			return result(), fail("PREPARED_PLAN")
		}
		if plan.FeeSat > x.cfg.Caps.FeePerTx {
			return result(), fail("FEE_CAP")
		}
		r.SignedGrant = prepared.SignedGrant
		r.Plan = &plan
		r.Phase = "prepared"
		if e = x.save(j, r); e != nil {
			return result(), e
		}
		x.at("prepared")
	}
	if r.Phase == "signing_uncertain" {
		return result(), fail("SIGNING_UNCERTAIN")
	}
	if r.Phase == "prepared" {
		if op.Kind == "grant-issue" {
			if e = x.chargeAt(j, current()); e != nil {
				return result(), e
			}
		}
		if e = x.identity(ctx); e != nil {
			return result(), e
		}
		// A fresh authenticated payment check precedes transaction signing too.
		if op.Kind == "grant-issue" {
			if e = x.issuer.Check(ctx, []byte(r.Request), []byte(r.Publication), current()); e != nil {
				return result(), e
			}
		}
		if e = x.observe(ctx, r.Spec.Inputs); e != nil {
			return result(), e
		}
		if op.Kind == "grant-issue" {
			seal := su.PlanInput{Point: su.Point{TxID: r.Spec.Pool.Point.TxID, Vout: r.Spec.Pool.Point.Vout}, ValueSat: r.Spec.Pool.ValueSat, Script: r.Spec.Pool.Script, Role: "seal"}
			if e = x.observe(ctx, []su.PlanInput{seal}); e != nil {
				return result(), e
			}
		}
		// Rebuild the exact allowed template before any chain signature. Even an
		// authentic issuer result cannot add unrelated outputs or extra inputs.
		var want rental.Plan
		if op.Kind == "grant-issue" {
			want, e = rental.MakeGrantIssuancePlan(x.policy().Policy, r.Spec, r.SignedGrant)
		} else {
			want, e = rental.MakePlan(x.policy(), r.Spec, nil, nil, nil, now)
		}
		if e != nil || !bytes.Equal(encode(want), encode(r.Plan)) || want.FeeSat > x.cfg.Caps.FeePerTx {
			return result(), fail("SIGNING_TEMPLATE")
		}
		if e = x.checkPlanSpending(want, current(), op.ID); e != nil {
			return result(), e
		}
		if x.cfg.Spending != nil {
			moved, err := movedByPlan(want, x.cfg.Policy.Policy.FundingScript)
			if err != nil || moved != x.state.Operations[j].MovedAtoms {
				return result(), fail("RESERVED_MOVEMENT")
			}
		}
		path, script := x.cfg.FundingKeyPath, x.cfg.Policy.Policy.FundingScript
		if op.Kind == "revoke" {
			path, script = x.cfg.GrantKeyPath, x.cfg.Policy.Policy.SealScript
		}
		key, e := loadKey(path, script)
		if e != nil {
			return result(), e
		}
		defer key.Zero()
		r.Phase = "signing_uncertain"
		if e = x.save(j, r); e != nil {
			return result(), e
		}
		x.at("signing_uncertain")
		// Persistence/key-read latency cannot reuse an expired payment admission.
		// Failure after this marker remains uncertain and never retries signing.
		if op.Kind == "grant-issue" {
			if e = x.issuer.Check(ctx, []byte(r.Request), []byte(r.Publication), current()); e != nil {
				return result(), e
			}
		}
		raw, id, e := signPlan(*r.Plan, key)
		if e != nil {
			return result(), e
		}
		x.at("chain_signed")
		r.RawTx = hex.EncodeToString(raw)
		r.TxID = id
		r.Phase = "signed"
		if op.Kind == "grant-issue" {
			s, e := rental.ParseSignedGrant(r.SignedGrant)
			if e != nil {
				return result(), e
			}
			r.Presentation = encode(rental.GrantPresentation{SignedGrant: s, Issuance: rental.IssuanceProof{TxID: id}})
		}
		if e = x.save(j, r); e != nil {
			return result(), e
		}
		x.at("signed")
	}
	if r.Phase == "signed" {
		if e = x.chargeSpendingAt(j, current()); e != nil {
			return result(), e
		}
		raw, _ := hex.DecodeString(r.RawTx)
		// A lost ACK can only retry these exact durable bytes, never re-sign.
		id, e := x.broadcaster.Send(ctx, raw)
		x.at("broadcast_returned")
		if e != nil {
			return result(), fail("BROADCAST_UNCERTAIN")
		}
		if id != r.TxID {
			return result(), fail("BROADCAST_TXID")
		}
		if e = x.chargeSpendingAt(j, current()); e != nil {
			return result(), e
		}
		r.Phase = "broadcast"
		if e = x.save(j, r); e != nil {
			return result(), e
		}
		x.at("broadcast")
	}
	if r.Phase == "broadcast" || r.Phase == "stored" {
		if e = x.trackOutputs(j, r, current()); e != nil {
			return result(), e
		}
	}
	if r.Phase == "broadcast" && op.Kind == "grant-issue" {
		got, e := x.sink.Put(ctx, r.SignedGrant)
		x.at("store_returned")
		if e != nil {
			return result(), fail("STORE_PENDING")
		}
		if got != hash(r.SignedGrant) {
			return result(), fail("STORE_HASH")
		}
		r.StoreHash = got
		r.Phase = "stored"
		if e = x.save(j, r); e != nil {
			return result(), e
		}
		x.at("stored")
	}
	if r.Phase == "stored" && op.Kind == "grant-issue" && x.cfg.PresentationDir != "" {
		if e = x.publishConfirmed(ctx, op, r); e != nil {
			return result(), e
		}
		x.at("presentation_written")
	}
	return result(), nil
}
func (x *Engine) trackOutputs(j int, r record, now int64) error {
	s := cloneState(x.state)
	changed := false
	for index, out := range r.Plan.Outputs {
		role := ""
		if out.Role == "change" {
			role = "funding"
		}
		if out.Role == "pool-seal" {
			role = "seal"
		}
		if role == "" {
			continue
		}
		pt := su.Point{TxID: r.TxID, Vout: uint32(index)}
		exists := false
		for _, v := range s.Inventory {
			if v.Input.Point == pt {
				exists = true
				break
			}
		}
		if exists {
			continue
		}
		if len(s.Inventory) >= MaxRecords {
			return fail("INVENTORY_BOUND")
		}
		s.Inventory = append(s.Inventory, Inventory{Input: su.PlanInput{Point: pt, ValueSat: out.ValueSat, Script: out.Script, Role: role}})
		changed = true
	}
	if !changed {
		return nil
	}
	s.LastTime = now
	return x.commit(s)
}

func (x *Engine) chargeAt(j int, now int64) error {
	op := x.state.Operations[j]
	if e := x.capIssueExcept(op.Intent, now, op.ID); e != nil {
		return e
	}
	if op.At == now {
		return nil
	}
	s := cloneState(x.state)
	s.Operations[j].At = now
	s.LastTime = now
	return x.commit(s)
}

func (x *Engine) paymentProfile(coin, network, genesis string) bool {
	if network != x.cfg.Policy.Policy.Network {
		return false
	}
	_, err := pc.ForNetwork(coin, network, genesis)
	return err == nil
}
