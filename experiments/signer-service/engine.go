package signerservice

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"sync"

	rental "github.com/relux-works/swarma-chain-lab/experiments/rental"
	"github.com/relux-works/swarma-chain-lab/experiments/rental/oplocator"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/durable"
)

type Inventory struct {
	Input    su.PlanInput `json:"input"`
	Reserved string       `json:"reserved,omitempty"`
}
type operation struct {
	MovedAtoms int64  `json:"moved_atoms,omitempty"`
	SpendAt    int64  `json:"spend_at,omitempty"`
	SourceID   string `json:"source_id,omitempty"`
	SourceHash string `json:"source_hash,omitempty"`
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	Intent     Intent `json:"intent"`
	At         int64  `json:"at"`
	Record     string `json:"record"`
}
type suppression struct {
	SourceID   string `json:"source_id"`
	SourceHash string `json:"source_hash"`
	Booking    string `json:"booking"`
	Contract   string `json:"contract"`
	Payment    string `json:"payment"`
}
type ledger struct {
	CustodyClosed string                 `json:"custody_closed,omitempty"`
	Version       int                    `json:"version"`
	Binding       string                 `json:"binding"`
	LastTime      int64                  `json:"last_time"`
	Inventory     []Inventory            `json:"inventory,omitempty"`
	Operations    []operation            `json:"operations,omitempty"`
	Suppressed    []suppression          `json:"suppressed,omitempty"`
	Intake        []intake               `json:"intake,omitempty"`
	Cursors       map[SourceClass]string `json:"cursors"`
}
type record struct {
	ID           string          `json:"id"`
	Phase        string          `json:"phase"`
	Request      string          `json:"request,omitempty"`
	Publication  string          `json:"publication,omitempty"`
	Spec         rental.PlanSpec `json:"spec"`
	SignedGrant  json.RawMessage `json:"signed_grant,omitempty"`
	Plan         *rental.Plan    `json:"plan,omitempty"`
	RawTx        string          `json:"raw_tx,omitempty"`
	TxID         string          `json:"txid,omitempty"`
	Presentation json.RawMessage `json:"presentation,omitempty"`
	StoreHash    string          `json:"store_hash,omitempty"`
}
type intake struct {
	ID     string      `json:"id"`
	Hash   string      `json:"hash"`
	Source SourceClass `json:"source"`
}

type Engine struct {
	mu          sync.Mutex
	cfg         Config
	issuer      Issuer
	node        su.Node
	broadcaster Broadcast
	sink        GrantStore
	store       *durable.Store
	state       ledger
	poisoned    bool
	// Tests install a subprocess-exit hook; no production environment variable
	// can alter signing or durability behaviour.
	boundary func(string)
}

func Open(c Config, issuer Issuer, node su.Node, b Broadcast, sink GrantStore) (*Engine, error) {
	// Detach configuration slices/maps from the caller before binding state.
	var detached Config
	if json.Unmarshal(encode(c), &detached) != nil {
		return nil, fail("CONFIG_ENCODING")
	}
	c = detached
	if e := c.validate(); e != nil {
		return nil, e
	}
	if issuer == nil || node == nil || b == nil || sink == nil {
		return nil, fail("DEPENDENCIES")
	}
	if e := privateRoot(c.StateDir); e != nil {
		return nil, e
	}
	s, e := durable.Open(c.StateDir, "signer.lock")
	if e != nil {
		return nil, e
	}
	x := &Engine{cfg: c, issuer: issuer, node: node, broadcaster: b, sink: sink, store: s}
	binding := hash(encode(c))
	raw, e := s.Read("ledger.json", 65536)
	if e != nil {
		s.Close()
		return nil, e
	}
	if raw == nil {
		x.state = ledger{Version: 1, Binding: binding, Cursors: map[SourceClass]string{}}
	} else {
		if strict(raw, &x.state) != nil || x.state.Version != 1 || x.state.Binding != binding || x.state.Cursors == nil || x.validLedger() != nil {
			s.Close()
			return nil, fail("LEDGER_CORRUPT")
		}
	}
	return x, nil
}
func (x *Engine) Close() { x.mu.Lock(); defer x.mu.Unlock(); x.poisoned = true; x.store.Close() }
func (x *Engine) at(name string) {
	if x.boundary != nil {
		x.boundary(name)
	}
}
func (x *Engine) validLedger() error {
	if len(x.state.Inventory) > MaxRecords || len(x.state.Operations) > MaxRecords || len(x.state.Suppressed) > MaxRecords || len(x.state.Intake) > MaxRecords || x.state.LastTime < 0 {
		return fail("LEDGER_BOUND")
	}
	ops := map[string]bool{}
	for _, op := range x.state.Operations {
		if !digest(op.ID) || ops[op.ID] || op.At < 1 || op.At > x.state.LastTime {
			return fail("LEDGER_OPERATION")
		}
		ops[op.ID] = true
		if _, e := x.readRecord(op); e != nil {
			return e
		}
	}
	seen := map[su.Point]bool{}
	for _, v := range x.state.Inventory {
		if seen[v.Input.Point] || x.validInventory(v.Input) != nil || (v.Reserved != "" && !ops[v.Reserved]) {
			return fail("LEDGER_INVENTORY")
		}
		seen[v.Input.Point] = true
	}
	for _, i := range x.state.Intake {
		if !digest(i.ID) || !digest(i.Hash) || (i.Source != BookingSource && i.Source != OperatorSource) {
			return fail("LEDGER_INTAKE")
		}
		b, e := x.store.Read("item-"+i.Hash+".json", 65536)
		if e != nil || hash(b) != i.Hash {
			return fail("LEDGER_INTAKE")
		}
	}
	return nil
}
func (x *Engine) readRecord(op operation) (record, error) {
	var r record
	if !digest(op.Record) {
		return r, fail("RECORD_HASH")
	}
	b, e := x.store.Read("blob-"+op.Record+".json", 65536)
	if e != nil || hash(b) != op.Record || strict(b, &r) != nil || r.ID != op.ID || r.Spec.Kind != op.Kind {
		return r, fail("RECORD_CORRUPT")
	}
	switch op.Kind {
	case "grant-issue", "revoke", "refill":
	default:
		return r, fail("RECORD_TEMPLATE")
	}
	switch r.Phase {
	case "reserved", "prepared", "signing_uncertain", "signed", "broadcast", "stored":
	default:
		return r, fail("RECORD_PHASE")
	}
	if r.Phase != "reserved" && r.Plan == nil {
		return r, fail("RECORD_PLAN")
	}
	if x.cfg.Spending != nil {
		moved, e := x.movement(r.Spec)
		if e != nil || op.MovedAtoms != moved || op.SpendAt < 1 || op.SpendAt > x.state.LastTime {
			return r, fail("RECORD_SPENDING")
		}
	}
	if r.Phase == "signed" || r.Phase == "broadcast" || r.Phase == "stored" {
		raw, e := hex.DecodeString(r.RawTx)
		if e != nil {
			return r, fail("RECORD_TRANSACTION")
		}
		tx, e := su.DecodeTransaction(raw)
		if e != nil || tx.ID() != r.TxID {
			return r, fail("RECORD_TRANSACTION")
		}
		var want rental.Plan
		if op.Kind == "grant-issue" {
			want, e = rental.MakeGrantIssuancePlan(x.policy().Policy, r.Spec, r.SignedGrant)
		} else {
			want, e = rental.MakePlan(x.policy(), r.Spec, nil, nil, nil, op.At)
		}
		if e != nil || !bytes.Equal(encode(want), encode(r.Plan)) || verifySignedPlan(want, raw) != nil {
			return r, fail("RECORD_TRANSACTION")
		}
		if op.Kind == "grant-issue" {
			proof, e := rental.PresentIssuedGrant(r.SignedGrant, r.TxID)
			if e != nil || !bytes.Equal(proof, r.Presentation) {
				return r, fail("RECORD_PRESENTATION")
			}
		}
		if r.Phase == "stored" && (op.Kind != "grant-issue" || r.StoreHash != hash(r.SignedGrant)) {
			return r, fail("RECORD_STORE")
		}

	}
	return r, nil
}
func cloneState(s ledger) ledger { var c ledger; _ = json.Unmarshal(encode(s), &c); return c }
func (x *Engine) commit(s ledger) error {
	b := encode(s)
	if len(b) > 65536 {
		return fail("LEDGER_FULL")
	}
	if e := x.store.Write("ledger.json", b); e != nil {
		x.poisoned = true
		return e
	}
	x.state = s
	return nil
}
func (x *Engine) save(index int, r record) error {
	b := encode(r)
	h := hash(b)
	if e := x.store.Write("blob-"+h+".json", b); e != nil {
		x.poisoned = true
		return e
	}
	s := cloneState(x.state)
	s.Operations[index].Record = h
	return x.commit(s)
}
func (x *Engine) ready(now int64) error {
	if x.poisoned {
		return fail("STATE_UNCERTAIN")
	}
	if x.state.CustodyClosed != "" {
		return fail("CUSTODY_KEY_ROTATED")
	}
	if now < 1 || now < x.state.LastTime {
		return fail("CLOCK_ROLLBACK")
	}
	return nil
}
func (x *Engine) validInventory(in su.PlanInput) error {
	if !digest(in.Point.TxID) || in.ValueSat < 1 || in.ValueSat > rental.MaxMoney {
		return fail("INVENTORY_INPUT")
	}
	p := x.cfg.Policy.Policy
	switch in.Role {
	case "seal":
		if in.Script != p.SealScript {
			return fail("SEAL_SCRIPT")
		}
	case "funding":
		if in.Script != p.FundingScript || in.Script == p.SealScript {
			return fail("FUNDING_SEAL_SCRIPT")
		}
		for _, s := range x.cfg.HistoricalSealScripts {
			if in.Script == s {
				return fail("FUNDING_SEAL_SCRIPT")
			}
		}
		for _, pt := range p.KnownPoolSeals {
			if in.Point == (su.Point{TxID: pt.TxID, Vout: pt.Vout}) {
				return fail("FUNDING_KNOWN_POOL")
			}
		}
	default:
		return fail("INVENTORY_ROLE")
	}
	return nil
}

// Enroll is private operator configuration, not an outbox instruction. Every
// explicit point is independently confirmed and unspent on the pinned node.
func (x *Engine) Enroll(ctx context.Context, inputs []su.PlanInput, now int64) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	if e := x.ready(now); e != nil {
		return e
	}
	if len(inputs) < 1 || len(x.state.Inventory)+len(inputs) > MaxRecords {
		return fail("INVENTORY_BOUND")
	}
	s := cloneState(x.state)
	seen := map[su.Point]bool{}
	for _, v := range s.Inventory {
		seen[v.Input.Point] = true
	}
	for _, in := range inputs {
		if seen[in.Point] {
			return fail("INVENTORY_DUPLICATE")
		}
		seen[in.Point] = true
		if e := x.validInventory(in); e != nil {
			return e
		}
		s.Inventory = append(s.Inventory, Inventory{Input: in})
	}
	if e := x.capExposure(s.Inventory); e != nil {
		return e
	}
	if e := x.observe(ctx, inputs); e != nil {
		return e
	}
	s.LastTime = now
	return x.commit(s)
}
func (x *Engine) policy() rental.IssuerPolicy {
	p := x.cfg.Policy
	p.Policy.KnownPoolSeals = append([]rental.Point(nil), p.Policy.KnownPoolSeals...)
	seen := map[rental.Point]bool{}
	for _, pt := range p.Policy.KnownPoolSeals {
		seen[pt] = true
	}
	for _, v := range x.state.Inventory {
		pt := rental.Point{TxID: v.Input.Point.TxID, Vout: v.Input.Point.Vout}
		if v.Input.Role == "seal" && !seen[pt] {
			p.Policy.KnownPoolSeals = append(p.Policy.KnownPoolSeals, pt)
			seen[pt] = true
		}
	}
	return p
}
func (x *Engine) observe(ctx context.Context, inputs []su.PlanInput) error {
	o := su.NewReadObservation(ctx, x.node)
	defer o.Close()
	p := x.cfg.Policy.Policy
	if e := o.Start(p.Network, p.Genesis); e != nil {
		return e
	}
	for _, in := range inputs {
		if e := x.validInventory(in); e != nil {
			return e
		}
		v, tx, e := o.PaymentTransaction(in.Point.TxID)
		if e != nil {
			return e
		}
		if _, e = o.Confirmed(v); e != nil {
			return e
		}
		if uint64(in.Point.Vout) >= uint64(len(tx.Outputs)) {
			return fail("PREVOUT_INDEX")
		}
		out := tx.Outputs[in.Point.Vout]
		if out.Value != in.ValueSat || hex.EncodeToString(out.Script) != in.Script {
			return fail("PREVOUT_BINDING")
		}
		var raw json.RawMessage
		if e = o.Call("gettxout", &raw, in.Point.TxID, in.Point.Vout, true); e != nil {
			return e
		}
		if bytes.Equal(raw, []byte("null")) || len(raw) == 0 {
			return fail("PREVOUT_SPENT")
		}
		var u struct {
			Confirmations int64       `json:"confirmations"`
			Value         json.Number `json:"value"`
			Script        struct {
				Hex string `json:"hex"`
			} `json:"scriptPubKey"`
		}
		if json.Unmarshal(raw, &u) != nil {
			return fail("PREVOUT_RESPONSE")
		}
		value, e := su.ParseCoins(string(u.Value))
		if e != nil || u.Confirmations < 1 || value != in.ValueSat || u.Script.Hex != in.Script {
			return fail("PREVOUT_BINDING")
		}
	}
	return o.Stable()
}
func (x *Engine) capIssue(i Intent, now int64) error { return x.capIssueExcept(i, now, "") }
func (x *Engine) capIssueExcept(i Intent, now int64, exclude string) error {
	if i.BudgetSat < 0 || i.BudgetSat > rental.MaxMoney {
		return fail("ISSUANCE_BUDGET")
	}
	var hc, dc int
	var hv, dv int64
	for _, op := range x.state.Operations {
		if op.Kind != "grant-issue" || op.ID == exclude {
			continue
		}
		r, e := x.readRecord(op)
		if e != nil {
			return e
		}
		pending := r.Phase != "stored"
		if pending || op.At/86400 == now/86400 {
			dc++
			if op.Intent.BudgetSat > x.cfg.Caps.BudgetDay-dv {
				return fail("ISSUANCE_CAP")
			}
			dv += op.Intent.BudgetSat
		}
		if pending || op.At/3600 == now/3600 {
			hc++
			if op.Intent.BudgetSat > x.cfg.Caps.BudgetHour-hv {
				return fail("ISSUANCE_CAP")
			}
			hv += op.Intent.BudgetSat
		}
	}
	c := x.cfg.Caps
	if hc >= c.CountHour || dc >= c.CountDay || i.BudgetSat > c.BudgetHour-hv || i.BudgetSat > c.BudgetDay-dv {
		return fail("ISSUANCE_CAP")
	}
	return nil
}
func (x *Engine) find(id string) int {
	for j, op := range x.state.Operations {
		if op.ID == id {
			return j
		}
	}
	return -1
}
func (x *Engine) pick(role string) (su.PlanInput, error) {
	for _, v := range x.state.Inventory {
		if v.Input.Role == role && v.Reserved == "" {
			return v.Input, nil
		}
	}
	return su.PlanInput{}, fail("INVENTORY_EMPTY")
}
func (x *Engine) reserve(op operation, r record, points []su.Point) error {
	if len(x.state.Operations) >= MaxRecords {
		return fail("OPERATION_BOUND")
	}
	if x.cfg.Spending != nil {
		moved, e := x.movement(r.Spec)
		if e != nil {
			return e
		}
		if e = x.capSpending(moved, op.At, ""); e != nil {
			return e
		}
		if e = x.capExposure(x.state.Inventory); e != nil {
			return e
		}
		op.MovedAtoms, op.SpendAt = moved, op.At
	}
	s := cloneState(x.state)
	for _, pt := range points {
		found := false
		for i := range s.Inventory {
			v := &s.Inventory[i]
			if v.Input.Point == pt {
				if v.Reserved != "" {
					return fail("INPUT_RESERVED")
				}
				v.Reserved = op.ID
				found = true
			}
		}
		if !found {
			return fail("INPUT_NOT_ENROLLED")
		}
	}
	b := encode(r)
	op.Record = hash(b)
	s.Operations = append(s.Operations, op)
	s.LastTime = op.At
	if len(encode(s)) > 65536 || len(b) > 65536 {
		return fail("LEDGER_FULL")
	}
	if e := x.store.Write("blob-"+op.Record+".json", b); e != nil {
		x.poisoned = true
		return e
	}
	if e := x.commit(s); e != nil {
		return e
	}
	x.at("reserved")
	return nil
}
func (x *Engine) feeProjection(spec rental.PlanSpec) (int64, error) {
	if spec.Kind != "grant-issue" {
		plan, e := rental.MakePlan(x.policy(), spec, nil, nil, nil, 0)
		return plan.FeeSat, e
	}
	tx := su.Transaction{Version: 2}
	var total int64
	for _, in := range spec.Inputs {
		if e := x.validInventory(in); e != nil {
			return 0, e
		}
		if in.Role != "funding" || in.ValueSat > rental.MaxMoney-total {
			return 0, fail("FUNDING_TEMPLATE")
		}
		total += in.ValueSat
		tx.Inputs = append(tx.Inputs, su.Input{Point: in.Point, Script: make([]byte, 140), Sequence: 0xfffffffe})
	}
	script, _ := hex.DecodeString(x.cfg.Policy.Policy.FundingScript)
	tx.Outputs = []su.Output{{Script: make([]byte, oplocator.IssuanceBlobScriptBytes)}, {Script: script}}
	_, fee, _, e := su.ReserveFee(tx, total, x.cfg.Policy.Policy.GrantFeeRate())
	return fee, e
}

// A frozen custody configuration cannot follow a current or pending grant-key
// rotation silently. Existing reservations survive refusal; migration is an
// explicit operator operation outside this bounded service unit.
func (x *Engine) identity(ctx context.Context) error {
	p := x.cfg.Policy.Policy
	key, _, e := rental.ResolveLandlordGrantKey(ctx, x.node, p, p.LandlordName)
	if e != nil {
		return e
	}
	if key != p.IssuerPubkey {
		s := cloneState(x.state)
		s.CustodyClosed = "CUSTODY_KEY_ROTATED"
		if e = x.commit(s); e != nil {
			return e
		}
		return fail("CUSTODY_KEY_ROTATED")
	}
	return nil
}
