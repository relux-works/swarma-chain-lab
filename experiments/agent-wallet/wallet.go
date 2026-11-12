package wallet

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"time"

	rental "github.com/relux-works/swarma-chain-lab/experiments/rental"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/durable"
)

type Config struct {
	Version       int           `json:"version"`
	Network       string        `json:"network"`
	Genesis       string        `json:"genesis"`
	Policy        rental.Policy `json:"policy"`
	Observer      su.Route      `json:"observer"`
	Wallet        WalletRoute   `json:"wallet"`
	Broadcast     su.Route      `json:"broadcast"`
	StateDir      string        `json:"state_dir"`
	ObjectsDir    string        `json:"objects_dir"`
	ChangeAddress string        `json:"change_address"`
	FeeRate       int64         `json:"fee_rate_sat_vb"`
	WalletDir     string        `json:"wallet_dir"`
	MemoryZone    string        `json:"memory_zone"`
}
type Record struct {
	GrantID     string     `json:"grant_id"`
	Nonce       string     `json:"nonce"`
	RequestHash string     `json:"request_sha256"`
	Action      string     `json:"action"`
	Phase       string     `json:"phase"`
	Reserved    int64      `json:"reserved_sat"`
	Fee         int64      `json:"fee_sat"`
	Inputs      []su.Point `json:"inputs"`
	TxID        string     `json:"txid"`
	UseSeal     *su.Point  `json:"use_seal,omitempty"`
	NewTxID     string     `json:"name_new_txid,omitempty"`
	NameVout    uint32     `json:"name_vout,omitempty"`
	NewScript   string     `json:"name_script,omitempty"`
	Salt        string     `json:"salt,omitempty"`
}
type state struct {
	Version int      `json:"version"`
	Binding string   `json:"binding"`
	Records []Record `json:"records"`
}
type Receipt struct {
	Status   string `json:"status"`
	Reason   string `json:"reason"`
	Message  string `json:"message"`
	GrantID  string `json:"grant_id,omitempty"`
	Nonce    string `json:"nonce,omitempty"`
	Phase    string `json:"phase,omitempty"`
	TxID     string `json:"txid,omitempty"`
	NewTxID  string `json:"name_new_txid,omitempty"`
	Reserved int64  `json:"reserved_sat,omitempty"`
}
type Budget struct {
	TotalRemaining int64  `json:"total_remaining_sat"`
	SpendRemaining int64  `json:"spend_remaining_sat"`
	NameRemaining  int64  `json:"name_remaining_sat"`
	GrantID        string `json:"grant_id"`
	Live           bool   `json:"live"`
	Reason         string `json:"reason"`
	Total          int64  `json:"total_cap_sat"`
	SpendCap       int64  `json:"spend_cap_sat"`
	NameCap        int64  `json:"name_cap_sat"`
	SpendReserved  int64  `json:"spend_reserved_sat"`
	NameReserved   int64  `json:"name_reserved_sat"`
	NamesReserved  int    `json:"names_reserved"`
}
type Wallet struct {
	mu                      sync.Mutex
	config                  Config
	node, wallet, broadcast su.Node
	authority               Authority
	store                   *durable.Store
	state                   state
	clock                   func() int64
	poisoned                bool
	grantRaw                []byte
	// Unexported seam for process-exit tests. The CLI does not read hook flags/env.
	hook func(string)
	// g2 is the PX1 G2 profile state (px1_wallet_seams.go); nil keeps W2.
	g2 *px1Wallet
}

func Open(c Config) (*Wallet, error) {
	// Legacy direct execution remains regtest-only. Main is opened exclusively
	// by the isolated action service, whose public action set excludes names.
	if c.Network != "regtest" || c.Genesis != su.RegtestGenesis {
		return nil, fail("CONFIG_REGTEST_ONLY")
	}
	return openWallet(c)
}

func (c Config) validateNetwork() error {
	if c.Version != 1 || !su.NetworkPinned(c.Network, c.Genesis) || c.Policy.Network != c.Network || c.Policy.Genesis != c.Genesis || c.FeeRate < 1 || c.FeeRate > 1000 {
		return fail("CONFIG_REGTEST_ONLY")
	}
	_, err := addressScriptForNetwork(c.ChangeAddress, c.Network, c.Genesis)
	return err
}

func openWallet(c Config) (*Wallet, error) {
	if err := c.validateNetwork(); err != nil {
		return nil, err
	}
	for _, p := range []string{c.StateDir, c.ObjectsDir, c.WalletDir, c.MemoryZone, c.Policy.StateDir} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return nil, fail("CONFIG_PATH")
		}
	}
	if c.StateDir == c.Policy.StateDir || c.StateDir == c.WalletDir || c.StateDir == c.MemoryZone {
		return nil, fail("CONFIG_PATH_SEPARATION")
	}
	if _, e := addressScriptForNetwork(c.ChangeAddress, c.Network, c.Genesis); e != nil {
		return nil, e
	}
	for _, r := range []su.Route{c.Wallet.Route, c.Broadcast} {
		if r.Host != c.Observer.Host || r.Port != c.Observer.Port {
			return nil, fail("RPC_NODE_MISMATCH")
		}
	}
	node, e := su.NewRPC(c.Observer)
	if e != nil {
		return nil, e
	}
	wallet, e := NewWalletRPC(c.Wallet)
	if e != nil {
		return nil, e
	}
	broadcast, e := NewBroadcasterRPC(c.Broadcast)
	if e != nil {
		return nil, e
	}
	w := &Wallet{config: c, node: node, wallet: wallet, broadcast: broadcast, clock: func() int64 { return time.Now().Unix() }}
	w.authority = CombinedAuthority{Kernel: KernelAuthority{Node: node, Policy: c.Policy}, Resolver: KernelResolver{Node: node, Policy: c.Policy}, Agent: c.Policy.AgentName, Landlord: c.Policy.LandlordName, StateDir: c.Policy.StateDir}
	w.store, e = durable.Open(c.StateDir, "wallet.lock")
	if e != nil {
		return nil, e
	}
	// Rotating an RPC password does not change the logical wallet/state binding.
	binding := c
	binding.Observer.Password = ""
	binding.Wallet.Route.Password = ""
	binding.Broadcast.Password = ""
	w.state = state{Version: 1, Binding: Hash(canonical(binding)), Records: []Record{}}
	b, e := w.store.Read("wallet.json", 65536)
	if e == nil && b != nil {
		expected := w.state.Binding
		e = strict(b, &w.state)
		if e == nil && (w.state.Version != 1 || w.state.Binding != expected || w.state.Records == nil || len(w.state.Records) > 32) {
			e = fail("JOURNAL_BINDING")
		}
		if e == nil {
			e = w.validateState()
		}
	}
	if e != nil {
		w.store.Close()
		return nil, e
	}
	return w, nil
}
func (w *Wallet) Close() { w.px1Close(); w.store.Close() }
func (w *Wallet) validateState() error {
	seen := map[string]bool{}
	inputs := map[su.Point]bool{}
	seals := map[su.Point]bool{}
	for _, r := range w.state.Records {
		key := r.GrantID + ":" + r.Nonce
		if seen[key] || !hexN(r.GrantID, 32) || !hexN(r.Nonce, 32) || !hexN(r.RequestHash, 32) || !hexN(r.TxID, 32) || r.Reserved < 1 || r.Reserved > MaxMoney || r.Fee < 1 || r.Fee > r.Reserved || len(r.Inputs) < 1 || len(r.Inputs) > 32 {
			return fail("JOURNAL_CORRUPT")
		}
		seen[key] = true
		if r.Phase != "reserved" && r.Phase != "complete" && r.Phase != "name-new-sent" && r.Phase != "reveal-reserved" {
			return fail("JOURNAL_PHASE")
		}
		if r.Action != "pay" && r.Action != "names.register" {
			return fail("JOURNAL_ACTION")
		}
		if r.Action == "pay" && (r.Phase == "name-new-sent" || r.Phase == "reveal-reserved" || r.Salt != "" || r.NewScript != "" || r.NewTxID != "") {
			return fail("JOURNAL_CORRUPT")
		}
		if r.Action == "names.register" && (!hexN(r.Salt, 20) || !hexN(r.NewTxID, 32) || len(r.NewScript) < 50 || !hexN(r.NewScript, len(r.NewScript)/2) || r.UseSeal != nil) {
			return fail("JOURNAL_CORRUPT")
		}
		for _, p := range r.Inputs {
			if !hexN(p.TxID, 32) || inputs[p] {
				return fail("JOURNAL_INPUTS")
			}
			inputs[p] = true
		}
		if r.UseSeal != nil {
			if !hexN(r.UseSeal.TxID, 32) || seals[*r.UseSeal] {
				return fail("JOURNAL_SEALS")
			}
			seals[*r.UseSeal] = true
		}
	}
	return nil
}
func (w *Wallet) persist() error {
	if w.poisoned {
		return fail("STATE_UNAVAILABLE")
	}
	b := canonical(w.state)
	if len(b) > 65536 {
		w.poisoned = true
		return fail("JOURNAL_LIMIT")
	}
	if e := w.store.Write("wallet.json", b); e != nil {
		w.poisoned = true
		return fail("JOURNAL_WRITE_UNCERTAIN")
	}
	return nil
}
func (w *Wallet) inputReserved(p su.Point) bool {
	for _, r := range w.state.Records {
		if containsPoint(r.Inputs, p) {
			return true
		}
	}
	return false
}
func (w *Wallet) used(g string) (spend, names int64, count int) {
	for _, r := range w.state.Records {
		if r.GrantID == g {
			if r.Action == "pay" {
				spend += r.Reserved
			} else {
				names += r.Reserved
				count++
			}
		}
	}
	return
}
func (w *Wallet) budgetCheck(g Grant, t Terms, r Request, cost int64) error {
	spend, names, count := w.used(g.ID)
	if cost < 1 || cost > g.Budget || spend > g.Budget-names || cost > g.Budget-spend-names {
		return fail("TOTAL_BUDGET_EXCEEDED")
	}
	if r.Action == "pay" {
		if spend > t.SpendCap || cost > t.SpendCap-spend {
			return fail("SPEND_BUDGET_EXCEEDED")
		}
	} else {
		if count >= t.NameCount || names > t.NameCap || cost > t.NameCap-names {
			return fail("NAME_BUDGET_EXCEEDED")
		}
	}
	return nil
}
func receipt(r Record, status, reason string) Receipt {
	return Receipt{Status: status, Reason: reason, Message: Explain(reason), GrantID: r.GrantID, Nonce: r.Nonce, Phase: r.Phase, TxID: r.TxID, NewTxID: r.NewTxID, Reserved: r.Reserved}
}
func refuse(e error) Receipt {
	if e.Error() == "USE_PENDING" {
		return Receipt{Status: "pending", Reason: e.Error(), Message: Explain(e.Error())}
	}
	return Receipt{Status: "refused", Reason: e.Error(), Message: Explain(e.Error())}
}
func (w *Wallet) Execute(ctx context.Context, grantRaw, termsRaw, requestRaw []byte, useTxID string) Receipt {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.config.Network == "main" {
		return refuse(fail("LEGACY_REGTEST_ONLY"))
	}
	if w.poisoned {
		return refuse(fail("STATE_UNAVAILABLE"))
	}
	s, e := ParseRequest(requestRaw)
	if e != nil {
		return refuse(e)
	}
	return w.executeAuthenticated(ctx, grantRaw, termsRaw, s.Request, s.Event.Pubkey, s.Event.CreatedAt, requestRaw, useTxID, nil)
}

// Caller holds w.mu and has verified the applicable signature. W1 commits its
// signed event; LIP-0006 commits unsigned request bytes, never a fabricated event.
func (w *Wallet) executeAuthenticated(ctx context.Context, grantRaw, termsRaw []byte, r Request, sender string, created int64, requestRaw []byte, useTxID string, beforeEffect func(Record) error) Receipt {
	if w.g2 != nil {
		return w.executeG2(ctx, grantRaw, termsRaw, r, sender, created, requestRaw, useTxID, beforeEffect)
	}
	if w.config.Network == "main" && r.Action != "pay" {
		return refuse(fail("MAIN_ACTION_UNSUPPORTED"))
	}
	g, e := w.authority.Parse(grantRaw)
	if e != nil {
		return refuse(e)
	}
	t, e := w.termsFor(g, termsRaw)
	if e != nil {
		return refuse(e)
	}
	if e = bindAuthenticatedRequest(g, t, r, sender, created, w.clock()); e != nil {
		return refuse(e)
	}
	w.grantRaw = append([]byte{}, grantRaw...)
	index := -1
	for i, prior := range w.state.Records {
		if prior.GrantID == g.ID && prior.Nonce == r.Nonce {
			if prior.RequestHash != Hash(requestRaw) {
				return refuse(fail("NONCE_CONFLICT"))
			}
			if prior.Phase != "name-new-sent" {
				return receipt(prior, "already-executed", "DURABLE_RESERVATION_NO_RETRY")
			}
			index = i
			break
		}
	}
	if e = w.authority.Check(ctx, grantRaw, g.Grantee, w.clock()); e != nil {
		return refuse(e)
	}
	if g.Kind == "single-use" {
		if e = w.checkUse(ctx, g, requestRaw, useTxID); e != nil {
			return refuse(e)
		}
	}
	var prior *Record
	if index >= 0 {
		p := w.state.Records[index]
		prior = &p
		if e = w.nameReady(ctx, p); e != nil {
			if e.Error() == "NAME_PENDING" {
				return receipt(p, "pending", "NAME_PENDING")
			}
			return refuse(e)
		}
	} else {
		if len(w.state.Records) >= 32 {
			return refuse(fail("JOURNAL_LIMIT"))
		}
		estimated := r.Amount
		if r.Action == "names.register" {
			estimated = NameDeposit + 2*r.FeeLimit
		}
		if e = w.budgetCheck(g, t, r, estimated); e != nil {
			return refuse(e)
		}
		if g.Kind == "single-use" {
			for _, p := range w.state.Records {
				if p.UseSeal != nil && *p.UseSeal == g.Seal {
					return refuse(fail("SINGLE_USE_ALREADY_RESERVED"))
				}
			}
		}
	}
	p, e := w.buildPlan(ctx, g, t, r, prior, nil)
	if e != nil {
		return refuse(e)
	}
	cost := r.Amount + p.Fee
	if r.Action == "names.register" {
		cost = NameDeposit + 2*r.FeeLimit
	}
	if prior == nil {
		if e = w.budgetCheck(g, t, r, cost); e != nil {
			return refuse(e)
		}
	} else if prior.Fee+p.Fee > prior.Reserved-NameDeposit {
		return refuse(fail("NAME_FEE_RESERVATION"))
	}
	if e = w.authority.Check(ctx, grantRaw, g.Grantee, w.clock()); e != nil {
		return refuse(e)
	}
	if g.Kind == "single-use" {
		if e = w.checkUse(ctx, g, requestRaw, useTxID); e != nil {
			return refuse(e)
		}
	}
	// Recheck every planned prevout immediately before durable reservation.
	for _, point := range p.Inputs {
		if _, e = readCoin(ctx, w.node, point); e != nil {
			return refuse(e)
		}
	}
	rec := Record{GrantID: g.ID, Nonce: r.Nonce, RequestHash: Hash(requestRaw), Action: r.Action, Phase: "reserved", Reserved: cost, Fee: p.Fee, Inputs: p.Inputs, TxID: p.TxID}
	if g.Kind == "single-use" {
		seal := g.Seal
		rec.UseSeal = &seal
	}
	if r.Action == "names.register" {
		if prior == nil {
			rec.NewTxID = p.TxID
			rec.NewScript = p.NameScript
			rec.NameVout = p.NameVout
			rec.Salt = p.Salt
		} else {
			rec = *prior
			rec.Phase = "reveal-reserved"
			rec.TxID = p.TxID
			rec.Fee += p.Fee
			rec.Inputs = append(append([]su.Point{}, prior.Inputs...), p.Inputs...)
		}
	}
	if index < 0 {
		index = len(w.state.Records)
		w.state.Records = append(w.state.Records, rec)
	} else {
		w.state.Records[index] = rec
	}
	if e = w.persist(); e != nil {
		return refuse(e)
	}
	if w.hook != nil {
		w.hook("after-reservation")
	}
	// W2 adds a durable service reservation and rechecks after reservation.
	// The historical entrypoint retains its existing protocol behavior.
	if beforeEffect != nil {
		if e = beforeEffect(rec); e != nil {
			return receipt(rec, "uncertain", "SERVICE_RESERVATION_UNCERTAIN")
		}
		if e = w.authority.Check(ctx, grantRaw, g.Grantee, w.clock()); e != nil {
			return receipt(rec, "refused", e.Error())
		}
		if g.Kind == "single-use" {
			if e = w.checkUse(ctx, g, requestRaw, useTxID); e != nil {
				return receipt(rec, "refused", e.Error())
			}
		}
		for _, point := range p.Inputs {
			if _, e = readCoin(ctx, w.node, point); e != nil {
				return receipt(rec, "refused", e.Error())
			}
		}
	}
	var txid string
	if e = call(ctx, w.broadcast, "sendrawtransaction", &txid, p.Raw); e != nil || txid != p.TxID {
		return receipt(rec, "uncertain", "BROADCAST_UNCERTAIN")
	}
	if w.hook != nil {
		w.hook("after-broadcast")
	}
	rec.Phase = "complete"
	if r.Action == "names.register" && prior == nil {
		rec.Phase = "name-new-sent"
	} else if r.Action == "names.register" {
		rec.Reserved = NameDeposit + rec.Fee
	}
	w.state.Records[index] = rec
	if e = w.persist(); e != nil {
		return receipt(rec, "uncertain", "JOURNAL_WRITE_UNCERTAIN")
	}
	if rec.Phase == "name-new-sent" {
		return receipt(rec, "pending", "NAME_PENDING")
	}
	return receipt(rec, "executed", "EXECUTED")
}

// px1Receipt is the wallet receipt of a wallet-layer journal v2 record.
func px1Receipt(r JournalRecordV2, status, reason string) Receipt {
	return Receipt{Status: status, Reason: reason, Message: Explain(reason), GrantID: r.GrantID, Nonce: r.Nonce, Phase: r.Phase, TxID: r.TxID, Reserved: r.Reserved}
}

// px1Follow appends a follow-up record of a reserved request. The debit stays
// retained whatever the follow-up says; an append failure is reported, never
// hidden, but cannot release anything.
func (w *Wallet) px1Follow(reserved JournalRecordV2, kind, phase string) (JournalRecordV2, error) {
	next := reserved
	next.Seq = 0
	next.Kind = kind
	next.Phase = phase
	next.LastTime = w.clock()
	return w.g2.journal.Append(next)
}

// executeG2 is the wallet layer of the G2 spend path (G2-PAYMENT-EXECUTOR-v1
// §3.5 steps 8-23). The caller holds w.mu and has authenticated the request
// (steps 1-7 belong to the service layer). Every refusal before step 19 has
// no debit and no broadcast; after step 19 the debit is retained.
func (w *Wallet) executeG2(ctx context.Context, grantRaw, termsRaw []byte, r Request, sender string, created int64, requestRaw []byte, useTxID string, beforeEffect func(Record) error) Receipt {
	x := w.g2
	if r.Action != "pay" {
		return refuse(fail("MAIN_ACTION_UNSUPPORTED"))
	}
	if useTxID != "" {
		return refuse(fail(CodeSingleUseDisabled))
	}
	if x.journal.Poisoned() {
		return refuse(fail("JOURNAL_WRITE_UNCERTAIN"))
	}
	g, e := w.authority.Parse(grantRaw)
	if e != nil {
		return refuse(e)
	}
	// Step 8 (defence in depth under the service-layer refusal).
	if g.Kind == "single-use" {
		return refuse(fail(CodeSingleUseDisabled))
	}
	// Step 10: terms v2 by contract_sha256, executor binding, operator ceilings.
	_, limits, e := w.px1TermsFor(g, termsRaw)
	if e != nil {
		return refuse(e)
	}
	// Step 12: binding and recipient by mode.
	if e = bindG2Request(g, limits, r, sender, created, w.clock(), x.checker); e != nil {
		return refuse(e)
	}
	w.grantRaw = append([]byte{}, grantRaw...)
	prior, e := w.px1Prior(g.ID, r.Nonce)
	if e != nil {
		return refuse(e)
	}
	if prior != nil {
		if Hash(requestRaw) != prior.RequestHash {
			return refuse(fail("NONCE_CONFLICT"))
		}
		return px1Receipt(*prior, "already-executed", "DURABLE_RESERVATION_NO_RETRY")
	}
	ledger, e := w.PX1Ledger()
	if e != nil {
		return refuse(e)
	}
	now := w.clock()
	intent := SpendIntent{GrantID: g.ID, Recipient: r.Address, AmountSat: r.Amount, FeeLimitSat: r.FeeLimit, Day: x.deps.day(now)}
	// Steps 13 and 15: dust, conservative transfer cap, cumulative caps on the
	// amount. Pure checks, so an over-cap request costs no node call.
	if e = x.checker.CheckPrePlan(limits, intent, ledger); e != nil {
		return refuse(e)
	}
	// Step 14: kernel check #1.
	if e = w.authority.Check(ctx, grantRaw, g.Grantee, w.clock()); e != nil {
		return refuse(e)
	}
	// Step 16: plan without the canary or retained inputs, fee within
	// min(fee_limit, fee cap); kernel check #2 runs inside before signing.
	guard := &planGuard{exclude: func(p su.Point) bool { return w.px1Excluded(p, ledger) }, feeCap: limits.FeeCapSat}
	p, e := w.buildPlan(ctx, g, Terms{}, r, nil, guard)
	if e != nil {
		return refuse(e)
	}
	// Step 17: every cap on amount + actual fee.
	intent.FeeSat = p.Fee
	if e = x.checker.CheckPostPlan(limits, intent, ledger); e != nil {
		return refuse(e)
	}
	// Step 18: kernel check #3 and every planned prevout re-read.
	if e = w.px1Recheck(ctx, grantRaw, g, p.Inputs); e != nil {
		return refuse(e)
	}
	// Step 19: durable wallet reservation (debit, day bucket, inputs, txid).
	reserved, e := x.journal.Append(JournalRecordV2{Kind: RecordReserve, GrantID: g.ID, Nonce: r.Nonce, RequestHash: Hash(requestRaw), Action: "spend", Phase: "reserved", Reserved: r.Amount + p.Fee, Fee: p.Fee, Day: intent.Day, Inputs: p.Inputs, TxID: p.TxID, Created: created, LastTime: now})
	if e != nil {
		return refuse(e)
	}
	if w.hook != nil {
		w.hook("after-reservation")
	}
	// Step 20 belongs to the service layer.
	if beforeEffect != nil {
		if e = beforeEffect(Record{GrantID: reserved.GrantID, Nonce: reserved.Nonce, RequestHash: reserved.RequestHash, Action: "pay", Phase: "reserved", Reserved: reserved.Reserved, Fee: reserved.Fee, Inputs: reserved.Inputs, TxID: reserved.TxID}); e != nil {
			return px1Receipt(reserved, "uncertain", "SERVICE_RESERVATION_UNCERTAIN")
		}
	}
	// Step 21: kernel check #4 (seal incl. mempool, window) and input re-read.
	if e = w.px1Recheck(ctx, grantRaw, g, p.Inputs); e != nil {
		if done, err := w.px1Follow(reserved, RecordRefuseRetained, "refused"); err == nil {
			reserved = done
		}
		return px1Receipt(reserved, "refused", safeCode(e))
	}
	// Step 22: broadcast; the returned txid must equal the plan txid.
	var txid string
	if e = call(ctx, w.broadcast, "sendrawtransaction", &txid, p.Raw); e != nil || txid != p.TxID {
		if done, err := w.px1Follow(reserved, RecordUncertain, "uncertain"); err == nil {
			reserved = done
		}
		return px1Receipt(reserved, "uncertain", "BROADCAST_UNCERTAIN")
	}
	if w.hook != nil {
		w.hook("after-broadcast")
	}
	// Step 23 (wallet layer): durable complete record.
	done, e := w.px1Follow(reserved, RecordComplete, "complete")
	if e != nil {
		return px1Receipt(reserved, "uncertain", px1FollowFailure(e))
	}
	return px1Receipt(done, "executed", "EXECUTED")
}

func (w *Wallet) nameReady(ctx context.Context, r Record) error {
	o := su.NewReadObservation(ctx, w.node)
	defer o.Close()
	if w.config.Network == "main" {
		return fail("MAIN_ACTION_UNSUPPORTED")
	}
	if e := o.Start("regtest", su.RegtestGenesis); e != nil {
		return e
	}
	view, _, e := o.Transaction(r.NewTxID)
	if e != nil {
		return e
	}
	if view.Confirmations < 12 {
		return fail("NAME_PENDING")
	}
	if _, e = o.Confirmed(view); e != nil {
		return e
	}
	return o.Stable()
}
func (w *Wallet) Budget(ctx context.Context, raw, termsRaw []byte) (Budget, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	var b Budget
	if w.poisoned {
		return b, fail("STATE_UNAVAILABLE")
	}
	if w.g2 != nil {
		// G2: the W2-shaped projection of the G2 ledger (no name budget).
		v, e := w.px1Budget(ctx, raw, termsRaw)
		if e != nil {
			return b, e
		}
		return Budget{TotalRemaining: v.TotalRemaining, SpendRemaining: v.SpendCap - v.SpendReserved, GrantID: v.GrantID, Live: v.Live, Reason: v.Reason, Total: v.TotalCap, SpendCap: v.SpendCap, SpendReserved: v.SpendReserved}, nil
	}
	g, e := w.authority.Parse(raw)
	if e != nil {
		return b, e
	}
	t, e := w.termsFor(g, termsRaw)
	if e != nil {
		return b, e
	}
	b.GrantID = g.ID
	b.Total = g.Budget
	b.SpendCap = t.SpendCap
	b.NameCap = t.NameCap
	b.SpendReserved, b.NameReserved, b.NamesReserved = w.used(g.ID)
	if b.SpendReserved > t.SpendCap || b.NameReserved > t.NameCap || b.SpendReserved > g.Budget-b.NameReserved {
		return b, fail("JOURNAL_BUDGET")
	}
	b.TotalRemaining = g.Budget - b.SpendReserved - b.NameReserved
	b.SpendRemaining = t.SpendCap - b.SpendReserved
	b.NameRemaining = t.NameCap - b.NameReserved
	e = w.authority.Check(ctx, raw, g.Grantee, w.clock())
	b.Live = e == nil
	b.Reason = "LIVE"
	if e != nil {
		b.Reason = e.Error()
	}
	if g.Kind == "single-use" && e == nil {
		b.Live = false
		b.Reason = "SINGLE_USE_REQUIRES_CONFIRMED_REQUEST"
	}
	return b, nil
}
func Explain(code string) string {
	switch code {
	case "EXECUTED":
		return "The transaction was accepted by the local node; this is not confirmation or finality."
	case "DURABLE_RESERVATION_NO_RETRY":
		return "This request was already reserved. It will never be sent again; a reserved phase may have an unknown outcome."
	case "NAME_PENDING":
		return "The name commitment was sent. Wait for 12 confirmations, then invoke the same request to advance to the reveal stage."
	case "USE_PENDING":
		return "The grantee seal spend is in the mempool. Wait for one confirmation; the wallet has not reserved or sent the requested payment."
	case "BROADCAST_UNCERTAIN":
		return "The request is reserved, but the broadcast result is uncertain. Do not retry or replace it."
	}
	if strings.Contains(code, "BUDGET") || strings.Contains(code, "FEE") {
		return "The amount and fees exceed the signed or durably remaining allowance."
	}
	if strings.HasPrefix(code, "GRANT_") {
		return "The supplied grant does not currently authorize this action; check its signer, agent, scope, time and revocation state."
	}
	if strings.HasPrefix(code, "RPC_") || strings.HasPrefix(code, "UTXO_") {
		return "The local wallet or node could not provide the required verified data; no new broadcast was authorized."
	}
	if strings.HasPrefix(code, "JOURNAL_") || strings.HasPrefix(code, "STATE_") {
		return "Wallet journal state is unavailable or uncertain. Preserve it and ask the operator to reconcile; never delete it to retry."
	}
	return "The request was refused because a required check failed: " + strings.ToLower(strings.ReplaceAll(code, "_", " ")) + "."
}
