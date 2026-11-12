package wallet

// PX1 stream S3 implementation (owner S3): payment tracker, canary watcher,
// float monitor, startup reconciliation, bounded alert sink, the status
// projection and one status-socket exchange. Signatures are frozen in
// px1_observe_api.go. Nothing here grants, restores or releases spending
// authority: tracker, canary and float states are observability only (Q12),
// and a debit is released only by an operator ReconcileRecordV2 (Q8).

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	sw "github.com/relux-works/swarma-chain-lab/experiments/sealwatch"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// Bounds of the S3 observers. They are fixed, not operator values.
const (
	px1oMaxConfirmationsK   = 100     // TrackerConfig.ConfirmationsK upper bound
	px1oMaxConflictBlocksN  = 1000    // TrackerConfig.ConflictBlocksN upper bound
	px1oMaxTracked          = 1 << 16 // tracked payments per process
	px1oMaxTrackedInputs    = 32      // inputs per payment (W2 plan bound)
	px1oConflictScanBlocks  = 64      // newest blocks searched for an input spender
	px1oReconcilePage       = 1000    // listtransactions page size
	px1oReconcileMaxPages   = 100     // more wallet rows than this refuses startup
	px1oStatusRequestMax    = 256     // status request frame bound
	px1oStatusResponseMax   = 4 << 20 // status response frame bound
	px1oAlertTail           = 64      // alerts kept in the status projection
	px1oAlertDetailMax      = 128     // schema bound of Alert.Detail
	px1oStatusSocketVersion = 1
)

// px1oStatusRequest is the only accepted status request, byte for byte.
var px1oStatusRequest = canonical(StatusSocketRequest{Version: px1oStatusSocketVersion, Action: "status"})

// ---------------------------------------------------------------------------
// Own-node observation helpers (observer route).

type px1oTip struct {
	Height int64
	Hash   string
}

func px1oReadTip(ctx context.Context, node su.Node) (px1oTip, error) {
	var t px1oTip
	if node == nil {
		return t, fail("RPC_UNAVAILABLE")
	}
	raw, e := node.Call(ctx, "getblockchaininfo")
	if e != nil {
		return t, px1oNodeError(e)
	}
	if sw.ProjectJSON(raw, map[string]any{"blocks": &t.Height, "bestblockhash": &t.Hash}, nil) != nil || t.Height < 0 || !hexN(t.Hash, 32) {
		return px1oTip{}, fail("NODE_PROJECTION")
	}
	return t, nil
}

// px1oXOnly reports a valid BIP-340 x-only public key in lowercase hex.
func px1oXOnly(s string) bool {
	if !hexN(s, 32) {
		return false
	}
	b, _ := hex.DecodeString(s)
	_, e := schnorr.ParsePubKey(b)
	return e == nil
}

// px1oNodeError keeps a bounded node failure code and collapses anything else.
func px1oNodeError(e error) error {
	if e == nil {
		return nil
	}
	if boundedCode(e.Error()) {
		return e
	}
	return fail("RPC_UNAVAILABLE")
}

// px1oRemoteNo reports Core's definitive "no such transaction" answer
// (CodeNoSuchTx from the transaction lookup route) and nothing else: an
// unreachable node, a refused login, a busy node and every other RPC error
// keep failing the pass.
func px1oRemoteNo(e error) bool {
	return e != nil && e.Error() == CodeNoSuchTx
}

// px1oOutputSpent reads gettxout with the mempool included. A JSON null means
// the outpoint is spent (mempool or chain) or does not exist on the active
// chain; both mean the outpoint is no longer available.
func px1oOutputSpent(ctx context.Context, node su.Node, p su.Point) (spent bool, valueSat int64, e error) {
	raw, e := node.Call(ctx, "gettxout", p.TxID, p.Vout, true)
	if e != nil {
		return false, 0, px1oNodeError(e)
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return true, 0, nil
	}
	var value json.Number
	var script json.RawMessage
	if sw.ProjectJSON(raw, map[string]any{"value": &value, "scriptPubKey": &script}, nil) != nil {
		return false, 0, fail("NODE_PROJECTION")
	}
	v, err := su.ParseCoins(value.String())
	if err != nil || v < 0 {
		return false, 0, fail("NODE_PROJECTION")
	}
	return false, v, nil
}

// px1oTxDepth reads getrawtransaction verbose. present is true for a mempool
// transaction (no blockhash) and for one in an active-chain block (depth >= 1).
// A transaction known only from a stale block (confirmations 0) is absent.
//
// Only a well-formed id (64 lowercase hex characters, as Core prints txids)
// can ever read as absent. Code -5 also covers malformed keys and ids, and
// Core 28 parses hex case-insensitively: it answers an unknown uppercase id
// with the exact "no such transaction" reply. So a malformed id is refused
// here with TRACKER_TXID and never reaches the node.
func px1oTxDepth(ctx context.Context, node su.Node, txid string) (present bool, depth int64, e error) {
	if !hexN(txid, 32) {
		return false, 0, fail("TRACKER_TXID")
	}
	raw, e := node.Call(ctx, "getrawtransaction", txid, true)
	if px1oRemoteNo(e) {
		return false, 0, nil
	}
	if e != nil {
		return false, 0, px1oNodeError(e)
	}
	var got, block string
	confirmations := int64(-1)
	if sw.ProjectJSON(raw, map[string]any{"txid": &got}, map[string]any{"blockhash": &block, "confirmations": &confirmations}) != nil || got != txid {
		return false, 0, fail("NODE_PROJECTION")
	}
	switch {
	case block == "":
		return true, 0, nil
	case confirmations >= 1:
		return true, confirmations, nil
	default:
		return false, 0, nil
	}
}

type px1oBlockTx struct {
	TxID string `json:"txid"`
	Vin  []struct {
		TxID string `json:"txid"`
		Vout uint32 `json:"vout"`
	} `json:"vin"`
}

// px1oFindSpender searches the newest blocks (down to floor) for a transaction
// spending one of inputs. It returns the spender txid and its height, or "".
func px1oFindSpender(ctx context.Context, node su.Node, tip px1oTip, floor int64, inputs []su.Point) (string, int64, error) {
	want := map[su.Point]bool{}
	for _, p := range inputs {
		want[p] = true
	}
	lowest := max(floor, tip.Height-px1oConflictScanBlocks+1, 0)
	for h := tip.Height; h >= lowest; h-- {
		var hash string
		if e := call(ctx, node, "getblockhash", &hash, h); e != nil {
			return "", 0, px1oNodeError(e)
		}
		if !hexN(hash, 32) {
			return "", 0, fail("NODE_PROJECTION")
		}
		var block struct {
			Hash string        `json:"hash"`
			Tx   []px1oBlockTx `json:"tx"`
		}
		if e := call(ctx, node, "getblock", &block, hash, 2); e != nil {
			return "", 0, px1oNodeError(e)
		}
		if block.Hash != hash {
			return "", 0, fail("NODE_PROJECTION")
		}
		for _, tx := range block.Tx {
			for _, in := range tx.Vin {
				if in.TxID != "" && want[su.Point{TxID: in.TxID, Vout: in.Vout}] {
					return tx.TxID, h, nil
				}
			}
		}
	}
	return "", 0, nil
}

// ---------------------------------------------------------------------------
// Tracker.

type px1oTracker struct {
	node     su.Node
	cfg      TrackerConfig
	payments []TrackedPayment // ordered by ReserveSeq
}

func px1oValidTrackerConfig(c TrackerConfig) bool {
	return c.ConfirmationsK >= 1 && c.ConfirmationsK <= px1oMaxConfirmationsK && c.ConflictBlocksN >= 1 && c.ConflictBlocksN <= px1oMaxConflictBlocksN
}

func px1oValidTrackedInputs(in []su.Point) bool {
	if len(in) < 1 || len(in) > px1oMaxTrackedInputs {
		return false
	}
	for _, p := range in {
		if !hexN(p.TxID, 32) {
			return false
		}
	}
	return true
}

func px1oPaymentKey(grantID, nonce string) string { return grantID + "/" + nonce }

// NewTracker returns the payment confirmation tracker. Startup reloads tracked
// payments from the wallet-layer journal: every request whose reservation was
// completed is tracked, and so is every request left reserved or uncertain
// (its broadcast may have happened before a crash, T10). Requests that ended
// refuse-retained were never broadcast and are not tracked. The latest track
// record of a payment restores its state; MissingSince and BroadcastTip are
// not journaled and restart at 0.
func NewTracker(node su.Node, cfg TrackerConfig, wallet JournalV2) (Tracker, error) {
	if node == nil {
		return nil, fail("RPC_UNAVAILABLE")
	}
	if !px1oValidTrackerConfig(cfg) {
		return nil, fail("SERVICE_CONFIG")
	}
	if wallet == nil {
		return nil, fail("STATE_UNAVAILABLE")
	}
	if wallet.Header().Layer != JournalLayerWallet {
		return nil, fail(CodeJournalSegment)
	}
	type request struct {
		reserve JournalRecordV2
		phase   string
		state   string
		depth   int64
	}
	requests := map[string]*request{}
	order := []string{}
	e := wallet.Iterate(1, func(r JournalRecordV2) error {
		key := px1oPaymentKey(r.GrantID, r.Nonce)
		q := requests[key]
		switch r.Kind {
		case RecordReserve:
			if q != nil || !hexN(r.TxID, 32) || !px1oValidTrackedInputs(r.Inputs) {
				return fail(CodeJournalSegment)
			}
			requests[key] = &request{reserve: r, phase: RecordReserve, state: TrackPending}
			order = append(order, key)
		case RecordComplete, RecordUncertain, RecordRefuseRetained:
			if q == nil || (r.TxID != "" && r.TxID != q.reserve.TxID) {
				return fail(CodeJournalSegment)
			}
			q.phase = r.Kind
		case RecordTrack:
			if q == nil || r.Track == nil || (r.Track.State != TrackConfirmed && r.Track.State != TrackConflicted) {
				return fail(CodeJournalSegment)
			}
			q.state, q.depth = r.Track.State, max(r.Track.Confirmations, 0)
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	t := &px1oTracker{node: node, cfg: cfg, payments: []TrackedPayment{}}
	for _, key := range order {
		q := requests[key]
		if q.phase == RecordRefuseRetained {
			continue
		}
		if len(t.payments) >= px1oMaxTracked {
			return nil, fail("TRACKER_LIMIT")
		}
		t.payments = append(t.payments, TrackedPayment{GrantID: q.reserve.GrantID, Nonce: q.reserve.Nonce, TxID: q.reserve.TxID, Inputs: append([]su.Point{}, q.reserve.Inputs...), ReserveSeq: q.reserve.Seq, State: q.state, Confirmations: q.depth})
	}
	sort.SliceStable(t.payments, func(i, j int) bool { return t.payments[i].ReserveSeq < t.payments[j].ReserveSeq })
	return t, nil
}

// Enqueue registers a payment after its complete record is durable. A second
// Enqueue of the same reservation with the same txid is a no-op (startup may
// already have reloaded it); with another txid it is refused.
func (t *px1oTracker) Enqueue(p TrackedPayment) error {
	if !hexN(p.GrantID, 32) || !hexN(p.Nonce, 32) || !hexN(p.TxID, 32) || p.ReserveSeq < 1 || p.BroadcastTip < 0 || !px1oValidTrackedInputs(p.Inputs) {
		return fail("TRACKER_PAYMENT")
	}
	i := sort.Search(len(t.payments), func(i int) bool { return t.payments[i].ReserveSeq >= p.ReserveSeq })
	if i < len(t.payments) && t.payments[i].ReserveSeq == p.ReserveSeq {
		if t.payments[i].TxID == p.TxID && t.payments[i].GrantID == p.GrantID && t.payments[i].Nonce == p.Nonce {
			if t.payments[i].BroadcastTip == 0 {
				t.payments[i].BroadcastTip = p.BroadcastTip
			}
			return nil
		}
		return fail("TRACKER_PAYMENT")
	}
	if len(t.payments) >= px1oMaxTracked {
		return fail("TRACKER_LIMIT")
	}
	p.Inputs = append([]su.Point{}, p.Inputs...)
	p.State, p.Confirmations, p.MissingSince = TrackPending, 0, 0
	t.payments = append(t.payments, TrackedPayment{})
	copy(t.payments[i+1:], t.payments[i:])
	t.payments[i] = p
	return nil
}

// px1oObservation is one payment's view at one tip.
type px1oObservation struct {
	present  bool   // in the mempool or an active-chain block
	depth    int64  // confirmations on the active chain, 0 if unmined
	conflict bool   // an input is no longer available and the payment is absent
	spender  string // the mined spender of a planned input, or ""
}

func (t *px1oTracker) observe(ctx context.Context, tip px1oTip, p TrackedPayment) (px1oObservation, error) {
	var o px1oObservation
	present, depth, e := px1oTxDepth(ctx, t.node, p.TxID)
	if e != nil {
		return o, e
	}
	if present {
		return px1oObservation{present: true, depth: depth}, nil
	}
	for _, in := range p.Inputs {
		spent, _, e := px1oOutputSpent(ctx, t.node, in)
		if e != nil {
			return o, e
		}
		if spent {
			o.conflict = true
		}
	}
	if !o.conflict || p.State == TrackConflicted {
		return o, nil
	}
	// An input is gone while the payment is not visible: either a node
	// without the transaction index mined the payment itself, or another
	// transaction spent the input.
	floor := int64(0)
	if p.BroadcastTip > 0 {
		floor = p.BroadcastTip
	}
	spender, height, e := px1oFindSpender(ctx, t.node, tip, floor, p.Inputs)
	if e != nil {
		return o, e
	}
	if spender == p.TxID {
		return px1oObservation{present: true, depth: tip.Height - height + 1}, nil
	}
	o.spender = spender
	return o, nil
}

// Tick reads the own node once. Every payment is observed at one tip; if the
// tip moves during the pass, the pass is discarded (TRACKER_TIP_MOVED) and no
// state changes. Rules, per payment:
//   - depth >= ConfirmationsK: confirmed;
//   - an input no longer available while the payment is absent: conflicted,
//     citing the mined spender when one is found in the newest blocks;
//   - absent for ConflictBlocksN blocks: conflicted;
//   - otherwise a confirmed payment that lost depth returns to pending, and a
//     conflicted payment stays conflicted until it is confirmed.
//
// Only transitions to confirmed or conflicted are returned (they are the two
// track record states). No transition grants, restores or releases a debit.
func (t *px1oTracker) Tick(ctx context.Context) ([]TrackTransition, error) {
	if len(t.payments) == 0 {
		return []TrackTransition{}, nil
	}
	tip, e := px1oReadTip(ctx, t.node)
	if e != nil {
		return nil, e
	}
	next := make([]TrackedPayment, len(t.payments))
	out := []TrackTransition{}
	for i, p := range t.payments {
		o, e := t.observe(ctx, tip, p)
		if e != nil {
			return nil, e
		}
		before := p.State
		p.Confirmations = o.depth
		if o.present {
			p.MissingSince = 0
		} else if p.MissingSince == 0 {
			p.MissingSince = tip.Height
		}
		conflictTxID := ""
		switch {
		case o.present && o.depth >= int64(t.cfg.ConfirmationsK):
			p.State = TrackConfirmed
		case o.conflict:
			p.State = TrackConflicted
			conflictTxID = o.spender
		case !o.present && tip.Height-p.MissingSince >= int64(t.cfg.ConflictBlocksN):
			p.State = TrackConflicted
		case p.State == TrackConfirmed:
			p.State = TrackPending
		}
		next[i] = p
		if p.State != before && p.State != TrackPending {
			out = append(out, TrackTransition{Payment: p, Record: TrackRecordV2{State: p.State, Height: tip.Height, BlockHash: tip.Hash, Confirmations: p.Confirmations, ConflictTxID: conflictTxID}})
		}
	}
	after, e := px1oReadTip(ctx, t.node)
	if e != nil {
		return nil, e
	}
	if after != tip {
		return nil, fail("TRACKER_TIP_MOVED")
	}
	t.payments = next
	return out, nil
}

// Snapshot returns a copy of every tracked payment, ordered by ReserveSeq.
func (t *px1oTracker) Snapshot() []TrackedPayment {
	out := make([]TrackedPayment, len(t.payments))
	for i, p := range t.payments {
		p.Inputs = append([]su.Point{}, p.Inputs...)
		out[i] = p
	}
	return out
}

// ---------------------------------------------------------------------------
// Canary.

type px1oCanary struct {
	node  su.Node
	cfg   CanaryConfig
	spent bool // sticky: once spent, always spent for this process
}

func px1oValidCanaryConfig(c CanaryConfig) bool {
	return hexN(c.Outpoint.TxID, 32) && c.ValueSat >= DustLimitSat && c.ValueSat <= MaxMoney
}

// NewCanary returns the canary watcher. Construction makes no node call.
func NewCanary(node su.Node, cfg CanaryConfig) (Canary, error) {
	if node == nil {
		return nil, fail("RPC_UNAVAILABLE")
	}
	if !px1oValidCanaryConfig(cfg) {
		return nil, fail("SERVICE_CONFIG")
	}
	return &px1oCanary{node: node, cfg: cfg}, nil
}

// Excluded reports whether p is the canary outpoint.
func (c *px1oCanary) Excluded(p su.Point) bool { return p == c.cfg.Outpoint }

// Check reads gettxout (mempool included). A missing outpoint is spent, and a
// spent canary stays spent for the life of the watcher even if a reorg makes
// it visible again. A node failure or an outpoint with another value is
// unknown, which is never treated as unspent.
func (c *px1oCanary) Check(ctx context.Context) (string, error) {
	if c.spent {
		return CanarySpent, nil
	}
	spent, value, e := px1oOutputSpent(ctx, c.node, c.cfg.Outpoint)
	if e != nil {
		return CanaryUnknown, e
	}
	if spent {
		c.spent = true
		return CanarySpent, nil
	}
	if value != c.cfg.ValueSat {
		return CanaryUnknown, fail("CANARY_VALUE")
	}
	return CanaryUnspent, nil
}

// ---------------------------------------------------------------------------
// Float monitor.

type px1oFloat struct {
	wallet   su.Node
	max, low int64
}

// NewFloatMonitor returns the float monitor over the w1-wallet route.
func NewFloatMonitor(wallet su.Node, maxFloatSat, lowFloatSat int64) (FloatMonitor, error) {
	if wallet == nil {
		return nil, fail("RPC_UNAVAILABLE")
	}
	if maxFloatSat < 1 || maxFloatSat > MaxMoney || lowFloatSat < 0 || lowFloatSat > maxFloatSat {
		return nil, fail("SERVICE_CONFIG")
	}
	return &px1oFloat{wallet: wallet, max: maxFloatSat, low: lowFloatSat}, nil
}

// Check reads getbalances once. The float is mine.trusted plus
// mine.untrusted_pending (immature coinbase is not spendable float). It is
// "low" strictly below the low-water mark, "excess" strictly above the
// ceiling, else "ok"; any read failure gives "unknown" and a zero balance.
func (f *px1oFloat) Check(ctx context.Context) (FloatReading, error) {
	r := FloatReading{MaxFloatSat: f.max, LowFloatSat: f.low, State: "unknown"}
	raw, e := f.wallet.Call(ctx, "getbalances")
	if e != nil {
		return r, px1oNodeError(e)
	}
	var mine json.RawMessage
	var trusted, pending json.Number
	if sw.ProjectJSON(raw, map[string]any{"mine": &mine}, nil) != nil || sw.ProjectJSON(mine, map[string]any{"trusted": &trusted, "untrusted_pending": &pending}, nil) != nil {
		return r, fail("BALANCE_RESPONSE")
	}
	a, e1 := su.ParseCoins(trusted.String())
	b, e2 := su.ParseCoins(pending.String())
	if e1 != nil || e2 != nil || a < 0 || b < 0 || a > MaxMoney-b {
		return r, fail("BALANCE_AMOUNT")
	}
	r.BalanceSat = a + b
	switch {
	case r.BalanceSat < f.low:
		r.State = "low"
	case r.BalanceSat > f.max:
		r.State = "excess"
	default:
		r.State = "ok"
	}
	return r, nil
}

// ---------------------------------------------------------------------------
// Startup reconciliation.

type px1oReconciler struct{ wallet su.Node }

// NewStartupReconciler returns the wallet-versus-journal startup check.
func NewStartupReconciler(walletRoute su.Node) (StartupReconciler, error) {
	if walletRoute == nil {
		return nil, fail("RPC_UNAVAILABLE")
	}
	return &px1oReconciler{wallet: walletRoute}, nil
}

// Reconcile lists every hot-wallet transaction (pages of px1oReconcilePage)
// and refuses STATE_RECONCILE_REQUIRED for any "send" whose txid no
// wallet-layer record carries: an out-of-band spend or a restored older
// journal (T13). More rows than the bound also refuse, because the check
// could not be completed. The hot wallet must therefore start without sends.
func (r *px1oReconciler) Reconcile(ctx context.Context, wallet JournalV2) error {
	if wallet == nil {
		return fail("STATE_UNAVAILABLE")
	}
	if wallet.Header().Layer != JournalLayerWallet {
		return fail(CodeJournalSegment)
	}
	known := map[string]bool{}
	if e := wallet.Iterate(1, func(rec JournalRecordV2) error {
		if rec.TxID != "" {
			known[rec.TxID] = true
		}
		return nil
	}); e != nil {
		return e
	}
	for page := 0; page < px1oReconcileMaxPages; page++ {
		var rows []json.RawMessage
		if e := call(ctx, r.wallet, "listtransactions", &rows, "*", px1oReconcilePage, page*px1oReconcilePage, false); e != nil {
			return px1oNodeError(e)
		}
		if rows == nil || len(rows) > px1oReconcilePage {
			return fail("HISTORY_BOUND")
		}
		for _, row := range rows {
			var txid, category string
			if sw.ProjectJSON(row, map[string]any{"txid": &txid, "category": &category}, nil) != nil || !hexN(txid, 32) {
				return fail("HISTORY_RESPONSE")
			}
			if category == "send" && !known[txid] {
				return fail(CodeStateReconcileRequired)
			}
		}
		if len(rows) < px1oReconcilePage {
			return nil
		}
	}
	return fail(CodeStateReconcileRequired)
}

// ---------------------------------------------------------------------------
// Alerts.

var px1oAlertCodes = map[string]bool{AlertCanarySpent: true, AlertPaymentConflicted: true, AlertUncertainVerdict: true, AlertJournalHighWater: true, AlertClockRollback: true, AlertSealClosed: true, AlertFloatLow: true, AlertFloatExcess: true}

// px1oDetailSafe admits only the typed public detail shapes that the
// production callers emit: "", a bounded code, a 64-hex txid or grant id, an
// outpoint "<txid>:<vout>", a decimal amount or count, and the journal ratio
// "<admitted>.<capacity>". Anything else (free text, lowercase words, a
// key=value pair) is not one of these shapes. This is a shape allowlist, not
// a secret detector: a 64-hex secret or an upper-case word still has an
// allowed shape, so callers pass only journal and configuration identifiers.
func px1oDetailSafe(s string) bool {
	if len(s) > px1oAlertDetailMax {
		return false
	}
	if s == "" || boundedCode(s) || hexN(s, 32) {
		return true
	}
	if i := strings.IndexByte(s, ':'); i >= 0 {
		return hexN(s[:i], 32) && px1oDecimal(s[i+1:], 10)
	}
	if i := strings.IndexByte(s, '.'); i >= 0 {
		return px1oDecimal(s[:i], 19) && px1oDecimal(s[i+1:], 19)
	}
	return px1oDecimal(s, 19)
}

// px1oDecimal reports 1..n ASCII digits.
func px1oDecimal(s string, n int) bool {
	if len(s) < 1 || len(s) > n {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// px1oSanitizeAlert admits only the closed alert code set. A detail that is
// not one of the typed shapes of px1oDetailSafe is replaced by "REDACTED".
func px1oSanitizeAlert(a Alert) (Alert, bool) {
	if !px1oAlertCodes[a.Code] {
		return Alert{}, false
	}
	if a.At < 0 {
		a.At = 0
	}
	if !px1oDetailSafe(a.Detail) {
		a.Detail = "REDACTED"
	}
	return a, true
}

type px1oLogSink struct{ write func(string) }

// NewLogAlertSink returns the bounded single-line log sink. A nil writer
// gives a sink that drops every alert.
func NewLogAlertSink(write func(line string)) AlertSink { return px1oLogSink{write: write} }

// Raise writes "PX1_ALERT code=<code> at=<unix> detail=<detail>". Codes
// outside the closed set are dropped.
func (s px1oLogSink) Raise(a Alert) {
	a, ok := px1oSanitizeAlert(a)
	if !ok || s.write == nil {
		return
	}
	s.write("PX1_ALERT code=" + a.Code + " at=" + strconv.FormatInt(a.At, 10) + " detail=" + a.Detail)
}

// ---------------------------------------------------------------------------
// Status projection.

// px1oStatusDay is the UTC calendar day of the projection (Q4); it equals
// UTCDay (S2) by contract, and TestPX1StatusDayMatchesUTCDay pins that.
func px1oStatusDay(unix int64) string { return time.Unix(unix, 0).UTC().Format("2006-01-02") }

// px1oRequest is one wallet-layer request folded for the status projection.
// phase is the accounting phase only: a track record never changes it (Q12).
type px1oRequest struct {
	grantID  string
	day      string
	phase    string // reserve | uncertain | refuse-retained | complete | released
	reserved int64
	released int64
}

// px1oReleased is the accounting phase of a request whose whole debit an
// operator reconciliation released.
const px1oReleased = "released"

// open reports the signer-service non-terminal set: a reservation without an
// outcome (a crash between reservation and broadcast) or an uncertain one,
// while any of its debit is still retained. An open request is charged in
// every day until a later outcome or a full release.
func (q *px1oRequest) open() bool {
	return q.phase == RecordReserve || q.phase == RecordUncertain
}

// px1oFoldGrants folds the wallet-layer journal per the frozen ledger rules:
// a debit is retained from reserve onward (reserve, uncertain,
// refuse-retained, complete, track) and only a reconcile record releases it,
// never above the retained amount. A partial release keeps the accounting
// phase (an open request stays open); only a release of the whole retained
// debit closes the request. A track record is observation only: it never
// changes the accounting phase, the day carry or the uncertain amount.
func px1oFoldGrants(j JournalV2) (map[string][]*px1oRequest, error) {
	bySeq := map[uint64]*px1oRequest{}
	byKey := map[string]*px1oRequest{}
	out := map[string][]*px1oRequest{}
	e := j.Iterate(1, func(r JournalRecordV2) error {
		key := px1oPaymentKey(r.GrantID, r.Nonce)
		switch r.Kind {
		case RecordReserve:
			if byKey[key] != nil || r.Reserved < 0 || r.Reserved > MaxMoney {
				return fail(CodeJournalSegment)
			}
			q := &px1oRequest{grantID: r.GrantID, day: r.Day, phase: RecordReserve, reserved: r.Reserved}
			bySeq[r.Seq], byKey[key] = q, q
			out[r.GrantID] = append(out[r.GrantID], q)
		case RecordComplete, RecordUncertain, RecordRefuseRetained:
			q := byKey[key]
			if q == nil {
				return fail(CodeJournalSegment)
			}
			q.phase = r.Kind
		case RecordTrack:
			if byKey[key] == nil {
				return fail(CodeJournalSegment)
			}
		case RecordReconcile:
			if r.Reconcile == nil {
				return fail(CodeJournalSegment)
			}
			q := bySeq[r.Reconcile.TargetSeq]
			if q == nil || r.Reconcile.ReleasedSat < 0 || r.Reconcile.ReleasedSat > q.reserved-q.released {
				return fail(CodeJournalSegment)
			}
			q.released += r.Reconcile.ReleasedSat
			if q.released == q.reserved {
				q.phase = px1oReleased
			}
		}
		return nil
	})
	return out, e
}

// px1oGrantStatus applies the ledger's numbers (FoldLedgerV2): reserved_sat
// is SpendUsed, uncertain_sat is UncertainSat (the retained debit of open
// requests) and day_used_sat/day_count are DayUsage. Day rule
// (signer-service): a request counts toward day D if it is open or its
// reservation day is D. The day count is a count of requests, not of
// retained atoms: a release lowers day_used_sat but never gives back a
// request counted today.
func px1oGrantStatus(l EffectiveLimits, requests []*px1oRequest, day string, seal StatusSealCheck) StatusGrant {
	g := StatusGrant{GrantID: l.GrantID, TotalCapSat: l.TotalCapSat, SpendCapSat: l.SpendCapSat, TransferCapSat: l.TransferCapSat, DayCapSat: l.DayCapSat, DayCountCap: l.DayCountCap, Day: day, Seal: seal}
	for _, q := range requests {
		retained := q.reserved - q.released
		g.ReservedSat += retained
		g.ReleasedSat += q.released
		if q.phase == RecordComplete {
			g.SpentSat += retained
		}
		if q.open() {
			g.UncertainSat += retained
		}
		if q.open() || q.day == day {
			g.DayUsedSat += retained
			g.DayCount++
		}
	}
	g.TotalRemainingSat = max(0, g.TotalCapSat-g.ReservedSat)
	g.DayRemainingSat = max(0, g.DayCapSat-g.DayUsedSat)
	g.DayCountRemaining = max(0, g.DayCountCap-g.DayCount)
	return g
}

var px1oSealVerdicts = map[string]bool{"live": true, "closed": true, "pending": true, "unknown": true}

func px1oUnobservedSeal() StatusSealCheck {
	return StatusSealCheck{Verdict: "unknown", Reason: "UNOBSERVED"}
}

// px1oRefusalCounts counts terminal refusals of the service layer by reason.
func px1oRefusalCounts(j JournalV2) ([]StatusCount, error) {
	counts := map[string]int{}
	e := j.Iterate(1, func(r JournalRecordV2) error {
		if r.Kind != RecordTerminal || r.Service == nil || r.Service.Receipt == nil || r.Service.Receipt.Receipt.Verdict != "refused" {
			return nil
		}
		code := r.Service.Receipt.Receipt.Reason
		if !boundedCode(code) {
			code = "SERVICE_FAILURE"
		}
		counts[code]++
		return nil
	})
	if e != nil {
		return nil, e
	}
	out := make([]StatusCount, 0, len(counts))
	for code, n := range counts {
		out = append(out, StatusCount{Code: code, Count: n})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Code < out[j].Code })
	return out, nil
}

// ProjectStatus builds the status projection from the two journals and the
// cached observations. It makes no node call and no journal write. Every list
// is present and sorted; grants follow in.Limits (one entry per grant id).
func ProjectStatus(in StatusInputs) (StatusProjectionV1, error) {
	var p StatusProjectionV1
	if in.Service == nil || in.Wallet == nil {
		return p, fail("STATE_UNAVAILABLE")
	}
	if in.Service.Header().Layer != JournalLayerService || in.Wallet.Header().Layer != JournalLayerWallet {
		return p, fail(CodeJournalSegment)
	}
	if (in.Network != "main" && in.Network != "regtest") || !px1oXOnly(in.ReceiptKey) || in.Now < 0 {
		return p, fail("SERVICE_CONFIG")
	}
	day := px1oStatusDay(in.Now)
	folded, e := px1oFoldGrants(in.Wallet)
	if e != nil {
		return p, e
	}
	limits := append([]EffectiveLimits{}, in.Limits...)
	sort.Slice(limits, func(i, j int) bool { return limits[i].GrantID < limits[j].GrantID })
	grants := make([]StatusGrant, 0, len(limits))
	for i, l := range limits {
		if !hexN(l.GrantID, 32) || i > 0 && limits[i-1].GrantID == l.GrantID {
			return p, fail("SERVICE_CONFIG")
		}
		seal, ok := in.Seals[l.GrantID]
		if !ok {
			seal = px1oUnobservedSeal()
		}
		if !px1oSealVerdicts[seal.Verdict] || !boundedCode(seal.Reason) {
			seal = px1oUnobservedSeal()
		}
		grants = append(grants, px1oGrantStatus(l, folded[l.GrantID], day, seal))
	}
	items := make([]TrackedPayment, 0, len(in.Tracked))
	payments := StatusPayments{}
	for _, t := range in.Tracked {
		t.Inputs = append([]su.Point{}, t.Inputs...)
		switch t.State {
		case TrackPending:
			payments.Pending++
		case TrackConfirmed:
			payments.Confirmed++
		case TrackConflicted:
			payments.Conflicted++
		default:
			return p, fail("TRACKER_PAYMENT")
		}
		items = append(items, t)
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].ReserveSeq < items[j].ReserveSeq })
	payments.Items = items
	refusals, e := px1oRefusalCounts(in.Service)
	if e != nil {
		return p, e
	}
	usage := in.Service.Usage()
	percent := 100
	if usage.SpendCapacity > 0 {
		percent = min(100, max(0, usage.Admitted)*100/usage.SpendCapacity)
	}
	floatReading := in.Float
	if floatReading.State != "ok" && floatReading.State != "low" && floatReading.State != "excess" {
		floatReading.State = "unknown"
	}
	canary := in.Canary
	if canary.State != CanaryUnspent && canary.State != CanarySpent {
		canary.State = CanaryUnknown
	}
	alerts := []Alert{}
	for _, a := range in.Alerts {
		if a, ok := px1oSanitizeAlert(a); ok {
			alerts = append(alerts, a)
		}
	}
	if len(alerts) > px1oAlertTail {
		alerts = alerts[len(alerts)-px1oAlertTail:]
	}
	return StatusProjectionV1{
		Version: StatusProjectionVersion, Service: WalletServiceID, Network: in.Network, ReceiptKey: in.ReceiptKey, GeneratedAt: in.Now,
		Poisoned: in.Poisoned || in.Service.Poisoned() || in.Wallet.Poisoned(),
		Tip:      in.Tip, Grants: grants, Payments: payments, Float: floatReading, Canary: canary,
		Journal:  StatusJournal{Admitted: usage.Admitted, SpendCapacity: usage.SpendCapacity, PercentUsed: percent, Segments: usage.Segments},
		Refusals: refusals, Alerts: alerts,
	}, nil
}

// ---------------------------------------------------------------------------
// Status socket exchange.

func px1oReadFrame(r io.Reader, limit int) ([]byte, error) {
	var prefix [4]byte
	if _, e := io.ReadFull(r, prefix[:]); e != nil {
		return nil, fail("STATUS_FRAME")
	}
	n := binary.BigEndian.Uint32(prefix[:])
	if n == 0 || n > uint32(limit) {
		return nil, fail("STATUS_FRAME_SIZE")
	}
	b := make([]byte, int(n))
	if _, e := io.ReadFull(r, b); e != nil {
		return nil, fail("STATUS_FRAME")
	}
	return b, nil
}

func px1oWriteFrame(w io.Writer, b []byte, limit int) error {
	if len(b) == 0 || len(b) > limit {
		return fail("STATUS_FRAME_SIZE")
	}
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(b)))
	frame := append(prefix[:], b...)
	for len(frame) > 0 {
		n, e := w.Write(frame)
		if e != nil || n <= 0 {
			return fail("STATUS_FRAME")
		}
		frame = frame[n:]
	}
	return nil
}

// ServeStatus serves one status connection and closes it. The request must
// be exactly canonical {"v":1,"action":"status"}; anything else closes the
// connection without a reply. source is called once per valid request; a
// source error also closes without a reply, so a caller never receives a
// partial or zero-value projection.
func ServeStatus(ctx context.Context, conn StatusConn, source func() (StatusProjectionV1, error)) error {
	if conn == nil || source == nil {
		return fail("STATUS_ARGUMENTS")
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	raw, e := px1oReadFrame(conn, px1oStatusRequestMax)
	if e != nil {
		return e
	}
	if !bytes.Equal(raw, px1oStatusRequest) {
		return fail("STATUS_REQUEST")
	}
	p, e := source()
	if e != nil {
		return px1oNodeError(e)
	}
	if p.Version != StatusProjectionVersion || p.Service != WalletServiceID {
		return fail("STATUS_PROJECTION")
	}
	if ctx.Err() != nil {
		return fail("STATUS_CANCELLED")
	}
	return px1oWriteFrame(conn, canonical(p), px1oStatusResponseMax)
}

// ExchangeStatus sends one status request over conn and strictly decodes the
// projection. Operators and the status page use it through the status socket.
func ExchangeStatus(ctx context.Context, conn StatusConn) (StatusProjectionV1, error) {
	var p StatusProjectionV1
	if conn == nil {
		return p, fail("STATUS_ARGUMENTS")
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if e := px1oWriteFrame(conn, px1oStatusRequest, px1oStatusRequestMax); e != nil {
		return p, e
	}
	raw, e := px1oReadFrame(conn, px1oStatusResponseMax)
	if e != nil {
		return p, e
	}
	if strict(raw, &p) != nil || !bytes.Equal(canonical(p), raw) || p.Version != StatusProjectionVersion || p.Service != WalletServiceID {
		return StatusProjectionV1{}, fail("STATUS_PROJECTION")
	}
	return p, nil
}
