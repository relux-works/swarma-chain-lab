package wallet

// PX1 stream S1 seam bodies and the wallet-layer G2 attachment (owner S1).
// Under W2 (no attachment) the wallet keeps its W2 journal and behaviour, and
// the seams expose no journal and no ledger.

import (
	"context"
	"encoding/hex"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// Wallet-layer journal v2 location and limits. The journal lives under the
// wallet config state_dir next to the W2 wallet.json; it takes its own lock so
// the W2 store lock (wallet.lock) is never shared.
const (
	px1WalletJournalLock    = "journal-v2.lock"
	px1SegmentMaxRecords    = 128
	px1SegmentMaxBytes      = 61440
	px1WalletBindingVersion = "swarma-wallet-g2-binding-v1"
)

// px1Deps are the cross-stream constructors the G2 wallet path consumes. The
// product values are the frozen S2/S3 entry points; tests replace them with
// fakes of the same frozen interfaces. A stub dependency fails closed.
type px1Deps struct {
	openJournal func(dir, lockName string, h JournalHeaderV2, l JournalLimitsV2) (JournalV2, error)
	fold        func(JournalV2) (LedgerView, error)
	day         func(unix int64) string
	canary      func(node su.Node, cfg CanaryConfig) (Canary, error)
}

func px1ProductDeps() px1Deps {
	return px1Deps{openJournal: OpenJournalV2, fold: FoldLedgerV2, day: UTCDay, canary: NewCanary}
}

// px1Wallet is the G2 profile state of one wallet. Wallet.g2 == nil means W2.
type px1Wallet struct {
	operator   G2OperatorConfig
	receiptKey string
	journal    JournalV2
	canary     Canary
	checker    CapChecker
	deps       px1Deps
}

// px1WalletBinding binds the wallet-layer journal to the W2 wallet binding
// (config without RPC passwords) and to this instance's receipt key, so a
// second executor never shares or adopts another executor's debits.
func px1WalletBinding(walletBinding, receiptKey string) string {
	return Hash(canonical(struct {
		Domain     string `json:"domain"`
		Wallet     string `json:"wallet_binding"`
		ReceiptKey string `json:"receipt_key"`
	}{px1WalletBindingVersion, walletBinding, receiptKey}))
}

// px1Attach selects the G2 profile for this wallet: it validates the operator
// block and receipt key, opens the wallet-layer journal v2 and the canary
// watcher. Any failure leaves the wallet unattached and refuses (fail closed).
// The service opener calls it once, before serving, with the receipt x-only key.
func (w *Wallet) px1Attach(op G2OperatorConfig, receiptKey string) error {
	return w.px1AttachWith(op, receiptKey, px1ProductDeps())
}

func (w *Wallet) px1AttachWith(op G2OperatorConfig, receiptKey string, deps px1Deps) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.g2 != nil || len(w.state.Records) != 0 {
		// A W2 journal with records is never silently continued under G2.
		return fail("SERVICE_PROFILE")
	}
	if e := ValidateG2OperatorConfig(op); e != nil {
		return e
	}
	if !validXOnly(receiptKey) {
		return fail("SERVICE_CONFIG")
	}
	if deps.openJournal == nil || deps.fold == nil || deps.day == nil || deps.canary == nil {
		return fail("SERVICE_CONFIG")
	}
	canary, e := deps.canary(w.node, op.Canary)
	if e != nil {
		return e
	}
	if canary == nil || !canary.Excluded(op.Canary.Outpoint) {
		return fail("SERVICE_CONFIG")
	}
	header := JournalHeaderV2{Version: 2, Layer: JournalLayerWallet, Binding: px1WalletBinding(w.state.Binding, receiptKey)}
	j, e := deps.openJournal(w.config.StateDir, px1WalletJournalLock, header, JournalLimitsV2{SpendCapacity: op.JournalSpendCapacity, SegmentMaxRecords: px1SegmentMaxRecords, SegmentMaxBytes: px1SegmentMaxBytes})
	if e != nil {
		return e
	}
	if j == nil || j.Header() != header {
		if j != nil {
			j.Close()
		}
		return fail(CodeJournalSegment)
	}
	w.g2 = &px1Wallet{operator: op, receiptKey: receiptKey, journal: j, canary: canary, checker: newCapCheckerFor(w.config.Network, w.config.Genesis), deps: deps}
	return nil
}

// px1OpenServiceWallet is the wallet opener of the production service
// (OpenActionService). It selects the profile before the service is built or
// serves anything: without a g2 block it is exactly openWallet (W2 unchanged);
// with a g2 block it attaches the wallet to the G2 profile under the service
// receipt key, and any failure closes the wallet and refuses startup. A present
// g2 block therefore never runs under W2 (review finding
// g2-profile-falls-through-to-w2). The call site in service.go is S2's file and
// was changed to this one call at the review's request.
func px1OpenServiceWallet(wc Config, c ServiceConfig, key *btcec.PrivateKey) (*Wallet, error) {
	w, e := openWallet(wc)
	if e != nil {
		return nil, e
	}
	if e = px1SelectProfile(w, c, key); e != nil {
		w.Close()
		return nil, e
	}
	return w, nil
}

// px1SelectProfile attaches w to the G2 profile when c carries a g2 block.
// The attach error is returned unchanged; an attach that reports success but
// leaves the wallet on W2 refuses SERVICE_PROFILE.
func px1SelectProfile(w *Wallet, c ServiceConfig, key *btcec.PrivateKey) error {
	if c.G2 == nil {
		return nil
	}
	if key == nil {
		return fail("SERVICE_CONFIG")
	}
	if e := w.px1Attach(*c.G2, hex.EncodeToString(schnorr.SerializePubKey(key.PubKey()))); e != nil {
		return e
	}
	if w.g2 == nil {
		return fail("SERVICE_PROFILE")
	}
	return nil
}

// PX1Journal returns the wallet-layer journal v2, or nil under W2.
func (w *Wallet) PX1Journal() JournalV2 {
	if w.g2 == nil {
		return nil
	}
	return w.g2.journal
}

// PX1Ledger folds the wallet-layer journal for the cap checker. Under W2 there
// is no ledger and the call refuses STATE_UNAVAILABLE.
func (w *Wallet) PX1Ledger() (LedgerView, error) {
	if w.g2 == nil || w.g2.journal == nil {
		return nil, fail("STATE_UNAVAILABLE")
	}
	if w.g2.journal.Poisoned() {
		return nil, fail("JOURNAL_WRITE_UNCERTAIN")
	}
	l, e := w.g2.deps.fold(w.g2.journal)
	if e != nil {
		return nil, e
	}
	if l == nil {
		return nil, fail("STATE_UNAVAILABLE")
	}
	return l, nil
}

// px1Excluded reports whether the G2 profile forbids planning p: the canary
// outpoint (compared directly and through the S3 watcher) and every input a
// retained wallet-layer record planned. W2 excludes nothing extra.
func (w *Wallet) px1Excluded(p su.Point, ledger LedgerView) bool {
	if w.g2 == nil {
		return false
	}
	return p == w.g2.operator.Canary.Outpoint || w.g2.canary.Excluded(p) || ledger == nil || ledger.InputReserved(p)
}

// px1Prior finds the latest wallet-layer record of (grantID, nonce), if any.
func (w *Wallet) px1Prior(grantID, nonce string) (*JournalRecordV2, error) {
	var prior *JournalRecordV2
	e := w.g2.journal.Iterate(1, func(r JournalRecordV2) error {
		if r.GrantID == grantID && r.Nonce == nonce {
			found := r
			prior = &found
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	return prior, nil
}

// px1Close releases the wallet-layer journal.
func (w *Wallet) px1Close() {
	if w.g2 != nil && w.g2.journal != nil {
		w.g2.journal.Close()
	}
}

// px1Effect re-runs the final kernel and input checks immediately before the
// broadcast (§3.5 step 21). It is shared by the W2-compatible callback shape.
func (w *Wallet) px1Recheck(ctx context.Context, grantRaw []byte, g Grant, inputs []su.Point) error {
	if e := w.authority.Check(ctx, grantRaw, g.Grantee, w.clock()); e != nil {
		return e
	}
	for _, point := range inputs {
		if _, e := readCoin(ctx, w.node, point); e != nil {
			return e
		}
	}
	return nil
}

// BudgetV2 is the extended G2 `budget` read effect (G2-PAYMENT-EXECUTOR-v1
// §3.3). Field order is the canonical JSON order. It is a read: no journal
// record, no node call except the kernel liveness check.
type BudgetV2 struct {
	GrantID           string `json:"grant_id"`
	TotalCap          int64  `json:"total_cap_sat"`
	SpendCap          int64  `json:"spend_cap_sat"`
	SpendReserved     int64  `json:"spend_reserved_sat"`
	TotalRemaining    int64  `json:"total_remaining_sat"`
	TransferCap       int64  `json:"transfer_cap_sat"`
	Day               string `json:"day"`
	DayUsed           int64  `json:"day_used_sat"`
	DayCount          int    `json:"day_count"`
	DayRemaining      int64  `json:"day_remaining_sat"`
	DayCountRemaining int    `json:"day_count_remaining"`
	Uncertain         int64  `json:"uncertain_sat"`
	Live              bool   `json:"live"`
	Reason            string `json:"reason"`
}

// px1Budget computes the G2 budget read. Caller holds w.mu. A folded ledger
// that exceeds the cumulative caps refuses JOURNAL_BUDGET instead of
// reporting a negative remainder.
func (w *Wallet) px1Budget(ctx context.Context, raw, termsRaw []byte) (BudgetV2, error) {
	var b BudgetV2
	if w.g2 == nil {
		return b, fail("STATE_UNAVAILABLE")
	}
	g, e := w.authority.Parse(raw)
	if e != nil {
		return b, e
	}
	_, l, e := w.px1TermsFor(g, termsRaw)
	if e != nil {
		return b, e
	}
	ledger, e := w.PX1Ledger()
	if e != nil {
		return b, e
	}
	now := w.clock()
	day := w.g2.deps.day(now)
	spent := ledger.SpendUsed(g.ID)
	used, count := ledger.DayUsage(g.ID, day)
	if spent < 0 || spent > l.TotalCapSat || spent > l.SpendCapSat || used < 0 || count < 0 {
		return b, fail("JOURNAL_BUDGET")
	}
	b = BudgetV2{GrantID: g.ID, TotalCap: l.TotalCapSat, SpendCap: l.SpendCapSat, SpendReserved: spent, TotalRemaining: l.TotalCapSat - spent, TransferCap: l.TransferCapSat,
		Day: day, DayUsed: used, DayCount: count, DayRemaining: max(0, l.DayCapSat-used), DayCountRemaining: max(0, l.DayCountCap-count), Uncertain: ledger.UncertainSat(g.ID)}
	e = w.authority.Check(ctx, raw, g.Grantee, now)
	b.Live = e == nil
	b.Reason = "LIVE"
	if e != nil {
		b.Reason = safeCode(e)
	}
	return b, nil
}

// px1FollowFailure is the receipt reason when the step-23 complete record
// cannot be appended after the broadcast. The debit stays retained in every
// case (the reserve record has no outcome). A clock step back below the
// reservation's last_time is refused by the journal with CLOCK_ROLLBACK and
// does not poison it, so it is reported as CLOCK_ROLLBACK rather than as a
// write uncertainty; every other append failure is JOURNAL_WRITE_UNCERTAIN.
func px1FollowFailure(e error) string {
	if e != nil && e.Error() == CodeClockRollback {
		return CodeClockRollback
	}
	return "JOURNAL_WRITE_UNCERTAIN"
}
