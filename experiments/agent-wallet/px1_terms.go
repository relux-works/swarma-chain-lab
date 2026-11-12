package wallet

// PX1 stream S1 implementation file (owner S1): terms v2, operator ceilings,
// effective limits and the cap checker. Signatures are frozen in
// px1_terms_api.go; the refusal order below follows that table exactly.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"slices"
	"time"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// Operator-block upper bounds that are not terms values. They only bound the
// configuration surface; a terms value is never raised by them.
const (
	px1MaxConfirmationsK  = 100
	px1MaxConflictBlocksN = 1000
	px1MaxReadRatePerHour = 3600
	px1MaxJournalCapacity = 1000000
)

// validXOnly reports whether s is a lowercase 64-hex BIP-340 x-only key.
func validXOnly(s string) bool {
	if !hexN(s, 32) {
		return false
	}
	b, _ := hex.DecodeString(s)
	_, e := schnorr.ParsePubKey(b)
	return e == nil
}

// ParseTermsV2 parses and binds terms v2 bytes; see the refusal table in
// px1_terms_api.go. The first failing row wins.
func ParseTermsV2(raw []byte, pins TermsV2Pins) (TermsV2, error) {
	var t TermsV2
	// Row 1: size and JSON object shape.
	var members map[string]json.RawMessage
	if len(raw) == 0 || len(raw) > 65536 || json.Unmarshal(raw, &members) != nil || members == nil {
		return TermsV2{}, fail(CodeContractSchema)
	}
	// Row 2: a terms v1 object under the G2 profile.
	if v, ok := members["version"]; ok && bytes.Equal(bytes.TrimSpace(v), []byte("1")) {
		return TermsV2{}, fail(CodeTermsVersionRequired)
	}
	// Row 3: SJ1-strict, no unknown or duplicate member, canonical bytes.
	if strict(raw, &t) != nil {
		return TermsV2{}, fail(CodeContractSchema)
	}
	// Row 4: fixed members and the executor key shape.
	if t.Version != TermsV2Version || t.Service != WalletServiceID || t.DayBasis != DayBasisUTCCalendar || !validXOnly(t.ExecutorKey) {
		return TermsV2{}, fail(CodeContractSchema)
	}
	// Row 5: network pins.
	if t.Network != pins.Network || t.Genesis != pins.Genesis || !su.NetworkPinned(pins.Network, pins.Genesis) {
		return TermsV2{}, fail(CodeTermsNetwork)
	}
	// Row 6: executor binding (G-12).
	if t.ExecutorKey != pins.ExecutorKey {
		return TermsV2{}, fail(CodeTermsExecutorMismatch)
	}
	// Row 7: recipient mode and list shape.
	switch {
	case t.Recipients == nil:
		return TermsV2{}, fail(CodeContractSchema)
	case t.RecipientMode == RecipientModeAllow:
		if len(t.Recipients) < 1 || len(t.Recipients) > MaxTermsRecipients || !slices.IsSorted(t.Recipients) {
			return TermsV2{}, fail(CodeContractSchema)
		}
	case t.RecipientMode == RecipientModeAny:
		if len(t.Recipients) != 0 {
			return TermsV2{}, fail(CodeContractSchema)
		}
	default:
		return TermsV2{}, fail(CodeContractSchema)
	}
	// Row 8 runs over the whole list before row 9, so an invalid address
	// anywhere wins over an earlier duplicate.
	for _, a := range t.Recipients {
		if _, e := addressScriptForNetwork(a, pins.Network, pins.Genesis); e != nil {
			return TermsV2{}, e
		}
	}
	// Row 9: duplicates (the list is sorted, so they are adjacent).
	for i := 1; i < len(t.Recipients); i++ {
		if t.Recipients[i] == t.Recipients[i-1] {
			return TermsV2{}, fail(CodeContractRecipients)
		}
	}
	// Row 10: cap ordering bound by the grant budget (absent budget = 0).
	if pins.GrantBudget > MaxMoney || t.TransferCap < 1 || t.TransferCap > t.DayCap || t.DayCap > t.SpendCap || t.SpendCap > pins.GrantBudget ||
		t.DayCountCap < 1 || t.DayCountCap > MaxDayCountCap || t.FeeCap < 1 || t.FeeCap > MaxFee {
		return TermsV2{}, fail(CodeContractBudget)
	}
	return t, nil
}

// ValidateG2OperatorConfig validates the "g2" operator block. Every violation
// refuses SERVICE_CONFIG.
func ValidateG2OperatorConfig(c G2OperatorConfig) error {
	ok := c.RequireTermsVersion == TermsV2Version && !c.AllowSingleUse &&
		c.MaxTransferSat >= 1 && c.MaxTransferSat <= c.MaxDaySat && c.MaxDaySat <= MaxMoney &&
		c.MaxDayCount >= 1 && c.MaxDayCount <= MaxDayCountCap &&
		c.MaxFeeSat >= 1 && c.MaxFeeSat <= MaxFee &&
		c.MaxFloatSat >= 1 && c.MaxFloatSat <= MaxMoney && c.LowFloatSat >= 0 && c.LowFloatSat < c.MaxFloatSat &&
		hexN(c.Canary.Outpoint.TxID, 32) && c.Canary.ValueSat >= DustLimitSat && c.Canary.ValueSat <= MaxMoney &&
		c.ConfirmationsK >= 1 && c.ConfirmationsK <= px1MaxConfirmationsK &&
		c.ConflictBlocksN >= 1 && c.ConflictBlocksN <= px1MaxConflictBlocksN &&
		c.ReadRatePerHour >= 1 && c.ReadRatePerHour <= px1MaxReadRatePerHour &&
		c.JournalSpendCapacity >= 1+JournalCapacityHeadroom && c.JournalSpendCapacity <= px1MaxJournalCapacity
	if !ok {
		return fail("SERVICE_CONFIG")
	}
	return nil
}

// EffectiveLimitsFor computes min(terms, operator ceiling) for one grant. The
// operator block only lowers a terms value; recipients come from terms only.
func EffectiveLimitsFor(g Grant, t TermsV2, c G2OperatorConfig) (EffectiveLimits, error) {
	if e := ValidateG2OperatorConfig(c); e != nil {
		return EffectiveLimits{}, e
	}
	// The terms must still be bound to this grant's budget (defence in depth
	// over ParseTermsV2 row 10, for a caller that skipped it).
	if g.Budget < 1 || g.Budget > MaxMoney || t.TransferCap < 1 || t.TransferCap > t.DayCap || t.DayCap > t.SpendCap || t.SpendCap > g.Budget ||
		t.DayCountCap < 1 || t.FeeCap < 1 {
		return EffectiveLimits{}, fail(CodeContractBudget)
	}
	switch t.RecipientMode {
	case RecipientModeAllow:
		if len(t.Recipients) < 1 {
			return EffectiveLimits{}, fail(CodeContractSchema)
		}
	case RecipientModeAny:
		if !c.AllowAnyRecipients {
			return EffectiveLimits{}, fail(CodeTermsRecipientMode)
		}
	default:
		return EffectiveLimits{}, fail(CodeContractSchema)
	}
	return EffectiveLimits{
		GrantID:        g.ID,
		TotalCapSat:    g.Budget,
		SpendCapSat:    t.SpendCap,
		TransferCapSat: min(t.TransferCap, c.MaxTransferSat),
		DayCapSat:      min(t.DayCap, c.MaxDaySat),
		DayCountCap:    min(t.DayCountCap, c.MaxDayCount),
		FeeCapSat:      min(t.FeeCap, c.MaxFeeSat),
		RecipientMode:  t.RecipientMode,
		Recipients:     append([]string{}, t.Recipients...),
	}, nil
}

// capChecker implements CapChecker. network/genesis bind any-mode recipients
// to one pinned network; the zero value (NewCapChecker) admits a canonical
// P2PKH of exactly one pinned network and relies on the caller's own network
// binding (wire parse and plan), which the wallet always applies.
type capChecker struct{ network, genesis string }

// NewCapChecker returns the PX1 cap checker.
func NewCapChecker() CapChecker { return capChecker{} }

// newCapCheckerFor returns a checker whose any-mode recipient check is bound
// to the given pinned network. The wallet G2 path always uses this form.
func newCapCheckerFor(network, genesis string) CapChecker {
	return capChecker{network: network, genesis: genesis}
}

func (capChecker) CheckExecutor(t TermsV2, receiptKey string) error {
	if !validXOnly(receiptKey) || t.ExecutorKey != receiptKey {
		return fail(CodeTermsExecutorMismatch)
	}
	return nil
}

func (c capChecker) CheckRecipient(l EffectiveLimits, address string) error {
	switch l.RecipientMode {
	case RecipientModeAllow:
		if slices.Contains(l.Recipients, address) {
			return nil
		}
	case RecipientModeAny:
		if c.network != "" || c.genesis != "" {
			if _, e := addressScriptForNetwork(address, c.network, c.genesis); e == nil {
				return nil
			}
			break
		}
		// Unbound checker: main and regtest P2PKH prefixes are disjoint, so a
		// canonical address decodes on at most one pinned network.
		for _, n := range [][2]string{{"main", su.MainGenesis}, {"regtest", su.RegtestGenesis}} {
			if _, e := addressScriptForNetwork(address, n[0], n[1]); e == nil {
				return nil
			}
		}
	}
	return fail(CodeAddressNotAllowed)
}

// validIntent rejects an intent that cannot belong to these limits. These are
// internal invariant failures, never a cap verdict, so they refuse
// STATE_UNAVAILABLE before any cap is read.
func validIntent(l EffectiveLimits, in SpendIntent, ledger LedgerView) error {
	if ledger == nil || in.GrantID == "" || in.GrantID != l.GrantID || in.AmountSat < 1 || in.AmountSat > MaxMoney || in.FeeLimitSat < 1 || in.FeeLimitSat > MaxFee || in.FeeSat < 0 || in.FeeSat > MaxFee {
		return fail("STATE_UNAVAILABLE")
	}
	if d, e := time.Parse(time.DateOnly, in.Day); e != nil || d.Format(time.DateOnly) != in.Day {
		return fail("STATE_UNAVAILABLE")
	}
	return nil
}

// cumulative applies the total, spend, day and day-count caps to one cost.
func cumulative(l EffectiveLimits, in SpendIntent, ledger LedgerView, cost int64) error {
	spent := ledger.SpendUsed(in.GrantID)
	if spent < 0 || spent > l.TotalCapSat || cost > l.TotalCapSat-spent {
		return fail(CodeTotalBudgetExceeded)
	}
	if spent > l.SpendCapSat || cost > l.SpendCapSat-spent {
		return fail(CodeSpendBudgetExceeded)
	}
	used, count := ledger.DayUsage(in.GrantID, in.Day)
	if used < 0 || used > l.DayCapSat || cost > l.DayCapSat-used {
		return fail(CodeDayCapExceeded)
	}
	if count < 0 || count >= l.DayCountCap {
		return fail(CodeDayCountExceeded)
	}
	return nil
}

func (capChecker) CheckPrePlan(l EffectiveLimits, in SpendIntent, ledger LedgerView) error {
	if e := validIntent(l, in, ledger); e != nil {
		return e
	}
	if in.AmountSat < DustLimitSat {
		return fail(CodeAmountDust)
	}
	// Conservative pre-plan transfer cost: the request's own fee ceiling.
	if in.AmountSat > l.TransferCapSat-in.FeeLimitSat {
		return fail(CodeTransferCapExceeded)
	}
	return cumulative(l, in, ledger, in.AmountSat)
}

func (capChecker) CheckPostPlan(l EffectiveLimits, in SpendIntent, ledger LedgerView) error {
	if e := validIntent(l, in, ledger); e != nil {
		return e
	}
	if in.FeeSat < 1 || in.FeeSat > in.FeeLimitSat {
		return fail(CodeFeeLimit)
	}
	if in.FeeSat > l.FeeCapSat {
		return fail(CodeFeeCapExceeded)
	}
	cost := in.AmountSat + in.FeeSat
	if cost > l.TransferCapSat {
		return fail(CodeTransferCapExceeded)
	}
	return cumulative(l, in, ledger, cost)
}
