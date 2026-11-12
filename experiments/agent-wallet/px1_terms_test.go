package wallet

// Owner S1. Unit layer of T1, T2, T4, T6, T7, T12 and T15 (G2-PAYMENT-EXECUTOR-v1
// §3.8) plus the parser, operator and cap-checker contracts. The wallet-level
// cases run the real S1 spend path against fakes of the frozen S2/S3
// interfaces and a fake wallet node; they never establish real-Core
// acceptance (see the Core cases in px1_core_test.go).

import (
	"errors"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

func px1Pins(budget int64) TermsV2Pins {
	return TermsV2Pins{Network: "main", Genesis: su.MainGenesis, ExecutorKey: px1ExecutorKey, GrantBudget: budget}
}

func wantCode(t *testing.T, label string, got error, want string) {
	t.Helper()
	if want == "" {
		if got != nil {
			t.Fatalf("%s: want accepted got %v", label, got)
		}
		return
	}
	if got == nil || got.Error() != want {
		t.Fatalf("%s: want %s got %v", label, want, got)
	}
}

// Other-encoding addresses of the allow-list key testKey(5) and outsiders.
func px1AddressVariants(t *testing.T) map[string]string {
	t.Helper()
	k, _ := testKey(5)
	h := btcutil.Hash160(k.PubKey().SerializeCompressed())
	p2sh, e := btcutil.NewAddressScriptHashFromHash(h, px1MainParams())
	if e != nil {
		t.Fatal(e)
	}
	bech, e := btcutil.NewAddressWitnessPubKeyHash(h, px1MainParams())
	if e != nil {
		t.Fatal(e)
	}
	mixed := []byte(px1AllowA)
	for i, c := range mixed {
		if c >= 'a' && c <= 'z' {
			mixed[i] = c - 32
			break
		}
	}
	return map[string]string{
		"outsider-main-p2pkh": px1Outsider,
		"p2sh-main":           p2sh.EncodeAddress(),
		"bech32-main":         bech.EncodeAddress(),
		"testnet-p2pkh":       testAddress(5), // regtest/testnet version byte 111
		"mixed-case":          string(mixed),
	}
}

// Claim: both golden terms fixtures parse under their own pins to exactly the fixture struct, and re-marshal to the golden bytes.
func TestPX1ParseTermsV2Golden(t *testing.T) {
	for _, c := range []struct {
		file   string
		want   TermsV2
		budget int64
	}{{"terms-v2-allow.json", px1TermsAllow(), 500000}, {"terms-v2-any.json", px1TermsAny(), 100000}} {
		raw := px1Golden(t, c.file)
		got, e := ParseTermsV2(raw, px1Pins(c.budget))
		if e != nil || !slices.Equal(got.Recipients, c.want.Recipients) || string(canonical(got)) != string(raw) {
			t.Fatalf("%s: want accepted got %v", c.file, e)
		}
	}
}

// Claim: every row of the frozen ParseTermsV2 refusal table refuses with its code, and the nearest valid neighbour of each row is accepted.
func TestPX1ParseTermsV2Refusals(t *testing.T) {
	good := canonical(px1TermsAllow())
	if _, e := ParseTermsV2(good, px1Pins(500000)); e != nil {
		t.Fatal("neighbour", e)
	}
	mut := func(f func(*TermsV2)) []byte {
		x := px1TermsAllow()
		x.Recipients = append([]string{}, x.Recipients...)
		f(&x)
		return canonical(x)
	}
	v1 := canonical(Terms{Version: 1, Recipients: []string{px1AllowA}, SpendCap: 1000, NameCap: 0, NameCount: 0})
	pins := px1Pins(500000)
	for _, c := range []struct {
		name string
		raw  []byte
		pins TermsV2Pins
		want string
	}{
		{"row1-empty", nil, pins, CodeContractSchema},
		{"row1-oversize", append(append([]byte{}, good...), make([]byte, 65537)...), pins, CodeContractSchema},
		{"row1-array", []byte(`[1]`), pins, CodeContractSchema},
		{"row1-null", []byte(`null`), pins, CodeContractSchema},
		{"row2-v1", v1, pins, CodeTermsVersionRequired},
		{"row3-whitespace", append([]byte(" "), good...), pins, CodeContractSchema},
		{"row3-unknown-member", []byte(strings.Replace(string(good), `{"version":2,`, `{"version":2,"extra":1,`, 1)), pins, CodeContractSchema},
		{"row3-duplicate-member", []byte(strings.Replace(string(good), `"day_basis":"utc-calendar"}`, `"day_basis":"utc-calendar","day_basis":"utc-calendar"}`, 1)), pins, CodeContractSchema},
		{"row3-reordered", canonical(map[string]any{"version": 2}), pins, CodeContractSchema},
		{"row3-case-alias", []byte(strings.Replace(string(good), `"spend_cap_sat"`, `"Spend_cap_sat"`, 1)), pins, CodeContractSchema},
		{"row4-version3", mut(func(x *TermsV2) { x.Version = 3 }), pins, CodeContractSchema},
		{"row4-service", mut(func(x *TermsV2) { x.Service = "wallet.btc" }), pins, CodeContractSchema},
		{"row4-day-basis", mut(func(x *TermsV2) { x.DayBasis = "rolling-24h" }), pins, CodeContractSchema},
		{"row4-executor-shape", mut(func(x *TermsV2) { x.ExecutorKey = strings.ToUpper(px1ExecutorKey) }), pins, CodeContractSchema},
		{"row4-executor-offcurve", mut(func(x *TermsV2) { x.ExecutorKey = strings.Repeat("f", 64) }), pins, CodeContractSchema},
		{"row5-network", good, TermsV2Pins{Network: "regtest", Genesis: su.RegtestGenesis, ExecutorKey: px1ExecutorKey, GrantBudget: 500000}, CodeTermsNetwork},
		{"row5-genesis", mut(func(x *TermsV2) { x.Genesis = su.RegtestGenesis }), pins, CodeTermsNetwork},
		{"row6-executor", good, TermsV2Pins{Network: "main", Genesis: su.MainGenesis, ExecutorKey: px1AllowKeyX(t, 8), GrantBudget: 500000}, CodeTermsExecutorMismatch},
		{"row7-mode", mut(func(x *TermsV2) { x.RecipientMode = "deny" }), pins, CodeContractSchema},
		{"row7-null", mut(func(x *TermsV2) { x.Recipients = nil }), pins, CodeContractSchema},
		{"row7-allow-empty", mut(func(x *TermsV2) { x.Recipients = []string{} }), pins, CodeContractSchema},
		{"row7-allow-unsorted", mut(func(x *TermsV2) { x.Recipients = []string{px1AllowB, px1AllowA} }), pins, CodeContractSchema},
		{"row7-allow-33", mut(func(x *TermsV2) { x.Recipients = px1ManyAddresses(t, 33) }), pins, CodeContractSchema},
		{"row7-any-nonempty", mut(func(x *TermsV2) { x.RecipientMode = RecipientModeAny }), pins, CodeContractSchema},
		{"row8-regtest-address", mut(func(x *TermsV2) { x.Recipients = []string{px1AllowA, testAddress(5)} }), pins, "ADDRESS_MAIN"},
		{"row8-p2sh", mut(func(x *TermsV2) { x.Recipients = []string{px1AddressVariants(t)["p2sh-main"]} }), pins, "ADDRESS_P2PKH_ONLY"},
		{"row8-before-row9", mut(func(x *TermsV2) { x.Recipients = []string{px1AllowA, px1AllowA, testAddress(5)} }), pins, "ADDRESS_MAIN"},
		{"row9-duplicate", mut(func(x *TermsV2) { x.Recipients = []string{px1AllowA, px1AllowA} }), pins, CodeContractRecipients},
		{"row10-budget-absent", good, px1Pins(0), CodeContractBudget},
		{"row10-budget-below-spend", good, px1Pins(499999), CodeContractBudget},
		{"row10-transfer-zero", mut(func(x *TermsV2) { x.TransferCap = 0 }), pins, CodeContractBudget},
		{"row10-transfer-over-day", mut(func(x *TermsV2) { x.TransferCap = x.DayCap + 1 }), pins, CodeContractBudget},
		{"row10-day-over-spend", mut(func(x *TermsV2) { x.DayCap = x.SpendCap + 1 }), pins, CodeContractBudget},
		{"row10-count-zero", mut(func(x *TermsV2) { x.DayCountCap = 0 }), pins, CodeContractBudget},
		{"row10-count-1001", mut(func(x *TermsV2) { x.DayCountCap = MaxDayCountCap + 1 }), pins, CodeContractBudget},
		{"row10-fee-zero", mut(func(x *TermsV2) { x.FeeCap = 0 }), pins, CodeContractBudget},
		{"row10-fee-over-max", mut(func(x *TermsV2) { x.FeeCap = MaxFee + 1 }), pins, CodeContractBudget},
		{"row10-budget-over-money", good, px1Pins(MaxMoney + 1), CodeContractBudget},
		// Valid neighbours at the row-7..10 boundaries.
		{"ok-budget-equals-spend", good, px1Pins(500000), ""},
		{"ok-equal-caps", mut(func(x *TermsV2) { x.TransferCap, x.DayCap, x.SpendCap = 500000, 500000, 500000 }), pins, ""},
		{"ok-count-1000-fee-max", mut(func(x *TermsV2) { x.DayCountCap, x.FeeCap = MaxDayCountCap, MaxFee }), pins, ""},
		{"ok-allow-32", mut(func(x *TermsV2) { x.Recipients = px1ManyAddresses(t, 32) }), pins, ""},
		{"ok-allow-one", mut(func(x *TermsV2) { x.Recipients = []string{px1AllowB} }), pins, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, e := ParseTermsV2(c.raw, c.pins)
			wantCode(t, c.name, e, c.want)
		})
	}
}

// px1AllowKeyX is testKey(n)'s x-only key.
func px1AllowKeyX(t *testing.T, n byte) string { _, x := testKey(n); return x }

// px1ManyAddresses returns n sorted distinct mainnet P2PKH addresses.
func px1ManyAddresses(t *testing.T, n int) []string {
	t.Helper()
	var out []string
	for i := 0; i < n; i++ {
		out = append(out, px1MainAddress(byte(40+i)))
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// Claim (T12, unit): terms naming another receipt key refuse TERMS_EXECUTOR_MISMATCH in both the parser and CheckExecutor; terms naming this instance's key are accepted.
func TestPX1ExecutorBinding(t *testing.T) {
	raw := canonical(px1TermsAllow())
	other := px1AllowKeyX(t, 8)
	_, e := ParseTermsV2(raw, TermsV2Pins{Network: "main", Genesis: su.MainGenesis, ExecutorKey: other, GrantBudget: 500000})
	wantCode(t, "parser other key", e, CodeTermsExecutorMismatch)
	_, e = ParseTermsV2(raw, px1Pins(500000))
	wantCode(t, "parser own key", e, "")
	c := NewCapChecker()
	wantCode(t, "check other key", c.CheckExecutor(px1TermsAllow(), other), CodeTermsExecutorMismatch)
	wantCode(t, "check empty key", c.CheckExecutor(TermsV2{}, ""), CodeTermsExecutorMismatch)
	wantCode(t, "check invalid key", c.CheckExecutor(TermsV2{ExecutorKey: "zz"}, "zz"), CodeTermsExecutorMismatch)
	wantCode(t, "check own key", c.CheckExecutor(px1TermsAllow(), px1ExecutorKey), "")
}

// Claim: the launch operator fixture validates, and each range or launch decision violation refuses SERVICE_CONFIG; allow_any_recipients=true (Q2 phase 2) is still a valid block.
func TestPX1OperatorConfig(t *testing.T) {
	wantCode(t, "fixture", ValidateG2OperatorConfig(px1Operator()), "")
	any := px1Operator()
	any.AllowAnyRecipients = true
	wantCode(t, "phase-2 any", ValidateG2OperatorConfig(any), "")
	for name, f := range map[string]func(*G2OperatorConfig){
		"terms-v1":          func(c *G2OperatorConfig) { c.RequireTermsVersion = 1 },
		"single-use":        func(c *G2OperatorConfig) { c.AllowSingleUse = true },
		"transfer-zero":     func(c *G2OperatorConfig) { c.MaxTransferSat = 0 },
		"transfer-over-day": func(c *G2OperatorConfig) { c.MaxTransferSat = c.MaxDaySat + 1 },
		"count-zero":        func(c *G2OperatorConfig) { c.MaxDayCount = 0 },
		"count-1001":        func(c *G2OperatorConfig) { c.MaxDayCount = MaxDayCountCap + 1 },
		"fee-zero":          func(c *G2OperatorConfig) { c.MaxFeeSat = 0 },
		"fee-over-max":      func(c *G2OperatorConfig) { c.MaxFeeSat = MaxFee + 1 },
		"float-zero":        func(c *G2OperatorConfig) { c.MaxFloatSat = 0 },
		"low-at-float":      func(c *G2OperatorConfig) { c.LowFloatSat = c.MaxFloatSat },
		"low-negative":      func(c *G2OperatorConfig) { c.LowFloatSat = -1 },
		"canary-txid":       func(c *G2OperatorConfig) { c.Canary.Outpoint.TxID = "" },
		"canary-dust":       func(c *G2OperatorConfig) { c.Canary.ValueSat = DustLimitSat - 1 },
		"k-zero":            func(c *G2OperatorConfig) { c.ConfirmationsK = 0 },
		"n-zero":            func(c *G2OperatorConfig) { c.ConflictBlocksN = 0 },
		"reads-zero":        func(c *G2OperatorConfig) { c.ReadRatePerHour = 0 },
		"capacity-64":       func(c *G2OperatorConfig) { c.JournalSpendCapacity = JournalCapacityHeadroom },
		"zero-block":        func(c *G2OperatorConfig) { *c = G2OperatorConfig{} },
	} {
		t.Run(name, func(t *testing.T) {
			c := px1Operator()
			f(&c)
			wantCode(t, name, ValidateG2OperatorConfig(c), "SERVICE_CONFIG")
		})
	}
	edge := px1Operator()
	edge.MaxDayCount, edge.MaxFeeSat, edge.JournalSpendCapacity, edge.LowFloatSat = MaxDayCountCap, MaxFee, JournalCapacityHeadroom+1, 0
	wantCode(t, "edge neighbour", ValidateG2OperatorConfig(edge), "")
}

// Claim: effective limits are min(terms, operator) per value, so the operator lowers but never raises a terms value; any-mode terms refuse TERMS_RECIPIENT_MODE unless the operator allows any (Q2); a budget-absent grant refuses CONTRACT_BUDGET (T4).
func TestPX1EffectiveLimits(t *testing.T) {
	g := px1Grant(canonical(px1TermsAllow()), 500000)
	low := px1Operator()
	low.MaxTransferSat, low.MaxDaySat, low.MaxDayCount, low.MaxFeeSat = 40000, 90000, 3, 7000
	l, e := EffectiveLimitsFor(g, px1TermsAllow(), low)
	if e != nil || l.TransferCapSat != 40000 || l.DayCapSat != 90000 || l.DayCountCap != 3 || l.FeeCapSat != 7000 || l.SpendCapSat != 500000 || l.TotalCapSat != 500000 || l.GrantID != g.ID {
		t.Fatalf("operator ceiling not applied: %+v %v", l, e)
	}
	high := px1Operator()
	high.MaxTransferSat, high.MaxDaySat, high.MaxDayCount, high.MaxFeeSat = 300000, 900000, 50, 900000
	l, e = EffectiveLimitsFor(g, px1TermsAllow(), high)
	if e != nil || l.TransferCapSat != 100000 || l.DayCapSat != 300000 || l.DayCountCap != 5 || l.FeeCapSat != 100000 {
		t.Fatalf("operator raised a terms value: %+v %v", l, e)
	}
	if !slices.Equal(l.Recipients, px1TermsAllow().Recipients) || l.RecipientMode != RecipientModeAllow {
		t.Fatal("recipients must come from terms")
	}
	ga := px1Grant(canonical(px1TermsAny()), 100000)
	_, e = EffectiveLimitsFor(ga, px1TermsAny(), px1Operator())
	wantCode(t, "any at launch", e, CodeTermsRecipientMode)
	phase2 := px1Operator()
	phase2.AllowAnyRecipients = true
	_, e = EffectiveLimitsFor(ga, px1TermsAny(), phase2)
	wantCode(t, "any in phase 2", e, "")
	absent := g
	absent.Budget = 0
	_, e = EffectiveLimitsFor(absent, px1TermsAllow(), px1Operator())
	wantCode(t, "budget absent", e, CodeContractBudget)
	_, e = EffectiveLimitsFor(g, px1TermsAllow(), G2OperatorConfig{})
	wantCode(t, "zero operator", e, "SERVICE_CONFIG")
}

// Claim (T15): in allow mode only the exact listed strings pass; a non-listed main P2PKH, a P2SH or bech32 encoding of a listed key, a testnet/regtest address and a mixed-case variant refuse ADDRESS_NOT_ALLOWED.
func TestPX1RecipientAllowMode(t *testing.T) {
	l, e := EffectiveLimitsFor(px1Grant(canonical(px1TermsAllow()), 500000), px1TermsAllow(), px1Operator())
	if e != nil {
		t.Fatal(e)
	}
	for _, c := range []CapChecker{NewCapChecker(), NewCapCheckerFor("main", su.MainGenesis)} {
		for _, ok := range []string{px1AllowA, px1AllowB} {
			wantCode(t, "listed "+ok, c.CheckRecipient(l, ok), "")
		}
		for name, a := range px1AddressVariants(t) {
			wantCode(t, name, c.CheckRecipient(l, a), CodeAddressNotAllowed)
		}
	}
}

// Claim: in any mode the frozen NewCapCheckerFor("main") admits every canonical main P2PKH and refuses P2SH, bech32, regtest/testnet and mixed-case encodings, and NewCapCheckerFor("regtest") admits a regtest P2PKH and refuses a main one; an unknown mode refuses on both.
func TestPX1RecipientAnyMode(t *testing.T) {
	op := px1Operator()
	op.AllowAnyRecipients = true
	l, e := EffectiveLimitsFor(px1Grant(canonical(px1TermsAny()), 100000), px1TermsAny(), op)
	if e != nil {
		t.Fatal(e)
	}
	bound := NewCapCheckerFor("main", su.MainGenesis)
	v := px1AddressVariants(t)
	wantCode(t, "bound outsider", bound.CheckRecipient(l, px1Outsider), "")
	wantCode(t, "bound listed", bound.CheckRecipient(l, px1AllowA), "")
	for _, name := range []string{"p2sh-main", "bech32-main", "testnet-p2pkh", "mixed-case"} {
		wantCode(t, "bound "+name, bound.CheckRecipient(l, v[name]), CodeAddressNotAllowed)
	}
	regtest := NewCapCheckerFor("regtest", su.RegtestGenesis)
	wantCode(t, "regtest-bound regtest", regtest.CheckRecipient(l, testAddress(5)), "")
	wantCode(t, "regtest-bound main", regtest.CheckRecipient(l, px1Outsider), CodeAddressNotAllowed)
	for _, c := range []CapChecker{bound, regtest} {
		wantCode(t, "unknown mode", c.CheckRecipient(EffectiveLimits{RecipientMode: "deny"}, px1Outsider), CodeAddressNotAllowed)
	}
}

// Claim (amendment 1, A4): the deprecated networkless NewCapChecker admits no any-mode recipient: a canonical main P2PKH, a canonical regtest P2PKH, an address the terms happen to list and every other encoding all refuse ADDRESS_NOT_ALLOWED; its allow mode still admits exactly the listed strings (valid neighbour), and the network-bearing NewCapCheckerFor admits the same main P2PKH in any mode.
func TestPX1NetworklessCapCheckerAnyMode(t *testing.T) {
	op := px1Operator()
	op.AllowAnyRecipients = true
	anyLimits, e := EffectiveLimitsFor(px1Grant(canonical(px1TermsAny()), 100000), px1TermsAny(), op)
	if e != nil {
		t.Fatal(e)
	}
	v := px1AddressVariants(t)
	unbound := NewCapChecker()
	// Ordered: the canonical P2PKH cases come first, so a plant that restores
	// the old main-or-regtest admission fails at its own named case.
	for _, c := range []struct{ name, address string }{
		{"networkless any main", px1Outsider},
		{"networkless any regtest", testAddress(5)},
		{"networkless any listed", px1AllowA},
		{"networkless any p2sh", v["p2sh-main"]},
		{"networkless any bech32", v["bech32-main"]},
		{"networkless any mixed-case", v["mixed-case"]},
		{"networkless any empty", ""},
	} {
		wantCode(t, c.name, unbound.CheckRecipient(anyLimits, c.address), CodeAddressNotAllowed)
	}
	allowLimits := px1Limits(t)
	wantCode(t, "networkless allow listed", unbound.CheckRecipient(allowLimits, px1AllowA), "")
	wantCode(t, "networkless allow outsider", unbound.CheckRecipient(allowLimits, px1Outsider), CodeAddressNotAllowed)
	wantCode(t, "pinned any main", NewCapCheckerFor("main", su.MainGenesis).CheckRecipient(anyLimits, px1Outsider), "")
}

func px1Limits(t *testing.T) EffectiveLimits {
	t.Helper()
	l, e := EffectiveLimitsFor(px1Grant(canonical(px1TermsAllow()), 500000), px1TermsAllow(), px1Operator())
	if e != nil {
		t.Fatal(e)
	}
	return l
}

// Claim (T2 pre-plan, T4): CheckPrePlan refuses dust, amount+fee_limit one atom over the transfer cap, then total, spend, day and day-count caps on the amount, each at its exact boundary with the at-cap neighbour accepted.
func TestPX1CheckPrePlan(t *testing.T) {
	l := px1Limits(t)
	day := px1TestDay(px1Now)
	in := func(amount, feeLimit int64) SpendIntent {
		return SpendIntent{GrantID: l.GrantID, Recipient: px1AllowA, AmountSat: amount, FeeLimitSat: feeLimit, Day: day}
	}
	c := NewCapChecker()
	empty := fixedLedger{day: day}
	for _, x := range []struct {
		name   string
		intent SpendIntent
		ledger fixedLedger
		want   string
	}{
		{"dust", in(DustLimitSat-1, 1000), empty, CodeAmountDust},
		{"dust-boundary", in(DustLimitSat, 1000), empty, ""},
		{"transfer-plus-one", in(97741, 2260), empty, CodeTransferCapExceeded},
		{"transfer-exact", in(97740, 2260), empty, ""},
		{"total-plus-one", in(50001, 1000), fixedLedger{spent: 450000, day: day}, CodeTotalBudgetExceeded},
		{"total-exact", in(50000, 1000), fixedLedger{spent: 450000, day: day}, ""},
		{"day-plus-one", in(50001, 1000), fixedLedger{spent: 250000, dayUsed: 250000, dayCount: 2, day: day}, CodeDayCapExceeded},
		{"day-exact", in(50000, 1000), fixedLedger{spent: 250000, dayUsed: 250000, dayCount: 2, day: day}, ""},
		{"count-full", in(1000, 1000), fixedLedger{spent: 5000, dayUsed: 5000, dayCount: 5, day: day}, CodeDayCountExceeded},
		{"count-last", in(1000, 1000), fixedLedger{spent: 4000, dayUsed: 4000, dayCount: 4, day: day}, ""},
		{"other-day-free", in(50000, 1000), fixedLedger{spent: 250000, dayUsed: 300000, dayCount: 5, day: "2026-11-05"}, ""},
		{"transfer-before-budget", in(97741, 2260), fixedLedger{spent: 500000, day: day}, CodeTransferCapExceeded},
		{"total-before-day", in(50001, 1000), fixedLedger{spent: 450000, dayUsed: 300000, dayCount: 5, day: day}, CodeTotalBudgetExceeded},
	} {
		t.Run(x.name, func(t *testing.T) { wantCode(t, x.name, c.CheckPrePlan(l, x.intent, x.ledger), x.want) })
	}
	// SPEND_BUDGET_EXCEEDED needs spend_cap < budget.
	ls := l
	ls.TotalCapSat = 600000
	wantCode(t, "spend-plus-one", c.CheckPrePlan(ls, in(50001, 1000), fixedLedger{spent: 450000, day: day}), CodeSpendBudgetExceeded)
	wantCode(t, "spend-exact", c.CheckPrePlan(ls, in(50000, 1000), fixedLedger{spent: 450000, day: day}), "")
}

// Claim (T2 post-plan): CheckPostPlan refuses fee over fee_limit, fee over the effective fee cap, amount+fee one atom over the transfer cap, then the cumulative caps on amount+fee; amount+fee exactly at each cap is accepted.
func TestPX1CheckPostPlan(t *testing.T) {
	l := px1Limits(t)
	l.FeeCapSat = 5000
	day := px1TestDay(px1Now)
	in := func(amount, feeLimit, fee int64) SpendIntent {
		return SpendIntent{GrantID: l.GrantID, Recipient: px1AllowA, AmountSat: amount, FeeLimitSat: feeLimit, FeeSat: fee, Day: day}
	}
	c := NewCapChecker()
	empty := fixedLedger{day: day}
	for _, x := range []struct {
		name   string
		intent SpendIntent
		ledger fixedLedger
		want   string
	}{
		{"fee-over-limit", in(1000, 2000, 2001), empty, CodeFeeLimit},
		{"fee-zero", in(1000, 2000, 0), empty, CodeFeeLimit},
		{"fee-at-limit", in(1000, 2000, 2000), empty, ""},
		{"fee-over-cap", in(1000, 9000, 5001), empty, CodeFeeCapExceeded},
		{"fee-at-cap", in(1000, 9000, 5000), empty, ""},
		{"transfer-plus-one", in(95001, 9000, 5000), empty, CodeTransferCapExceeded},
		{"transfer-exact", in(95000, 9000, 5000), empty, ""},
		{"total-plus-one", in(48001, 9000, 2000), fixedLedger{spent: 450000, day: day}, CodeTotalBudgetExceeded},
		{"total-exact", in(48000, 9000, 2000), fixedLedger{spent: 450000, day: day}, ""},
		{"day-plus-one", in(48001, 9000, 2000), fixedLedger{spent: 250000, dayUsed: 250000, dayCount: 1, day: day}, CodeDayCapExceeded},
		{"day-exact", in(48000, 9000, 2000), fixedLedger{spent: 250000, dayUsed: 250000, dayCount: 1, day: day}, ""},
		{"count-full", in(1000, 9000, 2000), fixedLedger{spent: 9000, dayUsed: 9000, dayCount: 5, day: day}, CodeDayCountExceeded},
	} {
		t.Run(x.name, func(t *testing.T) { wantCode(t, x.name, c.CheckPostPlan(l, x.intent, x.ledger), x.want) })
	}
}

// Claim: an intent that cannot belong to the limits (nil ledger, other grant, malformed day, out-of-range amount or fee limit) refuses STATE_UNAVAILABLE before any cap; the valid neighbour is accepted.
func TestPX1CheckIntentInvariants(t *testing.T) {
	l := px1Limits(t)
	day := px1TestDay(px1Now)
	ok := SpendIntent{GrantID: l.GrantID, Recipient: px1AllowA, AmountSat: 1000, FeeLimitSat: 1000, Day: day}
	c := NewCapChecker()
	wantCode(t, "neighbour", c.CheckPrePlan(l, ok, fixedLedger{day: day}), "")
	// A slice, not a map: the cases run in this fixed order, so the first
	// failing case (and the plant marker that names it) is deterministic.
	for _, entry := range []struct {
		name string
		f    func(*SpendIntent)
	}{
		{"other-grant", func(s *SpendIntent) { s.GrantID = strings.Repeat("b", 64) }},
		{"empty-day", func(s *SpendIntent) { s.Day = "" }},
		{"bad-day", func(s *SpendIntent) { s.Day = "2026-11-31" }},
		{"long-day", func(s *SpendIntent) { s.Day = "2026-11-07T00" }},
		{"zero-amount", func(s *SpendIntent) { s.AmountSat = 0 }},
		{"fee-limit", func(s *SpendIntent) { s.FeeLimitSat = 0 }},
	} {
		x := ok
		entry.f(&x)
		wantCode(t, entry.name, c.CheckPrePlan(l, x, fixedLedger{day: day}), "STATE_UNAVAILABLE")
		x.FeeSat = 1
		wantCode(t, entry.name+" post", c.CheckPostPlan(l, x, fixedLedger{day: day}), "STATE_UNAVAILABLE")
	}
	wantCode(t, "nil-ledger", c.CheckPrePlan(l, ok, nil), "STATE_UNAVAILABLE")
}

// Claim (T1, unit layer): an allow-listed spend at exactly transfer_cap fee-inclusive (amount + actual fee == cap) executes once, appends reserve then complete with the UTC day and a debit equal to the cap, and broadcasts exactly the planned transaction.
func TestPX1WalletSpendAtTransferCap(t *testing.T) {
	l := newPX1Lab(t, px1TermsAllow(), px1Operator(), 500000, px1ExecutorKey)
	r, raw := l.request(px1AllowA, 100000-l.chain.fee, l.chain.fee, 1)
	got := l.spend(r, raw, nil)
	if got.Status != "executed" || got.Reason != "EXECUTED" || got.Reserved != 100000 || got.Phase != "complete" {
		t.Fatalf("want executed at cap got %+v", got)
	}
	if l.kinds() != "reserve,complete" || len(l.chain.sent) != 1 || l.chain.sent[0] != got.TxID {
		t.Fatalf("journal/broadcast: %s %v", l.kinds(), l.chain.sent)
	}
	rec := l.journal.records[0]
	if rec.Day != px1TestDay(px1Now) || rec.Fee != l.chain.fee || rec.Reserved != 100000 || rec.Action != "spend" || rec.TxID != got.TxID || len(rec.Inputs) != 1 || rec.Created != px1Now-10 {
		t.Fatalf("reserve record: %+v", rec)
	}
	ledger, e := l.w.PX1Ledger()
	if e != nil || ledger.SpendUsed(l.grant.ID) != 100000 {
		t.Fatal("ledger debit", e)
	}
	if used, count := ledger.DayUsage(l.grant.ID, px1TestDay(px1Now)); used != 100000 || count != 1 {
		t.Fatal("day bucket", used, count)
	}
}

// Claim (T2, unit layer): one atom over the transfer cap (amount + fee_limit) refuses TRANSFER_CAP_EXCEEDED with no node call, no kernel call, no record and no broadcast; the at-cap neighbour executes.
func TestPX1WalletTransferCapOver(t *testing.T) {
	l := newPX1Lab(t, px1TermsAllow(), px1Operator(), 500000, px1ExecutorKey)
	r, raw := l.request(px1AllowA, 100000-l.chain.fee+1, l.chain.fee, 1)
	got := l.spend(r, raw, nil)
	if got.Status != "refused" || got.Reason != CodeTransferCapExceeded {
		t.Fatalf("want %s got %+v", CodeTransferCapExceeded, got)
	}
	if len(l.chain.calls) != 0 || l.auth.calls != 0 {
		t.Fatalf("pre-plan refusal reached the node: %v kernel=%d", l.chain.calls, l.auth.calls)
	}
	l.noEffect(t, "over cap")
	r, raw = l.request(px1AllowA, 100000-l.chain.fee, l.chain.fee, 2)
	if got = l.spend(r, raw, nil); got.Status != "executed" {
		t.Fatalf("neighbour: %+v", got)
	}
}

// Claim (T4, unit layer): after retained debits the next spend whose amount (pre-plan) or amount + fee (post-plan) exceeds the remaining total budget refuses TOTAL_BUDGET_EXCEEDED without a reservation or broadcast; a spend that exactly exhausts the budget executes.
func TestPX1WalletTotalBudget(t *testing.T) {
	terms := px1TermsAllow()
	terms.TransferCap, terms.DayCap, terms.SpendCap, terms.DayCountCap = 100000, 120000, 120000, 10
	op := px1Operator()
	l := newPX1Lab(t, terms, op, 120000, px1ExecutorKey)
	fee := l.chain.fee
	r, raw := l.request(px1AllowA, 100000-fee, fee, 1)
	if got := l.spend(r, raw, nil); got.Status != "executed" {
		t.Fatal(got)
	}
	l.chain.coins = l.chain.coins[1:] // the first coin is now a retained input
	// 20000 remain. Pre-plan: amount alone over the remainder.
	r, raw = l.request(px1AllowB, 20001, fee, 2)
	if got := l.spend(r, raw, nil); got.Reason != CodeTotalBudgetExceeded {
		t.Fatalf("pre-plan: want %s got %+v", CodeTotalBudgetExceeded, got)
	}
	// Post-plan: the amount fits, amount + actual fee does not.
	r, raw = l.request(px1AllowB, 20000-fee+1, fee, 3)
	if got := l.spend(r, raw, nil); got.Reason != CodeTotalBudgetExceeded {
		t.Fatalf("post-plan: want %s got %+v", CodeTotalBudgetExceeded, got)
	}
	if l.kinds() != "reserve,complete" || len(l.chain.sent) != 1 {
		t.Fatalf("refusal left an effect: %s", l.kinds())
	}
	r, raw = l.request(px1AllowB, 20000-fee, fee, 4)
	if got := l.spend(r, raw, nil); got.Status != "executed" || got.Reserved != 20000 {
		t.Fatalf("exhausting neighbour: %+v", got)
	}
}

// Claim (T4): a grant without a budget (budget 0) and terms v2 refuses CONTRACT_BUDGET in the wallet with no node call; the funded grant executes.
func TestPX1WalletBudgetAbsent(t *testing.T) {
	l := newPX1Lab(t, px1TermsAllow(), px1Operator(), 500000, px1ExecutorKey)
	l.auth.grant.Budget = 0
	r, raw := l.request(px1AllowA, 50000, 3000, 1)
	if got := l.spend(r, raw, nil); got.Reason != CodeContractBudget || len(l.chain.calls) != 0 {
		t.Fatalf("want %s got %+v calls=%v", CodeContractBudget, got, l.chain.calls)
	}
	l.auth.grant.Budget = 500000
	if got := l.spend(r, raw, nil); got.Status != "executed" {
		t.Fatalf("neighbour: %+v", got)
	}
}

// Claim (T12, unit layer): a second instance with its own receipt key and a fresh journal, given the same grant and terms, refuses TERMS_EXECUTOR_MISMATCH with no node call; the named executor executes.
func TestPX1WalletSecondInstance(t *testing.T) {
	second := newPX1Lab(t, px1TermsAllow(), px1Operator(), 500000, px1AllowKeyX(t, 8))
	r, raw := second.request(px1AllowA, 50000, 3000, 1)
	if got := second.spend(r, raw, nil); got.Reason != CodeTermsExecutorMismatch || len(second.chain.calls) != 0 {
		t.Fatalf("want %s got %+v", CodeTermsExecutorMismatch, got)
	}
	second.noEffect(t, "second instance")
	first := newPX1Lab(t, px1TermsAllow(), px1Operator(), 500000, px1ExecutorKey)
	if got := first.spend(r, raw, nil); got.Status != "executed" {
		t.Fatalf("named executor: %+v", got)
	}
}

// Claim (T15, wallet layer): a request to a non-listed address refuses ADDRESS_NOT_ALLOWED before any node call; the listed neighbour executes.
func TestPX1WalletRecipientNotListed(t *testing.T) {
	l := newPX1Lab(t, px1TermsAllow(), px1Operator(), 500000, px1ExecutorKey)
	r, raw := l.request(px1Outsider, 50000, 3000, 1)
	if got := l.spend(r, raw, nil); got.Reason != CodeAddressNotAllowed || len(l.chain.calls) != 0 {
		t.Fatalf("want %s got %+v", CodeAddressNotAllowed, got)
	}
	r, raw = l.request(px1AllowB, 50000, 3000, 2)
	if got := l.spend(r, raw, nil); got.Status != "executed" {
		t.Fatalf("neighbour: %+v", got)
	}
}

// Claim (Q2 phase 2, wallet layer): with an operator that allows any mode, the attached wallet's network-pinned checker executes a spend to a canonical main P2PKH that no list names, and refuses a regtest P2PKH and a P2SH encoding with ADDRESS_NOT_ALLOWED before any node call and with no record. Limit: unit layer with fakes; it proves the wallet uses a checker that admits any-mode recipients of its own network only.
func TestPX1WalletRecipientAnyMode(t *testing.T) {
	op := px1Operator()
	op.AllowAnyRecipients = true
	l := newPX1Lab(t, px1TermsAny(), op, 100000, px1ExecutorKey)
	v := px1AddressVariants(t)
	for i, a := range []string{testAddress(5), v["p2sh-main"]} {
		r, raw := l.request(a, 20000, 3000, byte(1+i))
		if got := l.spend(r, raw, nil); got.Reason != CodeAddressNotAllowed || len(l.chain.calls) != 0 {
			t.Fatalf("any-mode off-network %s: want %s got %+v calls=%v", a, CodeAddressNotAllowed, got, l.chain.calls)
		}
		l.noEffect(t, "any-mode off-network")
	}
	r, raw := l.request(px1Outsider, 20000, 3000, 9)
	if got := l.spend(r, raw, nil); got.Status != "executed" || got.Reason != "EXECUTED" {
		t.Fatalf("any-mode main outsider: want executed got %+v", got)
	}
}

// Claim: the canary outpoint and every input of a retained record are never planned (PLAN_RESERVED_INPUT, no reservation); once the wallet offers a free coin the same request executes.
func TestPX1WalletPlanExclusions(t *testing.T) {
	l := newPX1Lab(t, px1TermsAllow(), px1Operator(), 500000, px1ExecutorKey)
	canaryKey, _ := testKey(20)
	l.chain.coins = append([]fakeCoin{{point: px1Operator().Canary.Outpoint, value: 10000, key: canaryKey}}, l.chain.coins...)
	r, raw := l.request(px1AllowA, 50000, 3000, 1)
	if got := l.spend(r, raw, nil); got.Reason != CodePlanReservedInput {
		t.Fatalf("canary: want %s got %+v", CodePlanReservedInput, got)
	}
	l.noEffect(t, "canary")
	l.chain.coins = l.chain.coins[1:]
	if got := l.spend(r, raw, nil); got.Status != "executed" {
		t.Fatalf("free coin neighbour: %+v", got)
	}
	// The first coin is now held by a retained record; fund offers it again.
	r, raw = l.request(px1AllowA, 50000, 3000, 2)
	if got := l.spend(r, raw, nil); got.Reason != CodePlanReservedInput {
		t.Fatalf("retained input: want %s got %+v", CodePlanReservedInput, got)
	}
	l.chain.coins = l.chain.coins[1:]
	if got := l.spend(r, raw, nil); got.Status != "executed" {
		t.Fatalf("second free coin: %+v", got)
	}
}

// Claim: an actual fee above the effective fee cap (operator max_fee below the terms fee cap) refuses FEE_CAP_EXCEEDED before signing and without a reservation; at the cap it executes.
func TestPX1WalletFeeCap(t *testing.T) {
	op := px1Operator()
	op.MaxFeeSat = 2259
	l := newPX1Lab(t, px1TermsAllow(), op, 500000, px1ExecutorKey)
	r, raw := l.request(px1AllowA, 50000, 3000, 1)
	if got := l.spend(r, raw, nil); got.Reason != CodeFeeCapExceeded {
		t.Fatalf("want %s got %+v", CodeFeeCapExceeded, got)
	}
	if l.chain.called("signrawtransactionwithwallet") != 0 {
		t.Fatal("signed before fee cap")
	}
	l.noEffect(t, "fee cap")
	l.chain.fee = 2259
	if got := l.spend(r, raw, nil); got.Status != "executed" {
		t.Fatalf("neighbour: %+v", got)
	}
}

// Claim (T6, unit layer): a seal spent before the request refuses at kernel check #1 without a plan; a seal spend observed after the reservation (check #4) refuses with the debit retained (refuse-retained) and zero broadcasts.
func TestPX1WalletSealSpent(t *testing.T) {
	l := newPX1Lab(t, px1TermsAllow(), px1Operator(), 500000, px1ExecutorKey)
	l.auth.checks = []error{fail("GRANT_SEAL_SPENT")}
	r, raw := l.request(px1AllowA, 50000, 3000, 1)
	if got := l.spend(r, raw, nil); got.Reason != "GRANT_SEAL_SPENT" || l.chain.called("fundrawtransaction") != 0 {
		t.Fatalf("before request: %+v", got)
	}
	l.noEffect(t, "seal before")
	// Checks #1, #2 (plan) and #3 pass; #4 after the reservation fails.
	l.auth.calls, l.auth.checks = 0, []error{nil, nil, nil, fail("GRANT_SEAL_SPENT")}
	r, raw = l.request(px1AllowA, 50000, 3000, 2)
	got := l.spend(r, raw, func(Record) error { return nil })
	if got.Status != "refused" || got.Reason != "GRANT_SEAL_SPENT" || len(l.chain.sent) != 0 || l.chain.called("sendrawtransaction") != 0 {
		t.Fatalf("after reservation: %+v sent=%d", got, len(l.chain.sent))
	}
	ledger, _ := l.w.PX1Ledger()
	if l.kinds() != "reserve,refuse-retained" || ledger.SpendUsed(l.grant.ID) != got.Reserved || got.Reserved < 50001 {
		t.Fatalf("debit not retained: %s %d", l.kinds(), got.Reserved)
	}
	// Neighbour: a live seal (kernel script exhausted) executes on a free coin.
	l.chain.coins = l.chain.coins[1:]
	r, raw = l.request(px1AllowA, 50000, 3000, 3)
	if ok := l.spend(r, raw, func(Record) error { return nil }); ok.Status != "executed" || len(l.chain.sent) != 1 {
		t.Fatalf("live seal neighbour: %+v", ok)
	}
}

// Claim (T7, unit layer): created_at at not_after refuses REQUEST_TIME before any node call (created_at one second earlier passes binding); expiry between reservation and broadcast refuses GRANT_EXPIRED with the debit retained.
func TestPX1WalletExpiredWindow(t *testing.T) {
	l := newPX1Lab(t, px1TermsAllow(), px1Operator(), 500000, px1ExecutorKey)
	r, raw := l.request(px1AllowA, 50000, 3000, 1)
	bind := func(created, now int64) error {
		lim := px1Limits(t)
		lim.GrantID = l.grant.ID
		return bindG2Request(l.grant, lim, r, l.grant.Grantee, created, now, l.w.g2.checker)
	}
	wantCode(t, "at not_after", bind(l.grant.NotAfter, l.grant.NotAfter+5), "REQUEST_TIME")
	wantCode(t, "before not_before", bind(l.grant.NotBefore-1, px1Now), "REQUEST_TIME")
	wantCode(t, "future created", bind(px1Now+1, px1Now), "REQUEST_TIME")
	wantCode(t, "last second", bind(l.grant.NotAfter-1, l.grant.NotAfter+5), "")
	l.now = l.grant.NotAfter + 10
	if got := l.spend(r, raw, nil); got.Reason != "REQUEST_TIME" || len(l.chain.calls) != 0 {
		t.Fatalf("expired request: %+v", got)
	}
	l.now = px1Now
	l.auth.calls, l.auth.checks = 0, []error{nil, nil, nil, fail("GRANT_EXPIRED")}
	got := l.spend(r, raw, func(Record) error { return nil })
	if got.Status != "refused" || got.Reason != "GRANT_EXPIRED" || len(l.chain.sent) != 0 || l.kinds() != "reserve,refuse-retained" {
		t.Fatalf("expiry after reservation: %+v %s", got, l.kinds())
	}
}

// Claim: replay of the same wallet nonce returns the stored phase with DURABLE_RESERVATION_NO_RETRY and no second broadcast; the same nonce with other request bytes refuses NONCE_CONFLICT.
func TestPX1WalletReplay(t *testing.T) {
	l := newPX1Lab(t, px1TermsAllow(), px1Operator(), 500000, px1ExecutorKey)
	r, raw := l.request(px1AllowA, 50000, 3000, 1)
	first := l.spend(r, raw, nil)
	again := l.spend(r, raw, nil)
	if first.Status != "executed" || again.Status != "already-executed" || again.Reason != "DURABLE_RESERVATION_NO_RETRY" || again.TxID != first.TxID || len(l.chain.sent) != 1 {
		t.Fatalf("replay: %+v %+v", first, again)
	}
	r.Amount++
	if got := l.spend(r, canonical(r), nil); got.Reason != "NONCE_CONFLICT" || len(l.chain.sent) != 1 {
		t.Fatalf("conflict: %+v", got)
	}
}

// Claim: a broadcast error leaves the request uncertain (uncertain record, debit retained); a failing service reservation leaves it uncertain without a broadcast; a failing complete record reports JOURNAL_WRITE_UNCERTAIN.
func TestPX1WalletUncertainOutcomes(t *testing.T) {
	l := newPX1Lab(t, px1TermsAllow(), px1Operator(), 500000, px1ExecutorKey)
	r, raw := l.request(px1AllowA, 50000, 3000, 9)
	if ok := l.spend(r, raw, nil); ok.Status != "executed" {
		t.Fatalf("neighbour: %+v", ok)
	}
	l.chain.coins = l.chain.coins[1:]
	l.journal.records = nil
	l.chain.sent = nil
	l.chain.coins = append(l.chain.coins, fakeCoin{point: fakePoint(7), value: 1000000, key: l.chain.coins[0].key}, fakeCoin{point: fakePoint(8), value: 1000000, key: l.chain.coins[0].key})
	l.chain.sendErr = errors.New("RPC_DOWN")
	r, raw = l.request(px1AllowA, 50000, 3000, 1)
	if got := l.spend(r, raw, nil); got.Status != "uncertain" || got.Reason != "BROADCAST_UNCERTAIN" || l.kinds() != "reserve,uncertain" {
		t.Fatalf("broadcast: %+v %s", got, l.kinds())
	}
	ledger, _ := l.w.PX1Ledger()
	if ledger.UncertainSat(l.grant.ID) != 50000+l.chain.fee {
		t.Fatal("uncertain debit")
	}
	l.chain.sendErr = nil
	l.chain.coins = l.chain.coins[1:]
	r, raw = l.request(px1AllowA, 50000, 3000, 2)
	if got := l.spend(r, raw, func(Record) error { return errors.New("x") }); got.Reason != "SERVICE_RESERVATION_UNCERTAIN" || len(l.chain.sent) != 0 {
		t.Fatalf("service reservation: %+v", got)
	}
	l.chain.coins = l.chain.coins[1:]
	l.journal.failKind = RecordComplete
	r, raw = l.request(px1AllowA, 50000, 3000, 3)
	if got := l.spend(r, raw, nil); got.Status != "uncertain" || got.Reason != "JOURNAL_WRITE_UNCERTAIN" || len(l.chain.sent) != 1 {
		t.Fatalf("complete record: %+v", got)
	}
	if got := l.spend(r, raw, nil); got.Reason != "JOURNAL_WRITE_UNCERTAIN" {
		t.Fatalf("poisoned journal must refuse: %+v", got)
	}
}

// Claim: under G2 a single-use grant, a terms v1 object, terms whose hash differs from contract_sha256 and a use proof all refuse before any node call; the standing grant with matching terms v2 executes.
func TestPX1WalletTermsGate(t *testing.T) {
	l := newPX1Lab(t, px1TermsAllow(), px1Operator(), 500000, px1ExecutorKey)
	r, raw := l.request(px1AllowA, 50000, 3000, 1)
	run := func(label, want string, terms []byte, use string) {
		t.Helper()
		l.w.mu.Lock()
		got := l.w.executeAuthenticated(nil, []byte("grant"), terms, r, l.grant.Grantee, px1Now-10, raw, use, nil)
		l.w.mu.Unlock()
		if got.Reason != want || len(l.chain.calls) != 0 {
			t.Fatalf("%s: want %s got %+v", label, want, got)
		}
	}
	l.auth.grant.Kind = "single-use"
	run("single-use", CodeSingleUseDisabled, l.terms, "")
	l.auth.grant.Kind = ""
	run("use proof", CodeSingleUseDisabled, l.terms, strings.Repeat("d", 64))
	run("hash", "CONTRACT_HASH", canonical(px1TermsAny()), "")
	v1 := canonical(Terms{Version: 1, Recipients: []string{px1AllowA}, SpendCap: 1000})
	l.auth.grant.Contract = Hash(v1)
	run("terms v1", CodeTermsVersionRequired, v1, "")
	l.auth.grant.Contract = Hash(l.terms)
	if got := l.spend(r, raw, nil); got.Status != "executed" {
		t.Fatalf("neighbour: %+v", got)
	}
}

// Claim: the G2 budget read reports the folded debits, day bucket and the effective caps, and the W2-shaped budget projects the same totals.
func TestPX1WalletBudgetRead(t *testing.T) {
	l := newPX1Lab(t, px1TermsAllow(), px1Operator(), 500000, px1ExecutorKey)
	r, raw := l.request(px1AllowA, 50000, 3000, 1)
	if got := l.spend(r, raw, nil); got.Status != "executed" {
		t.Fatal(got)
	}
	cost := 50000 + l.chain.fee
	l.w.mu.Lock()
	b, e := l.w.px1Budget(nil, []byte("grant"), l.terms)
	l.w.mu.Unlock()
	want := BudgetV2{GrantID: l.grant.ID, TotalCap: 500000, SpendCap: 500000, SpendReserved: cost, TotalRemaining: 500000 - cost, TransferCap: 100000, Day: px1TestDay(px1Now), DayUsed: cost, DayCount: 1, DayRemaining: 300000 - cost, DayCountRemaining: 4, Uncertain: 0, Live: true, Reason: "LIVE"}
	if e != nil || b != want {
		t.Fatalf("budget v2:\n got %+v\nwant %+v %v", b, want, e)
	}
	w2, e := l.w.Budget(nil, []byte("grant"), l.terms)
	if e != nil || w2.TotalRemaining != 500000-cost || w2.SpendReserved != cost || w2.Total != 500000 || !w2.Live {
		t.Fatalf("budget w2 projection: %+v %v", w2, e)
	}
	var unattached Wallet
	if _, e = unattached.px1Budget(nil, nil, nil); e == nil {
		t.Fatal("W2 wallet has no G2 budget")
	}
}

// Claim: attachment fails closed: an invalid operator block, an invalid receipt key, a journal whose header differs (another layer, or the same header without or with another receipt key), a W2 journal with records, a canary watcher that does not exclude the canary, and a second attach all refuse and leave the wallet without a G2 profile; the fake-backed attach succeeds, opens the wallet-layer journal under a header carrying the receipt key, and pins the cap checker to the wallet's own network (main and regtest).
func TestPX1WalletAttach(t *testing.T) {
	fresh := func() *Wallet {
		return &Wallet{config: Config{Network: "main", Genesis: su.MainGenesis, StateDir: "/state/wallet"}, state: state{Version: 1, Binding: Hash([]byte("w")), Records: []Record{}}}
	}
	// want is the header px1Attach must open fresh()'s journal with.
	want := JournalHeaderV2{Version: 2, Layer: JournalLayerWallet, Binding: px1WalletBinding(Hash([]byte("w")), px1ExecutorKey), ReceiptKey: px1ExecutorKey}
	onDisk := func(mutate func(*JournalHeaderV2)) func(*fakeJournal) px1Deps {
		return func(j *fakeJournal) px1Deps {
			j.header = want
			mutate(&j.header)
			return px1FakeDeps(j)
		}
	}
	for name, c := range map[string]struct {
		op   G2OperatorConfig
		key  string
		deps func(*fakeJournal) px1Deps
		pre  func(*Wallet)
		want string
	}{
		"operator": {G2OperatorConfig{}, px1ExecutorKey, px1FakeDeps, nil, "SERVICE_CONFIG"},
		"key":      {px1Operator(), "00", px1FakeDeps, nil, "SERVICE_CONFIG"},
		"header": {px1Operator(), px1ExecutorKey, func(j *fakeJournal) px1Deps {
			j.header = JournalHeaderV2{Version: 2, Layer: JournalLayerService, Binding: strings.Repeat("0", 64)}
			return px1FakeDeps(j)
		}, nil, CodeJournalSegment},
		// A journal written before amendment 1 (no receipt_key) or under another
		// reconcile key is never adopted: the receipt key is pinned on disk.
		"header-keyless":    {px1Operator(), px1ExecutorKey, onDisk(func(h *JournalHeaderV2) { h.ReceiptKey = "" }), nil, CodeJournalSegment},
		"header-other-key":  {px1Operator(), px1ExecutorKey, onDisk(func(h *JournalHeaderV2) { h.ReceiptKey = px1AllowKeyX(t, 8) }), nil, CodeJournalSegment},
		"header-same-exact": {px1Operator(), px1ExecutorKey, onDisk(func(*JournalHeaderV2) {}), nil, ""},
		"w2-records":        {px1Operator(), px1ExecutorKey, px1FakeDeps, func(w *Wallet) { w.state.Records = []Record{testRecord()} }, "SERVICE_PROFILE"},
		"canary": {px1Operator(), px1ExecutorKey, func(j *fakeJournal) px1Deps {
			d := px1FakeDeps(j)
			d.canary = func(su.Node, CanaryConfig) (Canary, error) { return fakeCanary{fakePoint(9)}, nil }
			return d
		}, nil, "SERVICE_CONFIG"},
	} {
		t.Run(name, func(t *testing.T) {
			w := fresh()
			if c.pre != nil {
				c.pre(w)
			}
			e := w.px1AttachWith(c.op, c.key, c.deps(&fakeJournal{}))
			wantCode(t, name, e, c.want)
			if c.want == "" {
				if w.g2 == nil || w.PX1Journal() == nil {
					t.Fatal("accepted attach left the wallet on W2")
				}
				return
			}
			if w.g2 != nil || w.PX1Journal() != nil {
				t.Fatal("refused attach left a G2 profile")
			}
		})
	}
	w := fresh()
	j := &fakeJournal{}
	wantCode(t, "fake attach", w.px1AttachWith(px1Operator(), px1ExecutorKey, px1FakeDeps(j)), "")
	if w.PX1Journal() != JournalV2(j) || j.header.Binding != px1WalletBinding(w.state.Binding, px1ExecutorKey) || j.header.Layer != JournalLayerWallet {
		t.Fatal("journal binding")
	}
	if j.header.ReceiptKey != px1ExecutorKey || j.header != want {
		t.Fatalf("journal header receipt key: got %+v want %+v", j.header, want)
	}
	if w.g2.checker != NewCapCheckerFor("main", su.MainGenesis) {
		t.Fatalf("cap checker not pinned to the wallet network: %#v", w.g2.checker)
	}
	wantCode(t, "second attach", w.px1AttachWith(px1Operator(), px1ExecutorKey, px1FakeDeps(j)), "SERVICE_PROFILE")
	if px1WalletBinding(w.state.Binding, px1AllowKeyX(t, 8)) == j.header.Binding {
		t.Fatal("another receipt key must bind another journal")
	}
	reg := fresh()
	reg.config.Network, reg.config.Genesis = "regtest", su.RegtestGenesis
	wantCode(t, "regtest attach", reg.px1AttachWith(px1Operator(), px1ExecutorKey, px1FakeDeps(&fakeJournal{})), "")
	if reg.g2.checker != NewCapCheckerFor("regtest", su.RegtestGenesis) {
		t.Fatalf("cap checker not pinned to the regtest wallet network: %#v", reg.g2.checker)
	}
}

// Claim: the production attach (px1Attach) consumes exactly the frozen S2/S3
// entry points (OpenJournalV2, FoldLedgerV2, UTCDay, NewCanary) and returns the
// first failing one's refusal unchanged, leaving the wallet on W2. A wallet
// with no observer node makes the product canary constructor refuse, so the
// attach must report that same code; the fake-backed neighbour attaches.
// Limit: the code itself belongs to S3 (PX1_NOT_IMPLEMENTED while the S3
// stubs are present, RPC_UNAVAILABLE once NewCanary is implemented); this test
// pins only S1's propagation, so it holds on S1's branch and composed with S3.
func TestPX1WalletAttachProductDeps(t *testing.T) {
	d := px1ProductDeps()
	for _, f := range []struct {
		name       string
		got, would any
	}{
		{"openJournal", d.openJournal, OpenJournalV2},
		{"fold", d.fold, FoldLedgerV2},
		{"day", d.day, UTCDay},
		{"canary", d.canary, NewCanary},
	} {
		if f.got == nil || reflect.ValueOf(f.got).Pointer() != reflect.ValueOf(f.would).Pointer() {
			t.Fatalf("product deps: %s is not the frozen entry point", f.name)
		}
	}
	op := px1Operator()
	_, canaryErr := NewCanary(nil, op.Canary)
	if canaryErr == nil {
		t.Fatal("precondition: the product canary constructor admitted a wallet without an observer node")
	}
	w := &Wallet{config: Config{Network: "main", Genesis: su.MainGenesis, StateDir: t.TempDir()}, state: state{Version: 1, Binding: Hash([]byte("w")), Records: []Record{}}}
	wantCode(t, "product deps", w.px1Attach(op, px1ExecutorKey), canaryErr.Error())
	if w.g2 != nil || w.PX1Journal() != nil {
		t.Fatal("refused product attach left a G2 profile")
	}
	wantCode(t, "fake neighbour", w.px1AttachWith(op, px1ExecutorKey, px1FakeDeps(&fakeJournal{})), "")
	if w.g2 == nil {
		t.Fatal("fake neighbour left the wallet on W2")
	}
}

// Claim: an unattached (W2) wallet exposes no journal and refuses a ledger; an attached wallet exposes its journal and the folded ledger.
func TestPX1WalletSeams(t *testing.T) {
	var w Wallet
	if w.PX1Journal() != nil {
		t.Fatal("W2 journal seam")
	}
	if _, e := w.PX1Ledger(); e == nil || e.Error() != "STATE_UNAVAILABLE" {
		t.Fatal("W2 ledger seam", e)
	}
	l := newPX1Lab(t, px1TermsAllow(), px1Operator(), 500000, px1ExecutorKey)
	if l.w.PX1Journal() == nil {
		t.Fatal("G2 journal seam")
	}
	if v, e := l.w.PX1Ledger(); e != nil || v == nil {
		t.Fatal("G2 ledger seam", e)
	}
	l.journal.poisoned = true
	if _, e := l.w.PX1Ledger(); e == nil {
		t.Fatal("poisoned journal must refuse the ledger")
	}
}

// Claim: the g2 member is optional: without it the service config bytes (and so the W2 binding) are unchanged; with a valid block validServiceConfig accepts; an invalid block refuses SERVICE_CONFIG; LoadServiceConfig's closed schema admits the member.
func TestPX1ServiceConfigG2(t *testing.T) {
	root := privateDir(t)
	run := root + "/run"
	if e := os.Mkdir(run, 0750); e != nil {
		t.Fatal(e)
	}
	os.Chmod(run, 0750)
	_, pub := testKey(2)
	c := ServiceConfig{Version: 1, Service: WalletServiceID, Socket: run + "/wallet.sock", SocketGID: uint32(os.Getgid()), PeerUID: uint32(os.Getuid() + 1), Grantee: pub, SkewSeconds: 60, TimeoutSeconds: 2, StateDir: root + "/state", WalletConfig: root + "/wallet.json", ReceiptKeyFile: root + "/receipt.key"}
	if strings.Contains(string(canonical(c)), `"g2"`) {
		t.Fatal("nil g2 must not change W2 bytes")
	}
	wantCode(t, "w2", validServiceConfig(c), "")
	op := px1Operator()
	c.G2 = &op
	wantCode(t, "g2", validServiceConfig(c), "")
	bad := px1Operator()
	bad.AllowSingleUse = true
	c.G2 = &bad
	wantCode(t, "g2 single-use", validServiceConfig(c), "SERVICE_CONFIG")
	c.G2 = &op
	path := root + "/service.json"
	writeInstalled(t, path, canonical(c))
	got, e := LoadServiceConfig(path)
	if e != nil || got.G2 == nil || *got.G2 != op {
		t.Fatal("g2 member load", e)
	}
}
