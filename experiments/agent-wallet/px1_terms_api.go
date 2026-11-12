package wallet

// PX1 FROZEN CONTRACT, stream S1 surface: terms v2, operator ceilings, caps
// and the executor binding. Implementation lives in px1_terms.go (owner S1).

import su "github.com/relux-works/swarma-chain-lab/experiments/single-use"

// TermsV2 is the wallet.nmc terms object committed by a v3 grant's
// contract_sha256 (G2-PAYMENT-EXECUTOR-v1 §3.2). The struct field order IS the
// canonical JSON member order (Go json.Marshal, compact, no trailing newline):
//
//	{"version":2,"service":"wallet.nmc","executor_key":"<64 hex>","network":"main",
//	 "genesis":"<64 hex>","recipient_mode":"allow","recipients":["N..."],
//	 "spend_cap_sat":1000000,"transfer_cap_sat":100000,"day_cap_sat":300000,
//	 "day_count_cap":10,"fee_cap_sat":100000,"day_basis":"utc-calendar"}
//
// The bytes are stored as <sha256>.json in the service-owned objects
// directory, and SHA256(bytes) must equal the grant's contract_sha256. Golden
// fixtures: testdata/px1/terms-v2-allow.json and terms-v2-any.json. Every cap
// is fee-inclusive: cost = amount_sat + actual fee.
type TermsV2 struct {
	Version       int      `json:"version"`          // == TermsV2Version
	Service       string   `json:"service"`          // == WalletServiceID
	ExecutorKey   string   `json:"executor_key"`     // x-only receipt pubkey of THIS agent-walletd
	Network       string   `json:"network"`          // == service pin
	Genesis       string   `json:"genesis"`          // == service pin
	RecipientMode string   `json:"recipient_mode"`   // RecipientModeAllow | RecipientModeAny
	Recipients    []string `json:"recipients"`       // allow: 1..32 sorted unique P2PKH; any: [] (never null)
	SpendCap      int64    `json:"spend_cap_sat"`    // total pay cap over the grant window
	TransferCap   int64    `json:"transfer_cap_sat"` // per transfer
	DayCap        int64    `json:"day_cap_sat"`      // per UTC calendar day
	DayCountCap   int      `json:"day_count_cap"`    // transfers per UTC calendar day, 1..MaxDayCountCap
	FeeCap        int64    `json:"fee_cap_sat"`      // per transfer actual fee, 1..MaxFee
	DayBasis      string   `json:"day_basis"`        // == DayBasisUTCCalendar (Q4)
}

// TermsV2Pins are the service-side values ParseTermsV2 binds against.
// GrantBudget is the v3 grant's BudgetSat() (absent budget = 0, which makes
// terms v2 unusable: CONTRACT_BUDGET).
type TermsV2Pins struct {
	Network     string
	Genesis     string
	ExecutorKey string // x-only hex of this instance's receipt public key
	GrantBudget int64
}

// ParseTermsV2 signature (implemented in px1_terms.go):
//
//	func ParseTermsV2(raw []byte, pins TermsV2Pins) (TermsV2, error)
//
// Refusal order and codes are frozen; the first failing row wins:
//
//  1. len(raw) == 0 or > 65536, or not a JSON object             CONTRACT_SCHEMA
//  2. member "version" == 1 (a terms v1 object)                   TERMS_VERSION_REQUIRED
//  3. not SJ1-strict, unknown/duplicate member, or the bytes are
//     not byte-equal to canonical(TermsV2)                        CONTRACT_SCHEMA
//  4. version != 2, service != "wallet.nmc", day_basis != "utc-calendar",
//     executor_key not a valid x-only key                         CONTRACT_SCHEMA
//  5. network/genesis != pins                                      TERMS_NETWORK
//  6. executor_key != pins.ExecutorKey                             TERMS_EXECUTOR_MISMATCH
//  7. recipient_mode not allow|any; recipients null; allow with
//     0 or >32 or unsorted; any with a non-empty list             CONTRACT_SCHEMA
//  8. allow-list member not a P2PKH address of the pinned network  ADDRESS_* (existing addressScriptForNetwork codes)
//  9. duplicate allow-list member                                  CONTRACT_RECIPIENTS
//  10. not 0 < transfer_cap <= day_cap <= spend_cap <= GrantBudget,
//     day_count_cap not in 1..1000, fee_cap not in 1..MaxFee      CONTRACT_BUDGET
var _ func([]byte, TermsV2Pins) (TermsV2, error) = ParseTermsV2

// G2OperatorConfig is the "g2" member of the agent-walletd ServiceConfig
// (operator-owned, root:service 0640, hash-pinned by the deploy manifest).
// Its presence selects the G2 profile; absence keeps W2 behaviour unchanged.
// Field order is the canonical JSON order. Values only LOWER terms values
// (LIP-0008 operator-ceiling rule); they never raise one.
type G2OperatorConfig struct {
	RequireTermsVersion  int          `json:"require_terms_version"`  // must be 2
	AllowSingleUse       bool         `json:"allow_single_use"`       // must be false in PX1 (Q7)
	AllowAnyRecipients   bool         `json:"allow_any_recipients"`   // false at launch (Q2): terms "any" => TERMS_RECIPIENT_MODE
	MaxTransferSat       int64        `json:"max_transfer_sat"`       // ceiling on transfer_cap_sat
	MaxDaySat            int64        `json:"max_day_sat"`            // ceiling on day_cap_sat
	MaxDayCount          int          `json:"max_day_count"`          // ceiling on day_count_cap
	MaxFeeSat            int64        `json:"max_fee_sat"`            // ceiling on fee_cap_sat
	MaxFloatSat          int64        `json:"max_float_sat"`          // float ceiling, reporting only (never pulls funds)
	LowFloatSat          int64        `json:"low_float_sat"`          // float low-water mark for ALERT_FLOAT_LOW
	Canary               CanaryConfig `json:"canary"`                 // excluded from planning, watched every tick
	ConfirmationsK       int          `json:"confirmations_k"`        // DefaultConfirmationsK (Q12)
	ConflictBlocksN      int          `json:"conflict_blocks_n"`      // DefaultConflictBlocksN
	ReadRatePerHour      int          `json:"read_rate_per_hour"`     // DefaultReadRatePerHour
	JournalSpendCapacity int          `json:"journal_spend_capacity"` // >= RequiredSpendCapacity(...) for the configured grant
}

// CanaryConfig names the one canary UTXO in the hot wallet (§3.6).
type CanaryConfig struct {
	Outpoint su.Point `json:"outpoint"`
	ValueSat int64    `json:"value_sat"`
}

// ValidateG2OperatorConfig signature (px1_terms.go): structural and range
// validation of the operator block. Refuses SERVICE_CONFIG on any violation,
// including require_terms_version != 2 and allow_single_use == true.
var _ func(G2OperatorConfig) error = ValidateG2OperatorConfig

// EffectiveLimits are min(terms value, operator ceiling), computed once per
// request after ParseTermsV2. Recipients and mode come from terms only.
type EffectiveLimits struct {
	GrantID        string
	TotalCapSat    int64 // grant budget (v3 budget, fee-inclusive by executor rule)
	SpendCapSat    int64 // terms spend_cap_sat
	TransferCapSat int64
	DayCapSat      int64
	DayCountCap    int
	FeeCapSat      int64
	RecipientMode  string
	Recipients     []string
}

// EffectiveLimitsFor signature (px1_terms.go). Refuses TERMS_RECIPIENT_MODE
// when terms say "any" and the operator does not allow it.
var _ func(Grant, TermsV2, G2OperatorConfig) (EffectiveLimits, error) = EffectiveLimitsFor

// SpendIntent is one spend as seen by the cap checker. Pre-plan (steps 13 and
// 15) FeeSat is 0 and the conservative cost is AmountSat + FeeLimitSat for the
// transfer cap and AmountSat for the cumulative caps. Post-plan (step 17)
// FeeSat is the planned actual fee and every cap uses AmountSat + FeeSat.
type SpendIntent struct {
	GrantID     string
	Recipient   string
	AmountSat   int64
	FeeLimitSat int64
	FeeSat      int64
	Day         string // UTCDay(executor clock) at admission; never the request created_at
}

// CapChecker enforces §3.5 steps 12-17 against effective limits and the
// durable ledger. Every method is pure over its inputs: no node call, no
// write. A nil error means "within limits", never "authorized".
type CapChecker interface {
	// CheckExecutor: terms.executor_key == receiptKey, else TERMS_EXECUTOR_MISMATCH (G-12).
	CheckExecutor(t TermsV2, receiptKey string) error
	// CheckRecipient: allow mode requires membership (ADDRESS_NOT_ALLOWED);
	// any mode admits every canonical P2PKH address of the pinned network.
	CheckRecipient(l EffectiveLimits, address string) error
	// CheckPrePlan: AMOUNT_DUST, TRANSFER_CAP_EXCEEDED (amount+fee_limit),
	// then TOTAL_BUDGET_EXCEEDED, SPEND_BUDGET_EXCEEDED, DAY_CAP_EXCEEDED,
	// DAY_COUNT_EXCEEDED on amount alone, in that order.
	CheckPrePlan(l EffectiveLimits, in SpendIntent, ledger LedgerView) error
	// CheckPostPlan: FEE_LIMIT (fee > fee_limit), FEE_CAP_EXCEEDED,
	// TRANSFER_CAP_EXCEEDED, TOTAL_BUDGET_EXCEEDED, SPEND_BUDGET_EXCEEDED,
	// DAY_CAP_EXCEEDED, DAY_COUNT_EXCEEDED on amount+fee, in that order.
	CheckPostPlan(l EffectiveLimits, in SpendIntent, ledger LedgerView) error
}

// NewCapChecker signature (px1_terms.go).
var _ func() CapChecker = NewCapChecker
