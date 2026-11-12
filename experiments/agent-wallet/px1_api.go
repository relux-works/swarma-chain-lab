package wallet

// PX1 FROZEN CONTRACT (owner S0, see PX1-INTERFACES.md). Every *_api.go file
// under the px1_ prefix is frozen: streams implement the stubs in their own
// files and never change a type, field order, JSON name, code or signature
// declared here without a freeze amendment PR reviewed by all stream owners.

import "errors"

// ErrNotImplemented is the single sentinel every PX1 stub returns until its
// owning stream lands. Its text is a bounded wire code, so a stub reached by a
// G2-profile request fails closed as a refusal instead of an effect. No W2
// (non-G2) path calls a PX1 stub.
var ErrNotImplemented = errors.New("PX1_NOT_IMPLEMENTED")

// PX1 refusal and alert codes. Codes already emitted by W2 keep their existing
// spelling and are not repeated here (see G2-PAYMENT-EXECUTOR-v1 §3.3).
const (
	// Terms v2 (stream S1).
	CodeTermsVersionRequired  = "TERMS_VERSION_REQUIRED"  // terms v1 under a G2 config
	CodeTermsExecutorMismatch = "TERMS_EXECUTOR_MISMATCH" // executor_key != own receipt key
	CodeTermsNetwork          = "TERMS_NETWORK"           // terms network/genesis != service pins
	CodeTermsRecipientMode    = "TERMS_RECIPIENT_MODE"    // recipient_mode "any" while the operator allows only "allow" (Q2)
	CodeContractSchema        = "CONTRACT_SCHEMA"         // existing code, reused by the v2 parser
	CodeContractBudget        = "CONTRACT_BUDGET"         // existing code, reused by the v2 parser
	CodeContractRecipients    = "CONTRACT_RECIPIENTS"     // existing code, duplicate recipient

	// Spend caps (stream S1).
	CodeSingleUseDisabled   = "SINGLE_USE_DISABLED" // single-use grant under the G2 profile (Q7)
	CodeAmountDust          = "AMOUNT_DUST"         // amount_sat < DustLimitSat
	CodeTransferCapExceeded = "TRANSFER_CAP_EXCEEDED"
	CodeDayCapExceeded      = "DAY_CAP_EXCEEDED"
	CodeDayCountExceeded    = "DAY_COUNT_EXCEEDED"
	CodeTotalBudgetExceeded = "TOTAL_BUDGET_EXCEEDED" // existing code
	CodeSpendBudgetExceeded = "SPEND_BUDGET_EXCEEDED" // existing code
	CodeFeeLimit            = "FEE_LIMIT"             // existing code: actual fee > request fee_limit_sat
	CodeFeeCapExceeded      = "FEE_CAP_EXCEEDED"      // actual fee > effective fee cap
	CodeAddressNotAllowed   = "ADDRESS_NOT_ALLOWED"   // existing code
	CodePlanReservedInput   = "PLAN_RESERVED_INPUT"   // existing path, now also the canary outpoint

	// Journal v2, day buckets and clock (stream S2).
	CodeServiceJournalLimit    = "SERVICE_JOURNAL_LIMIT"   // existing code, journal v2 spend capacity exhausted
	CodeJournalCapacity        = "JOURNAL_CAPACITY_CONFIG" // startup: configured capacity < RequiredSpendCapacity
	CodeJournalSegment         = "JOURNAL_SEGMENT"         // startup: segment chain, order or binding broken
	CodeClockRollback          = "CLOCK_ROLLBACK"          // now < journal last_time
	CodeReadRateLimited        = "READ_RATE_LIMITED"       // balance/history/budget over the per-grantee hourly limit
	CodeReconcileAuthorization = "RECONCILE_AUTHORIZATION" // reconcile signature absent, unbound or not by JournalHeaderV2.ReceiptKey (amendment 1)

	// Tracker, canary, float and reconciliation (stream S3).
	CodeFloatCanarySpent       = "FLOAT_CANARY_SPENT"       // canary outpoint spent: service poisons itself
	CodeStateReconcileRequired = "STATE_RECONCILE_REQUIRED" // startup: wallet sends unknown to the journal
	CodeReconcileRateLimited   = "RECONCILE_RATE_LIMITED"   // operator release faster than ReconcileMinIntervalSeconds
	CodeReconcileEvidence      = "RECONCILE_EVIDENCE"       // release record without matching chain evidence
)

// Alert codes raised through AlertSink (§3.7). The set is closed for PX1.
const (
	AlertCanarySpent       = "ALERT_CANARY_SPENT"
	AlertPaymentConflicted = "ALERT_PAYMENT_CONFLICTED"
	AlertUncertainVerdict  = "ALERT_UNCERTAIN_VERDICT"
	AlertJournalHighWater  = "ALERT_JOURNAL_HIGH_WATER" // spend journal >= JournalAlertPercent
	AlertClockRollback     = "ALERT_CLOCK_ROLLBACK"
	AlertSealClosed        = "ALERT_SEAL_CLOSED"
	AlertFloatLow          = "ALERT_FLOAT_LOW"
	AlertFloatExcess       = "ALERT_FLOAT_EXCESS"
)

// Fixed PX1 constants. Operator values may lower, never raise, a terms value.
const (
	DustLimitSat                int64 = 546  // step 13: amount_sat >= DustLimitSat
	MaxDayCountCap                    = 1000 // terms v2 day_count_cap upper bound
	DayBasisUTCCalendar               = "utc-calendar"
	RecipientModeAllow                = "allow"
	RecipientModeAny                  = "any"
	MaxTermsRecipients                = 32
	TermsV2Version                    = 2
	DefaultConfirmationsK             = 2    // Q12: alerting only, never authority
	DefaultConflictBlocksN            = 6    // tracker: absent for N blocks => conflicted
	DefaultReadRatePerHour            = 60   // reads per grantee per hour
	JournalAlertPercent               = 80   // ALERT_JOURNAL_HIGH_WATER threshold
	JournalCapacityHeadroom           = 64   // RequiredSpendCapacity additive headroom
	ReconcileMinIntervalSeconds int64 = 3600 // at most one operator release per hour
)
