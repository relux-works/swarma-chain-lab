package wallet

// PX1 FROZEN CONTRACT, stream S3 surface: payment tracker, canary, float
// monitor, startup reconciliation, alerts and the status projection.
// Implementation lives in px1_observe.go (owner S3). Nothing here grants or
// restores spending authority: tracker states and alerts are observability
// only (Q12), and debits are released only by a ReconcileRecordV2 (Q8).

import (
	"context"

	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// Tracker states of a payment registered at step 23: an executed spend, or
// one whose outcome is uncertain, a rejected broadcast included (§3.4 state
// machine).
const (
	TrackPending    = "pending"    // registered (executed or uncertain), fewer than ConfirmationsK confirmations
	TrackConfirmed  = "confirmed"  // depth >= ConfirmationsK on the own node
	TrackConflicted = "conflicted" // absent from mempool+chain for ConflictBlocksN blocks, or an input spent by another tx
)

// TrackedPayment is one payment under observation: an executed spend, or one
// whose outcome is uncertain, a rejected broadcast included.
type TrackedPayment struct {
	GrantID       string     `json:"grant_id"`
	Nonce         string     `json:"nonce"` // derived 64-hex wallet-layer nonce
	TxID          string     `json:"txid"`
	Inputs        []su.Point `json:"inputs"`
	ReserveSeq    uint64     `json:"reserve_seq"`   // wallet-layer Seq of the reserve record
	BroadcastTip  int64      `json:"broadcast_tip"` // own-node height at broadcast
	State         string     `json:"state"`         // Track* constant
	Confirmations int64      `json:"confirmations"`
	MissingSince  int64      `json:"missing_since"` // first height the tx was absent, or 0
}

// TrackerConfig comes from G2OperatorConfig.
type TrackerConfig struct {
	ConfirmationsK  int // DefaultConfirmationsK
	ConflictBlocksN int // DefaultConflictBlocksN
}

// TrackTransition is one state change produced by Tick. The caller appends it
// as a RecordTrack wallet-layer record and raises AlertPaymentConflicted for
// conflicted transitions.
type TrackTransition struct {
	Payment TrackedPayment
	Record  TrackRecordV2
}

// Tracker follows executed payments, and payments whose outcome is uncertain
// (a rejected broadcast included), on the executor's own node through the
// observer route only (no wallet or broadcast route). It only observes: it
// never resends a transaction and never releases a debit.
type Tracker interface {
	// Enqueue registers a payment after its reserve record and its terminal
	// outcome record are durable (step 23): complete for an executed spend,
	// uncertain for a broadcast the node rejected or one that may have
	// happened. A spend left uncertain without an outcome record (that append
	// failed, or the request stopped before its broadcast) is registered on
	// its durable reserve record alone.
	Enqueue(p TrackedPayment) error
	// Tick reads the own node once and returns transitions since the last tick.
	Tick(ctx context.Context) ([]TrackTransition, error)
	// Snapshot returns every tracked payment, ordered by ReserveSeq.
	Snapshot() []TrackedPayment
}

// NewTracker signature (px1_observe.go). Startup reloads tracked payments by
// folding the reserve, outcome and track records of the wallet-layer journal;
// a request whose refuse-retained record is durable is not reloaded.
var _ func(node su.Node, cfg TrackerConfig, wallet JournalV2) (Tracker, error) = NewTracker

// Canary states.
const (
	CanaryUnspent = "unspent"
	CanarySpent   = "spent"
	CanaryUnknown = "unknown" // own node could not answer; never treated as unspent for admission
)

// Canary watches the configured canary outpoint (Prize-A pattern). A spent
// canary means wallet compromise: the caller poisons the service and every
// later spend refuses FLOAT_CANARY_SPENT (T14).
type Canary interface {
	// Excluded reports whether p must never be planned (PLAN_RESERVED_INPUT).
	Excluded(p su.Point) bool
	// Check reads gettxout (mempool included) on the own node.
	Check(ctx context.Context) (string, error)
}

// NewCanary signature (px1_observe.go).
var _ func(node su.Node, cfg CanaryConfig) (Canary, error) = NewCanary

// FloatReading is one float observation against the operator ceilings.
type FloatReading struct {
	BalanceSat  int64  `json:"balance_sat"`
	MaxFloatSat int64  `json:"max_float_sat"`
	LowFloatSat int64  `json:"low_float_sat"`
	State       string `json:"state"` // "ok" | "low" | "excess" | "unknown"
}

// FloatMonitor reports the hot wallet balance; it never moves funds.
type FloatMonitor interface {
	Check(ctx context.Context) (FloatReading, error)
}

// NewFloatMonitor signature (px1_observe.go). wallet is the w1-wallet route
// (getbalances only).
var _ func(wallet su.Node, maxFloatSat, lowFloatSat int64) (FloatMonitor, error) = NewFloatMonitor

// StartupReconciler compares the hot wallet's listtransactions sends with the
// wallet-layer journal txids. Any wallet send unknown to the journal (out-of-
// band spend or journal rollback) refuses STATE_RECONCILE_REQUIRED (T13).
type StartupReconciler interface {
	Reconcile(ctx context.Context, wallet JournalV2) error
}

// NewStartupReconciler signature (px1_observe.go).
var _ func(walletRoute su.Node) (StartupReconciler, error) = NewStartupReconciler

// Alert is one bounded alert (codes Alert*); Detail is a bounded code or a
// txid/outpoint, never a key, password, request body or terms body.
type Alert struct {
	Code   string `json:"code"`
	At     int64  `json:"at"`
	Detail string `json:"detail"`
}

// AlertSink receives alerts. PX1 ships a journald-line sink; transport to
// Matrix or the public page is deployment work.
type AlertSink interface {
	Raise(a Alert)
}

// NewLogAlertSink signature (px1_observe.go): bounded single-line log sink.
var _ func(write func(line string)) AlertSink = NewLogAlertSink

// StatusProjectionVersion is the "v" member of StatusProjectionV1.
const StatusProjectionVersion = 1

// StatusProjectionV1 is the operator status document (§3.7). It is built from
// journals plus the last cached tracker/canary/float/seal observations: a
// status request makes no node call and no journal write. Field order is the
// canonical JSON order; golden fixture testdata/px1/status-projection-v1.json,
// JSON Schema testdata/px1/status-projection-v1.schema.json. Every list is
// present ([] when empty, never null) and sorted as documented.
type StatusProjectionV1 struct {
	Version     int            `json:"v"`
	Service     string         `json:"service"` // WalletServiceID
	Network     string         `json:"network"`
	ReceiptKey  string         `json:"receipt_key"`  // x-only, verifies every published receipt
	GeneratedAt int64          `json:"generated_at"` // executor clock
	Poisoned    bool           `json:"poisoned"`
	Tip         StatusTip      `json:"tip"`
	Grants      []StatusGrant  `json:"grants"` // sorted by grant_id
	Payments    StatusPayments `json:"payments"`
	Float       FloatReading   `json:"float"`
	Canary      StatusCanary   `json:"canary"`
	Journal     StatusJournal  `json:"journal"`
	Refusals    []StatusCount  `json:"refusals"` // terminal refusal counts, sorted by code
	Alerts      []Alert        `json:"alerts"`   // last 64, oldest first
}

// StatusTip is the last own-node tip the service observed.
type StatusTip struct {
	Height     int64  `json:"height"`
	Hash       string `json:"hash"`
	ObservedAt int64  `json:"observed_at"`
}

// StatusGrant is the per-grant budget view (same numbers as the budget read).
type StatusGrant struct {
	GrantID           string          `json:"grant_id"`
	TotalCapSat       int64           `json:"total_cap_sat"`
	SpendCapSat       int64           `json:"spend_cap_sat"`
	TransferCapSat    int64           `json:"transfer_cap_sat"`
	DayCapSat         int64           `json:"day_cap_sat"`
	DayCountCap       int             `json:"day_count_cap"`
	SpentSat          int64           `json:"spent_sat"`    // complete records
	ReservedSat       int64           `json:"reserved_sat"` // all retained debits
	UncertainSat      int64           `json:"uncertain_sat"`
	ReleasedSat       int64           `json:"released_sat"` // reconcile records
	TotalRemainingSat int64           `json:"total_remaining_sat"`
	Day               string          `json:"day"`
	DayUsedSat        int64           `json:"day_used_sat"`
	DayCount          int             `json:"day_count"`
	DayRemainingSat   int64           `json:"day_remaining_sat"`
	DayCountRemaining int             `json:"day_count_remaining"`
	Seal              StatusSealCheck `json:"seal"`
}

// StatusSealCheck is the last rental.Check verdict for the grant.
type StatusSealCheck struct {
	Verdict string `json:"verdict"` // "live" | "closed" | "pending" | "unknown"
	Reason  string `json:"reason"`  // bounded code, e.g. LIVE or GRANT_SEAL_SPENT
	Height  int64  `json:"height"`
	At      int64  `json:"at"`
}

// StatusPayments summarizes tracker states; Items is sorted by reserve_seq.
type StatusPayments struct {
	Pending    int              `json:"pending"`
	Confirmed  int              `json:"confirmed"`
	Conflicted int              `json:"conflicted"`
	Items      []TrackedPayment `json:"items"`
}

// StatusCanary is the last canary observation.
type StatusCanary struct {
	Outpoint su.Point `json:"outpoint"`
	ValueSat int64    `json:"value_sat"`
	State    string   `json:"state"` // Canary* constant
	At       int64    `json:"at"`
}

// StatusJournal is the spend capacity view of the service layer.
type StatusJournal struct {
	Admitted      int `json:"admitted"`
	SpendCapacity int `json:"spend_capacity"`
	PercentUsed   int `json:"percent_used"` // floor(100*admitted/capacity)
	Segments      int `json:"segments"`
}

// StatusCount is one refusal code counter.
type StatusCount struct {
	Code  string `json:"code"`
	Count int    `json:"count"`
}

// StatusInputs are the cached observations ProjectStatus combines with the
// two journals. Callers fill them under the service mutex from the last tick.
type StatusInputs struct {
	Service    JournalV2
	Wallet     JournalV2
	Limits     []EffectiveLimits
	Seals      map[string]StatusSealCheck // by grant_id
	Tip        StatusTip
	Tracked    []TrackedPayment
	Float      FloatReading
	Canary     StatusCanary
	Alerts     []Alert
	ReceiptKey string
	Network    string
	Poisoned   bool
	Now        int64
}

// ProjectStatus signature (px1_observe.go): pure projection, no node call.
var _ func(in StatusInputs) (StatusProjectionV1, error) = ProjectStatus

// Operator status socket placement (freeze amendment 1, A8; the slot AF_UNIX
// confinement design), frozen. The status socket has its own runtime
// directory, owned by the service UID with the operator group, mode 0750; it
// is never bound into a slot. The agent-facing /run/swarma-wallet holds only
// wallet.sock. No agent-facing path shares a directory with the status socket.
const (
	StatusSocketDir     = "/run/swarma-wallet-status"
	StatusSocketPath    = StatusSocketDir + "/status.sock"
	StatusSocketDirMode = 0o750 // owner service UID, group operator group
	StatusSocketMode    = 0o660 // group operator group
)

// StatusSocketRequest is the only request accepted on the read-only operator
// status socket (StatusSocketPath, group = operator group, mode 0660, 4-byte
// big-endian length frame, one request per connection). The response is
// canonical(StatusProjectionV1) in the same framing.
type StatusSocketRequest struct {
	Version int    `json:"v"`      // 1
	Action  string `json:"action"` // "status"
}

// ServeStatus signature (px1_observe.go): serves one connection. The source
// callback must not touch the node or write a journal.
var _ func(ctx context.Context, conn StatusConn, source func() (StatusProjectionV1, error)) error = ServeStatus

// StatusConn is the minimal connection surface ServeStatus needs (net.Conn
// satisfies it); tests use an in-memory pipe.
type StatusConn interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	Close() error
}
