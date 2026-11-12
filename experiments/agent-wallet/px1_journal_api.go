package wallet

// PX1 FROZEN CONTRACT, stream S2 surface: journal v2 (records, append,
// segments, iteration, capacity), the ledger view the cap checker reads, the
// UTC day buckets, the clock-rollback guard and the read limiter.
// Implementation lives in px1_journal.go (owner S2).

import su "github.com/relux-works/swarma-chain-lab/experiments/single-use"

// Journal layers. The wallet layer lives under the wallet config state_dir
// (debits, day, inputs, txid); the service layer lives under the service
// state_dir (admission, receipts, nonces). Each keeps its own durable.Store
// lock exactly as W2 does today; the two are never merged.
const (
	JournalLayerWallet  = "wallet"
	JournalLayerService = "service"
)

// Record kinds. A request's state is the fold of its records in Seq order;
// nothing is ever rewritten or removed (append-only).
//
//	kind             layer    phase after   meaning
//	admit            service  pending       first admission of a spend/receive (step 7)
//	reserve          wallet   reserved      durable debit + day bucket + inputs + plan txid (step 19)
//	service-reserve  service  reserved      durable service reservation (step 20)
//	complete         wallet   complete      sendrawtransaction returned the plan txid (step 23)
//	uncertain        wallet   uncertain     broadcast/journal outcome ambiguous; debit retained
//	refuse-retained  wallet   refused       final check failed after reserve; debit retained
//	terminal         service  terminal      signed receipt stored (replay returns it byte-identical)
//	track            wallet   confirmed|conflicted   tracker observation (alerting only)
//	reconcile        wallet   released      operator release citing chain evidence (Q8)
const (
	RecordAdmit          = "admit"
	RecordReserve        = "reserve"
	RecordServiceReserve = "service-reserve"
	RecordComplete       = "complete"
	RecordUncertain      = "uncertain"
	RecordRefuseRetained = "refuse-retained"
	RecordTerminal       = "terminal"
	RecordTrack          = "track"
	RecordReconcile      = "reconcile"
)

// JournalRecordV2 is one append-only record. Field order is canonical JSON
// order. The common fields are the §3.4 binding set {grant_id, nonce,
// request_hash, action, phase, reserved_sat, fee_sat, day, inputs, txid,
// created, last_time}; exactly one of the optional members may be present and
// only for the kinds listed beside it.
type JournalRecordV2 struct {
	Seq         uint64             `json:"seq"`                 // assigned by Append: previous + 1, from 1
	Kind        string             `json:"kind"`                // Record* constant
	GrantID     string             `json:"grant_id"`            // 64 hex ("" only for receive)
	Nonce       string             `json:"nonce"`               // service layer: 32-hex action nonce; wallet layer: derived 64-hex wallet nonce
	RequestHash string             `json:"request_hash"`        // SHA256 of the canonical request bytes
	Action      string             `json:"action"`              // "spend" | "receive" (reads are never journaled)
	Phase       string             `json:"phase"`               // phase after this record (table above)
	Reserved    int64              `json:"reserved_sat"`        // fee-inclusive debit (reserve onward), else 0
	Fee         int64              `json:"fee_sat"`             // actual plan fee (reserve onward), else 0
	Day         string             `json:"day"`                 // UTCDay of the reservation clock (reserve onward), else ""
	Inputs      []su.Point         `json:"inputs"`              // planned inputs (reserve onward), else [] (never null)
	TxID        string             `json:"txid"`                // plan txid (reserve onward), else ""
	Created     int64              `json:"created"`             // request created_at
	LastTime    int64              `json:"last_time"`           // executor clock at append; non-decreasing across Seq
	Service     *ServiceRecordV2   `json:"service,omitempty"`   // admit, service-reserve, terminal
	Track       *TrackRecordV2     `json:"track,omitempty"`     // track
	Reconcile   *ReconcileRecordV2 `json:"reconcile,omitempty"` // reconcile
}

// ServiceRecordV2 carries the service-layer payload of W2's serviceEntry.
type ServiceRecordV2 struct {
	Request ActionRequest        `json:"request"`
	Peer    PeerIdentity         `json:"peer"`
	Receipt *SignedActionReceipt `json:"receipt,omitempty"` // terminal only
}

// TrackRecordV2 is one tracker transition (stream S3 produces, S2 stores).
type TrackRecordV2 struct {
	State         string `json:"state"`         // TrackConfirmed | TrackConflicted
	Height        int64  `json:"height"`        // own-node tip at observation
	BlockHash     string `json:"block_hash"`    // tip hash at observation
	Confirmations int64  `json:"confirmations"` // >= ConfirmationsK for confirmed
	ConflictTxID  string `json:"conflict_txid"` // spender of a planned input, or ""
}

// ReconcileRecordV2 releases a retained debit (Q8: operator reconciliation
// only, never automatic). It is created by the operator CLI running as the
// service UID, signed by the receipt key over
// SHA256("swarma-wallet-reconcile-v1" || canonical(record with Signature "")),
// rate-limited by ReconcileMinIntervalSeconds, and shown in the status
// projection. ReleasedSat never exceeds the record's retained debit.
type ReconcileRecordV2 struct {
	TargetSeq    uint64 `json:"target_seq"`    // Seq of the reserve record being released
	Evidence     string `json:"evidence"`      // "absent" | "conflict"
	Height       int64  `json:"height"`        // own-node tip height of the evidence
	BlockHash    string `json:"block_hash"`    // own-node tip hash of the evidence
	ConflictTxID string `json:"conflict_txid"` // required for "conflict", else ""
	ReleasedSat  int64  `json:"released_sat"`
	NoteSHA256   string `json:"note_sha256"` // SHA256 of the public operator note
	Signature    string `json:"signature"`   // BIP-340 by the receipt key
}

// JournalHeaderV2 opens every segment. Binding is the W2 binding (hash of
// config + receipt key + wallet binding, RPC passwords cleared); a segment
// whose header differs from the opener's expectation refuses JOURNAL_SEGMENT.
type JournalHeaderV2 struct {
	Version int    `json:"version"` // 2
	Layer   string `json:"layer"`   // JournalLayerWallet | JournalLayerService
	Binding string `json:"binding"` // 64 hex
}

// JournalSegmentV2 is one segment file "journal-v2-%06d.json" holding
// canonical JSON {header, index, prev_sha256, first_seq, records}. Sealed
// segments are immutable; only the active (last) segment is rewritten, always
// through durable.Store.Write (temp file, fsync, rename, directory fsync).
type JournalSegmentV2 struct {
	Header     JournalHeaderV2   `json:"header"`
	Index      int               `json:"index"`       // 1-based, contiguous
	PrevSHA256 string            `json:"prev_sha256"` // SHA256 of the sealed previous segment bytes; 64 zeros for index 1
	FirstSeq   uint64            `json:"first_seq"`
	Records    []JournalRecordV2 `json:"records"`
}

// JournalLimitsV2 are fixed at open. Capacity rules (frozen):
//   - SpendCapacity counts admit records only (spend and receive); reads never
//     consume capacity. It must be >= RequiredSpendCapacity for every grant the
//     service is configured to serve, else open refuses JOURNAL_CAPACITY_CONFIG.
//   - Admission with admitted == SpendCapacity refuses SERVICE_JOURNAL_LIMIT
//     before any effect; follow-up records of an admitted request are always
//     accepted (a reservation is never stranded by capacity).
//   - A segment seals when it reaches SegmentMaxRecords or the next append would
//     exceed SegmentMaxBytes of canonical JSON (<= 65536, the durable read cap).
//   - Usage at or above JournalAlertPercent of SpendCapacity raises
//     ALERT_JOURNAL_HIGH_WATER once per crossing.
type JournalLimitsV2 struct {
	SpendCapacity     int
	SegmentMaxRecords int // default 128
	SegmentMaxBytes   int // default 61440
}

// JournalUsageV2 is the capacity view used by admission and status.
type JournalUsageV2 struct {
	Admitted      int    `json:"admitted"`
	SpendCapacity int    `json:"spend_capacity"`
	Segments      int    `json:"segments"`
	LastSeq       uint64 `json:"last_seq"`
	LastTime      int64  `json:"last_time"`
}

// JournalV2 is the append-only, segmented, fsynced journal of one layer.
// Callers serialize access with the existing ActionService.mu / Wallet.mu.
type JournalV2 interface {
	Header() JournalHeaderV2
	// Append assigns Seq, enforces LastTime >= previous LastTime
	// (CLOCK_ROLLBACK), the kind/layer/phase table and capacity, then makes the
	// record durable before returning. A write error poisons the journal:
	// every later Append refuses JOURNAL_WRITE_UNCERTAIN.
	Append(rec JournalRecordV2) (JournalRecordV2, error)
	// Iterate visits records with Seq >= from in order; fn's error stops it.
	Iterate(from uint64, fn func(JournalRecordV2) error) error
	Usage() JournalUsageV2
	Poisoned() bool
	Close()
}

// OpenJournalV2 signature (px1_journal.go): opens or creates the layer journal
// under dir, verifies every segment's header, index, prev_sha256 chain and
// Seq contiguity (JOURNAL_SEGMENT), and takes the durable lock lockName.
var _ func(dir, lockName string, h JournalHeaderV2, l JournalLimitsV2) (JournalV2, error) = OpenJournalV2

// RequiredSpendCapacity signature (px1_journal.go):
// dayCountCap * UTCDaysSpanned(notBefore, notAfter) + JournalCapacityHeadroom.
var _ func(dayCountCap int, notBefore, notAfter int64) int = RequiredSpendCapacity

// UTCDay signature (px1_journal.go): "2006-01-02" of a Unix time in UTC (Q4).
var _ func(unix int64) string = UTCDay

// UTCDaysSpanned signature (px1_journal.go): the number of UTC calendar days
// intersecting [notBefore, notAfter); 0 when notAfter <= notBefore.
var _ func(notBefore, notAfter int64) int = UTCDaysSpanned

// LedgerView is the folded wallet-layer journal the cap checker reads. Debits
// are retained for reserve, uncertain, refuse-retained, complete and track
// records, and only a reconcile record releases them.
type LedgerView interface {
	// SpendUsed is the fee-inclusive retained debit of grantID.
	SpendUsed(grantID string) int64
	// DayUsage applies the signer-service rule: a record counts toward day D if
	// it is non-terminal (reserved or uncertain) or its reservation day is D.
	DayUsage(grantID, day string) (usedSat int64, count int)
	// UncertainSat is the retained debit of uncertain records of grantID.
	UncertainSat(grantID string) int64
	// InputReserved reports whether any retained record planned p.
	InputReserved(p su.Point) bool
}

// FoldLedgerV2 signature (px1_journal.go): folds a wallet-layer journal.
var _ func(JournalV2) (LedgerView, error) = FoldLedgerV2

// ClockGuard implements CLOCK_ROLLBACK (signer-service engine.go pattern).
type ClockGuard interface {
	// Now reads the clock and refuses CLOCK_ROLLBACK when it is below LastTime.
	Now() (int64, error)
	// LastTime is the highest time observed (journal last_time at startup).
	LastTime() int64
}

// NewClockGuard signature (px1_journal.go). lastTime is the journal's
// Usage().LastTime; startup with clock() < lastTime refuses CLOCK_ROLLBACK.
var _ func(clock func() int64, lastTime int64) (ClockGuard, error) = NewClockGuard

// ReadLimiter bounds balance/history/budget reads per grantee (T17). Reads are
// never journaled; admitted reads land in a rolling in-memory audit tail.
type ReadLimiter interface {
	// Admit returns READ_RATE_LIMITED above perHour reads in the trailing hour.
	Admit(grantee string, now int64) error
	// Tail returns the last audit entries, newest last, at most ReadAuditTailSize.
	Tail() []ReadAuditEntry
}

// ReadAuditTailSize bounds the rolling read audit tail.
const ReadAuditTailSize = 1024

// ReadAuditEntry is one admitted or refused read (no request body).
type ReadAuditEntry struct {
	At      int64  `json:"at"`
	Grantee string `json:"grantee"`
	Action  string `json:"action"`
	Verdict string `json:"verdict"` // "executed" | "refused"
	Reason  string `json:"reason"`
}

// NewReadLimiter signature (px1_journal.go).
var _ func(perHour int) ReadLimiter = NewReadLimiter
