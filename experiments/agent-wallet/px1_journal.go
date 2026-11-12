package wallet

// PX1 stream S2 implementation (owner S2): journal v2 (append-only segments
// with a SHA-256 chain), capacity, the folded ledger and UTC day buckets, the
// clock-rollback guard and the per-grantee read limiter. The frozen contract
// is px1_journal_api.go; FORMAT-JOURNAL-V2.md documents the record rules.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strings"
	"sync"
	"time"

	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/durable"
)

const (
	px1SegmentPrefix               = "journal-v2-"
	px1SegmentSuffix               = ".json"
	px1DefaultSegmentRecords       = 128
	px1DefaultSegmentBytes         = 61440
	px1MinSegmentBytes             = 4096
	px1MaxSegmentBytes             = 65536 // durable.Store read and write cap
	px1MaxPlanInputs               = 16    // plan.go: at most 16 P2PKH inputs
	px1MaxMoney              int64 = 21000000 * 100000000
	px1SecondsPerDay         int64 = 86400
	px1ZeroHash                    = "0000000000000000000000000000000000000000000000000000000000000000"
)

// Bounded refusal codes local to the journal engine (never wire-visible
// beyond safeCode, all upper-case).
const (
	codeJournalRecord     = "JOURNAL_RECORD"          // record violates the kind/layer/phase/transition table
	codeJournalRecordSize = "JOURNAL_RECORD_SIZE"     // a single record cannot fit an empty segment
	codeJournalUncertain  = "JOURNAL_WRITE_UNCERTAIN" // a write failed: poisoned
	codeJournalClosed     = "STATE_UNAVAILABLE"       // Append after Close
	codeJournalLayer      = "JOURNAL_LAYER"           // ledger fold of a non-wallet journal
)

// px1Kind is one row of the frozen kind table (px1_journal_api.go).
type px1Kind struct {
	layer  string
	phases []string
}

var px1Kinds = map[string]px1Kind{
	RecordAdmit:          {JournalLayerService, []string{"pending"}},
	RecordReserve:        {JournalLayerWallet, []string{"reserved"}},
	RecordServiceReserve: {JournalLayerService, []string{"reserved"}},
	RecordComplete:       {JournalLayerWallet, []string{"complete"}},
	RecordUncertain:      {JournalLayerWallet, []string{"uncertain"}},
	RecordRefuseRetained: {JournalLayerWallet, []string{"refused"}},
	RecordTerminal:       {JournalLayerService, []string{"terminal"}},
	RecordTrack:          {JournalLayerWallet, []string{TrackConfirmed, TrackConflicted}},
	RecordReconcile:      {JournalLayerWallet, []string{"released"}},
}

// px1Next is the transition table: the phase of a request before the record
// (the empty phase means "no record yet") and the kinds allowed to follow it.
var px1Next = map[string]map[string][]string{
	JournalLayerService: {
		"":         {RecordAdmit},
		"pending":  {RecordServiceReserve, RecordTerminal},
		"reserved": {RecordTerminal},
	},
	JournalLayerWallet: {
		"":              {RecordReserve},
		"reserved":      {RecordComplete, RecordUncertain, RecordRefuseRetained, RecordTrack, RecordReconcile},
		"uncertain":     {RecordTrack, RecordReconcile},
		"refused":       {RecordReconcile},
		"complete":      {RecordTrack, RecordReconcile},
		TrackConfirmed:  {RecordTrack, RecordReconcile},
		TrackConflicted: {RecordTrack, RecordReconcile},
	},
}

// px1Request is the folded state of one request key inside one journal.
type px1Request struct {
	first JournalRecordV2 // admit (service) or reserve (wallet) record
	phase string
	// released is the sum of reconcile ReleasedSat (wallet layer only).
	released int64
}

// px1JournalState is the validated in-memory image of the segments. It is
// rebuilt at open and extended only after a durable write succeeds.
type px1JournalState struct {
	layer         string
	records       []JournalRecordV2
	requests      map[string]*px1Request
	admitted      int
	lastSeq       uint64
	lastTime      int64
	lastReconcile int64 // LastTime of the latest reconcile record, or -1
}

func newPX1JournalState(layer string) *px1JournalState {
	return &px1JournalState{layer: layer, records: []JournalRecordV2{}, requests: map[string]*px1Request{}, lastReconcile: -1}
}

func px1Key(layer string, r JournalRecordV2) string {
	if layer == JournalLayerService {
		return r.Nonce
	}
	return r.GrantID + "/" + r.Nonce
}

func px1Day(s string) bool {
	if len(s) != 10 {
		return false
	}
	t, e := time.Parse("2006-01-02", s)
	return e == nil && t.Format("2006-01-02") == s
}

func px1Inputs(in []su.Point) bool {
	if len(in) < 1 || len(in) > px1MaxPlanInputs {
		return false
	}
	seen := map[su.Point]bool{}
	for _, p := range in {
		if !hexN(p.TxID, 32) || seen[p] {
			return false
		}
		seen[p] = true
	}
	return true
}

func px1SamePoints(a, b []su.Point) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// px1PlanZero reports a record without plan fields (admit, receive).
func px1PlanZero(r JournalRecordV2) bool {
	return r.Reserved == 0 && r.Fee == 0 && r.Day == "" && len(r.Inputs) == 0 && r.TxID == ""
}

// px1PlanValid reports a well-formed plan (reserve onward).
func px1PlanValid(r JournalRecordV2) bool {
	return r.Reserved > r.Fee && r.Fee >= 1 && r.Reserved <= px1MaxMoney && hexN(r.TxID, 32) && px1Inputs(r.Inputs)
}

func px1SamePlan(a, b JournalRecordV2) bool {
	return a.Reserved == b.Reserved && a.Fee == b.Fee && a.Day == b.Day && a.TxID == b.TxID && px1SamePoints(a.Inputs, b.Inputs)
}

// check validates rec (Seq already assigned) against the table, the request's
// folded phase and the journal clock. It never mutates the state.
func (s *px1JournalState) check(rec JournalRecordV2) error {
	if rec.LastTime < s.lastTime {
		return fail(CodeClockRollback)
	}
	kind, ok := px1Kinds[rec.Kind]
	if !ok || kind.layer != s.layer || rec.Seq != s.lastSeq+1 || rec.LastTime < 0 || rec.Created < 0 || rec.Inputs == nil {
		return fail(codeJournalRecord)
	}
	phaseOK := false
	for _, p := range kind.phases {
		phaseOK = phaseOK || rec.Phase == p
	}
	if !phaseOK || !hexN(rec.RequestHash, 32) {
		return fail(codeJournalRecord)
	}
	// Exactly the optional member of the kind, and only that one.
	service := rec.Kind == RecordAdmit || rec.Kind == RecordServiceReserve || rec.Kind == RecordTerminal
	if (rec.Service != nil) != service || (rec.Track != nil) != (rec.Kind == RecordTrack) || (rec.Reconcile != nil) != (rec.Kind == RecordReconcile) {
		return fail(codeJournalRecord)
	}
	if s.layer == JournalLayerService {
		if !hexN(rec.Nonce, 16) || (rec.Action != "spend" && rec.Action != "receive") || (rec.Action == "spend") != hexN(rec.GrantID, 32) || (rec.Action == "receive" && rec.GrantID != "") {
			return fail(codeJournalRecord)
		}
		q := rec.Service.Request
		if (rec.Service.Receipt != nil) != (rec.Kind == RecordTerminal) || q.Nonce != rec.Nonce || q.Action != rec.Action || q.Grant.ID != rec.GrantID || q.CreatedAt != rec.Created || Hash(canonical(q)) != rec.RequestHash {
			return fail(codeJournalRecord)
		}
		// Service-layer plan fields mirror the wallet reservation (spend) or
		// stay empty; the day bucket authority is the wallet layer only.
		if !px1PlanZero(rec) && (rec.Kind == RecordAdmit || rec.Action != "spend" || !px1PlanValid(rec) || (rec.Day != "" && !px1Day(rec.Day))) {
			return fail(codeJournalRecord)
		}
	} else {
		if !hexN(rec.Nonce, 32) || !hexN(rec.GrantID, 32) || rec.Action != "spend" || !px1PlanValid(rec) || rec.Day != UTCDay(s.firstTime(rec)) {
			return fail(codeJournalRecord)
		}
	}
	prior := s.requests[px1Key(s.layer, rec)]
	phase := ""
	if prior != nil {
		phase = prior.phase
	}
	allowed := false
	for _, k := range px1Next[s.layer][phase] {
		allowed = allowed || k == rec.Kind
	}
	if !allowed {
		return fail(codeJournalRecord)
	}
	if prior != nil {
		f := prior.first
		if f.RequestHash != rec.RequestHash || f.Action != rec.Action || f.Created != rec.Created {
			return fail(codeJournalRecord)
		}
		if s.layer == JournalLayerWallet && !px1SamePlan(f, rec) {
			return fail(codeJournalRecord)
		}
		if s.layer == JournalLayerService && (string(canonical(f.Service.Request)) != string(canonical(rec.Service.Request)) || f.Service.Peer != rec.Service.Peer) {
			return fail(codeJournalRecord)
		}
	}
	switch rec.Kind {
	case RecordTrack:
		t := rec.Track
		if t.State != rec.Phase || t.Height < 0 || !hexN(t.BlockHash, 32) || t.Confirmations < 0 || (t.State == TrackConfirmed && t.Confirmations < 1) || (t.ConflictTxID != "" && !hexN(t.ConflictTxID, 32)) {
			return fail(codeJournalRecord)
		}
	case RecordReconcile:
		c := rec.Reconcile
		retained := prior.first.Reserved - prior.released
		if c.TargetSeq != prior.first.Seq || (c.Evidence != "absent" && c.Evidence != "conflict") || c.Height < 0 || !hexN(c.BlockHash, 32) ||
			(c.Evidence == "conflict") != hexN(c.ConflictTxID, 32) || (c.Evidence == "absent" && c.ConflictTxID != "") ||
			c.ReleasedSat < 1 || c.ReleasedSat > retained || !hexN(c.NoteSHA256, 32) || !hexN(c.Signature, 64) {
			return fail(codeJournalRecord)
		}
		if s.lastReconcile >= 0 && rec.LastTime < s.lastReconcile+ReconcileMinIntervalSeconds {
			return fail(CodeReconcileRateLimited)
		}
	}
	return nil
}

// firstTime is the reservation clock of a wallet request: the reserve
// record's own LastTime, or the stored reserve record's for a follow-up.
func (s *px1JournalState) firstTime(rec JournalRecordV2) int64 {
	if p := s.requests[px1Key(s.layer, rec)]; p != nil {
		return p.first.LastTime
	}
	return rec.LastTime
}

// apply extends the state with an already checked record.
func (s *px1JournalState) apply(rec JournalRecordV2) {
	key := px1Key(s.layer, rec)
	p := s.requests[key]
	if p == nil {
		p = &px1Request{first: rec}
		s.requests[key] = p
	}
	p.phase = rec.Phase
	if rec.Kind == RecordAdmit {
		s.admitted++
	}
	if rec.Kind == RecordReconcile {
		p.released += rec.Reconcile.ReleasedSat
		s.lastReconcile = rec.LastTime
	}
	s.records = append(s.records, rec)
	s.lastSeq = rec.Seq
	s.lastTime = rec.LastTime
}

// px1Journal is the durable JournalV2 implementation.
type px1Journal struct {
	mu        sync.Mutex
	store     *durable.Store
	header    JournalHeaderV2
	limits    JournalLimitsV2
	state     *px1JournalState
	index     int    // active segment index (1-based)
	active    []byte // exact bytes of the active segment as last written/read
	firstSeq  uint64 // first_seq of the active segment
	prevHash  string // prev_sha256 of the active segment
	activeLen int    // records in the active segment
	poisoned  bool
	closed    bool
}

func px1SegmentName(index int) string {
	return fmt.Sprintf("%s%06d%s", px1SegmentPrefix, index, px1SegmentSuffix)
}

func px1SHA256(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// OpenJournalV2 opens or creates one layer journal.
func OpenJournalV2(dir, lockName string, h JournalHeaderV2, l JournalLimitsV2) (JournalV2, error) {
	if h.Version != 2 || (h.Layer != JournalLayerWallet && h.Layer != JournalLayerService) || !hexN(h.Binding, 32) {
		return nil, fail(CodeJournalSegment)
	}
	if l.SegmentMaxRecords == 0 {
		l.SegmentMaxRecords = px1DefaultSegmentRecords
	}
	if l.SegmentMaxBytes == 0 {
		l.SegmentMaxBytes = px1DefaultSegmentBytes
	}
	if l.SpendCapacity < 1 || l.SegmentMaxRecords < 1 || l.SegmentMaxBytes < px1MinSegmentBytes || l.SegmentMaxBytes > px1MaxSegmentBytes {
		return nil, fail(CodeJournalCapacity)
	}
	store, e := durable.Open(dir, lockName)
	if e != nil {
		return nil, e
	}
	j := &px1Journal{store: store, header: h, limits: l, state: newPX1JournalState(h.Layer)}
	if e = j.load(dir); e != nil {
		store.Close()
		return nil, e
	}
	return j, nil
}

// load verifies every segment (header, index, prev_sha256 chain, first_seq,
// Seq contiguity, record table) or creates segment 1 for a new journal.
func (j *px1Journal) load(dir string) error {
	entries, e := os.ReadDir(dir)
	if e != nil {
		return fail(CodeJournalSegment)
	}
	count := 0
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), px1SegmentPrefix) {
			count++
		}
	}
	if count == 0 {
		return j.create()
	}
	prev := px1ZeroHash
	for index := 1; index <= count; index++ {
		raw, e := j.store.Read(px1SegmentName(index), px1MaxSegmentBytes)
		if e != nil || raw == nil {
			return fail(CodeJournalSegment)
		}
		var seg JournalSegmentV2
		if strict(raw, &seg) != nil || seg.Header != j.header || seg.Index != index || seg.PrevSHA256 != prev || seg.FirstSeq != j.state.lastSeq+1 || seg.Records == nil || (index < count && len(seg.Records) == 0) {
			return fail(CodeJournalSegment)
		}
		for _, rec := range seg.Records {
			if j.state.check(rec) != nil {
				return fail(CodeJournalSegment)
			}
			j.state.apply(rec)
		}
		prev = px1SHA256(raw)
		j.index, j.active, j.firstSeq, j.prevHash, j.activeLen = index, raw, seg.FirstSeq, seg.PrevSHA256, len(seg.Records)
	}
	return nil
}

// create durably writes an empty segment 1, pinning the header binding.
func (j *px1Journal) create() error {
	seg := JournalSegmentV2{Header: j.header, Index: 1, PrevSHA256: px1ZeroHash, FirstSeq: 1, Records: []JournalRecordV2{}}
	raw := canonical(seg)
	if e := j.store.Write(px1SegmentName(1), raw); e != nil {
		return fail(codeJournalUncertain)
	}
	j.index, j.active, j.firstSeq, j.prevHash, j.activeLen = 1, raw, 1, px1ZeroHash, 0
	return nil
}

func (j *px1Journal) Header() JournalHeaderV2 { return j.header }

func (j *px1Journal) Append(rec JournalRecordV2) (JournalRecordV2, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return JournalRecordV2{}, fail(codeJournalClosed)
	}
	if j.poisoned {
		return JournalRecordV2{}, fail(codeJournalUncertain)
	}
	if rec.Inputs == nil {
		rec.Inputs = []su.Point{}
	}
	rec = px1Clone(rec)
	rec.Seq = j.state.lastSeq + 1
	if e := j.state.check(rec); e != nil {
		return JournalRecordV2{}, e
	}
	// Capacity counts admissions only; follow-ups are never refused by it.
	if rec.Kind == RecordAdmit && j.state.admitted >= j.limits.SpendCapacity {
		return JournalRecordV2{}, fail(CodeServiceJournalLimit)
	}
	index, prev, first, records := j.index, j.prevHash, j.firstSeq, j.activeRecords()
	candidate := canonical(JournalSegmentV2{Header: j.header, Index: index, PrevSHA256: prev, FirstSeq: first, Records: append(records, rec)})
	if len(records)+1 > j.limits.SegmentMaxRecords || len(candidate) > j.limits.SegmentMaxBytes {
		if len(records) == 0 {
			return JournalRecordV2{}, fail(codeJournalRecordSize)
		}
		// Seal the active segment (its bytes are already durable) and open
		// the next one chained to the sealed bytes.
		index, prev, first = j.index+1, px1SHA256(j.active), rec.Seq
		candidate = canonical(JournalSegmentV2{Header: j.header, Index: index, PrevSHA256: prev, FirstSeq: first, Records: []JournalRecordV2{rec}})
		if len(candidate) > j.limits.SegmentMaxBytes {
			return JournalRecordV2{}, fail(codeJournalRecordSize)
		}
	}
	if e := j.store.Write(px1SegmentName(index), candidate); e != nil {
		j.poisoned = true
		return JournalRecordV2{}, fail(codeJournalUncertain)
	}
	if index != j.index {
		j.activeLen = 0
	}
	j.index, j.active, j.firstSeq, j.prevHash = index, candidate, first, prev
	j.activeLen++
	j.state.apply(rec)
	return px1Clone(rec), nil
}

// activeRecords returns a copy of the active segment's records.
func (j *px1Journal) activeRecords() []JournalRecordV2 {
	all := j.state.records
	out := make([]JournalRecordV2, j.activeLen, j.activeLen+1)
	copy(out, all[len(all)-j.activeLen:])
	return out
}

func (j *px1Journal) Iterate(from uint64, fn func(JournalRecordV2) error) error {
	j.mu.Lock()
	records := j.state.records
	j.mu.Unlock()
	for _, r := range records {
		if r.Seq < from {
			continue
		}
		if e := fn(px1Clone(r)); e != nil {
			return e
		}
	}
	return nil
}

func (j *px1Journal) Usage() JournalUsageV2 {
	j.mu.Lock()
	defer j.mu.Unlock()
	return JournalUsageV2{Admitted: j.state.admitted, SpendCapacity: j.limits.SpendCapacity, Segments: j.index, LastSeq: j.state.lastSeq, LastTime: j.state.lastTime}
}

func (j *px1Journal) Poisoned() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.poisoned
}

func (j *px1Journal) Close() {
	j.mu.Lock()
	defer j.mu.Unlock()
	if !j.closed {
		j.closed = true
		j.store.Close()
	}
}

// px1Clone deep-copies a record so callers can never alias journal memory.
func px1Clone(r JournalRecordV2) JournalRecordV2 {
	r.Inputs = append([]su.Point{}, r.Inputs...)
	if r.Service != nil {
		s := *r.Service
		s.Request.Params = append(json.RawMessage(nil), s.Request.Params...)
		if s.Receipt != nil {
			receipt := *s.Receipt
			receipt.Receipt.Effect = append(json.RawMessage(nil), receipt.Receipt.Effect...)
			s.Receipt = &receipt
		}
		r.Service = &s
	}
	if r.Track != nil {
		t := *r.Track
		r.Track = &t
	}
	if r.Reconcile != nil {
		c := *r.Reconcile
		r.Reconcile = &c
	}
	return r
}

// px1JournalHighWater reports usage at or above JournalAlertPercent of the
// spend capacity (ALERT_JOURNAL_HIGH_WATER is raised by the S3 runtime).
func px1JournalHighWater(u JournalUsageV2) bool {
	return u.SpendCapacity > 0 && int64(u.Admitted)*100 >= int64(u.SpendCapacity)*JournalAlertPercent
}

// RequiredSpendCapacity is the minimum journal spend capacity for a grant:
// dayCountCap * UTCDaysSpanned(notBefore, notAfter) + JournalCapacityHeadroom.
// An invalid day count or an overflowing window returns -1, which callers
// treat as unsatisfiable (fail closed).
func RequiredSpendCapacity(dayCountCap int, notBefore, notAfter int64) int {
	if dayCountCap < 1 || dayCountCap > MaxDayCountCap {
		return -1
	}
	days := UTCDaysSpanned(notBefore, notAfter)
	if days > (math.MaxInt32-JournalCapacityHeadroom)/dayCountCap {
		return -1
	}
	return dayCountCap*days + JournalCapacityHeadroom
}

// px1CapacityFits is the admission-side reading of RequiredSpendCapacity.
func px1CapacityFits(capacity, required int) bool {
	return required >= 0 && capacity >= required
}

// UTCDay is the UTC calendar day key of a Unix time (Q4).
func UTCDay(unix int64) string { return time.Unix(unix, 0).UTC().Format("2006-01-02") }

func px1FloorDay(t int64) int64 {
	d := t / px1SecondsPerDay
	if t%px1SecondsPerDay < 0 {
		d--
	}
	return d
}

// UTCDaysSpanned counts UTC calendar days intersecting [notBefore, notAfter).
func UTCDaysSpanned(notBefore, notAfter int64) int {
	if notAfter <= notBefore {
		return 0
	}
	days := px1FloorDay(notAfter-1) - px1FloorDay(notBefore) + 1
	if days > math.MaxInt32 {
		return math.MaxInt32
	}
	return int(days)
}

// px1Ledger is the folded wallet-layer journal.
type px1Ledger struct {
	requests []px1LedgerRequest
}

type px1LedgerRequest struct {
	grantID  string
	day      string
	phase    string
	retained int64
	inputs   []su.Point
}

func px1AddSat(a, b int64) int64 {
	if b > 0 && a > math.MaxInt64-b {
		return math.MaxInt64
	}
	return a + b
}

// FoldLedgerV2 folds a wallet-layer journal into the cap checker's view.
func FoldLedgerV2(j JournalV2) (LedgerView, error) {
	if j == nil {
		return nil, fail("STATE_UNAVAILABLE")
	}
	if j.Header().Layer != JournalLayerWallet {
		return nil, fail(codeJournalLayer)
	}
	if j.Poisoned() {
		return nil, fail(codeJournalUncertain)
	}
	// Re-check the table on the way in: the fold accepts any JournalV2, so a
	// foreign implementation cannot smuggle an unbacked release or phase.
	state := newPX1JournalState(JournalLayerWallet)
	e := j.Iterate(1, func(r JournalRecordV2) error {
		if r.Inputs == nil {
			r.Inputs = []su.Point{}
		}
		if e := state.check(r); e != nil {
			return fail(codeJournalRecord)
		}
		state.apply(r)
		return nil
	})
	if e != nil {
		return nil, e
	}
	l := &px1Ledger{requests: make([]px1LedgerRequest, 0, len(state.requests))}
	for _, r := range state.records {
		if r.Kind != RecordReserve {
			continue
		}
		p := state.requests[px1Key(JournalLayerWallet, r)]
		l.requests = append(l.requests, px1LedgerRequest{grantID: r.GrantID, day: r.Day, phase: p.phase, retained: r.Reserved - p.released, inputs: r.Inputs})
	}
	return l, nil
}

func (l *px1Ledger) SpendUsed(grantID string) int64 {
	var sum int64
	for _, r := range l.requests {
		if r.grantID == grantID {
			sum = px1AddSat(sum, r.retained)
		}
	}
	return sum
}

// px1Open is the signer-service "non-terminal" set: a reserved record with no
// follow-up (a crash between reservation and outcome) or an uncertain one.
// Both are charged in every day until a later record or a reconcile.
func px1Open(phase string) bool { return phase == "reserved" || phase == "uncertain" }

func (l *px1Ledger) DayUsage(grantID, day string) (int64, int) {
	var used int64
	count := 0
	for _, r := range l.requests {
		if r.grantID == grantID && (px1Open(r.phase) || r.day == day) {
			used = px1AddSat(used, r.retained)
			count++
		}
	}
	return used, count
}

func (l *px1Ledger) UncertainSat(grantID string) int64 {
	var sum int64
	for _, r := range l.requests {
		if r.grantID == grantID && px1Open(r.phase) {
			sum = px1AddSat(sum, r.retained)
		}
	}
	return sum
}

func (l *px1Ledger) InputReserved(p su.Point) bool {
	for _, r := range l.requests {
		if r.phase == "released" {
			continue
		}
		for _, in := range r.inputs {
			if in == p {
				return true
			}
		}
	}
	return false
}

// px1ClockGuard implements CLOCK_ROLLBACK.
type px1ClockGuard struct {
	mu    sync.Mutex
	clock func() int64
	last  int64
}

// NewClockGuard returns the CLOCK_ROLLBACK guard.
func NewClockGuard(clock func() int64, lastTime int64) (ClockGuard, error) {
	if clock == nil || lastTime < 0 {
		return nil, fail("SERVICE_CONFIG")
	}
	if clock() < lastTime {
		return nil, fail(CodeClockRollback)
	}
	return &px1ClockGuard{clock: clock, last: lastTime}, nil
}

func (g *px1ClockGuard) Now() (int64, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.clock()
	if now < g.last {
		return 0, fail(CodeClockRollback)
	}
	g.last = now
	return now, nil
}

func (g *px1ClockGuard) LastTime() int64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.last
}

// px1ReadLimiter is a per-grantee trailing-hour read limiter with a rolling
// audit tail. It holds no request bodies.
type px1ReadLimiter struct {
	mu      sync.Mutex
	perHour int
	seen    map[string][]int64
	tail    []ReadAuditEntry
}

const px1ReadMaxGrantees = 1024

// NewReadLimiter returns the per-grantee read limiter. perHour < 1 refuses
// every read (fail closed).
func NewReadLimiter(perHour int) ReadLimiter {
	return &px1ReadLimiter{perHour: perHour, seen: map[string][]int64{}, tail: []ReadAuditEntry{}}
}

func (r *px1ReadLimiter) Admit(grantee string, now int64) error {
	return r.admit(grantee, "read", now)
}

// admit is Admit with the read action recorded in the audit tail.
func (r *px1ReadLimiter) admit(grantee, action string, now int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Keep reads inside the trailing hour. A timestamp after now (clock went
	// back) stays counted: a rollback never frees read budget.
	kept := r.seen[grantee][:0]
	for _, t := range r.seen[grantee] {
		if t > now-3600 {
			kept = append(kept, t)
		}
	}
	if _, known := r.seen[grantee]; !known && len(r.seen) >= px1ReadMaxGrantees {
		for g, ts := range r.seen {
			if len(ts) == 0 || ts[len(ts)-1] <= now-3600 {
				delete(r.seen, g)
			}
		}
	}
	_, known := r.seen[grantee]
	verdict, reason := "executed", "READ"
	var e error
	if r.perHour < 1 || len(kept) >= r.perHour || (!known && len(r.seen) >= px1ReadMaxGrantees) {
		verdict, reason, e = "refused", CodeReadRateLimited, fail(CodeReadRateLimited)
	} else {
		kept = append(kept, now)
	}
	if len(kept) == 0 {
		delete(r.seen, grantee)
	} else {
		r.seen[grantee] = kept
	}
	r.tail = append(r.tail, ReadAuditEntry{At: now, Grantee: grantee, Action: action, Verdict: verdict, Reason: reason})
	if len(r.tail) > ReadAuditTailSize {
		r.tail = append([]ReadAuditEntry{}, r.tail[len(r.tail)-ReadAuditTailSize:]...)
	}
	return e
}

func (r *px1ReadLimiter) Tail() []ReadAuditEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]ReadAuditEntry{}, r.tail...)
}
