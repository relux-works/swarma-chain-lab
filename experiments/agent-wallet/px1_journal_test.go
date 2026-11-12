package wallet

// Owner S2: journal v2, day buckets, clock guard, read limiter and the G2
// service layer. Core layers of T3/T5/T8/T9/T10 need S1's wallet-layer G2
// path and terms-v2 grant fixtures; they are pending integration step 3.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/durable"
)

func px1jHex(n int) string { return fmt.Sprintf("%064x", n) }

// px1jPrivateDir is a fresh 0700 state root. t.TempDir follows the process
// umask (0755 under umask 022), and durable.Open requires 0700, so every
// journal fixture uses this child instead of weakening durable.Open.
func px1jPrivateDir(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "state")
	if e := os.Mkdir(d, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(d, 0700); e != nil {
		t.Fatal(e)
	}
	return d
}

// px1jReceiptKeyN is the fixture receipt key (testKey(9), the frozen executor
// key); wallet journals in these tests verify reconcile records under it.
const px1jReceiptKeyN = 9

// px1jSignReconcile signs c with testKey(n) over the frozen preimage,
// computed here independently of the product digest function:
// SHA256("swarma-wallet-reconcile-v1" || canonical(c with Signature "")).
func px1jSignReconcile(t *testing.T, c ReconcileRecordV2, n int) *ReconcileRecordV2 {
	t.Helper()
	c.Signature = ""
	digest := sha256.Sum256(append([]byte("swarma-wallet-reconcile-v1"), canonical(c)...))
	key, _ := testKey(byte(n))
	sig, e := schnorr.Sign(key, digest[:])
	if e != nil {
		t.Fatal(e)
	}
	c.Signature = hex.EncodeToString(sig.Serialize())
	return &c
}

// px1jReserve is a well-formed wallet-layer reserve record at time t.
func px1jReserve(grant, nonce int, t, reserved int64, input int) JournalRecordV2 {
	return JournalRecordV2{Kind: RecordReserve, GrantID: px1jHex(grant), Nonce: px1jHex(1000 + nonce), RequestHash: px1jHex(2000 + nonce), Action: "spend", Phase: "reserved", Reserved: reserved, Fee: 1000, Day: UTCDay(t), Inputs: []su.Point{{TxID: px1jHex(3000 + input), Vout: 0}}, TxID: px1jHex(4000 + nonce), Created: t, LastTime: t}
}

func px1jFollowRec(r JournalRecordV2, kind, phase string, t int64) JournalRecordV2 {
	r.Seq, r.Kind, r.Phase, r.LastTime = 0, kind, phase, t
	return r
}

// px1jOpenWallet opens a wallet-layer journal that verifies reconcile
// signatures under the fixture receipt key.
func px1jOpenWallet(t *testing.T, dir string, l JournalLimitsV2) JournalV2 {
	t.Helper()
	j, e := px1jOpenWalletKey(dir, l, px1jReceiptKeyN)
	if e != nil {
		t.Fatal(e)
	}
	return j
}

// px1jOpenWalletKey opens the wallet journal under testKey(n)'s public key,
// or with no receipt key at all for n == 0 (the frozen OpenJournalV2).
func px1jOpenWalletKey(dir string, l JournalLimitsV2, n int) (JournalV2, error) {
	h := JournalHeaderV2{Version: 2, Layer: JournalLayerWallet, Binding: px1jHex(7)}
	if n == 0 {
		return OpenJournalV2(dir, "journal-v2.lock", h, l)
	}
	priv, _ := testKey(byte(n))
	key, e := schnorr.ParsePubKey(schnorr.SerializePubKey(priv.PubKey()))
	if e != nil {
		return nil, e
	}
	j, e := px1jOpenJournal(dir, "journal-v2.lock", h, l, key)
	if e != nil {
		return nil, e
	}
	return j, nil
}

func px1jMust(t *testing.T, j JournalV2, r JournalRecordV2) JournalRecordV2 {
	t.Helper()
	out, e := j.Append(r)
	if e != nil {
		t.Fatal("append", r.Kind, e)
	}
	return out
}

func px1jCode(t *testing.T, e error, code string) {
	t.Helper()
	if e == nil || e.Error() != code {
		t.Fatalf("want %s, got %v", code, e)
	}
}

// Claim: UTCDay keys the UTC calendar day (Q4) and UTCDaysSpanned counts the
// days intersecting [notBefore, notAfter); RequiredSpendCapacity is
// day_count * days + 64 and fails closed (-1) for an invalid day count or an
// overflowing window. Table-driven over the boundary seconds.
func TestPX1DaysAndCapacity(t *testing.T) {
	const day = int64(86400)
	midnight := int64(1794441600) // 2026-11-12T00:00:00Z
	if UTCDay(midnight-1) != "2026-11-11" || UTCDay(midnight) != "2026-11-12" || UTCDay(midnight+day-1) != "2026-11-12" || UTCDay(-1) != "1969-12-31" {
		t.Fatal("UTC day boundary")
	}
	for _, c := range []struct {
		nb, na int64
		days   int
	}{{0, 0, 0}, {10, 5, 0}, {0, 1, 1}, {0, day, 1}, {0, day + 1, 2}, {day - 1, day + 1, 2}, {midnight - 1, midnight, 1}, {midnight - 1, midnight + 1, 2}, {-1, 1, 2}, {0, 7 * day, 7}} {
		if got := UTCDaysSpanned(c.nb, c.na); got != c.days {
			t.Fatalf("[%d,%d): %d != %d", c.nb, c.na, got, c.days)
		}
	}
	if RequiredSpendCapacity(5, 0, 7*day) != 5*7+JournalCapacityHeadroom || RequiredSpendCapacity(10, midnight, midnight+30*day) != 364 {
		t.Fatal("capacity rule")
	}
	if RequiredSpendCapacity(0, 0, day) != -1 || RequiredSpendCapacity(MaxDayCountCap+1, 0, day) != -1 || RequiredSpendCapacity(MaxDayCountCap, 0, 1<<62) != -1 {
		t.Fatal("invalid capacity input must be unsatisfiable")
	}
	if px1jCapacityFits(2048, -1) || !px1jCapacityFits(2048, 2048) || px1jCapacityFits(2047, 2048) {
		t.Fatal("capacity fit")
	}
}

// Claim: records survive reopen byte-for-byte with contiguous Seq assigned by
// Append; segments seal at the record limit and chain by prev_sha256. A
// tampered sealed segment, a missing middle segment, a foreign binding or a
// stray segment name refuses JOURNAL_SEGMENT, while the untouched copy reopens.
func TestPX1JournalSegmentsChain(t *testing.T) {
	dir := px1jPrivateDir(t)
	l := JournalLimitsV2{SpendCapacity: 8, SegmentMaxRecords: 2}
	j := px1jOpenWallet(t, dir, l)
	base := int64(1794009600)
	for i := 0; i < 3; i++ {
		r := px1jMust(t, j, px1jReserve(1, i, base+int64(i), 50000, i))
		if r.Seq != uint64(2*i+1) {
			t.Fatal("seq", r.Seq)
		}
		px1jMust(t, j, px1jFollowRec(r, RecordComplete, "complete", base+int64(i)))
	}
	if u := j.Usage(); u.Segments != 3 || u.LastSeq != 6 || u.LastTime != base+2 || u.Admitted != 0 {
		t.Fatal("usage", u)
	}
	j.Close()
	j = px1jOpenWallet(t, dir, l)
	var seqs []uint64
	_ = j.Iterate(3, func(r JournalRecordV2) error { seqs = append(seqs, r.Seq); return nil })
	if len(seqs) != 4 || seqs[0] != 3 || seqs[3] != 6 {
		t.Fatal("iterate from", seqs)
	}
	j.Close()
	copyDir := func(t *testing.T) string {
		d := px1jPrivateDir(t)
		for i := 1; i <= 3; i++ {
			b, _ := os.ReadFile(filepath.Join(dir, px1jSegmentName(i)))
			os.WriteFile(filepath.Join(d, px1jSegmentName(i)), b, 0600)
		}
		return d
	}
	open := func(d string, binding string) error {
		j, e := OpenJournalV2(d, "journal-v2.lock", JournalHeaderV2{Version: 2, Layer: JournalLayerWallet, Binding: binding}, l)
		if e == nil {
			j.Close()
		}
		return e
	}
	if e := open(copyDir(t), px1jHex(7)); e != nil {
		t.Fatal("untouched copy must reopen", e)
	}
	// Re-encode segment 1 canonically with a different amount: the bytes stay
	// canonical, so only the prev_sha256 chain of segment 2 can catch it.
	d := copyDir(t)
	var seg JournalSegmentV2
	b, _ := os.ReadFile(filepath.Join(d, px1jSegmentName(1)))
	json.Unmarshal(b, &seg)
	seg.Records[0].Reserved, seg.Records[1].Reserved = 49999, 49999
	os.WriteFile(filepath.Join(d, px1jSegmentName(1)), canonical(seg), 0600)
	px1jCode(t, open(d, px1jHex(7)), CodeJournalSegment)
	d = copyDir(t)
	os.Remove(filepath.Join(d, px1jSegmentName(2)))
	px1jCode(t, open(d, px1jHex(7)), CodeJournalSegment)
	px1jCode(t, open(copyDir(t), px1jHex(8)), CodeJournalSegment)
	d = copyDir(t)
	os.WriteFile(filepath.Join(d, px1jSegmentPrefix+"stray"), []byte("x"), 0600)
	px1jCode(t, open(d, px1jHex(7)), CodeJournalSegment)
}

// Claim: Append enforces the frozen kind/layer/phase table, the per-request
// transition order, plan equality of follow-ups, the reservation day, and the
// reconcile release bound and rate limit; each refusal has an accepted
// neighbour and a refused record is never stored.
func TestPX1JournalRecordTable(t *testing.T) {
	j := px1jOpenWallet(t, px1jPrivateDir(t), JournalLimitsV2{SpendCapacity: 4})
	defer j.Close()
	t0 := int64(1794009600)
	r := px1jReserve(1, 1, t0, 50000, 1)
	bad := []struct {
		name string
		rec  JournalRecordV2
		code string
	}{
		{"service kind on wallet layer", func() JournalRecordV2 { x := r; x.Kind = RecordAdmit; x.Phase = "pending"; return x }(), px1jCodeRecord},
		{"follow-up before reserve", px1jFollowRec(r, RecordComplete, "complete", t0), px1jCodeRecord},
		{"wrong phase for kind", func() JournalRecordV2 { x := r; x.Phase = "complete"; return x }(), px1jCodeRecord},
		{"day not of the reservation clock", func() JournalRecordV2 { x := r; x.Day = UTCDay(t0 - 1); return x }(), px1jCodeRecord},
		{"fee not below the debit", func() JournalRecordV2 { x := r; x.Fee = x.Reserved; return x }(), px1jCodeRecord},
		{"no planned input", func() JournalRecordV2 { x := r; x.Inputs = []su.Point{}; return x }(), px1jCodeRecord},
	}
	for _, c := range bad {
		_, e := j.Append(c.rec)
		if e == nil || e.Error() != c.code {
			t.Fatal(c.name, e)
		}
	}
	if j.Usage().LastSeq != 0 {
		t.Fatal("refused record stored")
	}
	res := px1jMust(t, j, r)
	_, e := j.Append(r)
	px1jCode(t, e, px1jCodeRecord) // a second reserve of the same request
	other := px1jFollowRec(res, RecordComplete, "complete", t0+1)
	other.Reserved--
	_, e = j.Append(other)
	px1jCode(t, e, px1jCodeRecord) // follow-up with another plan
	done := px1jMust(t, j, px1jFollowRec(res, RecordComplete, "complete", t0+1))
	_, e = j.Append(px1jFollowRec(res, RecordUncertain, "uncertain", t0+1))
	px1jCode(t, e, px1jCodeRecord) // uncertain after complete
	track := px1jFollowRec(done, RecordTrack, TrackConfirmed, t0+2)
	track.Track = &TrackRecordV2{State: TrackConfirmed, Height: 10, BlockHash: px1jHex(9), Confirmations: 0}
	_, e = j.Append(track)
	px1jCode(t, e, px1jCodeRecord) // confirmed with zero confirmations
	track.Track.Confirmations = 2
	px1jMust(t, j, track)
	rec := px1jFollowRec(done, RecordReconcile, "released", t0+3)
	rec.Reconcile = px1jSignReconcile(t, ReconcileRecordV2{TargetSeq: res.Seq, Evidence: "absent", Height: 11, BlockHash: px1jHex(9), ReleasedSat: 50001, NoteSHA256: px1jHex(5)}, px1jReceiptKeyN)
	_, e = j.Append(rec)
	px1jCode(t, e, px1jCodeRecord) // release above the retained debit
	rec.Reconcile = px1jSignReconcile(t, ReconcileRecordV2{TargetSeq: done.Seq, Evidence: "absent", Height: 11, BlockHash: px1jHex(9), ReleasedSat: 50000, NoteSHA256: px1jHex(5)}, px1jReceiptKeyN)
	_, e = j.Append(rec)
	px1jCode(t, e, px1jCodeRecord) // target is not the reserve record
	rec.Reconcile = px1jSignReconcile(t, ReconcileRecordV2{TargetSeq: res.Seq, Evidence: "absent", Height: 11, BlockHash: px1jHex(9), ReleasedSat: 50000, NoteSHA256: px1jHex(5)}, px1jReceiptKeyN)
	px1jMust(t, j, rec)
	second := px1jMust(t, j, px1jReserve(1, 2, t0+4, 30000, 2))
	rel := px1jFollowRec(second, RecordReconcile, "released", t0+4)
	rel.Reconcile = px1jSignReconcile(t, ReconcileRecordV2{TargetSeq: second.Seq, Evidence: "conflict", Height: 12, BlockHash: px1jHex(9), ConflictTxID: px1jHex(6), ReleasedSat: 1, NoteSHA256: px1jHex(5)}, px1jReceiptKeyN)
	_, e = j.Append(rel)
	px1jCode(t, e, CodeReconcileRateLimited)
	rel.LastTime = t0 + 3 + ReconcileMinIntervalSeconds
	px1jMust(t, j, rel)
}

// Claim (T16, unit): the guard refuses CLOCK_ROLLBACK at startup when the
// clock is below the journal's last_time and on any later read below the
// highest time seen, never lowering it; equal time is accepted. The journal
// itself refuses a record whose last_time goes back, also after reopen.
func TestPX1T16ClockRollback(t *testing.T) {
	now := int64(1000)
	clock := func() int64 { return now }
	_, e := NewClockGuard(clock, 1001)
	px1jCode(t, e, CodeClockRollback)
	g, e := NewClockGuard(clock, 1000)
	if e != nil {
		t.Fatal("equal startup time", e)
	}
	now = 1005
	if v, e := g.Now(); e != nil || v != 1005 {
		t.Fatal(v, e)
	}
	now = 1004
	_, e = g.Now()
	px1jCode(t, e, CodeClockRollback)
	if g.LastTime() != 1005 {
		t.Fatal("rollback lowered the guard")
	}
	now = 1005
	if _, e = g.Now(); e != nil {
		t.Fatal("equal time", e)
	}
	dir := px1jPrivateDir(t)
	j := px1jOpenWallet(t, dir, JournalLimitsV2{SpendCapacity: 4})
	t0 := int64(1794009600)
	px1jMust(t, j, px1jReserve(1, 1, t0, 50000, 1))
	_, e = j.Append(px1jReserve(1, 2, t0-1, 50000, 2))
	px1jCode(t, e, CodeClockRollback)
	px1jMust(t, j, px1jReserve(1, 3, t0, 50000, 3))
	j.Close()
	j = px1jOpenWallet(t, dir, JournalLimitsV2{SpendCapacity: 4})
	defer j.Close()
	_, e = NewClockGuard(func() int64 { return t0 - 1 }, j.Usage().LastTime)
	px1jCode(t, e, CodeClockRollback)
	_, e = j.Append(px1jReserve(1, 4, t0-1, 50000, 4))
	px1jCode(t, e, CodeClockRollback)
}

// Claim (T3, unit with injected clock): day usage follows the signer rule.
// A complete or refused-retained record counts only on its reservation day;
// a reserved-without-outcome or uncertain record counts on every day, also
// after UTC midnight. Rollover happens at 00:00:00 UTC exactly, not one
// second before. The day cap is reached at cap and exceeded by cap+1; the
// day count cap admits the 5th and refuses the 6th. A reconcile releases
// sats (spend and day) but never the day count on the reservation day, and
// unreserves the inputs.
// The cap arithmetic here mirrors S1's CapChecker rule; the CapChecker itself
// is covered by S1 and by the Core layer.
func TestPX1T3DayBuckets(t *testing.T) {
	j := px1jOpenWallet(t, px1jPrivateDir(t), JournalLimitsV2{SpendCapacity: 64})
	defer j.Close()
	const dayCap, countCap = int64(300000), 5
	midnight := int64(1794441600) // 2026-11-12T00:00:00Z
	d0, d1 := UTCDay(midnight-1), UTCDay(midnight)
	grant := px1jHex(1)
	fits := func(l LedgerView, day string, cost int64) bool {
		used, count := l.DayUsage(grant, day)
		return used+cost <= dayCap && count+1 <= countCap
	}
	ledger := func() LedgerView {
		l, e := FoldLedgerV2(j)
		if e != nil {
			t.Fatal(e)
		}
		return l
	}
	// Day d0: complete 149999, uncertain 50000, refused-retained 50000,
	// reserved (crash) 50000: 299999 of the 300000 cap, count 4.
	at := midnight - 100
	a := px1jMust(t, j, px1jReserve(1, 1, at, 149999, 1))
	px1jMust(t, j, px1jFollowRec(a, RecordComplete, "complete", at))
	b := px1jMust(t, j, px1jReserve(1, 2, at, 50000, 2))
	px1jMust(t, j, px1jFollowRec(b, RecordUncertain, "uncertain", at))
	c := px1jMust(t, j, px1jReserve(1, 3, at, 50000, 3))
	px1jMust(t, j, px1jFollowRec(c, RecordRefuseRetained, "refused", at))
	px1jMust(t, j, px1jReserve(1, 4, at, 50000, 4))
	px1jMust(t, j, px1jReserve(2, 5, at, 90000, 5)) // another grant never mixes in
	l := ledger()
	if used, count := l.DayUsage(grant, d0); used != 299999 || count != 4 {
		t.Fatal("d0 usage", used, count)
	}
	if !fits(l, d0, 1) || fits(l, d0, 2) {
		t.Fatal("day cap boundary: cap must fit, cap+1 must not")
	}
	if l.SpendUsed(grant) != 299999 || l.UncertainSat(grant) != 100000 || l.SpendUsed(px1jHex(2)) != 90000 {
		t.Fatal("spend/uncertain", l.SpendUsed(grant), l.UncertainSat(grant))
	}
	// One second before midnight is still d0: no rollover.
	if UTCDay(midnight-1) != d0 {
		t.Fatal("rollover before midnight")
	}
	// After midnight only the open records (uncertain + reserved) still count.
	if used, count := l.DayUsage(grant, d1); used != 100000 || count != 2 {
		t.Fatal("d1 usage after rollover", used, count)
	}
	// Day count: fill d1 to 5 transfers with small completes, then refuse.
	for i := 0; i < 3; i++ {
		r := px1jMust(t, j, px1jReserve(1, 10+i, midnight+int64(i), 10000, 10+i))
		px1jMust(t, j, px1jFollowRec(r, RecordComplete, "complete", midnight+int64(i)))
		if !fits(ledger(), d1, 10000) && i < 2 {
			t.Fatal("count below cap must fit", i)
		}
	}
	if _, count := ledger().DayUsage(grant, d1); count != 5 || fits(ledger(), d1, 1) {
		t.Fatal("6th transfer of the day must not fit", count)
	}
	// Operator reconciliation of the uncertain record releases its sats and
	// inputs, never its count; the debit returns only through this record.
	l = ledger()
	if !l.InputReserved(su.Point{TxID: px1jHex(3002), Vout: 0}) || !l.InputReserved(su.Point{TxID: px1jHex(3003), Vout: 0}) {
		t.Fatal("retained inputs must stay reserved")
	}
	rel := px1jFollowRec(b, RecordReconcile, "released", midnight+10)
	rel.Reconcile = px1jSignReconcile(t, ReconcileRecordV2{TargetSeq: b.Seq, Evidence: "absent", Height: 100, BlockHash: px1jHex(9), ReleasedSat: 50000, NoteSHA256: px1jHex(5)}, px1jReceiptKeyN)
	px1jMust(t, j, rel)
	l = ledger()
	// The released record is terminal now: it leaves d1 (open set) and keeps
	// its d0 count with a zero remaining debit.
	used, count := l.DayUsage(grant, d1)
	if used != 80000 || count != 4 || l.SpendUsed(grant) != 279999 || l.UncertainSat(grant) != 50000 || l.InputReserved(su.Point{TxID: px1jHex(3002), Vout: 0}) {
		t.Fatal("reconcile release", used, count, l.SpendUsed(grant), l.UncertainSat(grant))
	}
	if usedD0, countD0 := l.DayUsage(grant, d0); usedD0 != 249999 || countD0 != 4 {
		t.Fatal("released record on d0", usedD0, countD0)
	}
}

// Claim: SpendCapacity counts admit records only. At capacity the next
// admission refuses SERVICE_JOURNAL_LIMIT, while follow-ups of admitted
// requests are still accepted; the high-water helper fires at 80%.
func TestPX1JournalCapacity(t *testing.T) {
	j, e := OpenJournalV2(px1jPrivateDir(t), "service-v2.lock", JournalHeaderV2{Version: 2, Layer: JournalLayerService, Binding: px1jHex(7)}, JournalLimitsV2{SpendCapacity: 2})
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	admit := func(n int) JournalRecordV2 {
		q := actionFixture(t, "spend")
		q.Nonce = fmt.Sprintf("%032x", n)
		return JournalRecordV2{Kind: RecordAdmit, GrantID: q.Grant.ID, Nonce: q.Nonce, RequestHash: Hash(canonical(q)), Action: "spend", Phase: "pending", Inputs: []su.Point{}, Created: q.CreatedAt, LastTime: 600, Service: &ServiceRecordV2{Request: q, Peer: PeerIdentity{1201, 1301}}}
	}
	if px1jHighWater(j.Usage()) {
		t.Fatal("empty journal above high water")
	}
	first := px1jMust(t, j, admit(1))
	px1jMust(t, j, admit(2))
	if !px1jHighWater(j.Usage()) {
		t.Fatal("full journal below high water")
	}
	_, e = j.Append(admit(3))
	px1jCode(t, e, CodeServiceJournalLimit)
	follow := first
	follow.Seq, follow.Kind, follow.Phase = 0, RecordServiceReserve, "reserved"
	px1jMust(t, j, follow)
	_, e = j.Append(admit(1))
	px1jCode(t, e, px1jCodeRecord) // a second admit of the same nonce
	if u := j.Usage(); u.Admitted != 2 || u.SpendCapacity != 2 {
		t.Fatal(u)
	}
}

// Claim: a failed durable write poisons the journal: that append refuses
// JOURNAL_WRITE_UNCERTAIN and so does every later append, even once the
// directory is writable again; appends before the fault succeed.
func TestPX1JournalPoison(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("directory permissions do not bind root")
	}
	dir := px1jPrivateDir(t)
	j := px1jOpenWallet(t, dir, JournalLimitsV2{SpendCapacity: 4})
	defer j.Close()
	t0 := int64(1794009600)
	px1jMust(t, j, px1jReserve(1, 1, t0, 50000, 1))
	os.Chmod(dir, 0500)
	_, e := j.Append(px1jReserve(1, 2, t0, 50000, 2))
	os.Chmod(dir, 0700)
	px1jCode(t, e, px1jCodeUncertain)
	if !j.Poisoned() {
		t.Fatal("not poisoned")
	}
	_, e = j.Append(px1jReserve(1, 3, t0, 50000, 3))
	px1jCode(t, e, px1jCodeUncertain)
	if _, e = FoldLedgerV2(j); e == nil {
		t.Fatal("poisoned ledger folded")
	}
}

// Claim (T17, unit): of 10,000 reads by one grantee inside an hour exactly
// DefaultReadRatePerHour are admitted and the rest refuse READ_RATE_LIMITED;
// another grantee is unaffected, reads are admitted again after the hour, a
// clock step back frees nothing, and the audit tail stays bounded, newest last.
func TestPX1T17ReadLimiter(t *testing.T) {
	r := NewReadLimiter(DefaultReadRatePerHour)
	admitted := 0
	for i := 0; i < 10000; i++ {
		e := r.Admit("a", 1000+int64(i%1800))
		if e == nil {
			admitted++
		} else if e.Error() != CodeReadRateLimited {
			t.Fatal(e)
		}
	}
	if admitted != DefaultReadRatePerHour {
		t.Fatal("admitted", admitted)
	}
	if r.Admit("b", 2000) != nil {
		t.Fatal("other grantee limited")
	}
	px1jCode(t, r.Admit("a", 999), CodeReadRateLimited)
	if r.Admit("a", 1000+3600) != nil {
		t.Fatal("read after the trailing hour")
	}
	tail := r.Tail()
	if len(tail) != ReadAuditTailSize || tail[len(tail)-1].At != 4600 || tail[len(tail)-1].Verdict != "executed" || tail[len(tail)-2].Reason != CodeReadRateLimited {
		t.Fatal("tail", len(tail))
	}
	px1jCode(t, NewReadLimiter(0).Admit("a", 1), CodeReadRateLimited)
}

// px1jFailNode answers every RPC with a bounded error: no read can succeed and
// no effect can happen through it.
type px1jFailNode struct{}

func (px1jFailNode) Call(context.Context, string, ...any) (json.RawMessage, error) {
	return nil, errors.New("NODE_UNAVAILABLE")
}

// px1jServiceFixture is a G2 service over a node that refuses every call,
// with S1's operator validator replaced by an accept-all fake (the S1 stub
// returns PX1_NOT_IMPLEMENTED until S1 lands).
func px1jServiceFixture(t *testing.T, stateDir string, clock *int64, capacity int) *ActionService {
	t.Helper()
	key, pub := testKey(9)
	_, grantee := testKey(2)
	objects := filepath.Join(filepath.Dir(stateDir), "objects")
	os.MkdirAll(objects, 0700)
	w := &Wallet{config: Config{Network: "regtest", Genesis: su.RegtestGenesis, ObjectsDir: objects}, node: px1jFailNode{}, wallet: px1jFailNode{}, broadcast: px1jFailNode{}}
	s := &ActionService{config: ServiceConfig{Version: 1, Service: WalletServiceID, PeerUID: 1201, Grantee: grantee, SkewSeconds: 120, StateDir: stateDir}, wallet: w, key: key, pub: pub, clock: func() int64 { return *clock }}
	store, e := durable.Open(stateDir, "service.lock")
	if e != nil {
		t.Fatal(e)
	}
	s.store = store
	s.state = serviceState{1, px1jHex(77), []serviceEntry{}}
	op := px1Operator()
	op.JournalSpendCapacity = capacity
	if e = s.px1jOpenService(op, s.state.Binding, px1jServiceDeps{validate: func(G2OperatorConfig) error { return nil }, open: OpenJournalV2}); e != nil {
		store.Close()
		t.Fatal(e)
	}
	t.Cleanup(func() { px1jCloseFixture(s) })
	return s
}

func px1jCloseFixture(s *ActionService) {
	if s.g2 != nil {
		s.g2.journal.Close()
	}
	s.store.Close()
}

func px1jStateDir(t *testing.T) string {
	d := filepath.Join(t.TempDir(), "service")
	if e := os.Mkdir(d, 0700); e != nil {
		t.Fatal(e)
	}
	return d
}

func px1jActionRaw(t *testing.T, action string, nonce int, mutate func(*ActionRequest)) []byte {
	t.Helper()
	q := actionFixture(t, action)
	q.Nonce = fmt.Sprintf("%032x", nonce)
	if mutate != nil {
		mutate(&q)
	}
	return actionEnvelope(t, q)
}

func px1jReceipt(t *testing.T, raw []byte) ActionReceipt {
	t.Helper()
	var r SignedActionReceipt
	if e := strict(raw, &r); e != nil {
		t.Fatal("receipt bytes", e)
	}
	return r.Receipt
}

var px1jPeer = PeerIdentity{UID: 1201, GID: 1301}

// Claim (T17, service): 10,000 balance requests consume no journal capacity
// (60 reach the node, the rest refuse READ_RATE_LIMITED before any node call),
// and a spend is still admitted afterwards with journal_seq 1.
func TestPX1T17ReadFloodService(t *testing.T) {
	clock := int64(500)
	s := px1jServiceFixture(t, px1jStateDir(t), &clock, 4)
	ctx := context.Background()
	limited := 0
	for i := 0; i < 10000; i++ {
		r := px1jReceipt(t, s.handle(ctx, px1jActionRaw(t, "balance", i, nil), px1jPeer))
		if r.Verdict != "refused" || r.Sequence != 0 {
			t.Fatal("read", r.Verdict, r.Sequence)
		}
		if r.Reason == CodeReadRateLimited {
			limited++
		}
	}
	if limited != 10000-DefaultReadRatePerHour || s.g2.journal.Usage().Admitted != 0 || s.g2.journal.Usage().LastSeq != 0 {
		t.Fatal("reads journaled or not limited", limited, s.g2.journal.Usage())
	}
	r := px1jReceipt(t, s.handle(ctx, px1jActionRaw(t, "spend", 20000, nil), px1jPeer))
	if r.Sequence != 1 || r.Reason == CodeServiceJournalLimit || s.g2.journal.Usage().Admitted != 1 {
		t.Fatal("spend after read flood", r.Reason, r.Sequence)
	}
}

// Claim (T5, unit): under G2 a request for another grantee refuses
// GRANTEE_MISMATCH and a foreign peer UID refuses SERVICE_PEER, both before
// admission (journal_seq 0, nothing journaled); the pinned grantee and peer
// are admitted. A single-use request refuses SINGLE_USE_DISABLED at step 8
// before any grant read. GRANT_GRANTEE_MISMATCH needs a real v3 grant
// object (Core layer, pending S1 fixtures).
func TestPX1T5ServiceRefusals(t *testing.T) {
	clock := int64(500)
	s := px1jServiceFixture(t, px1jStateDir(t), &clock, 8)
	ctx := context.Background()
	other := func(q *ActionRequest) { _, q.Grantee = testKey(4) }
	otherRaw := func() []byte {
		q := actionFixture(t, "spend")
		q.Nonce = fmt.Sprintf("%032x", 1)
		other(&q)
		return canonical(ActionEnvelope{Request: q, Signature: signDigest(t, ActionDigest(q), 4)})
	}()
	if r := px1jReceipt(t, s.handle(ctx, otherRaw, px1jPeer)); r.Reason != "GRANTEE_MISMATCH" || r.Sequence != 0 {
		t.Fatal("grantee", r.Reason)
	}
	if r := px1jReceipt(t, s.handle(ctx, px1jActionRaw(t, "spend", 2, nil), PeerIdentity{UID: 1202, GID: 1301})); r.Reason != "SERVICE_PEER" || r.Sequence != 0 {
		t.Fatal("peer", r.Reason)
	}
	if s.g2.journal.Usage().LastSeq != 0 {
		t.Fatal("refusal before admission was journaled")
	}
	single := px1jActionRaw(t, "spend", 3, func(q *ActionRequest) { q.Grant.Kind = "single-use" })
	if r := px1jReceipt(t, s.handle(ctx, single, px1jPeer)); r.Reason != CodeSingleUseDisabled || r.Verdict != "refused" || r.Sequence != 1 {
		t.Fatal("single-use", r.Reason)
	}
	// Valid neighbour: the standing request passes steps 4-8 and refuses only
	// at the grant object lookup (no object provisioned in this fixture).
	if r := px1jReceipt(t, s.handle(ctx, px1jActionRaw(t, "spend", 4, nil), px1jPeer)); r.Sequence != 3 || r.Reason == CodeSingleUseDisabled || r.Reason == "GRANTEE_MISMATCH" {
		t.Fatal("standing neighbour", r.Reason, r.Sequence)
	}
}

// Claim (T8, service-layer unit): a terminal receipt replays byte-identical,
// also after a restart; the same nonce with other bytes refuses
// NONCE_CONFLICT; a request whose service reservation is durable replays as
// uncertain DURABLE_RESERVATION_NO_RETRY and that answer is itself stored.
// A G2 spend never reaches the wallet while S1's layer is unattached
// (PX1_NOT_IMPLEMENTED). Replay after a successful spend is Core, pending S1.
func TestPX1T8ServiceReplay(t *testing.T) {
	clock := int64(500)
	dir := px1jStateDir(t)
	s := px1jServiceFixture(t, dir, &clock, 8)
	ctx := context.Background()
	raw := px1jActionRaw(t, "spend", 1, nil)
	first := s.handle(ctx, raw, px1jPeer)
	if px1jReceipt(t, first).Sequence != 1 {
		t.Fatal("first")
	}
	clock = 1000 // replay is outside the skew window: it never re-admits
	if string(s.handle(ctx, raw, px1jPeer)) != string(first) {
		t.Fatal("replay not byte-identical")
	}
	conflict := px1jActionRaw(t, "spend", 1, func(q *ActionRequest) {
		q.Params = canonical(SpendParams{To: testAddress(3), Amount: 100001, FeeLimit: 100000})
	})
	if r := px1jReceipt(t, s.handle(ctx, conflict, px1jPeer)); r.Reason != "NONCE_CONFLICT" {
		t.Fatal("nonce conflict", r.Reason)
	}
	// A durable service reservation (crash after step 20) for nonce 2.
	clock = 500
	q := actionFixture(t, "spend")
	q.Nonce = fmt.Sprintf("%032x", 2)
	admit, e := s.g2.journal.Append(JournalRecordV2{Kind: RecordAdmit, GrantID: q.Grant.ID, Nonce: q.Nonce, RequestHash: Hash(canonical(q)), Action: "spend", Phase: "pending", Inputs: []su.Point{}, Created: q.CreatedAt, LastTime: 500, Service: &ServiceRecordV2{Request: q, Peer: px1jPeer}})
	if e != nil {
		t.Fatal(e)
	}
	reserve := admit
	reserve.Seq, reserve.Kind, reserve.Phase = 0, RecordServiceReserve, "reserved"
	reserve.Reserved, reserve.Fee, reserve.Inputs, reserve.TxID = 101000, 1000, []su.Point{{TxID: px1jHex(5), Vout: 1}}, px1jHex(6)
	if _, e = s.g2.journal.Append(reserve); e != nil {
		t.Fatal(e)
	}
	px1jCloseFixture(s)
	clock = 2000
	s = px1jServiceFixture(t, dir, &clock, 8)
	if string(s.handle(ctx, raw, px1jPeer)) != string(first) {
		t.Fatal("replay after restart not byte-identical")
	}
	reserved := s.handle(ctx, actionEnvelope(t, q), px1jPeer)
	if r := px1jReceipt(t, reserved); r.Verdict != "uncertain" || r.Reason != "DURABLE_RESERVATION_NO_RETRY" || r.Sequence != admit.Seq {
		t.Fatal("reserved replay", r.Verdict, r.Reason)
	}
	if string(s.handle(ctx, actionEnvelope(t, q), px1jPeer)) != string(reserved) {
		t.Fatal("uncertain answer not stored")
	}
	// Fail closed until S1 attaches the wallet layer: a fully bound standing
	// spend refuses before any wallet call (covered through step 8 above; the
	// guard itself is exercised by the mutation manifest).
	if s.wallet.PX1Journal() != nil {
		t.Fatal("S1 wallet layer unexpectedly attached on the frozen base")
	}
}

// Claim: G2 startup refuses a W2 service journal with entries
// (SERVICE_PROFILE), a stored receipt that does not verify under this
// receipt key (SERVICE_JOURNAL_RECEIPT), and a clock below the journal's
// last_time (CLOCK_ROLLBACK); the untouched journal reopens. The seams report
// the journal and a copy of the profile under G2 and nil under W2. With the
// product dependencies the operator block goes through S1's validator in any
// landing order: the stub refuses PX1_NOT_IMPLEMENTED, S1's validator admits
// the frozen operator fixture; a single-use block never opens either way.
func TestPX1ServiceStartup(t *testing.T) {
	clock := int64(500)
	dir := px1jStateDir(t)
	s := px1jServiceFixture(t, dir, &clock, 8)
	if s.PX1ServiceJournal() == nil || s.PX1Profile() == nil || s.PX1Profile().JournalSpendCapacity != 8 {
		t.Fatal("G2 seams")
	}
	s.PX1Profile().JournalSpendCapacity = 1
	if s.g2.operator.JournalSpendCapacity != 8 {
		t.Fatal("profile aliasing")
	}
	var w2 ActionService
	if w2.PX1ServiceJournal() != nil || w2.PX1Profile() != nil {
		t.Fatal("W2 seams")
	}
	s.handle(context.Background(), px1jActionRaw(t, "spend", 1, nil), px1jPeer)
	px1jCloseFixture(s)
	op := px1Operator()
	openWith := func(mutate func(*ActionService), deps px1jServiceDeps) error {
		key, pub := testKey(9)
		_, grantee := testKey(2)
		w := &Wallet{config: Config{Network: "regtest", Genesis: su.RegtestGenesis}, node: px1jFailNode{}}
		x := &ActionService{config: ServiceConfig{Version: 1, Service: WalletServiceID, PeerUID: 1201, Grantee: grantee, SkewSeconds: 120, StateDir: dir}, wallet: w, key: key, pub: pub, clock: func() int64 { return clock }, state: serviceState{1, px1jHex(77), []serviceEntry{}}}
		if mutate != nil {
			mutate(x)
		}
		e := x.px1jOpenService(op, x.state.Binding, deps)
		if e == nil {
			x.g2.journal.Close()
		}
		return e
	}
	open := func(mutate func(*ActionService)) error {
		return openWith(mutate, px1jServiceDeps{validate: func(G2OperatorConfig) error { return nil }, open: OpenJournalV2})
	}
	if e := open(nil); e != nil {
		t.Fatal("untouched reopen", e)
	}
	px1jCode(t, open(func(x *ActionService) { x.state.Entries = []serviceEntry{{}} }), "SERVICE_PROFILE")
	px1jCode(t, open(func(x *ActionService) { x.key, x.pub = testKey(8) }), "SERVICE_JOURNAL_RECEIPT")
	px1jCode(t, open(func(x *ActionService) { x.config.PeerUID = 1202 }), "SERVICE_JOURNAL_ENTRY")
	clock = 499
	px1jCode(t, open(nil), CodeClockRollback)
	clock = 500
	px1jCode(t, open(func(x *ActionService) { x.state.Binding = px1jHex(78) }), CodeJournalSegment)
	if e := open(nil); e != nil {
		t.Fatal("reopen after refusals", e)
	}
	// A G2 operator block that enables single-use never opens (Q7).
	op.AllowSingleUse = true
	px1jCode(t, open(nil), "SERVICE_CONFIG")
	op.AllowSingleUse = false
	// Product dependencies: S1's stub refuses PX1_NOT_IMPLEMENTED; once S1
	// lands, its validator admits the frozen operator fixture.
	if e := openWith(nil, px1jServiceProductDeps()); e != nil && !errors.Is(e, ErrNotImplemented) && e.Error() != "PX1_NOT_IMPLEMENTED" {
		t.Fatal("product validator", e)
	}
	op.AllowSingleUse = true
	if e := openWith(nil, px1jServiceProductDeps()); e == nil {
		t.Fatal("product dependencies opened a single-use operator block")
	}
}

// Claim: until integration step 3 the G2 profile is never selected from a
// service configuration, so every opened service keeps W2 behaviour.
func TestPX1ProfileSelectionPending(t *testing.T) {
	if px1jProfileOf(ServiceConfig{}) != nil {
		t.Fatal("G2 selected before S1's config member lands")
	}
}

// Claim (T16, service): after an admission at time T, a new spend with the
// clock stepped back below T refuses CLOCK_ROLLBACK before admission
// (journal_seq 0, nothing journaled); at T itself it is admitted.
func TestPX1T16ServiceClockRollback(t *testing.T) {
	clock := int64(500)
	s := px1jServiceFixture(t, px1jStateDir(t), &clock, 8)
	ctx := context.Background()
	if r := px1jReceipt(t, s.handle(ctx, px1jActionRaw(t, "spend", 1, nil), px1jPeer)); r.Sequence != 1 {
		t.Fatal("first admission", r.Reason)
	}
	clock = 499
	if r := px1jReceipt(t, s.handle(ctx, px1jActionRaw(t, "spend", 2, nil), px1jPeer)); r.Reason != CodeClockRollback || r.Sequence != 0 {
		t.Fatal("rollback admission", r.Reason, r.Sequence)
	}
	if r := px1jReceipt(t, s.handle(ctx, px1jActionRaw(t, "balance", 3, nil), px1jPeer)); r.Reason != CodeClockRollback {
		t.Fatal("rollback read", r.Reason)
	}
	if s.g2.journal.Usage().Admitted != 1 {
		t.Fatal("rollback journaled")
	}
	clock = 500
	if r := px1jReceipt(t, s.handle(ctx, px1jActionRaw(t, "spend", 2, nil), px1jPeer)); r.Sequence != 3 { // admit 1, terminal 2, admit 3
		t.Fatal("equal time neighbour", r.Reason)
	}
}
