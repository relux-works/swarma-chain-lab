package wallet

// Owner S3. Revision 3 regression tests: tracker observations are never
// discarded while the wallet journal refuses their track records (retry
// first, then backpressure instead of compaction), and the status-versus-
// ledger equivalence runs over authenticated S2 journals (the public
// OpenJournalV2 under a keyed header, freeze amendment 1) while unsigned and
// unbound releases stay refused.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// ---------------------------------------------------------------------------
// Tracker observations survive a long append refusal.

// px1oCountingTracker records every transition its inner tracker returns, in
// order, and how often it was polled.
type px1oCountingTracker struct {
	Tracker
	ticks    int
	returned []TrackTransition
}

func (c *px1oCountingTracker) Tick(ctx context.Context) ([]TrackTransition, error) {
	c.ticks++
	out, e := c.Tracker.Tick(ctx)
	if e == nil {
		c.returned = append(c.returned, out...)
	}
	return out, e
}

// px1oCountTracker wraps the lab's tracker (the fake, or the real NewTracker
// over the lab chain and wallet journal when real is set) in a counter.
func px1oCountTracker(l *px1oRuntimeLab, real bool) *px1oCountingTracker {
	counter := &px1oCountingTracker{}
	l.r.deps.newTracker = func(node su.Node, cfg TrackerConfig, wallet JournalV2) (Tracker, error) {
		var inner Tracker = l.tracker
		if real {
			tracker, e := NewTracker(node, cfg, wallet)
			if e != nil {
				return nil, e
			}
			inner = tracker
		}
		counter.Tracker = inner
		return counter, nil
	}
	return counter
}

// px1oBacklogAlerts returns the backlog alerts raised so far.
func px1oBacklogAlerts(l *px1oRuntimeLab) []Alert {
	out := []Alert{}
	for _, a := range l.r.alerts {
		if a.Detail == px1oTrackBacklog {
			out = append(out, a)
		}
	}
	return out
}

// px1oSameTrack reports whether rec is the track record of transition t.
func px1oSameTrack(rec JournalRecordV2, t TrackTransition) bool {
	return rec.Kind == RecordTrack && rec.Track != nil && rec.TxID == t.Payment.TxID && rec.Nonce == t.Payment.Nonce &&
		rec.Track.State == t.Record.State && rec.Track.Height == t.Record.Height && rec.Track.BlockHash == t.Record.BlockHash
}

// Claim: while queued transitions cannot be written, the runtime does not
// poll the tracker (backpressure), keeps the queue as it was, and raises one
// backlog alert per episode, coded by the refusal (CLOCK_ROLLBACK raises
// ALERT_CLOCK_ROLLBACK, any other refusal ALERT_JOURNAL_HIGH_WATER), detail
// TRACK_BACKLOG. When the refusal clears, one pass writes the queued records
// first and then the tracker's next transition, each once and in order.
// Valid neighbour: the same passes without a refusal poll the tracker on
// every pass and raise no backlog alert.
func TestPX1oTrackBacklogBackpressure(t *testing.T) {
	for _, refuse := range []bool{false, true} {
		l := px1oNewRuntimeLab(t)
		counter := px1oCountTracker(l, false)
		w := l.env.wallet.(*px1oFakeJournal)
		transitions := []TrackTransition{}
		for n := 1; n <= 3; n++ {
			reserve := w.add(px1oLedgerReserve(n, 50000, px1oLedgerT0))
			w.add(px1oLedgerFollow(RecordComplete, "complete", reserve, px1oLedgerT0))
			transitions = append(transitions, TrackTransition{
				Payment: TrackedPayment{ReserveSeq: reserve.Seq, GrantID: reserve.GrantID, Nonce: reserve.Nonce, TxID: reserve.TxID, Inputs: reserve.Inputs},
				Record:  TrackRecordV2{State: TrackConfirmed, Height: 300, BlockHash: strings.Repeat("b", 64), Confirmations: 2},
			})
		}
		durable := len(w.records)
		want := ""
		if refuse {
			want = CodeClockRollback
			w.appendErr = errors.New(CodeClockRollback)
		}
		pass := func(name string) {
			t.Helper()
			e := l.r.tick(context.Background(), l.env)
			if (want == "" && e != nil) || (want != "" && (e == nil || e.Error() != want)) {
				t.Fatalf("refuse=%v %s: pass returned %v, want %q", refuse, name, e, want)
			}
		}
		l.tracker.out = append([]TrackTransition{}, transitions[:2]...)
		pass("first")
		l.tracker.out = append([]TrackTransition{}, transitions[2])
		pass("second")
		pass("third")
		if !refuse {
			if counter.ticks != 3 || len(w.records) != durable+3 || len(px1oBacklogAlerts(l)) != 0 {
				t.Fatalf("neighbour: %d polls, %d records, backlog alerts %v", counter.ticks, len(w.records)-durable, px1oBacklogAlerts(l))
			}
			continue
		}
		if counter.ticks != 1 || len(l.tracker.out) != 1 {
			t.Fatalf("TRACK_POLLED_WHILE_BACKLOGGED: %d polls during the refusal, %d transitions left in the tracker", counter.ticks, len(l.tracker.out))
		}
		if len(l.r.tracks) != 2 || len(w.records) != durable {
			t.Fatalf("TRACK_BACKLOG_QUEUE: %d queued, %d written during the refusal", len(l.r.tracks), len(w.records)-durable)
		}
		if a := px1oBacklogAlerts(l); len(a) != 1 || a[0].Code != AlertClockRollback {
			t.Fatalf("TRACK_BACKLOG_ALERT: want one ALERT_CLOCK_ROLLBACK for the episode, have %+v", a)
		}
		w.appendErr, want = nil, ""
		pass("recovery")
		if counter.ticks != 2 || len(l.r.tracks) != 0 || len(w.records) != durable+3 {
			t.Fatalf("TRACK_BACKLOG_RECOVERY: %d polls, %d queued, %d written", counter.ticks, len(l.r.tracks), len(w.records)-durable)
		}
		for i, rec := range w.records[durable:] {
			if !px1oSameTrack(rec, transitions[i]) {
				t.Fatalf("TRACK_BACKLOG_ORDER: record %d is %s %s, want transition %d", i, rec.Kind, rec.TxID, i)
			}
		}
		// A second episode with a non-clock refusal is a new alert.
		w.appendErr, want = errors.New("JOURNAL_RECORD_SIZE"), "JOURNAL_RECORD_SIZE"
		l.tracker.out = []TrackTransition{{Payment: transitions[0].Payment, Record: TrackRecordV2{State: TrackConflicted, Height: 301, BlockHash: strings.Repeat("b", 64), ConflictTxID: strings.Repeat("c", 64)}}}
		pass("second episode")
		pass("second episode again")
		if a := px1oBacklogAlerts(l); len(a) != 2 || a[1].Code != AlertJournalHighWater {
			t.Fatalf("TRACK_BACKLOG_ALERT: want a second episode alert ALERT_JOURNAL_HIGH_WATER, have %+v", a)
		}
	}
}

// Claim (boundary regression, track-transition-lost-on-append-refusal): with
// the real NewTracker/Tick over a supported number of payments (32769, below
// the 65536 tracked-payment bound) whose confirmation, reorg and
// reconfirmation would together queue more than px1oMaxTracked observations,
// every transition the tracker returns while appends refuse stays queued and
// the queue never exceeds px1oMaxTracked; after recovery the journal holds
// exactly one track record per returned transition, in the returned order,
// more than px1oMaxTracked records in total across two refusal episodes. The
// 2-payment batch is the valid neighbour. Node responses and the journal are
// isolated fixtures: a runtime-unit claim, not a service-wiring claim.
func TestPX1oTrackBacklogBoundary(t *testing.T) {
	for _, count := range []int{2, px1oMaxTracked/2 + 1} {
		l := px1oNewRuntimeLab(t)
		counter := px1oCountTracker(l, true)
		l.env.profile.JournalSpendCapacity = count*2 + 1
		w := l.env.wallet.(*px1oFakeJournal)
		txids := make([]string, 0, count)
		for n := 1; n <= count; n++ {
			rec := px1oLedgerReserve(n, 50000, px1oLedgerT0)
			rec.Nonce, rec.RequestHash, rec.TxID = fmt.Sprintf("%064x", n), fmt.Sprintf("%064x", 1<<20+n), fmt.Sprintf("%064x", 1<<21+n)
			rec.Inputs = []su.Point{{TxID: fmt.Sprintf("%064x", 1<<22+n), Vout: 0}}
			reserve := w.add(rec)
			w.add(px1oLedgerFollow(RecordComplete, "complete", reserve, px1oLedgerT0))
			txids = append(txids, reserve.TxID)
			l.chain.mined[reserve.TxID] = 198
		}
		durable := len(w.records)
		pass := func(name, want string) {
			t.Helper()
			e := l.r.tick(context.Background(), l.env)
			if (want == "" && e != nil) || (want != "" && (e == nil || e.Error() != want)) {
				t.Fatalf("payments=%d %s: pass returned %v, want %q", count, name, e, want)
			}
			written := len(w.records) - durable
			if len(l.r.tracks) > px1oMaxTracked {
				t.Fatalf("TRACK_QUEUE_UNBOUNDED payments=%d %s: %d queued", count, name, len(l.r.tracks))
			}
			if written+len(l.r.tracks) != len(counter.returned) {
				t.Fatalf("TRACK_OBSERVATION_DROPPED payments=%d %s: returned=%d written=%d queued=%d", count, name, len(counter.returned), written, len(l.r.tracks))
			}
		}
		// Episode 1: confirmation, then a reorg and reconfirmation, all
		// while every append refuses.
		w.appendErr = errors.New(CodeClockRollback)
		pass("confirm refused", CodeClockRollback)
		if len(counter.returned) != count {
			t.Fatalf("payments=%d: the real tracker returned %d confirmations", count, len(counter.returned))
		}
		l.chain.epoch++
		for _, txid := range txids {
			l.chain.mined[txid] = 200
		}
		pass("reorg refused", CodeClockRollback)
		l.chain.height++
		pass("reconfirm refused", CodeClockRollback)
		w.appendErr = nil
		pass("recovery", "")
		// Episode 2: depth lost, then reconfirmed while appends refuse.
		for _, txid := range txids {
			l.chain.mined[txid] = l.chain.height
		}
		pass("depth lost", "")
		w.appendErr = errors.New(CodeClockRollback)
		l.chain.height++
		pass("reconfirm refused again", CodeClockRollback)
		pass("still refused", CodeClockRollback)
		w.appendErr = nil
		pass("recovery again", "")
		written := w.records[durable:]
		if len(l.r.tracks) != 0 || len(written) != len(counter.returned) {
			t.Fatalf("TRACK_OBSERVATION_DROPPED payments=%d: returned=%d written=%d queued=%d", count, len(counter.returned), len(written), len(l.r.tracks))
		}
		if len(written) < 2*count || (count > 2 && len(written) <= px1oMaxTracked) {
			t.Fatalf("payments=%d: %d records do not cover both episodes across the %d bound", count, len(written), px1oMaxTracked)
		}
		for i, rec := range written {
			if !px1oSameTrack(rec, counter.returned[i]) {
				t.Fatalf("TRACK_BACKLOG_ORDER payments=%d: record %d is not returned transition %d", count, i, i)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Status equals the ledger over authenticated S2 journals (freeze amendment 1,
// A5 and A6).
//
// The fixture opens S2's wallet journal through the public OpenJournalV2 under
// a header whose ReceiptKey is the frozen executor key px1ExecutorKey, and
// signs each release just before its append, for the Seq that Append assigns
// (Usage().LastSeq+1), over the A6 preimage assembled here independently of
// the product:
//
//	SHA256("swarma-wallet-reconcile-v2" || canonical({binding, grant_id,
//	nonce, seq, reconcile with signature ""}))
//
// The digest is checked equal to the frozen ReconcileDigestV2, and the signed
// record is checked with the frozen VerifyReconcileV2 before it is appended.
// No S2 private name is used.

// px1oLedgerReceiptKeyN is the fixture receipt key: testKey(9), whose x-only
// public key is the frozen executor key px1ExecutorKey.
const px1oLedgerReceiptKeyN = 9

// px1oLedgerBinding is the Binding of the fixture wallet journal.
var px1oLedgerBinding = strings.Repeat("7", 64)

// px1oLedgerHeader is the fixture wallet-layer header naming receiptKey as
// the reconcile signer ("" names none, so every release refuses).
func px1oLedgerHeader(receiptKey string) JournalHeaderV2 {
	return JournalHeaderV2{Version: 2, Layer: JournalLayerWallet, Binding: px1oLedgerBinding, ReceiptKey: receiptKey}
}

// px1oLedgerKeyedHeader is the fixture header under the executor key. It
// fails the test unless testKey(9) is that key.
func px1oLedgerKeyedHeader(t *testing.T) JournalHeaderV2 {
	t.Helper()
	if _, xonly := testKey(px1oLedgerReceiptKeyN); xonly != px1ExecutorKey {
		t.Fatal("fixture receipt key is not the executor key")
	}
	return px1oLedgerHeader(px1ExecutorKey)
}

// px1oPrivateDir is a fresh 0700 state root: durable.Open requires 0700, and
// t.TempDir follows the process umask.
func px1oPrivateDir(t *testing.T) string {
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

// px1oOpenLedgerJournal opens a fresh S2 wallet journal through the public
// OpenJournalV2 under h.
func px1oOpenLedgerJournal(t *testing.T, h JournalHeaderV2) JournalV2 {
	t.Helper()
	j, e := OpenJournalV2(px1oPrivateDir(t), "journal-v2.lock", h, JournalLimitsV2{SpendCapacity: 8})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(j.Close)
	return j
}

// px1oSignDigest signs digest with testKey(n) and returns the hex signature.
func px1oSignDigest(t *testing.T, digest []byte, n byte) string {
	t.Helper()
	key, _ := testKey(n)
	sig, e := schnorr.Sign(key, digest)
	if e != nil {
		t.Fatal(e)
	}
	return hex.EncodeToString(sig.Serialize())
}

// px1oSignAt returns rec at position seq with its release signed by testKey(n)
// for the journal headed by h, over the A6 preimage assembled here. It fails
// the test (RECONCILE_PREIMAGE) unless that digest equals the frozen
// ReconcileDigestV2.
func px1oSignAt(t *testing.T, h JournalHeaderV2, rec JournalRecordV2, seq uint64, n byte) JournalRecordV2 {
	t.Helper()
	c := *rec.Reconcile
	c.Signature = ""
	rec.Seq, rec.Reconcile = seq, &c
	preimage := struct {
		Binding   string            `json:"binding"`
		GrantID   string            `json:"grant_id"`
		Nonce     string            `json:"nonce"`
		Seq       uint64            `json:"seq"`
		Reconcile ReconcileRecordV2 `json:"reconcile"`
	}{h.Binding, rec.GrantID, rec.Nonce, seq, c}
	digest := sha256.Sum256(append([]byte("swarma-wallet-reconcile-v2"), canonical(preimage)...))
	if frozen, e := ReconcileDigestV2(h, rec); e != nil || !bytes.Equal(frozen, digest[:]) {
		t.Fatalf("RECONCILE_PREIMAGE: the A6 preimage assembled in the test differs from ReconcileDigestV2 (%v)", e)
	}
	c.Signature = px1oSignDigest(t, digest[:], n)
	return rec
}

// px1oSignNext signs rec for the Seq that j's next Append assigns, under j's
// own header, as the operator tool does while it holds the journal lock.
func px1oSignNext(t *testing.T, j JournalV2, rec JournalRecordV2, n byte) JournalRecordV2 {
	t.Helper()
	return px1oSignAt(t, j.Header(), rec, j.Usage().LastSeq+1, n)
}

// px1oGenuineSignature is a genuine receipt-key signature for the context
// (h, rec at seq): testKey(n) over the frozen ReconcileDigestV2, the message
// the operator tool signs. The refusal control moves it to another context.
func px1oGenuineSignature(t *testing.T, h JournalHeaderV2, rec JournalRecordV2, seq uint64, n byte) string {
	t.Helper()
	rec.Seq = seq
	digest, e := ReconcileDigestV2(h, rec)
	if e != nil {
		t.Fatal(e)
	}
	return px1oSignDigest(t, digest, n)
}

// px1oWithSignature returns rec with a copy of its release carrying sig.
func px1oWithSignature(rec JournalRecordV2, sig string) JournalRecordV2 {
	c := *rec.Reconcile
	c.Signature = sig
	rec.Reconcile = &c
	return rec
}

// px1oFirstRelease is the index of the first reconcile record, or -1.
func px1oFirstRelease(j *px1oFakeJournal) int {
	for i, rec := range j.records {
		if rec.Kind == RecordReconcile {
			return i
		}
	}
	return -1
}

// px1oSignedLedgerJournal builds a phase case into an S2 wallet journal opened
// through the public OpenJournalV2 under the keyed header: every record of
// the case in order, each release signed for the Seq Append assigns and
// verified with VerifyReconcileV2 before it is appended.
func px1oSignedLedgerJournal(t *testing.T, build func(*px1oFakeJournal)) JournalV2 {
	t.Helper()
	h := px1oLedgerKeyedHeader(t)
	fake := px1oJournal(JournalLayerWallet)
	build(fake)
	j := px1oOpenLedgerJournal(t, h)
	for _, rec := range fake.records {
		want := rec.Seq
		if rec.Reconcile != nil {
			rec = px1oSignNext(t, j, rec, px1oLedgerReceiptKeyN)
			if e := VerifyReconcileV2(j.Header(), rec); e != nil {
				t.Fatalf("FIXTURE_RELEASE_UNVERIFIED seq %d: the fixture release does not verify under the header key: %v", rec.Seq, e)
			}
		}
		out, e := j.Append(rec)
		if e != nil {
			t.Fatalf("authenticated fixture record %d (%s) refused: %v", want, rec.Kind, e)
		}
		if out.Seq != want {
			t.Fatalf("fixture Seq %d stored as %d", want, out.Seq)
		}
	}
	return j
}

// Claim: S2's ledger folds a foreign JournalV2 release only when it verifies
// under that journal's own header key. For each of the five release cases: a
// foreign fake under the keyed header refuses the placeholder signature
// (RECONCILE_AUTHORIZATION), and a fake under ReceiptKey "" refuses even the
// genuine signatures. Valid neighbours: the seven cases without a release
// fold, and the keyed fake with genuine signatures folds to the case's
// independently written expectation.
func TestPX1oLedgerFoldsOnlySignedForeignRelease(t *testing.T) {
	h := px1oLedgerKeyedHeader(t)
	releases := 0
	for _, c := range px1oLedgerCases() {
		fake := px1oJournal(JournalLayerWallet)
		fake.header = h
		c.build(fake)
		_, foldErr := FoldLedgerV2(fake)
		if px1oFirstRelease(fake) < 0 {
			if foldErr != nil {
				t.Errorf("%s: a foreign journal without a release was refused: %v", c.name, foldErr)
			}
			continue
		}
		releases++
		if foldErr == nil || foldErr.Error() != CodeReconcileAuthorization {
			t.Errorf("UNAUTHENTICATED_RELEASE_ACCEPTED %s: foreign placeholder release folded (%v)", c.name, foldErr)
		}
		for i, rec := range fake.records {
			if rec.Reconcile != nil {
				fake.records[i] = px1oSignAt(t, h, rec, rec.Seq, px1oLedgerReceiptKeyN)
			}
		}
		fake.header = px1oLedgerHeader("")
		if _, e := FoldLedgerV2(fake); e == nil || e.Error() != CodeReconcileAuthorization {
			t.Errorf("UNAUTHENTICATED_RELEASE_ACCEPTED %s: a keyless foreign journal folded a release (%v)", c.name, e)
		}
		fake.header = h
		ledger, e := FoldLedgerV2(fake)
		if e != nil {
			t.Fatalf("%s: the keyed foreign journal with genuine releases was refused: %v", c.name, e)
		}
		used, count := ledger.DayUsage(px1oG, px1oStatusDay(px1oLedgerT0))
		if got := (px1oLedgerWant{ledger.SpendUsed(px1oG), ledger.UncertainSat(px1oG), used, count}); got != c.want[0] {
			t.Errorf("%s: the signed foreign journal folds to %+v, want %+v", c.name, got, c.want[0])
		}
	}
	if releases != 5 {
		t.Fatalf("expected five release cases, have %d", releases)
	}
}

// Claim: an unauthenticated or unbound release releases nothing. For each of
// the five release cases, S2's wallet journal (public OpenJournalV2) refuses
// RECONCILE_AUTHORIZATION, with LastSeq unchanged and the ledger and status
// still at the full reservation, for: the placeholder signature; a signature
// by another key; a payload altered after signing; a header with ReceiptKey
// "" (even for a genuine signature); and a genuine receipt-key signature over
// ReconcileDigestV2 made for another Binding, another grant_id, another
// nonce or another Seq. Valid neighbours: the records before the release
// append under every header, and on the keyed journal the release signed for
// this Binding, grant, nonce and the assigned Seq applies and lowers the
// ledger by its amount. Each row is a subtest, so a plant can select one.
func TestPX1oLedgerRefusesUnsignedRelease(t *testing.T) {
	h := px1oLedgerKeyedHeader(t)
	next := func(j JournalV2) uint64 { return j.Usage().LastSeq + 1 }
	genuine := func(j JournalV2, rec JournalRecordV2) JournalRecordV2 {
		return px1oWithSignature(rec, px1oGenuineSignature(t, j.Header(), rec, next(j), px1oLedgerReceiptKeyN))
	}
	otherBinding := h
	otherBinding.Binding = strings.Repeat("8", 64)
	rows := []struct {
		name   string
		marker string
		header JournalHeaderV2
		sign   func(j JournalV2, rec JournalRecordV2) JournalRecordV2
	}{
		{"placeholder-signature", "UNAUTHENTICATED_RELEASE_ACCEPTED", h, func(_ JournalV2, rec JournalRecordV2) JournalRecordV2 { return rec }},
		{"another-key", "UNAUTHENTICATED_RELEASE_ACCEPTED", h, func(j JournalV2, rec JournalRecordV2) JournalRecordV2 {
			return px1oWithSignature(rec, px1oGenuineSignature(t, j.Header(), rec, next(j), 8))
		}},
		{"note-altered-after-signing", "UNAUTHENTICATED_RELEASE_ACCEPTED", h, func(j JournalV2, rec JournalRecordV2) JournalRecordV2 {
			s := genuine(j, rec)
			s.Reconcile.NoteSHA256 = strings.Repeat("c", 64)
			return s
		}},
		{"empty-receipt-key", "UNAUTHENTICATED_RELEASE_ACCEPTED", px1oLedgerHeader(""), genuine},
		{"cross-binding", "UNBOUND_RELEASE_ACCEPTED", h, func(j JournalV2, rec JournalRecordV2) JournalRecordV2 {
			return px1oWithSignature(rec, px1oGenuineSignature(t, otherBinding, rec, next(j), px1oLedgerReceiptKeyN))
		}},
		{"cross-grant", "UNBOUND_RELEASE_ACCEPTED", h, func(j JournalV2, rec JournalRecordV2) JournalRecordV2 {
			moved := rec
			moved.GrantID = strings.Repeat("f", 64)
			return px1oWithSignature(rec, px1oGenuineSignature(t, j.Header(), moved, next(j), px1oLedgerReceiptKeyN))
		}},
		{"cross-nonce", "UNBOUND_RELEASE_ACCEPTED", h, func(j JournalV2, rec JournalRecordV2) JournalRecordV2 {
			moved := rec
			moved.Nonce = strings.Repeat("f", 64)
			return px1oWithSignature(rec, px1oGenuineSignature(t, j.Header(), moved, next(j), px1oLedgerReceiptKeyN))
		}},
		{"cross-seq", "UNBOUND_RELEASE_ACCEPTED", h, func(j JournalV2, rec JournalRecordV2) JournalRecordV2 {
			return px1oWithSignature(rec, px1oGenuineSignature(t, j.Header(), rec, next(j)+1, px1oLedgerReceiptKeyN))
		}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			releases := 0
			for _, c := range px1oLedgerCases() {
				fake := px1oJournal(JournalLayerWallet)
				c.build(fake)
				first := px1oFirstRelease(fake)
				if first < 0 {
					continue
				}
				releases++
				j := px1oOpenLedgerJournal(t, row.header)
				for _, rec := range fake.records[:first] {
					if _, e := j.Append(rec); e != nil {
						t.Fatalf("%s: record before the release refused: %v", c.name, e)
					}
				}
				before := j.Usage().LastSeq
				release := fake.records[first]
				if _, e := j.Append(row.sign(j, release)); e == nil || e.Error() != CodeReconcileAuthorization {
					t.Errorf("%s %s/%s: append returned %v, want %s", row.marker, row.name, c.name, e, CodeReconcileAuthorization)
					if e == nil {
						continue
					}
				}
				ledger, e := FoldLedgerV2(j)
				if e != nil {
					t.Fatalf("%s: ledger after the refusal: %v", c.name, e)
				}
				if j.Usage().LastSeq != before || ledger.SpendUsed(px1oG) != release.Reserved || px1oLedgerStatus(t, j, px1oLedgerT0).ReservedSat != release.Reserved {
					t.Errorf("%s %s/%s: seq %d->%d, ledger %d, want the full %d retained", row.marker, row.name, c.name, before, j.Usage().LastSeq, ledger.SpendUsed(px1oG), release.Reserved)
				}
				if row.header.ReceiptKey == "" {
					continue
				}
				out, e := j.Append(px1oSignNext(t, j, release, px1oLedgerReceiptKeyN))
				if e != nil || out.Seq != before+1 {
					t.Fatalf("%s: the correctly bound release was refused or misplaced: %v (seq %d)", c.name, e, out.Seq)
				}
				if ledger, e = FoldLedgerV2(j); e != nil || ledger.SpendUsed(px1oG) != release.Reserved-release.Reconcile.ReleasedSat {
					t.Fatalf("%s: the signed release did not lower the ledger: %v", c.name, e)
				}
			}
			if releases != 5 {
				t.Fatalf("expected five release cases, have %d", releases)
			}
		})
	}
}
