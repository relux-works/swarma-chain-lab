package wallet

// Owner S3. Revision 3 regression tests: tracker observations are never
// discarded while the wallet journal refuses their track records (retry
// first, then backpressure instead of compaction), and the status-versus-
// ledger equivalence runs over authenticated S2 journals while unsigned
// releases stay refused.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
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
// Status equals the ledger over authenticated S2 journals.
//
// The fixture uses S2's pre-amendment keyed seam: px1jOpenJournal with a
// receipt key, and the v1 signing preimage
// SHA256("swarma-wallet-reconcile-v1" || canonical(reconcile with
// signature "")), computed here and checked equal to px1jReconcileDigest, and
// each signature checked with px1jReconcileSigned before it is appended.
//
// Migration when freeze amendment 1 lands (ReceiptKey in the header, the
// v2 preimage):
//  1. open the wallet journal with the public OpenJournalV2 and a header
//     whose ReceiptKey is the fixture key (px1ExecutorKey), not with
//     px1jOpenJournal and a separate key argument;
//  2. sign ReconcileDigestV2(header, rec), that is SHA256(
//     "swarma-wallet-reconcile-v2" || canonical(ReconcilePreimageV2{Binding,
//     GrantID, Nonce, Seq, Reconcile with signature ""})), where Seq is the
//     Seq Append will assign (Usage().LastSeq+1), and check it with
//     VerifyReconcileV2 instead of px1jReconcileSigned;
//  3. keep the expected values and the refusal control unchanged, and add
//     refusals for a release signed under another Binding, another grant or
//     nonce, and another Seq (all RECONCILE_AUTHORIZATION).

// px1oLedgerReceiptKeyN is the fixture receipt key: testKey(9), whose x-only
// public key is the frozen executor key px1ExecutorKey.
const px1oLedgerReceiptKeyN = 9

func px1oLedgerReceiptKey(t *testing.T) *btcec.PublicKey {
	t.Helper()
	priv, xonly := testKey(px1oLedgerReceiptKeyN)
	if xonly != px1ExecutorKey {
		t.Fatal("fixture receipt key is not the executor key")
	}
	key, e := schnorr.ParsePubKey(schnorr.SerializePubKey(priv.PubKey()))
	if e != nil {
		t.Fatal(e)
	}
	return key
}

// px1oOpenLedgerJournal opens a fresh S2 wallet-layer journal. A nil key is
// the frozen public OpenJournalV2, which has no receipt key.
func px1oOpenLedgerJournal(t *testing.T, key *btcec.PublicKey) JournalV2 {
	t.Helper()
	h := JournalHeaderV2{Version: 2, Layer: JournalLayerWallet, Binding: strings.Repeat("7", 64)}
	l := JournalLimitsV2{SpendCapacity: 8}
	var j JournalV2
	var e error
	if key == nil {
		j, e = OpenJournalV2(px1jPrivateDir(t), "journal-v2.lock", h, l)
	} else {
		j, e = px1jOpenJournal(px1jPrivateDir(t), "journal-v2.lock", h, l, key)
	}
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(j.Close)
	return j
}

// px1oSignRelease signs a reconcile payload with testKey(n) over the frozen
// v1 preimage, computed here independently of S2's digest function.
func px1oSignRelease(t *testing.T, c ReconcileRecordV2, n byte) *ReconcileRecordV2 {
	t.Helper()
	c.Signature = ""
	digest := sha256.Sum256(append([]byte("swarma-wallet-reconcile-v1"), canonical(c)...))
	if digest != px1jReconcileDigest(c) {
		t.Fatal("RECONCILE_PREIMAGE: S2's digest is not the frozen preimage")
	}
	key, _ := testKey(n)
	sig, e := schnorr.Sign(key, digest[:])
	if e != nil {
		t.Fatal(e)
	}
	c.Signature = hex.EncodeToString(sig.Serialize())
	return &c
}

// px1oSignedLedgerJournal builds a phase case into an S2 keyed wallet journal:
// every record of the case in order, each release signed by the receipt key.
func px1oSignedLedgerJournal(t *testing.T, build func(*px1oFakeJournal)) JournalV2 {
	t.Helper()
	key := px1oLedgerReceiptKey(t)
	fake := px1oJournal(JournalLayerWallet)
	build(fake)
	j := px1oOpenLedgerJournal(t, key)
	for _, rec := range fake.records {
		if rec.Reconcile != nil {
			rec.Reconcile = px1oSignRelease(t, *rec.Reconcile, px1oLedgerReceiptKeyN)
			if !px1jReconcileSigned(*rec.Reconcile, key) {
				t.Fatal("fixture release does not verify under the receipt key")
			}
		}
		out, e := j.Append(rec)
		if e != nil {
			t.Fatalf("authenticated fixture record %d (%s) refused: %v", rec.Seq, rec.Kind, e)
		}
		if out.Seq != rec.Seq {
			t.Fatalf("fixture Seq %d stored as %d", rec.Seq, out.Seq)
		}
	}
	return j
}

// Claim: an unauthenticated release releases nothing. For each of the five
// release cases: S2's ledger refuses the foreign fake journal carrying the
// placeholder-signature release (JOURNAL_RECORD); a keyed S2 journal refuses
// the placeholder signature, a signature by another key and a payload altered
// after signing (RECONCILE_AUTHORIZATION), with no record written and the
// ledger and status still at the full reservation; and the keyless public
// journal refuses even a correctly signed release. Valid neighbours: the
// foreign journals of the seven cases without a release fold, the keyless
// journal accepts the records before the release, and the keyed journal then
// accepts the correctly signed release and lowers the ledger by its amount.
func TestPX1oLedgerRefusesUnsignedRelease(t *testing.T) {
	key := px1oLedgerReceiptKey(t)
	releases := 0
	for _, c := range px1oLedgerCases() {
		fake := px1oJournal(JournalLayerWallet)
		c.build(fake)
		first := -1
		for i, rec := range fake.records {
			if rec.Kind == RecordReconcile && first < 0 {
				first = i
			}
		}
		_, foldErr := FoldLedgerV2(fake)
		if first < 0 {
			if foldErr != nil {
				t.Errorf("%s: a foreign journal without a release was refused: %v", c.name, foldErr)
			}
			continue
		}
		releases++
		if foldErr == nil || foldErr.Error() != "JOURNAL_RECORD" {
			t.Errorf("UNAUTHENTICATED_RELEASE_ACCEPTED %s: foreign placeholder release folded (%v)", c.name, foldErr)
		}
		release := fake.records[first]
		for _, v := range []struct {
			name  string
			keyed bool
			sign  func(ReconcileRecordV2) *ReconcileRecordV2
		}{
			{"placeholder signature", true, func(r ReconcileRecordV2) *ReconcileRecordV2 { return &r }},
			{"another key", true, func(r ReconcileRecordV2) *ReconcileRecordV2 { return px1oSignRelease(t, r, 8) }},
			{"note altered after signing", true, func(r ReconcileRecordV2) *ReconcileRecordV2 {
				s := px1oSignRelease(t, r, px1oLedgerReceiptKeyN)
				s.NoteSHA256 = strings.Repeat("c", 64)
				return s
			}},
			{"no receipt key", false, func(r ReconcileRecordV2) *ReconcileRecordV2 { return px1oSignRelease(t, r, px1oLedgerReceiptKeyN) }},
		} {
			var jkey *btcec.PublicKey
			if v.keyed {
				jkey = key
			}
			j := px1oOpenLedgerJournal(t, jkey)
			for _, rec := range fake.records[:first] {
				if _, e := j.Append(rec); e != nil {
					t.Fatalf("%s/%s: record before the release refused: %v", c.name, v.name, e)
				}
			}
			before := j.Usage().LastSeq
			rec := release
			rec.Reconcile = v.sign(*release.Reconcile)
			if _, e := j.Append(rec); e == nil || e.Error() != "RECONCILE_AUTHORIZATION" {
				t.Errorf("UNAUTHENTICATED_RELEASE_ACCEPTED %s/%s: append returned %v", c.name, v.name, e)
			}
			ledger, e := FoldLedgerV2(j)
			if e != nil {
				t.Fatalf("%s/%s: ledger after the refusal: %v", c.name, v.name, e)
			}
			if j.Usage().LastSeq != before || ledger.SpendUsed(px1oG) != release.Reserved || px1oLedgerStatus(t, j, px1oLedgerT0).ReservedSat != release.Reserved {
				t.Errorf("UNAUTHENTICATED_RELEASE_ACCEPTED %s/%s: seq %d->%d, ledger %d, want the full %d retained", c.name, v.name, before, j.Usage().LastSeq, ledger.SpendUsed(px1oG), release.Reserved)
			}
			if !v.keyed {
				continue
			}
			rec.Reconcile = px1oSignRelease(t, *release.Reconcile, px1oLedgerReceiptKeyN)
			if _, e := j.Append(rec); e != nil {
				t.Fatalf("%s/%s: the correctly signed release was refused: %v", c.name, v.name, e)
			}
			if ledger, e = FoldLedgerV2(j); e != nil || ledger.SpendUsed(px1oG) != release.Reserved-release.Reconcile.ReleasedSat {
				t.Fatalf("%s/%s: the signed release did not lower the ledger: %v", c.name, v.name, e)
			}
		}
	}
	if releases != 5 {
		t.Fatalf("expected five release cases, have %d", releases)
	}
}
