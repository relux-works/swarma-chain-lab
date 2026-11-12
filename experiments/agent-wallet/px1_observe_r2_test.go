package wallet

// Owner S3. Revision 2 regression tests: status equals the ledger in every
// accounting phase, tracker transitions survive a refused append, the G2
// admission halt seam, uncertain-verdict alerts of both layers, typed alert
// details and the status socket access contract (S5 R3, T19).

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// ---------------------------------------------------------------------------
// Status equals the ledger.

// px1oLedgerT0 is 2026-11-06 21:30:00 UTC (day D); D+1 is a day later.
const px1oLedgerT0 int64 = 1794000600

// px1oLedgerReserve is a wallet-layer reserve record that the S2 journal
// table accepts: day = UTCDay(last_time), fee below the reservation, one
// input, hex request hash and txid.
func px1oLedgerReserve(n int, reserved int64, at int64) JournalRecordV2 {
	return JournalRecordV2{Kind: RecordReserve, GrantID: px1oG, Nonce: px1oHex('1', n), RequestHash: px1oHex('9', n), Action: "spend", Phase: "reserved", Reserved: reserved, Fee: 1000,
		Day: px1oStatusDay(at), Inputs: []su.Point{{TxID: px1oHex('e', n), Vout: 0}}, TxID: px1oHex('d', n), Created: at, LastTime: at}
}

func px1oLedgerFollow(kind, phase string, reserve JournalRecordV2, at int64) JournalRecordV2 {
	r := reserve
	r.Kind, r.Phase, r.LastTime = kind, phase, at
	return r
}

func px1oLedgerTrack(state string, reserve JournalRecordV2, at int64) JournalRecordV2 {
	r := px1oLedgerFollow(RecordTrack, state, reserve, at)
	t := TrackRecordV2{State: state, Height: 300, BlockHash: strings.Repeat("b", 64)}
	if state == TrackConfirmed {
		t.Confirmations = 2
	} else {
		t.ConflictTxID = strings.Repeat("c", 64)
	}
	r.Track = &t
	return r
}

func px1oLedgerRelease(reserve JournalRecordV2, sat int64, at int64) JournalRecordV2 {
	r := px1oLedgerFollow(RecordReconcile, "released", reserve, at)
	r.Reconcile = &ReconcileRecordV2{TargetSeq: reserve.Seq, Evidence: "absent", Height: 300, BlockHash: strings.Repeat("a", 64), ReleasedSat: sat, NoteSHA256: strings.Repeat("b", 64), Signature: strings.Repeat("ab", 64)}
	return r
}

// px1oLedgerWant is one day's expected grant numbers.
type px1oLedgerWant struct {
	reserved, uncertain, dayUsed int64
	dayCount                     int
}

// px1oLedgerCases builds one request of 50000 atoms reserved on day D in each
// accounting phase. want[0] is day D, want[1] is day D+1 (UTC rollover).
func px1oLedgerCases() []struct {
	name  string
	build func(w *px1oFakeJournal)
	want  [2]px1oLedgerWant
} {
	const a = 50000
	t := px1oLedgerT0 - 7300 // 19:28 UTC on day D
	return []struct {
		name  string
		build func(w *px1oFakeJournal)
		want  [2]px1oLedgerWant
	}{
		{"reserved", func(w *px1oFakeJournal) { w.add(px1oLedgerReserve(1, a, t)) },
			[2]px1oLedgerWant{{a, a, a, 1}, {a, a, a, 1}}},
		{"uncertain", func(w *px1oFakeJournal) {
			r := w.add(px1oLedgerReserve(1, a, t))
			w.add(px1oLedgerFollow(RecordUncertain, "uncertain", r, t+10))
		}, [2]px1oLedgerWant{{a, a, a, 1}, {a, a, a, 1}}},
		{"complete", func(w *px1oFakeJournal) {
			r := w.add(px1oLedgerReserve(1, a, t))
			w.add(px1oLedgerFollow(RecordComplete, "complete", r, t+10))
		}, [2]px1oLedgerWant{{a, 0, a, 1}, {a, 0, 0, 0}}},
		{"refuse-retained", func(w *px1oFakeJournal) {
			r := w.add(px1oLedgerReserve(1, a, t))
			w.add(px1oLedgerFollow(RecordRefuseRetained, "refused", r, t+10))
		}, [2]px1oLedgerWant{{a, 0, a, 1}, {a, 0, 0, 0}}},
		{"complete+track-confirmed", func(w *px1oFakeJournal) {
			r := w.add(px1oLedgerReserve(1, a, t))
			w.add(px1oLedgerFollow(RecordComplete, "complete", r, t+10))
			w.add(px1oLedgerTrack(TrackConfirmed, r, t+20))
		}, [2]px1oLedgerWant{{a, 0, a, 1}, {a, 0, 0, 0}}},
		{"uncertain+track-conflicted", func(w *px1oFakeJournal) {
			r := w.add(px1oLedgerReserve(1, a, t))
			w.add(px1oLedgerFollow(RecordUncertain, "uncertain", r, t+10))
			w.add(px1oLedgerTrack(TrackConflicted, r, t+20))
		}, [2]px1oLedgerWant{{a, a, a, 1}, {a, a, a, 1}}},
		{"reserved+track-confirmed", func(w *px1oFakeJournal) {
			r := w.add(px1oLedgerReserve(1, a, t))
			w.add(px1oLedgerTrack(TrackConfirmed, r, t+20))
		}, [2]px1oLedgerWant{{a, a, a, 1}, {a, a, a, 1}}},
		{"complete+full-release", func(w *px1oFakeJournal) {
			r := w.add(px1oLedgerReserve(1, a, t))
			w.add(px1oLedgerFollow(RecordComplete, "complete", r, t+10))
			w.add(px1oLedgerRelease(r, a, t+20))
		}, [2]px1oLedgerWant{{0, 0, 0, 1}, {0, 0, 0, 0}}},
		{"uncertain+full-release", func(w *px1oFakeJournal) {
			r := w.add(px1oLedgerReserve(1, a, t))
			w.add(px1oLedgerFollow(RecordUncertain, "uncertain", r, t+10))
			w.add(px1oLedgerRelease(r, a, t+20))
		}, [2]px1oLedgerWant{{0, 0, 0, 1}, {0, 0, 0, 0}}},
		{"uncertain+partial-release", func(w *px1oFakeJournal) {
			r := w.add(px1oLedgerReserve(1, a, t))
			w.add(px1oLedgerFollow(RecordUncertain, "uncertain", r, t+10))
			w.add(px1oLedgerRelease(r, 1, t+20))
		}, [2]px1oLedgerWant{{a - 1, a - 1, a - 1, 1}, {a - 1, a - 1, a - 1, 1}}},
		{"complete+partial-release", func(w *px1oFakeJournal) {
			r := w.add(px1oLedgerReserve(1, a, t))
			w.add(px1oLedgerFollow(RecordComplete, "complete", r, t+10))
			w.add(px1oLedgerRelease(r, 20000, t+20))
		}, [2]px1oLedgerWant{{a - 20000, 0, a - 20000, 1}, {a - 20000, 0, 0, 0}}},
		{"uncertain+partial-then-full-release", func(w *px1oFakeJournal) {
			r := w.add(px1oLedgerReserve(1, a, t))
			w.add(px1oLedgerFollow(RecordUncertain, "uncertain", r, t+10))
			w.add(px1oLedgerRelease(r, 1, t+20))
			w.add(px1oLedgerRelease(r, a-1, t+20+ReconcileMinIntervalSeconds))
		}, [2]px1oLedgerWant{{0, 0, 0, 1}, {0, 0, 0, 0}}},
	}
}

func px1oLedgerStatus(t *testing.T, w JournalV2, now int64) StatusGrant {
	t.Helper()
	s := px1oJournal(JournalLayerService)
	s.usage = JournalUsageV2{SpendCapacity: 2048, Segments: 1}
	in := StatusInputs{Service: s, Wallet: w, Limits: []EffectiveLimits{{GrantID: px1oG, TotalCapSat: 500000, SpendCapSat: 500000, TransferCapSat: 100000, DayCapSat: 300000, DayCountCap: 5}},
		ReceiptKey: px1ExecutorKey, Network: "regtest", Now: now}
	p, e := ProjectStatus(in)
	if e != nil {
		t.Fatal(e)
	}
	return p.Grants[0]
}

// Claim: the status grant numbers follow the ledger rule in every accounting
// phase on day D and after the UTC rollover to D+1, against expected values
// written from the frozen rule (not from either implementation): reserved
// and uncertain requests carry into D+1 and count as uncertain_sat; complete
// and refuse-retained ones stay on D; a track record changes nothing; a
// release lowers atoms but never today's request count; a partial release
// keeps an open request open; only a full release closes it. The pairs
// (with and without track, partial and full release) are each other's
// valid neighbours.
func TestPX1oStatusLedgerPhases(t *testing.T) {
	for _, c := range px1oLedgerCases() {
		w := px1oJournal(JournalLayerWallet)
		c.build(w)
		for i, now := range []int64{px1oLedgerT0, px1oLedgerT0 + 86400} {
			g := px1oLedgerStatus(t, w, now)
			got := px1oLedgerWant{g.ReservedSat, g.UncertainSat, g.DayUsedSat, g.DayCount}
			if got != c.want[i] {
				t.Errorf("STATUS_LEDGER_PHASE %s day+%d: got %+v want %+v", c.name, i, got, c.want[i])
			}
			if g.DayCountRemaining != 5-c.want[i].dayCount || g.DayRemainingSat != 300000-c.want[i].dayUsed || g.TotalRemainingSat != 500000-c.want[i].reserved {
				t.Errorf("STATUS_LEDGER_PHASE %s day+%d: remaining values inconsistent: %+v", c.name, i, g)
			}
		}
	}
}

// Claim: over authenticated S2 wallet journals (the public OpenJournalV2
// under a header whose ReceiptKey is the executor key; every release signed
// by that key over the A6 digest, which binds the journal Binding, grant_id,
// nonce and the Seq Append assigns), the status grant numbers equal S2's
// FoldLedgerV2 (SpendUsed, DayUsage, UncertainSat) and the independently
// written expectations, on day D and D+1, for all 12 phase cases including
// the five full/partial release cases. The unsigned and unbound release
// records of the same cases are refused by
// TestPX1oLedgerRefusesUnsignedRelease, the refusal neighbour.
func TestPX1oStatusMatchesLedgerPhases(t *testing.T) {
	for _, c := range px1oLedgerCases() {
		t.Run(c.name, func(t *testing.T) {
			w := px1oSignedLedgerJournal(t, c.build)
			ledger, e := FoldLedgerV2(w)
			if e != nil {
				t.Fatalf("STATUS_NOT_LEDGER %s: ledger refused the authenticated journal: %v", c.name, e)
			}
			for i, now := range []int64{px1oLedgerT0, px1oLedgerT0 + 86400} {
				g := px1oLedgerStatus(t, w, now)
				used, count := ledger.DayUsage(px1oG, g.Day)
				if got := (px1oLedgerWant{g.ReservedSat, g.UncertainSat, g.DayUsedSat, g.DayCount}); got != c.want[i] {
					t.Errorf("STATUS_LEDGER_PHASE %s day+%d: authenticated status %+v want %+v", c.name, i, got, c.want[i])
				}
				if ledger.SpendUsed(px1oG) != g.ReservedSat || used != g.DayUsedSat || count != g.DayCount || ledger.UncertainSat(px1oG) != g.UncertainSat {
					t.Errorf("STATUS_NOT_LEDGER %s day+%d: status %d/%d/%d/%d ledger %d/%d/%d/%d", c.name, i, g.ReservedSat, g.UncertainSat, g.DayUsedSat, g.DayCount, ledger.SpendUsed(px1oG), ledger.UncertainSat(px1oG), used, count)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Track transitions survive a refused append.

// px1oRefuseNth makes the n-th following Append call (1-based) refuse code.
func px1oRefuseNth(j *px1oFakeJournal, n int, code string) {
	calls := 0
	j.appendHook = func(JournalRecordV2) error {
		calls++
		if calls == n {
			return errors.New(code)
		}
		return nil
	}
}

// Claim: when one pass yields two transitions and the second append refuses
// CLOCK_ROLLBACK, the first record is written once, the refused one is
// retried on the next pass (although the tracker reports nothing new) and
// written exactly once, in order; the conflict alert is raised once, on
// observation, not again on the retry, and the refusal raises one backlog
// alert (ALERT_CLOCK_ROLLBACK, detail TRACK_BACKLOG). Valid neighbour:
// TestPX1RuntimeTrackRecords (no refusal: every record written in its own pass).
func TestPX1oTrackAppendPartialRetry(t *testing.T) {
	l := px1oNewRuntimeLab(t)
	w := l.env.wallet.(*px1oFakeJournal)
	ra := w.add(px1oReserve(px1oG, px1oN1, px1oTx1, 50000, "2026-11-06", px1oPoint('e', 1)))
	w.add(px1oFollow(RecordComplete, "complete", ra))
	rb := w.add(px1oReserve(px1oG, px1oN2, px1oTx2, 40000, "2026-11-06", px1oPoint('e', 2)))
	w.add(px1oFollow(RecordComplete, "complete", rb))
	pa := TrackedPayment{GrantID: px1oG, Nonce: px1oN1, TxID: px1oTx1, Inputs: ra.Inputs, ReserveSeq: ra.Seq}
	pb := TrackedPayment{GrantID: px1oG, Nonce: px1oN2, TxID: px1oTx2, Inputs: rb.Inputs, ReserveSeq: rb.Seq}
	l.tracker.out = []TrackTransition{
		{Payment: pa, Record: TrackRecordV2{State: TrackConfirmed, Height: 202, BlockHash: strings.Repeat("b", 64), Confirmations: 2}},
		{Payment: pb, Record: TrackRecordV2{State: TrackConflicted, Height: 202, BlockHash: strings.Repeat("b", 64), ConflictTxID: strings.Repeat("c", 64)}},
	}
	px1oRefuseNth(w, 2, CodeClockRollback)
	if e := l.r.tick(context.Background(), l.env); e == nil || e.Error() != CodeClockRollback {
		t.Fatalf("refused append not returned: %v", e)
	}
	if len(w.records) != 5 || w.records[4].TxID != px1oTx1 || len(l.r.tracks) != 1 {
		t.Fatalf("TRACK_PARTIAL: want the first record written and the second queued, have %d records, %d queued", len(w.records), len(l.r.tracks))
	}
	w.appendHook = nil
	l.env.now++
	if e := l.r.tick(context.Background(), l.env); e != nil {
		t.Fatal("recovery pass", e)
	}
	if e := l.r.tick(context.Background(), l.env); e != nil {
		t.Fatal("idle pass", e)
	}
	if len(w.records) != 6 || w.records[5].Kind != RecordTrack || w.records[5].TxID != px1oTx2 || w.records[5].Track.State != TrackConflicted || len(l.r.tracks) != 0 {
		t.Fatalf("TRACK_RETRY_LOST: want the refused record written exactly once on retry, have %d records", len(w.records))
	}
	if strings.Join(l.codes(), ",") != AlertPaymentConflicted+","+AlertClockRollback || l.r.alerts[1].Detail != px1oTrackBacklog {
		t.Fatalf("conflict alert not exactly once, or backlog alert not exactly once: %v", l.codes())
	}
}

// Claim: a transition refused before a restart is not lost: the restarted
// runtime reloads the tracker from the durable journal (no track record, so
// the payment is pending again), observes the same transition and writes
// exactly one track record. Valid neighbour: the same restart after a
// successful write appends nothing more.
func TestPX1oTrackAppendRefusedThenRestart(t *testing.T) {
	l := px1oNewRuntimeLab(t)
	l.r.deps.newTracker = NewTracker
	w := l.env.wallet.(*px1oFakeJournal)
	reserve := w.add(px1oReserve(px1oG, px1oN1, px1oTx1, 50000, "2026-11-06", su.Point{TxID: px1oTx2, Vout: 0}))
	w.add(px1oFollow(RecordComplete, "complete", reserve))
	l.chain.mined[px1oTx1] = 198
	w.appendErr = errors.New(CodeClockRollback)
	if e := l.r.tick(context.Background(), l.env); e == nil || e.Error() != CodeClockRollback {
		t.Fatalf("expected clock refusal, got %v", e)
	}
	w.appendErr = nil
	restart := func() *px1Runtime {
		deps := *l.r.deps
		return &px1Runtime{deps: &deps, sink: NewLogAlertSink(nil)}
	}
	for pass, want := range []int{3, 3} {
		r := restart()
		l.env.now++
		if e := r.tick(context.Background(), l.env); e != nil {
			t.Fatal(e)
		}
		if len(w.records) != want || w.records[2].Kind != RecordTrack || w.records[2].Track.State != TrackConfirmed {
			t.Fatalf("TRACK_RESTART_LOST pass %d: have %d records, want %d", pass, len(w.records), want)
		}
	}
}

// Claim: a transition of a request whose whole debit was released is dropped
// without a track record and without failing the pass (the journal table
// accepts no track after a full release, so a queued one would block every
// later record); a partially released request (valid neighbour) still gets
// its track record.
func TestPX1oTrackSkipsReleased(t *testing.T) {
	for _, c := range []struct {
		release int64
		records int
	}{{50000, 3}, {1, 4}} {
		l := px1oNewRuntimeLab(t)
		w := l.env.wallet.(*px1oFakeJournal)
		reserve := w.add(px1oReserve(px1oG, px1oN1, px1oTx1, 50000, "2026-11-06", px1oPoint('e', 1)))
		w.add(px1oFollow(RecordComplete, "complete", reserve))
		rec := px1oFollow(RecordReconcile, "released", reserve)
		rec.Reconcile = &ReconcileRecordV2{TargetSeq: reserve.Seq, Evidence: "absent", ReleasedSat: c.release}
		w.add(rec)
		pay := TrackedPayment{GrantID: px1oG, Nonce: px1oN1, TxID: px1oTx1, Inputs: reserve.Inputs, ReserveSeq: reserve.Seq}
		l.tracker.out = []TrackTransition{{Payment: pay, Record: TrackRecordV2{State: TrackConfirmed, Height: 202, BlockHash: strings.Repeat("b", 64), Confirmations: 2}}}
		if e := l.r.tick(context.Background(), l.env); e != nil {
			t.Fatal(e)
		}
		if len(w.records) != c.records || len(l.r.tracks) != 0 {
			t.Fatalf("TRACK_AFTER_RELEASE: release %d left %d records (want %d), %d queued", c.release, len(w.records), c.records, len(l.r.tracks))
		}
	}
}

// ---------------------------------------------------------------------------
// Admission halt seam (S2 request: FLOAT_CANARY_SPENT).

// Claim: the halt seam refuses FLOAT_CANARY_SPENT exactly when the canary was
// observed spent (T14 service half), keeps a sticky reconciliation refusal,
// refuses SERVICE_STATE_UNAVAILABLE before the first pass and while the last
// canary read is unknown (unknown never admits), also through the service's
// bound runtime (a fresh service, integration), and admits ("") after a pass
// with an unspent canary (valid neighbour), also once a later read recovers.
func TestPX1oHalted(t *testing.T) {
	var fresh ActionService
	if got := fresh.px1oHalted(); got != "SERVICE_STATE_UNAVAILABLE" {
		t.Fatalf("HALT_NOT_READY: a fresh service runtime admitted before the first pass: %q", got)
	}
	l := px1oNewRuntimeLab(t)
	if got := l.r.halted(); got != "SERVICE_STATE_UNAVAILABLE" {
		t.Fatalf("HALT_NOT_READY: admitted before the first pass: %q", got)
	}
	if e := l.r.tick(context.Background(), l.env); e != nil || l.r.halted() != "" {
		t.Fatalf("unspent canary after a pass must admit: %v %q", e, l.r.halted())
	}
	l.canary.state = CanaryUnknown
	l.r.tick(context.Background(), l.env)
	if got := l.r.halted(); got != "SERVICE_STATE_UNAVAILABLE" {
		t.Fatalf("HALT_UNKNOWN: unknown canary admitted: %q", got)
	}
	l.canary.state = CanaryUnspent
	if l.r.tick(context.Background(), l.env); l.r.halted() != "" {
		t.Fatal("recovered canary read must admit again")
	}
	l.canary.state = CanarySpent
	l.r.tick(context.Background(), l.env)
	l.canary.state = CanaryUnspent
	l.r.tick(context.Background(), l.env)
	if got := l.r.halted(); got != CodeFloatCanarySpent {
		t.Fatalf("HALT_CANARY: spent canary must refuse FLOAT_CANARY_SPENT, got %q", got)
	}
	r := px1oNewRuntimeLab(t)
	r.reconciler.err = errors.New(CodeStateReconcileRequired)
	r.r.tick(context.Background(), r.env)
	if got := r.r.halted(); got != CodeStateReconcileRequired {
		t.Fatalf("HALT_RECONCILE: %q", got)
	}
}

// ---------------------------------------------------------------------------
// Alerts.

// Claim: a service-layer terminal record whose receipt verdict is uncertain
// raises ALERT_UNCERTAIN_VERDICT once with its bounded reason code, a refused
// or executed terminal record (valid neighbours) raises nothing, and a later
// pass does not raise it again.
func TestPX1oUncertainServiceVerdict(t *testing.T) {
	l := px1oNewRuntimeLab(t)
	s := l.env.service.(*px1oFakeJournal)
	for _, v := range []struct{ verdict, reason string }{{"refused", "TRANSFER_CAP_EXCEEDED"}, {"executed", "EXECUTED"}, {"uncertain", "BROADCAST_UNCERTAIN"}} {
		s.add(JournalRecordV2{Kind: RecordTerminal, Service: &ServiceRecordV2{Receipt: &SignedActionReceipt{Receipt: ActionReceipt{Verdict: v.verdict, Reason: v.reason}}}})
	}
	for i := 0; i < 2; i++ {
		if e := l.r.tick(context.Background(), l.env); e != nil {
			t.Fatal(e)
		}
	}
	if len(l.r.alerts) != 1 || l.r.alerts[0] != (Alert{Code: AlertUncertainVerdict, At: l.env.now, Detail: "BROADCAST_UNCERTAIN"}) {
		t.Fatalf("SERVICE_UNCERTAIN_ALERT: want one alert for the uncertain verdict, have %+v", l.r.alerts)
	}
}

// Claim: an alert detail passes only in a typed public shape (bounded code,
// 64-hex id, outpoint, decimal, ratio, empty); a lowercase or mixed-case
// alphanumeric marker, a key=value pair or an oversized value is REDACTED.
// Limit: a 64-hex value has the txid shape and passes, so this is a shape
// allowlist, not a secret detector.
func TestPX1oAlertDetailShapes(t *testing.T) {
	tx := strings.Repeat("d", 64)
	for _, ok := range []string{"", "CLOCK_ROLLBACK", tx, tx + ":1", "1639.2048", "400000"} {
		if !px1oDetailSafe(ok) {
			t.Errorf("typed detail %q refused", ok)
		}
	}
	for _, bad := range []string{"syntheticSensitiveMarker", "hunter2secret", "password=abc", "Key:1", tx + ":x", "1.2.3", "-5", strings.Repeat("d", 65)} {
		if px1oDetailSafe(bad) {
			t.Errorf("DETAIL_NOT_TYPED: %q accepted", bad)
		}
	}
	a, _ := px1oSanitizeAlert(Alert{Code: AlertFloatLow, Detail: "syntheticSensitiveMarker"})
	if a.Detail != "REDACTED" {
		t.Fatal("sanitizer kept an untyped detail")
	}
}

// ---------------------------------------------------------------------------
// Status socket access (S5 R3, T19).

// px1oShortDir is a private directory with a short path: an AF_UNIX socket
// path is limited to 107 bytes, and t.TempDir embeds the test name.
func px1oShortDir(t *testing.T) string {
	t.Helper()
	dir, e := os.MkdirTemp("", "s3")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// Claim: the status socket refuses to start when the agent account (peer_uid)
// is a member of the operator group or its groups cannot be read
// (STATUS_SOCKET_AGENT), using the real account database for this test's own
// UID and for a UID with no account; this check stays as defence in depth
// beside the A8 directory. Valid neighbour: the same lookup with an operator
// group the agent is not in passes the agent check and reaches the directory
// check, which this unprivileged test cannot satisfy for a group it is not in
// (STATUS_SOCKET_DIR).
func TestPX1oStatusSocketAgentGroup(t *testing.T) {
	path := filepath.Join(px1oStatusTestDir(t), "s.sock")
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	if _, e := px1oListenStatus(path, px1oStatusAccess{operatorGID: gid, agentGID: gid + 1, agentUID: uid, agentSocket: px1oAgentSocketPath}); e == nil || e.Error() != "STATUS_SOCKET_AGENT" {
		t.Fatalf("AGENT_IN_OPERATOR_GROUP: agent in the operator group accepted: %v", e)
	}
	if _, e := px1oListenStatus(path, px1oStatusAccess{operatorGID: gid, agentGID: gid + 1, agentUID: 3999999, agentSocket: px1oAgentSocketPath}); e == nil || e.Error() != "STATUS_SOCKET_AGENT" {
		t.Fatalf("AGENT_UNKNOWN: unreadable agent account accepted: %v", e)
	}
	if _, e := px1oListenStatus(path, px1oStatusAccess{operatorGID: 3999998, agentGID: gid + 1, agentUID: uid, agentSocket: px1oAgentSocketPath}); e == nil || e.Error() != "STATUS_SOCKET_DIR" {
		t.Fatalf("agent outside the operator group must pass the agent check: %v", e)
	}
	if _, e := os.Lstat(path); !os.IsNotExist(e) {
		t.Fatal("a refused start left a socket behind")
	}
}

// Claim: on a real Unix socket, a connection whose SO_PEERCRED UID is the
// agent's is closed without a reply and the projection source is never
// called (T19 barrier kept as defence in depth under A8); the same client is
// served when the agent UID is another one (valid neighbour). This test runs
// as one UID; the agent UID's EACCES on the status directory and an
// operator-only UID's exchange are T18 host work.
func TestPX1oStatusSocketAgentPeerRefused(t *testing.T) {
	saved := px1oAgentGroups
	t.Cleanup(func() { px1oAgentGroups = saved })
	px1oAgentGroups = func(uint32) ([]string, error) { return []string{"65534"}, nil }
	for _, c := range []struct {
		agentUID uint32
		served   bool
	}{{uint32(os.Getuid()), false}, {65534, true}} {
		path := filepath.Join(px1oStatusTestDir(t), "s.sock")
		gid := uint32(os.Getgid())
		l, e := px1oListenStatus(path, px1oStatusAccess{operatorGID: gid, agentGID: gid + 1, agentUID: c.agentUID, agentSocket: px1oAgentSocketPath})
		if e != nil {
			t.Fatal(e)
		}
		calls := 0
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			done <- px1oServeStatusListener(ctx, l, c.agentUID, func() (StatusProjectionV1, error) { calls++; return px1StatusFixture(), nil })
		}()
		_, e = ReadPX1Status(context.Background(), path)
		cancel()
		if le := <-done; le != nil {
			t.Fatal(le)
		}
		if c.served != (e == nil) || c.served != (calls == 1) {
			t.Fatalf("AGENT_PEER_SERVED: agent uid %d served=%v want %v (err %v, source calls %d)", c.agentUID, e == nil, c.served, e, calls)
		}
	}
}
