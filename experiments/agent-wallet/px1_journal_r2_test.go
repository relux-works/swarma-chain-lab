package wallet

// Owner S2, revision 2: regression tests for the PR78 review findings
// (reconcile authorization, partial release, track observation, private
// fixture roots, stream-private names) and the S3-R2 halt mapping. Each
// refusal has a valid neighbour in the same test.

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// px1jSnap is a comparable view of every ledger quantity of one request:
// grant total, its reservation day and the next UTC day, uncertainty and
// its first planned input.
type px1jSnap struct {
	Spend, DayUsed, NextUsed, Uncertain int64
	DayCount, NextCount                 int
	Input                               bool
}

func px1jSnapOf(t *testing.T, j JournalV2, reserve JournalRecordV2) px1jSnap {
	t.Helper()
	l, e := FoldLedgerV2(j)
	if e != nil {
		t.Fatal("fold", e)
	}
	used, count := l.DayUsage(reserve.GrantID, reserve.Day)
	next, nextCount := l.DayUsage(reserve.GrantID, UTCDay(reserve.LastTime+px1jSecondsPerDay))
	return px1jSnap{Spend: l.SpendUsed(reserve.GrantID), DayUsed: used, DayCount: count, NextUsed: next, NextCount: nextCount, Uncertain: l.UncertainSat(reserve.GrantID), Input: l.InputReserved(reserve.Inputs[0])}
}

// px1jAuth is an unsigned "absent" release of reserve.
func px1jAuth(reserve JournalRecordV2, released, height int64) ReconcileRecordV2 {
	return ReconcileRecordV2{TargetSeq: reserve.Seq, Evidence: "absent", Height: height, BlockHash: px1jHex(9), ReleasedSat: released, NoteSHA256: px1jHex(5)}
}

func px1jRelease(reserve JournalRecordV2, c *ReconcileRecordV2, at int64) JournalRecordV2 {
	rec := px1jFollowRec(reserve, RecordReconcile, "released", at)
	rec.Reconcile = c
	return rec
}

// px1jListJournal is a foreign JournalV2 (not this package's engine) that
// serves fixed wallet-layer records; it carries no receipt key.
type px1jListJournal struct{ records []JournalRecordV2 }

func (l px1jListJournal) Header() JournalHeaderV2 {
	return JournalHeaderV2{Version: 2, Layer: JournalLayerWallet, Binding: px1jHex(7)}
}
func (l px1jListJournal) Append(JournalRecordV2) (JournalRecordV2, error) {
	return JournalRecordV2{}, errors.New("READ_ONLY")
}
func (l px1jListJournal) Iterate(from uint64, fn func(JournalRecordV2) error) error {
	for _, r := range l.records {
		if r.Seq >= from {
			if e := fn(r); e != nil {
				return e
			}
		}
	}
	return nil
}
func (l px1jListJournal) Usage() JournalUsageV2 { return JournalUsageV2{} }
func (l px1jListJournal) Poisoned() bool        { return false }
func (l px1jListJournal) Close()                {}

// Claim (finding reconcile-authorization-unchecked, Append): a retained
// debit is released only by a reconcile whose BIP-340 signature verifies
// under the journal's receipt key over the frozen preimage. A zero
// signature, another key's signature, a record altered after signing (amount,
// evidence height, note) and any reconcile on a journal opened without a
// receipt key (the frozen OpenJournalV2) refuse RECONCILE_AUTHORIZATION;
// replaying an applied authorization refuses JOURNAL_RECORD. Every refusal
// leaves the journal and the ledger unchanged; the signed neighbour releases.
func TestPX1jReconcileAuthorization(t *testing.T) {
	now := int64(1794441599)
	setup := func(t *testing.T, keyN int) (JournalV2, JournalRecordV2) {
		j, e := px1jOpenWalletKey(px1jPrivateDir(t), JournalLimitsV2{SpendCapacity: 4}, keyN)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(j.Close)
		reserve := px1jMust(t, j, px1jReserve(1, 1, now, 50000, 1))
		px1jMust(t, j, px1jFollowRec(reserve, RecordUncertain, "uncertain", now))
		return j, reserve
	}
	refusals := []struct {
		name string
		keyN int
		auth func(t *testing.T, r JournalRecordV2) *ReconcileRecordV2
	}{
		{"zero signature", px1jReceiptKeyN, func(t *testing.T, r JournalRecordV2) *ReconcileRecordV2 {
			c := px1jAuth(r, 50000, 100)
			c.Signature = strings.Repeat("00", 64)
			return &c
		}},
		{"another key", px1jReceiptKeyN, func(t *testing.T, r JournalRecordV2) *ReconcileRecordV2 {
			return px1jSignReconcile(t, px1jAuth(r, 50000, 100), 8)
		}},
		{"amount altered after signing", px1jReceiptKeyN, func(t *testing.T, r JournalRecordV2) *ReconcileRecordV2 {
			c := px1jSignReconcile(t, px1jAuth(r, 1, 100), px1jReceiptKeyN)
			c.ReleasedSat = 50000
			return c
		}},
		{"evidence altered after signing", px1jReceiptKeyN, func(t *testing.T, r JournalRecordV2) *ReconcileRecordV2 {
			c := px1jSignReconcile(t, px1jAuth(r, 50000, 100), px1jReceiptKeyN)
			c.Height = 101
			return c
		}},
		{"note altered after signing", px1jReceiptKeyN, func(t *testing.T, r JournalRecordV2) *ReconcileRecordV2 {
			c := px1jSignReconcile(t, px1jAuth(r, 50000, 100), px1jReceiptKeyN)
			c.NoteSHA256 = px1jHex(6)
			return c
		}},
		{"journal without a receipt key", 0, func(t *testing.T, r JournalRecordV2) *ReconcileRecordV2 {
			return px1jSignReconcile(t, px1jAuth(r, 50000, 100), px1jReceiptKeyN)
		}},
	}
	for _, c := range refusals {
		t.Run(c.name, func(t *testing.T) {
			j, reserve := setup(t, c.keyN)
			before, seq := px1jSnapOf(t, j, reserve), j.Usage().LastSeq
			_, e := j.Append(px1jRelease(reserve, c.auth(t, reserve), now))
			px1jCode(t, e, px1jCodeReconcileAuth)
			if after := px1jSnapOf(t, j, reserve); j.Usage().LastSeq != seq || after != before || before.Spend != 50000 {
				t.Fatal("refused release changed the journal or the ledger", after)
			}
		})
	}
	t.Run("signed release then replay", func(t *testing.T) {
		j, reserve := setup(t, px1jReceiptKeyN)
		signed := px1jSignReconcile(t, px1jAuth(reserve, 20000, 100), px1jReceiptKeyN)
		px1jMust(t, j, px1jRelease(reserve, signed, now))
		after := px1jSnapOf(t, j, reserve)
		if after.Spend != 30000 || !after.Input || after.NextUsed != 30000 || after.NextCount != 1 {
			t.Fatal("signed partial release", after)
		}
		replay := *signed
		if _, e := j.Append(px1jRelease(reserve, &replay, now+ReconcileMinIntervalSeconds)); e == nil || e.Error() != px1jCodeRecord {
			t.Fatal("RECONCILE_REPLAY_ACCEPTED", e)
		}
		if px1jSnapOf(t, j, reserve) != after {
			t.Fatal("replay changed the ledger")
		}
	})
}

// Claim (finding reconcile-authorization-unchecked, open and fold): a
// journal holding a signed release reopens under its receipt key and folds
// the same release. The same bytes refuse JOURNAL_SEGMENT when reopened
// under another key or with no key (the frozen OpenJournalV2), and when the
// active segment's signature is replaced on disk by another key's valid
// signature. FoldLedgerV2 refuses a release served by any other JournalV2
// implementation (no receipt key); the same records without it fold.
func TestPX1jReconcileReplayOpen(t *testing.T) {
	dir := px1jPrivateDir(t)
	l := JournalLimitsV2{SpendCapacity: 4}
	now := int64(1794441599)
	j := px1jOpenWallet(t, dir, l)
	reserve := px1jMust(t, j, px1jReserve(1, 1, now, 50000, 1))
	px1jMust(t, j, px1jRelease(reserve, px1jSignReconcile(t, px1jAuth(reserve, 50000, 100), px1jReceiptKeyN), now))
	var records []JournalRecordV2
	_ = j.Iterate(1, func(r JournalRecordV2) error { records = append(records, r); return nil })
	j.Close()
	segment := filepath.Join(dir, px1jSegmentName(1))
	copyDir := func(t *testing.T, raw []byte) string {
		d := px1jPrivateDir(t)
		if raw == nil {
			raw, _ = os.ReadFile(segment)
		}
		if e := os.WriteFile(filepath.Join(d, px1jSegmentName(1)), raw, 0600); e != nil {
			t.Fatal(e)
		}
		return d
	}
	ok, e := px1jOpenWalletKey(copyDir(t, nil), l, px1jReceiptKeyN)
	if e != nil {
		t.Fatal("signed journal must reopen", e)
	}
	if s := px1jSnapOf(t, ok, reserve); s.Spend != 0 || s.Input || s.DayCount != 1 {
		t.Fatal("reopened release", s)
	}
	ok.Close()
	for _, keyN := range []int{8, 0} {
		if _, e = px1jOpenWalletKey(copyDir(t, nil), l, keyN); e == nil || e.Error() != CodeJournalSegment {
			t.Fatal("RECONCILE_LOADED_UNVERIFIED key", keyN, e)
		}
	}
	var seg JournalSegmentV2
	raw, _ := os.ReadFile(segment)
	if e = strict(raw, &seg); e != nil || len(seg.Records) != 2 {
		t.Fatal("segment", e)
	}
	seg.Records[1].Reconcile = px1jSignReconcile(t, *seg.Records[1].Reconcile, 8)
	if _, e = px1jOpenWalletKey(copyDir(t, canonical(seg)), l, px1jReceiptKeyN); e == nil || e.Error() != CodeJournalSegment {
		t.Fatal("RECONCILE_LOADED_UNVERIFIED replaced signature", e)
	}
	if _, e = FoldLedgerV2(px1jListJournal{records}); e == nil {
		t.Fatal("FOREIGN_RELEASE_FOLDED")
	}
	if l, e := FoldLedgerV2(px1jListJournal{records[:1]}); e != nil || l.SpendUsed(reserve.GrantID) != 50000 {
		t.Fatal("foreign journal without a release must fold", e)
	}
}

// Claim: the frozen evidence rules hold for a correctly signed release:
// evidence is "absent" or "conflict"; "absent" cites no spender; "conflict"
// cites a 64-hex spender other than the payment's own plan txid. Each
// violation refuses RECONCILE_EVIDENCE and stores nothing; the signed absent
// and conflict neighbours release.
func TestPX1jReconcileEvidence(t *testing.T) {
	now := int64(1794441599)
	for _, c := range []struct {
		name, evidence, conflict, code string
	}{
		{"unknown evidence", "gone", "", CodeReconcileEvidence},
		{"absent naming a spender", "absent", "zz", CodeReconcileEvidence},
		{"absent naming a hex spender", "absent", px1jHex(6), CodeReconcileEvidence},
		{"conflict without a spender", "conflict", "", CodeReconcileEvidence},
		{"conflict naming its own txid", "conflict", px1jHex(4001), CodeReconcileEvidence},
		{"absent neighbour", "absent", "", ""},
		{"conflict neighbour", "conflict", px1jHex(6), ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			j := px1jOpenWallet(t, px1jPrivateDir(t), JournalLimitsV2{SpendCapacity: 4})
			defer j.Close()
			reserve := px1jMust(t, j, px1jReserve(1, 1, now, 50000, 1))
			auth := px1jAuth(reserve, 50000, 100)
			auth.Evidence, auth.ConflictTxID = c.evidence, c.conflict
			_, e := j.Append(px1jRelease(reserve, px1jSignReconcile(t, auth, px1jReceiptKeyN), now))
			if c.code == "" {
				if e != nil || px1jSnapOf(t, j, reserve).Spend != 0 {
					t.Fatal("valid evidence refused", e)
				}
				return
			}
			if e == nil || e.Error() != c.code || j.Usage().LastSeq != 1 {
				t.Fatalf("EVIDENCE_ACCEPTED %s: %v", c.name, e)
			}
		})
	}
}

// Claim (finding partial-release-drops-retained-state): a partial release
// keeps the remainder reserved. After releasing 1 of 50000 atoms of an
// uncertain reservation the input stays reserved and 49999 is still charged
// on the next UTC day with count 1; a second signed partial release stays
// consistent, also after reopen. Only the release that brings the retained
// debit to zero frees the input and the next-day carry, while the
// reservation day keeps its count; nothing may follow it. A partial release
// of a complete payment keeps it complete (its own day only) and trackable.
func TestPX1jPartialRelease(t *testing.T) {
	now := int64(1794441599) // 23:59:59 UTC: the next second is the next day
	dir := px1jPrivateDir(t)
	l := JournalLimitsV2{SpendCapacity: 8}
	j := px1jOpenWallet(t, dir, l)
	defer func() { j.Close() }()
	reserve := px1jMust(t, j, px1jReserve(1, 1, now, 50000, 1))
	px1jMust(t, j, px1jFollowRec(reserve, RecordUncertain, "uncertain", now))
	at := now
	release := func(sat int64) error {
		_, e := j.Append(px1jRelease(reserve, px1jSignReconcile(t, px1jAuth(reserve, sat, at), px1jReceiptKeyN), at))
		at += ReconcileMinIntervalSeconds
		return e
	}
	expect := func(step string, want px1jSnap) {
		t.Helper()
		if got := px1jSnapOf(t, j, reserve); got != want {
			t.Fatalf("%s: got %+v want %+v", step, got, want)
		}
	}
	if e := release(1); e != nil {
		t.Fatal(e)
	}
	expect("partial release 1", px1jSnap{Spend: 49999, DayUsed: 49999, DayCount: 1, NextUsed: 49999, NextCount: 1, Uncertain: 49999, Input: true})
	if e := release(49998); e != nil {
		t.Fatal(e)
	}
	held := px1jSnap{Spend: 1, DayUsed: 1, DayCount: 1, NextUsed: 1, NextCount: 1, Uncertain: 1, Input: true}
	expect("partial release 49998", held)
	j.Close()
	j = px1jOpenWallet(t, dir, l)
	expect("after reopen", held)
	if e := release(1); e != nil {
		t.Fatal(e)
	}
	expect("final release", px1jSnap{DayCount: 1})
	if e := release(1); e == nil || e.Error() != px1jCodeRecord {
		t.Fatal("record after the full release", e)
	}
	// A complete payment, partially released, stays complete.
	c := px1jOpenWallet(t, px1jPrivateDir(t), l)
	defer c.Close()
	paid := px1jMust(t, c, px1jReserve(1, 2, now, 50000, 2))
	px1jMust(t, c, px1jFollowRec(paid, RecordComplete, "complete", now))
	px1jMust(t, c, px1jRelease(paid, px1jSignReconcile(t, px1jAuth(paid, 1, 100), px1jReceiptKeyN), now))
	if got := px1jSnapOf(t, c, paid); got != (px1jSnap{Spend: 49999, DayUsed: 49999, DayCount: 1, Input: true}) {
		t.Fatal("partially released complete payment", got)
	}
	track := px1jFollowRec(paid, RecordTrack, TrackConfirmed, now+1)
	track.Track = &TrackRecordV2{State: TrackConfirmed, Height: 100, BlockHash: px1jHex(9), Confirmations: 2}
	px1jMust(t, c, track)
}

// Claim (finding track-overwrites-accounting-phase, Q12): a track record is
// observation only. For a reserved, an uncertain and a complete request,
// confirmed and conflicted observations (twice, flipping state) leave every
// ledger quantity equal to the untracked neighbour, also after reopen, and
// the execution transitions of the untracked phase stay open: a complete
// after a track on a reserved request, a signed release otherwise.
func TestPX1jTrackObservationOnly(t *testing.T) {
	now := int64(1794441599)
	l := JournalLimitsV2{SpendCapacity: 4}
	observe := func(state string) *TrackRecordV2 {
		if state == TrackConfirmed {
			return &TrackRecordV2{State: state, Height: 100, BlockHash: px1jHex(9), Confirmations: 2}
		}
		return &TrackRecordV2{State: state, Height: 100, BlockHash: px1jHex(9), ConflictTxID: px1jHex(6)}
	}
	for _, phase := range []string{"reserved", "uncertain", "complete"} {
		for _, states := range [][]string{{TrackConfirmed, TrackConflicted}, {TrackConflicted, TrackConfirmed}} {
			t.Run(phase+"/"+states[0], func(t *testing.T) {
				build := func(tracked bool) (JournalV2, JournalRecordV2, string) {
					dir := px1jPrivateDir(t)
					j := px1jOpenWallet(t, dir, l)
					reserve := px1jMust(t, j, px1jReserve(1, 1, now, 50000, 1))
					if phase != "reserved" {
						px1jMust(t, j, px1jFollowRec(reserve, map[string]string{"uncertain": RecordUncertain, "complete": RecordComplete}[phase], phase, now))
					}
					for i, state := range states {
						if tracked {
							rec := px1jFollowRec(reserve, RecordTrack, state, now+1+int64(i))
							rec.Track = observe(state)
							px1jMust(t, j, rec)
						}
					}
					return j, reserve, dir
				}
				plain, reserve, _ := build(false)
				want := px1jSnapOf(t, plain, reserve)
				plain.Close()
				j, _, dir := build(true)
				if got := px1jSnapOf(t, j, reserve); got != want {
					t.Fatalf("TRACK_CHANGED_LEDGER: got %+v want %+v", got, want)
				}
				j.Close()
				j = px1jOpenWallet(t, dir, l)
				defer j.Close()
				if got := px1jSnapOf(t, j, reserve); got != want {
					t.Fatalf("TRACK_CHANGED_LEDGER after reopen: got %+v want %+v", got, want)
				}
				next := px1jRelease(reserve, px1jSignReconcile(t, px1jAuth(reserve, 50000, 100), px1jReceiptKeyN), now+3)
				if phase == "reserved" {
					next = px1jFollowRec(reserve, RecordComplete, "complete", now+3)
				}
				if _, e := j.Append(next); e != nil {
					t.Fatal("execution transition after a track", next.Kind, e)
				}
			})
		}
	}
}

// Claim: a confirmed track names no spender, and a conflicted track never
// names the payment's own plan txid (JOURNAL_RECORD, nothing stored); the
// confirmed neighbour without a spender and the conflicted neighbour naming
// another spender are stored.
func TestPX1jTrackShape(t *testing.T) {
	now := int64(1794441599)
	j := px1jOpenWallet(t, px1jPrivateDir(t), JournalLimitsV2{SpendCapacity: 4})
	defer j.Close()
	reserve := px1jMust(t, j, px1jReserve(1, 1, now, 50000, 1))
	px1jMust(t, j, px1jFollowRec(reserve, RecordComplete, "complete", now))
	track := func(state, conflict string, confirmations int64) error {
		rec := px1jFollowRec(reserve, RecordTrack, state, now)
		rec.Track = &TrackRecordV2{State: state, Height: 100, BlockHash: px1jHex(9), Confirmations: confirmations, ConflictTxID: conflict}
		_, e := j.Append(rec)
		return e
	}
	if e := track(TrackConfirmed, px1jHex(6), 2); e == nil || e.Error() != px1jCodeRecord {
		t.Fatal("CONFIRMED_WITH_SPENDER", e)
	}
	if e := track(TrackConflicted, reserve.TxID, 0); e == nil || e.Error() != px1jCodeRecord {
		t.Fatal("CONFLICT_WITH_OWN_TXID", e)
	}
	if j.Usage().LastSeq != 2 {
		t.Fatal("refused track stored")
	}
	if e := track(TrackConfirmed, "", 2); e != nil {
		t.Fatal("confirmed neighbour", e)
	}
	if e := track(TrackConflicted, px1jHex(6), 0); e != nil {
		t.Fatal("conflicted neighbour", e)
	}
}

// Claim (finding journal-test-directory-mode): the journal keeps durable's
// private-root check. A 0755 state root refuses PRIVATE_STATE_ROOT and
// stays empty, while the px1jPrivateDir fixture root is 0700 whatever the
// process umask (run the suite under umask 022 and 077) and opens.
func TestPX1jPrivateStateRoot(t *testing.T) {
	l := JournalLimitsV2{SpendCapacity: 4}
	private := px1jPrivateDir(t)
	if info, e := os.Stat(private); e != nil || info.Mode().Perm() != 0700 {
		t.Fatal("FIXTURE_ROOT_NOT_PRIVATE", e)
	}
	j, e := px1jOpenWalletKey(private, l, px1jReceiptKeyN)
	if e != nil {
		t.Fatal("private root", e)
	}
	j.Close()
	public := filepath.Join(t.TempDir(), "public")
	if e = os.Mkdir(public, 0700); e != nil || os.Chmod(public, 0755) != nil {
		t.Fatal("setup", e)
	}
	_, e = px1jOpenWalletKey(public, l, px1jReceiptKeyN)
	px1jCode(t, e, "PRIVATE_STATE_ROOT")
	if entries, _ := os.ReadDir(public); len(entries) != 0 {
		t.Fatal("refused open wrote state")
	}
}

type px1jFakeHalter struct{ code string }

func (h *px1jFakeHalter) px1oHalted() string { return h.code }

// Claim (S3-R2): the halt answer is bounded on the wire: "" admits; the
// codes S3's seam documents (FLOAT_CANARY_SPENT, STATE_RECONCILE_REQUIRED,
// SERVICE_STATE_UNAVAILABLE, PX1_NOT_IMPLEMENTED) pass through; any other
// value refuses SERVICE_STATE_UNAVAILABLE and is never echoed. The probe
// asks a value that has the seam method and never halts one that lacks it.
func TestPX1jHaltCode(t *testing.T) {
	for in, want := range map[string]string{
		"":                          "",
		CodeFloatCanarySpent:        CodeFloatCanarySpent,
		CodeStateReconcileRequired:  CodeStateReconcileRequired,
		"SERVICE_STATE_UNAVAILABLE": "SERVICE_STATE_UNAVAILABLE",
		"PX1_NOT_IMPLEMENTED":       "PX1_NOT_IMPLEMENTED",
		"secret detail":             "SERVICE_STATE_UNAVAILABLE",
	} {
		if got := px1jHaltCode(in); got != want {
			t.Fatalf("HALT_CODE %q: got %q want %q", in, got, want)
		}
	}
	if got := px1jProbeHalt(&px1jFakeHalter{CodeFloatCanarySpent}); got != CodeFloatCanarySpent {
		t.Fatal("HALT_PROBE_IGNORED", got)
	}
	if got := px1jProbeHalt(&struct{}{}); got != "" {
		t.Fatal("a value without the seam halted", got)
	}
}

// Claim (S3-R2, T14 at the service layer): with the halt reporting a spent
// canary, a G2 spend refuses FLOAT_CANARY_SPENT before admission
// (journal_seq 0, nothing journaled), an unknown halt answer refuses
// SERVICE_STATE_UNAVAILABLE, and a read is not halted; with no halt the same
// spend is admitted. Limit: the halt here is a substitute for S3's seam; the
// end-to-end T14 with a real spent canary is S3's Core layer.
func TestPX1jServiceHalt(t *testing.T) {
	clock := int64(500)
	s := px1jServiceFixture(t, px1jStateDir(t), &clock, 4)
	ctx := context.Background()
	halt := CodeFloatCanarySpent
	s.g2.halt = func(*ActionService) string { return halt }
	if r := px1jReceipt(t, s.handle(ctx, px1jActionRaw(t, "spend", 1, nil), px1jPeer)); r.Reason != CodeFloatCanarySpent || r.Sequence != 0 || s.g2.journal.Usage().LastSeq != 0 {
		t.Fatal("CANARY_HALT_IGNORED", r.Reason, r.Sequence)
	}
	halt = "detail"
	if r := px1jReceipt(t, s.handle(ctx, px1jActionRaw(t, "spend", 1, nil), px1jPeer)); r.Reason != "SERVICE_STATE_UNAVAILABLE" || r.Sequence != 0 {
		t.Fatal("unknown halt answer", r.Reason)
	}
	if r := px1jReceipt(t, s.handle(ctx, px1jActionRaw(t, "balance", 2, nil), px1jPeer)); r.Reason == CodeFloatCanarySpent || r.Reason == "SERVICE_STATE_UNAVAILABLE" {
		t.Fatal("read halted", r.Reason)
	}
	halt = ""
	if r := px1jReceipt(t, s.handle(ctx, px1jActionRaw(t, "spend", 1, nil), px1jPeer)); r.Sequence != 1 {
		t.Fatal("no-halt neighbour", r.Reason, r.Sequence)
	}
}

// Claim: under G2 a poisoned service refuses SERVICE_STATE_UNAVAILABLE at
// step 5, before admission (journal_seq 0, nothing journaled); the same
// request on the unpoisoned service is admitted.
func TestPX1jServicePoisoned(t *testing.T) {
	clock := int64(500)
	s := px1jServiceFixture(t, px1jStateDir(t), &clock, 4)
	ctx := context.Background()
	s.poisoned = true
	if r := px1jReceipt(t, s.handle(ctx, px1jActionRaw(t, "spend", 1, nil), px1jPeer)); r.Reason != "SERVICE_STATE_UNAVAILABLE" || r.Sequence != 0 || s.g2.journal.Usage().LastSeq != 0 {
		t.Fatal("POISON_IGNORED", r.Reason, r.Sequence)
	}
	s.poisoned = false
	if r := px1jReceipt(t, s.handle(ctx, px1jActionRaw(t, "spend", 1, nil), px1jPeer)); r.Sequence != 1 {
		t.Fatal("unpoisoned neighbour", r.Reason)
	}
}

// px1jStreamFiles are the files S2 alone owns in this package.
var px1jStreamFiles = []string{"px1_journal.go", "px1_service_seams.go", "px1_journal_test.go", "px1_journal_r2_test.go", "px1_journal_review_test.go"}

// px1jFrozenNames are the exported names S2 implements from the frozen API.
var px1jFrozenNames = map[string]bool{"OpenJournalV2": true, "RequiredSpendCapacity": true, "UTCDay": true, "UTCDaysSpanned": true, "FoldLedgerV2": true, "NewClockGuard": true, "NewReadLimiter": true, "PX1ServiceJournal": true, "PX1Profile": true}

// Claim (finding cross-stream-package-identifiers): every package-level
// name declared in an S2-only file is a frozen exported name, a Test
// function, a method of an S2 px1j type, or carries the px1j prefix; every
// px1-named function, method or type in service.go carries it too. The
// planted unprefixed helper px1Hex is reported as UNPREFIXED.
func TestPX1jNamesPrefixed(t *testing.T) {
	fs := token.NewFileSet()
	bad := []string{}
	check := func(file string, name, recv string, s2Only bool) {
		switch {
		case strings.HasPrefix(name, "px1j"), strings.HasPrefix(recv, "px1j"), px1jFrozenNames[name] && (recv == "" || recv == "ActionService"):
		case s2Only && strings.HasPrefix(name, "Test") && recv == "":
		case !s2Only && !strings.HasPrefix(strings.ToLower(name), "px1"):
		default:
			bad = append(bad, file+":"+recv+"."+name)
		}
	}
	for _, file := range append([]string{"service.go"}, px1jStreamFiles...) {
		f, e := parser.ParseFile(fs, file, nil, 0)
		if e != nil {
			t.Fatal(e)
		}
		s2Only := file != "service.go"
		for _, d := range f.Decls {
			switch x := d.(type) {
			case *ast.FuncDecl:
				recv := ""
				if x.Recv != nil {
					rt := x.Recv.List[0].Type
					if star, ok := rt.(*ast.StarExpr); ok {
						rt = star.X
					}
					if id, ok := rt.(*ast.Ident); ok {
						recv = id.Name
					}
				}
				check(file, x.Name.Name, recv, s2Only)
			case *ast.GenDecl:
				for _, spec := range x.Specs {
					switch y := spec.(type) {
					case *ast.TypeSpec:
						check(file, y.Name.Name, "", s2Only)
					case *ast.ValueSpec:
						for _, n := range y.Names {
							if n.Name != "_" {
								check(file, n.Name, "", s2Only)
							}
						}
					}
				}
			}
		}
	}
	if len(bad) != 0 {
		t.Fatal("UNPREFIXED", bad)
	}
}
