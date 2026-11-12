package wallet

// Owner S3. The independent review controls of revision 2 (rev160), kept
// under their original test names. Only the helper type is renamed to the
// S3 px1o prefix and the code is gofmt-formatted; assertions are unchanged.
// The third control of that review, TestRev160PendingTransitionsRetainedAtBound,
// is not kept: it requires the fake tracker to be polled while appends
// refuse, which revision 3 forbids (backpressure). Its invariant, no returned
// observation dropped, is TestPX1oTrackBacklogBoundary and
// TestPX1oTrackBacklogBackpressure.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// Control: repeated refusal of the first append preserves both observations;
// recovery writes each once in order, as does the no-refusal neighbour.
func TestRev160RetryHeadAtomic(t *testing.T) {
	for _, refuse := range []bool{false, true} {
		lab := px1oNewRuntimeLab(t)
		journal := lab.env.wallet.(*px1oFakeJournal)
		first := journal.add(px1oLedgerReserve(1, 50000, px1oLedgerT0))
		journal.add(px1oLedgerFollow(RecordComplete, "complete", first, px1oLedgerT0))
		second := journal.add(px1oLedgerReserve(2, 50000, px1oLedgerT0))
		journal.add(px1oLedgerFollow(RecordComplete, "complete", second, px1oLedgerT0))
		for _, reserve := range []JournalRecordV2{first, second} {
			lab.tracker.out = append(lab.tracker.out, TrackTransition{
				Payment: TrackedPayment{ReserveSeq: reserve.Seq, GrantID: reserve.GrantID, Nonce: reserve.Nonce, TxID: reserve.TxID, Inputs: reserve.Inputs},
				Record:  TrackRecordV2{State: TrackConfirmed, Height: 300, BlockHash: strings.Repeat("b", 64), Confirmations: 2},
			})
		}
		if refuse {
			journal.appendErr = errors.New(CodeClockRollback)
			for attempt := 0; attempt < 2; attempt++ {
				err := lab.r.tick(context.Background(), lab.env)
				if err == nil || err.Error() != CodeClockRollback {
					t.Fatal("expected append refusal", err)
				}
				if len(journal.records) != 4 || len(lab.r.tracks) != 2 {
					t.Fatalf("REFUSAL_LOST_QUEUED_HEAD records=%d queued=%d", len(journal.records), len(lab.r.tracks))
				}
			}
			journal.appendErr = nil
		}
		for attempt := 0; attempt < 2; attempt++ {
			if err := lab.r.tick(context.Background(), lab.env); err != nil {
				t.Fatal(err)
			}
		}
		if len(journal.records) != 6 || journal.records[4].TxID != first.TxID || journal.records[5].TxID != second.TxID || len(lab.r.tracks) != 0 {
			t.Fatal("recovery must write each observation once in order")
		}
	}
}

type px1oRev160ObservedTracker struct {
	Tracker
	observed int
}

func (tracker *px1oRev160ObservedTracker) Tick(ctx context.Context) ([]TrackTransition, error) {
	transitions, err := tracker.Tracker.Tick(ctx)
	if err == nil {
		tracker.observed += len(transitions)
	}
	return transitions, err
}

// Control: the real NewTracker/Tick path also preserves two confirmation
// observations across reorg/reconfirmation while each journal append refuses.
// Node responses and the append-refusing journal are isolated fixtures.
func TestRev160RealTrackerPendingBoundary(t *testing.T) {
	for _, count := range []int{2, px1oMaxTracked/2 + 1} {
		lab := px1oNewRuntimeLab(t)
		var observed *px1oRev160ObservedTracker
		lab.r.deps.newTracker = func(node su.Node, config TrackerConfig, journal JournalV2) (Tracker, error) {
			tracker, err := NewTracker(node, config, journal)
			if err != nil {
				return nil, err
			}
			observed = &px1oRev160ObservedTracker{Tracker: tracker}
			return observed, nil
		}
		lab.env.profile.JournalSpendCapacity = count*2 + 1
		journal := lab.env.wallet.(*px1oFakeJournal)
		transactions := make([]string, 0, count)
		for index := 1; index <= count; index++ {
			record := px1oLedgerReserve(index, 50000, px1oLedgerT0)
			record.Nonce = fmt.Sprintf("%064x", index)
			reserve := journal.add(record)
			journal.add(px1oLedgerFollow(RecordComplete, "complete", reserve, px1oLedgerT0))
			transactions = append(transactions, reserve.TxID)
			lab.chain.mined[reserve.TxID] = 198
		}
		journal.appendErr = errors.New(CodeClockRollback)
		for round := 0; round < 3; round++ {
			if round == 1 {
				lab.chain.epoch++
				for _, transaction := range transactions {
					lab.chain.mined[transaction] = 200
				}
			}
			if round == 2 {
				lab.chain.height++
			}
			err := lab.r.tick(context.Background(), lab.env)
			if err == nil || err.Error() != CodeClockRollback {
				t.Fatal("expected refusal", err)
			}
			if observed == nil || observed.observed == 0 {
				t.Fatal("no real transition exercised")
			}
			want := observed.observed
			if len(journal.records) != 2*count {
				t.Fatal("refused append changed durable fixture")
			}
			if len(lab.r.tracks) != want {
				t.Fatalf("REAL_TRACKER_PENDING_LOSS payments=%d round=%d retained=%d want=%d", count, round, len(lab.r.tracks), want)
			}
		}
	}
}

// Control: actual S2 keyed durable journals and S3 projections agree for
// every phase case and both days. Signing fixture records does not change
// either implementation or the independently specified expected balances.
func TestRev160SignedStatusLedgerEquivalence(t *testing.T) {
	for _, scenario := range px1oLedgerCases() {
		t.Run(scenario.name, func(t *testing.T) {
			fake := px1oJournal(JournalLayerWallet)
			scenario.build(fake)
			journal := px1jOpenWallet(t, px1jPrivateDir(t), JournalLimitsV2{SpendCapacity: 8})
			defer journal.Close()
			for _, record := range fake.records {
				if record.Reconcile != nil {
					record.Reconcile = px1jSignReconcile(t, *record.Reconcile, px1jReceiptKeyN)
				}
				if _, err := journal.Append(record); err != nil {
					t.Fatal("authenticated journal fixture", err)
				}
			}
			ledger, err := FoldLedgerV2(journal)
			if err != nil {
				t.Fatal(err)
			}
			for dayIndex, now := range []int64{px1oLedgerT0, px1oLedgerT0 + 86400} {
				inputs := px1oFixtureInputs(journal, px1oJournal(JournalLayerService))
				inputs.Now = now
				inputs.Limits[0].GrantID = px1oG
				projection, err := ProjectStatus(inputs)
				if err != nil {
					t.Fatal(err)
				}
				grant := projection.Grants[0]
				used, count := ledger.DayUsage(px1oG, grant.Day)
				want := scenario.want[dayIndex]
				if grant.ReservedSat != want.reserved || grant.UncertainSat != want.uncertain || grant.DayUsedSat != want.dayUsed || grant.DayCount != want.dayCount {
					t.Errorf("status differs from independent expectation: %+v want %+v", grant, want)
				}
				if ledger.SpendUsed(px1oG) != grant.ReservedSat || ledger.UncertainSat(px1oG) != grant.UncertainSat || used != grant.DayUsedSat || count != grant.DayCount {
					t.Error("authenticated status disagrees with ledger")
				}
			}
		})
	}
}
