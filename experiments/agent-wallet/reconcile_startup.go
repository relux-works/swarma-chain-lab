package wallet

import (
	"context"

	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// startupReconcileRoute keeps wallet history and read-only chain observation on
// their existing credential routes; pins come from the admitted wallet config.
// The frozen NewStartupReconciler signature and RPC whitelists stay unchanged.
type startupReconcileRoute struct {
	su.Node
	observer su.Node
	network  string
	genesis  string
}

// startupKnownConflicts never writes or releases a debit. Only records from the
// actual opened hash-chained engine may add an exception; generic JournalV2
// implementations cannot turn a lifted valid signature into chain provenance.
func startupKnownConflicts(ctx context.Context, route su.Node, journal JournalV2, records []JournalRecordV2, known map[string]bool) error {
	reserves := map[uint64]JournalRecordV2{}
	releases := []JournalRecordV2{}
	for _, r := range records {
		if r.Kind == RecordReserve {
			reserves[r.Seq] = r
		}
		if r.Kind == RecordReconcile {
			if r.Reconcile == nil {
				return fail(CodeJournalSegment)
			}
			if r.Reconcile.Evidence == "conflict" {
				releases = append(releases, r)
			}
		}
	}
	if len(releases) == 0 {
		return nil
	}
	if _, ok := journal.(*px1jJournal); !ok {
		return fail(CodeJournalSegment)
	}
	// Reuse the existing key/binding/seq/signature and record-table verification.
	if _, e := FoldLedgerV2(journal); e != nil {
		return fail(CodeJournalSegment)
	}
	source, ok := route.(startupReconcileRoute)
	if !ok || source.observer == nil || !su.NetworkPinned(source.network, source.genesis) {
		return fail(CodeReconcileEvidence)
	}
	for _, r := range releases {
		evidence := r.Reconcile
		reserve, ok := reserves[evidence.TargetSeq]
		if !ok {
			return fail(CodeReconcileEvidence)
		}
		if _, e := reconcileConflictAt(ctx, source.observer, reserve, evidence.ConflictTxID, source.network, source.genesis, evidence); e != nil {
			return fail(CodeReconcileEvidence)
		}
		known[evidence.ConflictTxID] = true
	}
	return nil
}
