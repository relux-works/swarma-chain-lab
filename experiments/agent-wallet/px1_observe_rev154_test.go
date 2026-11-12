package wallet

// Owner S3. The independent reviewer's reproductions of the r1 findings
// status-releases-day-count and track-transition-lost-on-append-refusal, and
// the reviewer's status privacy export, kept under their original names. The
// only edits are the r2 helper renames (px1o prefix), gofmt, and a temporary
// output path when REV154_SCHEMA_OUTPUT is unset.

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// Claim: an operator release lowers the monetary debit, not the count of
// today's executed requests. Unreleased and fully released are neighbours.
func TestRev154StatusCountRetained(t *testing.T) {
	for _, release := range []bool{false, true} {
		wallet := px1oJournal(JournalLayerWallet)
		reserve := wallet.add(px1oReserve(px1oG, px1oN1, px1oTx1, 50000, "2026-11-06", su.Point{TxID: px1oTx2, Vout: 0}))
		wallet.add(px1oFollow(RecordComplete, "complete", reserve))
		if release {
			rec := px1oFollow(RecordReconcile, "released", reserve)
			rec.Reconcile = &ReconcileRecordV2{TargetSeq: reserve.Seq, Evidence: "absent", Height: 200, BlockHash: strings.Repeat("a", 64), ReleasedSat: 50000, NoteSHA256: strings.Repeat("b", 64), Signature: strings.Repeat("ab", 64)}
			wallet.add(rec)
		}
		input := px1oFixtureInputs(wallet, px1oJournal(JournalLayerService))
		input.Limits[0].GrantID = px1oG
		projection, err := ProjectStatus(input)
		if err != nil {
			t.Fatal(err)
		}
		grant := projection.Grants[0]
		t.Logf("released=%v day_count=%d remaining=%d retained=%d", release, grant.DayCount, grant.DayCountRemaining, grant.ReservedSat)
		if grant.DayCount != 1 || grant.DayCountRemaining != 4 {
			t.Errorf("STATUS_COUNT_RELEASED: got %d/%d want 1/4", grant.DayCount, grant.DayCountRemaining)
		}
	}
}

// Claim: a non-poisoning append refusal must not consume a tracker transition;
// after the clock recovers, the next successful pass persists the observation.
func TestRev154TrackAppendRetry(t *testing.T) {
	lab := px1oNewRuntimeLab(t)
	lab.r.deps.newTracker = NewTracker
	wallet := lab.env.wallet.(*px1oFakeJournal)
	reserve := wallet.add(px1oReserve(px1oG, px1oN1, px1oTx1, 50000, "2026-11-06", su.Point{TxID: px1oTx2, Vout: 0}))
	wallet.add(px1oFollow(RecordComplete, "complete", reserve))
	lab.chain.mined[px1oTx1] = 198
	wallet.appendErr = errors.New(CodeClockRollback)
	if err := lab.r.tick(context.Background(), lab.env); err == nil || err.Error() != CodeClockRollback {
		t.Fatalf("expected clock refusal, got %v", err)
	}
	if len(wallet.records) != 2 {
		t.Fatal("refused append changed journal")
	}
	wallet.appendErr = nil
	lab.env.now++
	if err := lab.r.tick(context.Background(), lab.env); err != nil {
		t.Fatal("recovery pass", err)
	}
	if len(wallet.records) != 3 || wallet.records[2].Kind != RecordTrack {
		t.Fatalf("TRACK_RETRY_LOST: successful recovery left %d records, tracker=%s", len(wallet.records), lab.r.tracker.Snapshot()[0].State)
	}
}

// Claim: request bodies and peer details are not serialized in the status;
// export an actual projection for independent JSON Schema validation.
func TestRev154StatusSchemaAndPrivacy(t *testing.T) {
	day := px1oStatusDay(px1StatusFixture().GeneratedAt)
	wallet, service := px1oStatusJournals(day)
	marker := "REVIEW_SYNTHETIC_PRIVATE_REQUEST_MARKER"
	for index := range service.records {
		service.records[index].Service.Request.Params = []byte(`{"password":"` + marker + `"}`)
	}
	projection, err := ProjectStatus(px1oFixtureInputs(wallet, service))
	if err != nil {
		t.Fatal(err)
	}
	raw := canonical(projection)
	if bytes.Contains(raw, []byte(marker)) || bytes.Contains(raw, []byte(`"request"`)) || bytes.Contains(raw, []byte(`"peer"`)) {
		t.Fatal("STATUS_PRIVATE_FIELDS")
	}
	path := os.Getenv("REV154_SCHEMA_OUTPUT")
	if path == "" {
		path = filepath.Join(t.TempDir(), "status-projection.json")
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}
