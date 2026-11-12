package wallet

// Owner S2: the reproduction tests of the PR #78 revision-1 review, kept with
// the TestPX1jReview prefix. Adapted only where revision 2 changed the
// contract: helpers carry the px1j prefix, journal roots are private 0700
// children (px1jPrivateDir), and the partial-release reproduction signs its
// reconcile record with the fixture receipt key, because a shape-only
// signature is now refused RECONCILE_AUTHORIZATION. Freeze amendment 1: the
// signed preimage is the v2 one (binding, grant_id, nonce, seq, payload)
// and the key is the journal header's ReceiptKey.

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// Claim: valid fixture authorization and a zero-signature neighbour must not
// receive the same release decision. No custody material is used or printed.
func TestPX1jReviewReconcileAuthorization(t *testing.T) {
	for _, valid := range []bool{true, false} {
		journal := px1jOpenWallet(t, px1jPrivateDir(t), JournalLimitsV2{SpendCapacity: 4})
		now := int64(1794441599)
		reserve := px1jMust(t, journal, px1jReserve(1, 1, now, 50000, 1))
		rec := px1jFollowRec(reserve, RecordReconcile, "released", now)
		auth := ReconcileRecordV2{TargetSeq: reserve.Seq, Evidence: "absent", Height: 100, BlockHash: px1jHex(9), ReleasedSat: 50000, NoteSHA256: px1jHex(5)}
		preimage := struct {
			Binding   string            `json:"binding"`
			GrantID   string            `json:"grant_id"`
			Nonce     string            `json:"nonce"`
			Seq       uint64            `json:"seq"`
			Reconcile ReconcileRecordV2 `json:"reconcile"`
		}{journal.Header().Binding, rec.GrantID, rec.Nonce, reserve.Seq + 1, auth}
		digest := sha256.Sum256(append([]byte("swarma-wallet-reconcile-v2"), canonical(preimage)...))
		key, _ := testKey(9)
		signature, err := schnorr.Sign(key, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		auth.Signature = hex.EncodeToString(signature.Serialize())
		if !valid {
			auth.Signature = strings.Repeat("00", 64)
		}
		raw, _ := hex.DecodeString(auth.Signature)
		check, err := schnorr.ParseSignature(raw)
		verified := err == nil && check.Verify(digest[:], key.PubKey())
		if verified != valid {
			t.Fatal("signature control invalid")
		}
		rec.Reconcile = &auth
		_, err = journal.Append(rec)
		t.Logf("valid_authorization=%v append_error=%v", valid, err)
		if valid && err != nil {
			t.Errorf("valid release refused: %v", err)
		}
		if !valid && err == nil {
			t.Error("RECONCILE_AUTHORIZATION_UNCHECKED: invalid signature accepted")
		}
		journal.Close()
	}
}

// Claim: releasing one atom of an uncertain reservation must not release its
// still-retained input or its remaining next-day debit. Full release is the neighbour.
func TestPX1jReviewPartialRelease(t *testing.T) {
	for _, release := range []int64{50000, 1} {
		t.Run(map[bool]string{true: "full", false: "partial"}[release == 50000], func(t *testing.T) {
			journal := px1jOpenWallet(t, px1jPrivateDir(t), JournalLimitsV2{SpendCapacity: 4})
			defer journal.Close()
			now := int64(1794441599)
			reserve := px1jMust(t, journal, px1jReserve(1, 1, now, 50000, 1))
			px1jMust(t, journal, px1jFollowRec(reserve, RecordUncertain, "uncertain", now))
			rec := px1jFollowRec(reserve, RecordReconcile, "released", now)
			rec.Reconcile = &ReconcileRecordV2{TargetSeq: reserve.Seq, Evidence: "absent", Height: 100, BlockHash: px1jHex(9), ReleasedSat: release, NoteSHA256: px1jHex(5)}
			px1jMust(t, journal, px1jSignNext(t, journal, rec, px1jReceiptKeyN))
			ledger, err := FoldLedgerV2(journal)
			if err != nil {
				t.Fatal(err)
			}
			retained := 50000 - release
			if got := ledger.SpendUsed(reserve.GrantID); got != retained {
				t.Fatalf("retained total %d want %d", got, retained)
			}
			input := su.Point{TxID: px1jHex(3001), Vout: 0}
			if got := ledger.InputReserved(input); got != (retained > 0) {
				t.Errorf("PARTIAL_RELEASE_INPUT: reserved=%v retained=%d", got, retained)
			}
			used, count := ledger.DayUsage(reserve.GrantID, UTCDay(now+1))
			if retained > 0 && (used != retained || count != 1) {
				t.Errorf("PARTIAL_RELEASE_DAY: got %d/%d want %d/1", used, count, retained)
			}
		})
	}
}

// Claim: an observation-only conflicted track cannot make an unresolved
// reservation stop counting on the next day; reserve-only is the neighbour.
func TestPX1jReviewTrackUncertain(t *testing.T) {
	for _, tracked := range []bool{false, true} {
		journal := px1jOpenWallet(t, px1jPrivateDir(t), JournalLimitsV2{SpendCapacity: 4})
		now := int64(1794441599)
		reserve := px1jMust(t, journal, px1jReserve(1, 1, now, 50000, 1))
		px1jMust(t, journal, px1jFollowRec(reserve, RecordUncertain, "uncertain", now))
		if tracked {
			rec := px1jFollowRec(reserve, RecordTrack, TrackConflicted, now+1)
			rec.Track = &TrackRecordV2{State: TrackConflicted, Height: 100, BlockHash: px1jHex(9)}
			px1jMust(t, journal, rec)
		}
		ledger, err := FoldLedgerV2(journal)
		if err != nil {
			t.Fatal(err)
		}
		used, count := ledger.DayUsage(reserve.GrantID, UTCDay(now+1))
		t.Logf("tracked=%v total=%d day=%d count=%d uncertain=%d", tracked, ledger.SpendUsed(reserve.GrantID), used, count, ledger.UncertainSat(reserve.GrantID))
		if used != 50000 || count != 1 {
			t.Errorf("TRACK_ERASES_UNCERTAIN_DAY: got %d/%d", used, count)
		}
		journal.Close()
	}
}

// Claim under test: malformed operator authorization must not erase retained
// debit. This probe isolates the journal boundary; it does not claim agent-UID write access.
func TestPX1jReviewForgedReconcile(t *testing.T) {
	journal := px1jOpenWallet(t, px1jPrivateDir(t), JournalLimitsV2{SpendCapacity: 4})
	defer journal.Close()
	now := int64(1794441599)
	reserve := px1jMust(t, journal, px1jReserve(1, 1, now, 50000, 1))
	ledger, err := FoldLedgerV2(journal)
	if err != nil || ledger.SpendUsed(reserve.GrantID) != 50000 {
		t.Fatal("reserve neighbour", err)
	}
	rec := px1jFollowRec(reserve, RecordReconcile, "released", now)
	rec.Reconcile = &ReconcileRecordV2{TargetSeq: reserve.Seq, Evidence: "absent", Height: 100, BlockHash: px1jHex(9), ReleasedSat: 50000, NoteSHA256: px1jHex(5), Signature: strings.Repeat("00", 64)}
	_, err = journal.Append(rec)
	if err != nil {
		t.Logf("forged release rejected: %v", err)
		return
	}
	ledger, err = FoldLedgerV2(journal)
	if err != nil {
		t.Fatal(err)
	}
	t.Fatalf("FORGED_RECONCILE_ACCEPTED: zero signature reduced retained total from 50000 to %d", ledger.SpendUsed(reserve.GrantID))
}
