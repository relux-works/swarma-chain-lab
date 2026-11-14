package wallet

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
)

func outOfRangeScalar(t *testing.T, sig string) string {
	t.Helper()
	b, e := hex.DecodeString(sig)
	if e != nil || len(b) != 64 {
		t.Fatal("signature fixture", e)
	}
	btcec.S256().N.FillBytes(b[32:])
	return hex.EncodeToString(b)
}

// Wire, action and receipt verification reject non-canonical scalars without
// producing parsed authority, beside their unchanged valid signed controls.
func TestBIP340WalletBoundaries(t *testing.T) {
	t.Run("wire", func(t *testing.T) {
		raw := signRequest(t, testRequest(), 2)
		if _, e := ParseRequest(raw); e != nil {
			t.Fatal(e)
		}
		var event Event
		if e := json.Unmarshal(raw, &event); e != nil {
			t.Fatal(e)
		}
		event.Sig = outOfRangeScalar(t, event.Sig)
		if _, e := ParseRequest(canonical(event)); e == nil || e.Error() != "REQUEST_SIGNATURE" {
			t.Fatal("signature boundary", e)
		}
		if _, e := ParseRequest(raw); e != nil {
			t.Fatal(e)
		}
	})
	t.Run("action", func(t *testing.T) {
		raw := actionEnvelope(t, actionFixture(t, "balance"))
		if _, e := ParseAction(raw, WalletServiceID); e != nil {
			t.Fatal(e)
		}
		var event ActionEnvelope
		if e := json.Unmarshal(raw, &event); e != nil {
			t.Fatal(e)
		}
		event.Signature = outOfRangeScalar(t, event.Signature)
		if _, e := ParseAction(canonical(event), WalletServiceID); e == nil {
			t.Fatal("non-canonical action accepted")
		}
		if _, e := ParseAction(raw, WalletServiceID); e != nil {
			t.Fatal(e)
		}
	})
	t.Run("receipt", func(t *testing.T) {
		raw, e := os.ReadFile("testdata/service-v1/receipt.json")
		if e != nil {
			t.Fatal(e)
		}
		var r SignedActionReceipt
		if e = json.Unmarshal(raw, &r); e != nil {
			t.Fatal(e)
		}
		key := "5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc"
		parse := func(b []byte) error {
			_, e := ParseActionReceipt(b, key, r.Receipt.RequestHash, r.Receipt.Grantee)
			return e
		}
		if e = parse(raw); e != nil {
			t.Fatal(e)
		}
		bad := []byte(strings.Replace(string(raw), r.Signature, outOfRangeScalar(t, r.Signature), 1))
		if e = parse(bad); e == nil {
			t.Fatal("non-canonical receipt accepted")
		}
		if e = parse(raw); e != nil {
			t.Fatal(e)
		}
	})
}

// Rejected reconcile signatures cannot append a release or reduce retained debit; the valid signed release remains usable.
func TestBIP340ReconcileBoundary(t *testing.T) {
	j := px1jOpenWallet(t, px1jPrivateDir(t), JournalLimitsV2{SpendCapacity: 4})
	defer j.Close()
	const now = int64(1794441599)
	reserve := px1jMust(t, j, px1jReserve(1, 1, now, 50000, 1))
	rec := px1jFollowRec(reserve, RecordReconcile, "released", now)
	rec.Reconcile = &ReconcileRecordV2{TargetSeq: reserve.Seq, Evidence: "absent", Height: 100, BlockHash: px1jHex(9), ReleasedSat: 50000, NoteSHA256: px1jHex(5)}
	good := px1jSignNext(t, j, rec, px1jReceiptKeyN)
	if e := VerifyReconcileV2(j.Header(), good); e != nil {
		t.Fatal("valid control", e)
	}
	bad := good
	auth := *good.Reconcile
	auth.Signature = outOfRangeScalar(t, auth.Signature)
	bad.Reconcile = &auth
	seq := j.Usage().LastSeq
	if _, e := j.Append(bad); e == nil || e.Error() != CodeReconcileAuthorization {
		t.Fatal("invalid signature released debit", e)
	}
	ledger, e := FoldLedgerV2(j)
	if e != nil || ledger.SpendUsed(reserve.GrantID) != 50000 || j.Usage().LastSeq != seq {
		t.Fatal("rejected release changed state", e)
	}
	px1jMust(t, j, good)
	ledger, e = FoldLedgerV2(j)
	if e != nil || ledger.SpendUsed(reserve.GrantID) != 0 {
		t.Fatal("valid neighbour could not release", e)
	}
}
