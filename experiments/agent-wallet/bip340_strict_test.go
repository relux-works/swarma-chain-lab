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
