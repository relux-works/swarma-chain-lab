package booking

import (
	"encoding/hex"
	"github.com/btcsuite/btcd/btcec/v2"
	"testing"
)

// Event and contract signatures reject an out-of-range scalar beside a valid
// signed event; the scalar is deliberately invalid, not a claimed forgery.
func TestBIP340SignatureBoundaries(t *testing.T) {
	e := Event{CreatedAt: 100, Kind: ConsentKind, Tags: [][]string{}, Content: ""}
	if err := e.Sign(testKey(1)); err != nil {
		t.Fatal(err)
	}
	if err := e.Verify(); err != nil {
		t.Fatal("valid event", err)
	}
	good := e.Sig
	b, _ := hex.DecodeString(good)
	btcec.S256().N.FillBytes(b[32:])
	e.Sig = hex.EncodeToString(b)
	if verifySignature(e.Pubkey, e.ID, e.Sig) {
		t.Fatal("scalar boundary accepted")
	}
	if err := e.Verify(); err == nil || err.Error() != "EVENT_SIGNATURE" {
		t.Fatal("wrong rejection", err)
	}
	e.Sig = good
	if err := e.Verify(); err != nil {
		t.Fatal("valid neighbour", err)
	}
}
