package nostr

import (
	"encoding/hex"
	"github.com/btcsuite/btcd/btcec/v2"
	"strings"
	"testing"
)

// Nostr authentication distinguishes scalar encoding rejection from failed
// mathematics, beside a genuinely signed valid event.
func TestBIP340SignatureBoundary(t *testing.T) {
	k, err := PrivKeyFromHex(strings.Repeat("0", 63) + "1")
	if err != nil {
		t.Fatal(err)
	}
	e := &Event{CreatedAt: 100, Kind: 1, Tags: [][]string{}, Content: ""}
	if err = k.SignEvent(e); err != nil {
		t.Fatal(err)
	}
	if err = VerifySignature(e); err != nil {
		t.Fatal("valid control", err)
	}
	good := e.Sig
	b, _ := hex.DecodeString(good)
	btcec.S256().N.FillBytes(b[32:])
	e.Sig = hex.EncodeToString(b)
	if err = VerifySignature(e); err == nil || err.Error() != "signature: BIP340: s >= n" {
		t.Fatal("scalar was not rejected before verification", err)
	}
	e.Sig = good
	if err = VerifySignature(e); err != nil {
		t.Fatal("valid neighbour", err)
	}
}
