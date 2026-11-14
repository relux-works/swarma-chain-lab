package executor

import (
	"encoding/hex"
	"github.com/btcsuite/btcd/btcec/v2"
	"testing"
)

// The actual executor request parser rejects a non-canonical scalar and yields
// no request, while the unchanged signed request passes.
func TestBIP340RequestBoundary(t *testing.T) {
	e := sampleEvent()
	if _, err := ParseRequest(canonical(e)); err != nil {
		t.Fatal("valid control", err)
	}
	good := e.Sig
	b, _ := hex.DecodeString(good)
	btcec.S256().N.FillBytes(b[32:])
	e.Sig = hex.EncodeToString(b)
	r, err := ParseRequest(canonical(e))
	if err == nil || err.Error() != "EVENT_SIGNATURE" || r.Action != "" {
		t.Fatalf("invalid signature returned request: %+v %v", r, err)
	}
	e.Sig = good
	if _, err = ParseRequest(canonical(e)); err != nil {
		t.Fatal("valid neighbour", err)
	}
}
