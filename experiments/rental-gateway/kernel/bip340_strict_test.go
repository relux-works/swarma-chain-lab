package kernel_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernel"
)

// Presentation IDs are never returned for s >= n, even in valid canonical
// framing; the real v3 fixture's signed bytes and stable ID remain accepted.
func TestBIP340PresentationBoundary(t *testing.T) {
	raw, err := os.ReadFile("../../rental/testdata/grant-v3/presentation.json")
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		SignedGrant struct {
			Signature string `json:"signature"`
		} `json:"signed_grant"`
	}
	if err = json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	id, err := kernel.PresentationID(raw)
	if err != nil || id == "" {
		t.Fatal("valid control", err)
	}
	b, _ := hex.DecodeString(p.SignedGrant.Signature)
	for _, scalar := range []string{"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142", strings.Repeat("f", 64)} {
		s, _ := hex.DecodeString(scalar)
		copy(b[32:], s)
		bad := []byte(strings.Replace(string(raw), p.SignedGrant.Signature, hex.EncodeToString(b), 1))
		if got, err := kernel.PresentationID(bad); err == nil || got != "" {
			t.Fatalf("non-canonical signature received ID: %s %v", got, err)
		}
		if got, err := kernel.PresentationID(raw); err != nil || got != id {
			t.Fatal("valid neighbour", err)
		}
	}
	// Keep the independently specified group order in the fixture pinned to the curve.
	if btcec.S256().N.Text(16) != "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141" {
		t.Fatal("curve order")
	}
}
