package grantcheck

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernel"
)

// Invalid scalar encodings fail before backend calls, state writes, or cache
// replacement; the valid control exercises routing with the existing unit backend,
// not chain admission. The Core suite independently qualifies real admission.
func TestBIP340InboundBoundary(t *testing.T) {
	c, backend, p := unitChecker(t)
	peer := xonly(2)
	assertVerdict(t, c.Inbound(context.Background(), peer, &p), Live, CodeLive, false, false)
	snapshot := func() map[string]string {
		t.Helper()
		files := map[string]string{}
		err := filepath.WalkDir(c.config.StateDir, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			b, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			files[path] = string(b)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return files
	}
	before := snapshot()
	calls := backend.PresentCalls
	var proof rental.GrantPresentation
	if e := json.Unmarshal(p.Bytes, &proof); e != nil {
		t.Fatal(e)
	}
	for _, scalar := range []string{"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142", strings.Repeat("f", 64)} {
		t.Run(scalar, func(t *testing.T) {
			sig, _ := hex.DecodeString(proof.SignedGrant.Signature)
			s, _ := hex.DecodeString(scalar)
			copy(sig[32:], s)
			bad := bytes.Replace(p.Bytes, []byte(proof.SignedGrant.Signature), []byte(hex.EncodeToString(sig)), 1)
			v := c.Inbound(context.Background(), peer, &Presentation{Bytes: bad, GrantID: proof.SignedGrant.ID()})
			assertVerdict(t, v, Refused, CodeInvalidPresentation, false, false)
			if backend.PresentCalls != calls || !bytes.Equal(backend.Cached[peer], p.Bytes) {
				t.Fatal("invalid proof reached backend or replaced cache")
			}
			after := snapshot()
			if len(before) != len(after) {
				t.Fatal("state files changed")
			}
			for path, b := range before {
				if after[path] != b {
					t.Fatal("state bytes changed")
				}
			}
			if id, e := kernel.PresentationID(bad); e == nil || id != "" {
				t.Fatal("invalid proof received id")
			}
		})
	}
	assertVerdict(t, c.Inbound(context.Background(), peer, &p), Live, CodeLive, false, false)
	// The scalar boundary is the actual secp256k1 order, independently of framing.
	if btcec.S256().N.Text(16) != "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141" {
		t.Fatal("curve order")
	}
}
