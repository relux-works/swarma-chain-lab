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
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"

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

// Real issuer-produced proof reaches live; invalid scalar encodings cannot alter checker/kernel state or create an ID.
func TestCoreBIP340InboundBoundary(t *testing.T) {
	agent, err := nostr.GeneratePrivKey()
	if err != nil {
		t.Fatal(err)
	}
	l := newCoreLab(t, agent.PubKeyHex())
	renter, err := nostr.GeneratePrivKey()
	if err != nil {
		t.Fatal(err)
	}
	raw := l.grant(renter, "canonical-boundary", l.seal(), true)
	id, err := kernel.PresentationID(raw)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(l.private, "boundary-checker")
	if err = os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	c, err := New(Config{ConstructionProfile: "W", Identity: "canonical-boundary", AgentName: e2eAgentName, LandlordName: e2eLandlordName, IssuerPubkey: l.issuerPub, StateDir: dir, Node: l.observer, Now: func() time.Time { return time.Unix(500, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	p := Presentation{GrantID: id, Bytes: raw}
	assertVerdict(t, c.Inbound(context.Background(), renter.PubKeyHex(), &p), Live, CodeLive, false, false)
	snapshot := func() map[string]string {
		t.Helper()
		result := map[string]string{}
		err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
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
			result[path] = string(b)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	before := snapshot()
	var proof rental.GrantPresentation
	if err = json.Unmarshal(raw, &proof); err != nil {
		t.Fatal(err)
	}
	original := proof.SignedGrant.Signature
	sig, _ := hex.DecodeString(original)
	btcec.S256().N.FillBytes(sig[32:])
	proof.SignedGrant.Signature = hex.EncodeToString(sig)
	bad, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	signedBytes, err := json.Marshal(proof.SignedGrant)
	if err != nil {
		t.Fatal(err)
	}
	altered := Presentation{GrantID: rental.Hash(signedBytes), Bytes: bad}
	assertVerdict(t, c.Inbound(context.Background(), renter.PubKeyHex(), &altered), Refused, CodeInvalidPresentation, false, false)
	after := snapshot()
	if len(before) != len(after) {
		t.Fatal("invalid scalar changed state file set")
	}
	for path, b := range before {
		if after[path] != b {
			t.Fatal("invalid scalar changed state bytes")
		}
	}
	if got, err := kernel.PresentationID(bad); err == nil || got != "" {
		t.Fatal("invalid scalar received presentation ID")
	}
	script, err := rental.GrantSealScript(l.issuerPub)
	if err != nil {
		t.Fatal(err)
	}
	untouched := filepath.Join(l.private, "must-not-open")
	result := rental.Check(context.Background(), l.observer, rental.Policy{ConstructionProfile: "W", Network: "regtest", Genesis: proof.SignedGrant.Grant.Genesis, AgentName: e2eAgentName, LandlordName: e2eLandlordName, SealScript: script, StateDir: untouched}, bad, e2eAgentName, renter.PubKeyHex(), 500)
	if result.Verdict != "refused" || result.Reason != "GRANT_SIGNATURE" || result.GrantID != "" || result.Calls != 0 {
		t.Fatalf("invalid scalar reached kernel state or node: %+v", result)
	}
	if _, err = os.Stat(untouched); !os.IsNotExist(err) {
		t.Fatal("invalid scalar opened kernel state", err)
	}
	assertVerdict(t, c.Inbound(context.Background(), renter.PubKeyHex(), &p), Live, CodeLive, false, false)
}

func coreFileHash(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return rental.Hash(b)
}
