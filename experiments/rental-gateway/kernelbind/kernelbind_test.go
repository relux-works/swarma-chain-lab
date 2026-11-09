package kernelbind_test

// Unit controls for the detached-kernel binding that need no
// chain: policy pinning in New, receipt field mapping on refusal
// paths, presentation id enforcement, and the absent-cache error
// mapping. Live paths against a genuine Core are in the opt-in
// core_e2e_test.go.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"

	"relux.works/swarma-chain-lab/experiments/rental"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/kernel"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/kernelbind"
	singleuse "relux.works/swarma-chain-lab/experiments/single-use"
)

func xonly(n byte) string {
	b := make([]byte, 32)
	b[31] = n
	_, p := btcec.PrivKeyFromBytes(b)
	return hex.EncodeToString(schnorr.SerializePubKey(p))
}

func stateDir(t *testing.T) string {
	t.Helper()
	// The kernel's durable store demands an existing 0700 root.
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func newAdapter(t *testing.T) *kernelbind.Adapter {
	t.Helper()
	a, err := kernelbind.New(nil, stateDir(t), "id/test-agent", xonly(1))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// TestNewPinsPolicy proves New fixes the detached policy: regtest
// network + pinned genesis, the given agent name, and the seal
// script derived from the issuer key; a malformed issuer key is
// refused at construction.
func TestNewPinsPolicy(t *testing.T) {
	a := newAdapter(t)
	p := a.Policy
	wantScript, err := rental.GrantSealScript(xonly(1))
	if err != nil {
		t.Fatal(err)
	}
	if p.Network != "regtest" || p.Genesis != singleuse.RegtestGenesis ||
		p.AgentName != "id/test-agent" || p.SealScript != wantScript || p.StateDir == "" {
		t.Fatalf("policy pins wrong: %+v", p)
	}
	if _, err := kernelbind.New(nil, t.TempDir(), "id/test-agent", "not-a-key"); err == nil {
		t.Fatal("malformed issuer key accepted")
	}
}

// TestCheckMapsRefusal proves a malformed envelope comes back as a
// mapped refused receipt (never an error, never an admission) with
// the kernel's id/checked-at fields carried over.
func TestCheckMapsRefusal(t *testing.T) {
	a := newAdapter(t)
	raw := []byte("not an envelope")
	r, err := a.Check(context.Background(), raw, "id/test-agent", xonly(2), 500)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if r.Verdict != kernel.Refused || r.Admits() || r.CertificateSHA256 != hex.EncodeToString(sum[:]) ||
		r.StationName != "id/test-agent" || r.CheckedAt != 500 || r.Reason == "" {
		t.Fatalf("mapped receipt wrong: %+v", r)
	}
}

// TestPresentRejectsBadID proves Present refuses before any cache
// write when the presented id is not the SHA-256 of the bytes, and
// nothing becomes cached for the sender.
func TestPresentRejectsBadID(t *testing.T) {
	a := newAdapter(t)
	sender := xonly(2)
	r, err := a.Present(context.Background(), []byte("envelope-ish"),
		strings.Repeat("0", 64), "id/test-agent", sender, 500)
	if err != nil {
		t.Fatal(err)
	}
	if r.Verdict != kernel.Refused || r.Reason != "PRESENTATION_ID" {
		t.Fatalf("bad-id present = %+v, want refused/PRESENTATION_ID", r)
	}
	if _, err := a.CachedCertificate(sender); !errors.Is(err, kernel.ErrNoPresentation) {
		t.Fatalf("cache after refused present: err = %v, want ErrNoPresentation", err)
	}
}

// TestCachedCertificateAbsent proves the absent-cache kernel error
// maps to kernel.ErrNoPresentation so the gateway can demand an
// inline presentation.
func TestCachedCertificateAbsent(t *testing.T) {
	a := newAdapter(t)
	if _, err := a.CachedCertificate(xonly(9)); !errors.Is(err, kernel.ErrNoPresentation) {
		t.Fatalf("absent cache err = %v, want ErrNoPresentation", err)
	}
}
