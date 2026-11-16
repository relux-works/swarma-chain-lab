package session

import (
	"crypto/sha256"
	"testing"

	"github.com/relux-works/swarma-chain-lab/experiments/model-proxy/internal/redactcheck"
)

// Token and each distinct ephemeral carrier conceal synthetic bytes in the
// shared bad-verb/container, JSON, text and slog battery. No real draw is logged.
func TestTokenBadVerb(t *testing.T) {
	token, raw := outputToken(t)
	forbidden := redactcheck.SecretForms(raw[:])
	t.Run("Token", func(t *testing.T) { redactcheck.Check(t, token, forbidden...) })
	t.Run("Facts.Token", func(t *testing.T) { redactcheck.Check(t, Facts{Token: token}, forbidden...) })
	t.Run("Facts.Random", func(t *testing.T) { redactcheck.Check(t, Facts{Random: token}, forbidden...) })
	t.Run("Result.Token", func(t *testing.T) { redactcheck.Check(t, Result{Code: Admitted, Token: &token}, forbidden...) })
}

// Zero storage still means 32 zero octets; reveal returns independent copies,
// and the unchanged SHA-256 oracle uses the original synthetic bytes.
func TestTokenStorageSemantics(t *testing.T) {
	token, raw := outputToken(t)
	if tokenDigest(token) != sha256.Sum256(raw[:]) {
		t.Fatal("token digest changed")
	}
	copy := token.RevealForOpen()
	copy[0] ^= 0xff
	if token.RevealForOpen() != raw {
		t.Fatal("opening output mutated token storage")
	}
	var zero Token
	if zero.RevealForOpen() != [32]byte{} || tokenDigest(zero) != sha256.Sum256(make([]byte, 32)) {
		t.Fatal("zero token semantics changed")
	}
}
