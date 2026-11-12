package rental

// Owner S4. STUB CONTRACT: replace with issuance tests (signer order, digest
// recomputation, refusal on a wrong key or signature, ParseSignedGrant round
// trip, IssuanceCommitment) when the implementation lands.

import (
	"context"
	"errors"
	"testing"
	"time"
)

type px1RecordingSigner struct {
	key   string
	calls int
}

func (s *px1RecordingSigner) XOnlyKey() string { return s.key }
func (s *px1RecordingSigner) Sign(context.Context, PayGrantSigningRequest) (PayGrantSignature, error) {
	s.calls++
	return PayGrantSignature{}, errors.New("unexpected")
}

// Claim: until S4 lands, every issuance entry point refuses with the sentinel,
// produces no grant bytes, and never calls a signer.
func TestPX1PayGrantStubsFailClosed(t *testing.T) {
	if b, e := EncodePayTermsV2(px1PayTermsAllow()); b != nil || !errors.Is(e, ErrPayGrantNotImplemented) {
		t.Fatal(e)
	}
	if PayGrantBookingRef([]byte("x")) != "" {
		t.Fatal("booking ref stub")
	}
	if !errors.Is(ValidatePayGrantV2Input(PayGrantV2Input{Terms: px1PayTermsAllow()}), ErrPayGrantNotImplemented) {
		t.Fatal("validate stub")
	}
	g, l := &px1RecordingSigner{key: "g"}, &px1RecordingSigner{key: "l"}
	r, e := IssuePayGrantV2(context.Background(), PayGrantV2Input{Terms: px1PayTermsAllow()}, g, l)
	if !errors.Is(e, ErrPayGrantNotImplemented) || r.SignedGrant != nil || g.calls+l.calls != 0 {
		t.Fatal("issue stub", e)
	}
	s := NewFileExchangeSigner(t.TempDir(), t.TempDir(), px1ExecutorKey, time.Millisecond)
	if _, e := s.Sign(context.Background(), PayGrantSigningRequest{}); !errors.Is(e, ErrPayGrantNotImplemented) || s.XOnlyKey() != px1ExecutorKey {
		t.Fatal("file signer stub", e)
	}
}
