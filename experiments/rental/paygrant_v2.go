package rental

// PX1 stream S4 implementation file (owner S4). STUBS: every entry point
// refuses with ErrPayGrantNotImplemented until S4 lands. Signatures are frozen
// in paygrant_v2_api.go.

import (
	"context"
	"errors"
	"time"
)

// ErrPayGrantNotImplemented is the PX1 stub sentinel of this module; its text
// equals agent-wallet's ErrNotImplemented code.
var ErrPayGrantNotImplemented = errors.New("PX1_NOT_IMPLEMENTED")

// EncodePayTermsV2 returns the canonical terms v2 bytes.
func EncodePayTermsV2(t PayTermsV2) ([]byte, error) { return nil, ErrPayGrantNotImplemented }

// PayGrantBookingRef derives the consent "booking" tag. STUB: returns "".
func PayGrantBookingRef(terms []byte) string { return "" }

// ValidatePayGrantV2Input validates the ceremony input.
func ValidatePayGrantV2Input(in PayGrantV2Input) error { return ErrPayGrantNotImplemented }

// IssuePayGrantV2 issues Cedar's pay grant through external signers.
func IssuePayGrantV2(ctx context.Context, in PayGrantV2Input, grantee, landlord DigestSigner) (PayGrantV2Result, error) {
	return PayGrantV2Result{}, ErrPayGrantNotImplemented
}

type stubFileExchangeSigner struct{ key string }

// NewFileExchangeSigner returns the offline file-exchange signer.
func NewFileExchangeSigner(outbox, inbox, key string, poll time.Duration) DigestSigner {
	return stubFileExchangeSigner{key}
}

func (s stubFileExchangeSigner) XOnlyKey() string { return s.key }
func (stubFileExchangeSigner) Sign(context.Context, PayGrantSigningRequest) (PayGrantSignature, error) {
	return PayGrantSignature{}, ErrPayGrantNotImplemented
}
