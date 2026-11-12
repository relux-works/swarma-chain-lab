package rental

// PX1 FROZEN CONTRACT, stream S4 surface: the terms-v2 pay-grant issuance
// helper (G2-PAYMENT-EXECUTOR-v1 Q5(a), COLEAD-REVIEW-PX1 Q1(a)/Q5).
// Implementation lives in paygrant_v2.go (owner S4). See
// experiments/agent-wallet/PX1-INTERFACES.md.
//
// Two grants exist in G2 and this helper issues only the second:
//  1. the renter's rental grant (scope deliver, renter consent) through the
//     existing booking/issuance V2 path, unchanged;
//  2. Cedar's pay grant: landlord -> Cedar's action key, Cedar's own kind-8181
//     consent, scope ["pay"], contract_sha256 = SHA256(terms v2 bytes).
//
// No private key is read by this package for a pay grant. Three external
// signatures are requested through DigestSigner, in this frozen order:
//  1. grantee (Cedar's action key): the NIP-01 id of the kind-8181 consent;
//  2. landlord (the ROTATED grant key in Ivan's Mac Keychain, never the exec1
//     M5 key): the raw contract_sha256 (GrantConsent.LandlordSig);
//  3. landlord: SHA256("swarma-grant-v3" || canonical grant), the grant signature.
//
// The issuance transaction is then planned with the existing
// MakeGrantIssuancePlan(policy, spec, SignedGrant) and signed/broadcast by the
// lead node; after confirmation PresentIssuedGrant(SignedGrant, txid) yields
// the presentation installed as <grant_id>.json next to <contract_sha256>.json
// (the terms bytes) in the wallet service objects directory.
//
// The agent-wallet module must not import these symbols until its rental
// require edge is refreshed to a published snapshot that contains them
// (experiments/MODULE-GRAPH.md); rental never imports agent-wallet.

import (
	"context"
	"encoding/json"
	"time"
)

// PayTermsV2 mirrors wallet.TermsV2 (experiments/agent-wallet/px1_terms_api.go)
// member for member and in the same order. Both modules pin the same golden
// bytes (testdata/px1/terms-v2-allow.json, SHA-256 frozen in
// paygrant_v2_freeze_test.go); the agent-wallet parser is the authority.
type PayTermsV2 struct {
	Version       int      `json:"version"`
	Service       string   `json:"service"`
	ExecutorKey   string   `json:"executor_key"`
	Network       string   `json:"network"`
	Genesis       string   `json:"genesis"`
	RecipientMode string   `json:"recipient_mode"`
	Recipients    []string `json:"recipients"`
	SpendCap      int64    `json:"spend_cap_sat"`
	TransferCap   int64    `json:"transfer_cap_sat"`
	DayCap        int64    `json:"day_cap_sat"`
	DayCountCap   int      `json:"day_count_cap"`
	FeeCap        int64    `json:"fee_cap_sat"`
	DayBasis      string   `json:"day_basis"`
}

// PayGrantV2Input is everything the issuing ceremony decides. Ivan decides the
// amounts, the window and the allow-list; the helper only validates them.
type PayGrantV2Input struct {
	Network             string     // "main" for G2
	Genesis             string     // pinned genesis of Network
	AgentName           string     // "id/ivanopcode-cedar"
	LandlordName        string     // "id/ivanopcode"
	IssuerKey           string     // x-only ROTATED landlord grant key; must equal the landlord signer's XOnlyKey()
	GranteeKey          string     // x-only Cedar action key (Q1(a)); must equal the grantee signer's XOnlyKey()
	NotBefore           int64      // window start, Unix seconds
	NotAfter            int64      // window end (exclusive); multi-day allowed, no 3600 s cap
	Seal                Point      // landlord-controlled seal; spending it revokes (signer-service revoke)
	BudgetSat           int64      // v3 budget, >= Terms.SpendCap (absent budget is refused)
	Terms               PayTermsV2 // Terms.ExecutorKey is the receipt key of the ONE agent-walletd
	ConsentCreatedAt    int64      // kind-8181 created_at; NotBefore <= x < NotAfter
	PrivacyNoticeSHA256 string     // 64 hex; SHA256 of the published G2 privacy notice ("privacy" tag)
}

// PayGrantScope is the only scope a terms-v2 pay grant carries.
var PayGrantScope = []string{"pay"}

// Signing purposes, in the frozen call order.
const (
	SignPurposeConsentEvent = "pay-grant-consent-event"        // grantee key, digest = NIP-01 event id
	SignPurposeContract     = "pay-grant-contract-countersign" // landlord key, digest = contract_sha256
	SignPurposeGrant        = "pay-grant-v3"                   // landlord key, digest = SHA256("swarma-grant-v3" || canonical grant)
)

// PayGrantSigningRequest is what an external signer receives. Terms always
// carries the canonical terms v2 bytes; Payload carries the object whose
// digest is requested (consent: the unsigned event with id; contract:
// {"contract_sha256":...}; grant: the canonical grant without signature). A
// conforming signer recomputes Digest from Terms and Payload, shows the terms
// to the human key holder, and refuses on any mismatch: it never signs a bare
// digest.
type PayGrantSigningRequest struct {
	Version   int             `json:"v"` // 1
	Purpose   string          `json:"purpose"`
	SignerKey string          `json:"signer_key"`
	Digest    string          `json:"digest"`
	Terms     json.RawMessage `json:"terms"`
	Payload   json.RawMessage `json:"payload"`
}

// PayGrantSignature is the signer's answer; the helper verifies it with
// VerifySignature(SignerKey, Digest, Signature) before using it.
type PayGrantSignature struct {
	Version   int    `json:"v"` // 1
	Purpose   string `json:"purpose"`
	SignerKey string `json:"signer_key"`
	Digest    string `json:"digest"`
	Signature string `json:"signature"` // 128 hex BIP-340
}

// DigestSigner is an external BIP-340 signer (Ivan's Mac for the landlord key,
// Cedar's slot tool for the action key).
type DigestSigner interface {
	XOnlyKey() string
	Sign(ctx context.Context, req PayGrantSigningRequest) (PayGrantSignature, error)
}

// PayGrantV2Result is the issued, not yet committed, pay grant.
type PayGrantV2Result struct {
	GrantID            string          `json:"grant_id"`            // SignedGrant.ID()
	ContractSHA256     string          `json:"contract_sha256"`     // SHA256(Terms)
	Terms              json.RawMessage `json:"terms"`               // canonical terms v2 bytes
	SignedGrant        json.RawMessage `json:"signed_grant"`        // canonical SignedGrant, ParseSignedGrant-valid
	IssuanceCommitment string          `json:"issuance_commitment"` // IssuanceCommitment(SignedGrant)
}

// Frozen entry points (implemented in paygrant_v2.go).
var (
	// EncodePayTermsV2 validates terms shape (same rules as wallet.ParseTermsV2
	// rows 3-10 without the executor pin) and returns canonical bytes.
	_ func(PayTermsV2) ([]byte, error) = EncodePayTermsV2
	// PayGrantBookingRef is the "booking" consent tag of a pay grant:
	// SHA256("swarma-g2-pay-booking-v1" || terms bytes). There is no booking.
	_ func(terms []byte) string = PayGrantBookingRef
	// ValidatePayGrantV2Input checks the input without any signer.
	_ func(PayGrantV2Input) error = ValidatePayGrantV2Input
	// IssuePayGrantV2 runs the three signatures in the frozen order and returns
	// a ParseSignedGrant-valid result. Any signer error or invalid signature
	// refuses with no partial result.
	_ func(ctx context.Context, in PayGrantV2Input, grantee, landlord DigestSigner) (PayGrantV2Result, error) = IssuePayGrantV2
	// NewFileExchangeSigner is the offline transport for Ivan's Mac: it writes
	// outbox/<purpose>-<digest>.request.json (0600) and polls
	// inbox/<purpose>-<digest>.signature.json until ctx ends.
	_ func(outbox, inbox, key string, poll time.Duration) DigestSigner = NewFileExchangeSigner
)
