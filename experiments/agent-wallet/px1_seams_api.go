package wallet

// PX1 FROZEN CONTRACT: the only cross-stream seams inside agent-wallet. Each
// method body lives in exactly one stream-owned file; callers in other
// streams use these methods and never read another stream's struct fields.
//
// Profile selection: ServiceConfig gains `G2 *G2OperatorConfig
// json:"g2,omitempty"` (S1, service_config.go). nil keeps W2 bytes, journal
// binding and behaviour unchanged; non-nil selects the G2 profile, in which a
// reached stub refuses PX1_NOT_IMPLEMENTED (fail closed).
//
// Lock order is unchanged from W2: ActionService.mu, then Wallet.mu. PX1Tick
// and PX1Status take both in that order; no seam is called with Wallet.mu held
// alone.

import "context"

var (
	// S1, px1_wallet_seams.go: the wallet-layer journal (nil under W2).
	_ func(*Wallet) JournalV2 = (*Wallet).PX1Journal
	// S1, px1_wallet_seams.go: the folded ledger of the wallet-layer journal.
	_ func(*Wallet) (LedgerView, error) = (*Wallet).PX1Ledger
	// S2, px1_service_seams.go: the service-layer journal (nil under W2).
	_ func(*ActionService) JournalV2 = (*ActionService).PX1ServiceJournal
	// S2, px1_service_seams.go: the active operator block (nil under W2).
	_ func(*ActionService) *G2OperatorConfig = (*ActionService).PX1Profile
	// S3, px1_runtime.go: called by S2's service.go at step 23, after the
	// complete record is durable, with ActionService.mu held.
	_ func(*ActionService, TrackedPayment) error = (*ActionService).PX1Enqueue
	// S3, px1_runtime.go: one tracker/canary/float/seal observation pass,
	// driven by cmd/agent-walletd (S3). Appends track records, raises alerts,
	// poisons the service on a spent canary.
	_ func(*ActionService, context.Context) error = (*ActionService).PX1Tick
	// S3, px1_runtime.go: the status projection, no node call, no write.
	_ func(*ActionService) (StatusProjectionV1, error) = (*ActionService).PX1Status
)
