package wallet

// PX1 stream S3 implementation file (owner S3). STUBS: every function returns
// ErrNotImplemented until S3 lands. Signatures are frozen in px1_observe_api.go.

import (
	"context"

	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// NewTracker returns the payment confirmation tracker.
func NewTracker(node su.Node, cfg TrackerConfig, wallet JournalV2) (Tracker, error) {
	return nil, ErrNotImplemented
}

// NewCanary returns the canary watcher.
func NewCanary(node su.Node, cfg CanaryConfig) (Canary, error) { return nil, ErrNotImplemented }

// NewFloatMonitor returns the float monitor.
func NewFloatMonitor(wallet su.Node, maxFloatSat, lowFloatSat int64) (FloatMonitor, error) {
	return nil, ErrNotImplemented
}

// NewStartupReconciler returns the wallet-versus-journal startup check.
func NewStartupReconciler(walletRoute su.Node) (StartupReconciler, error) {
	return nil, ErrNotImplemented
}

type stubAlertSink struct{}

// NewLogAlertSink returns the bounded log alert sink. STUB: drops alerts.
func NewLogAlertSink(write func(line string)) AlertSink { return stubAlertSink{} }

func (stubAlertSink) Raise(Alert) {}

// ProjectStatus builds the status projection from journals and cached
// observations.
func ProjectStatus(in StatusInputs) (StatusProjectionV1, error) {
	return StatusProjectionV1{}, ErrNotImplemented
}

// ServeStatus serves one status socket connection.
func ServeStatus(ctx context.Context, conn StatusConn, source func() (StatusProjectionV1, error)) error {
	return ErrNotImplemented
}
