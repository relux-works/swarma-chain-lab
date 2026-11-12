package wallet

// Owner S3. STUB CONTRACT: replace these tests with T11/T13/T14 and status
// projection coverage when the implementation lands.

import (
	"context"
	"errors"
	"testing"
)

// Claim: until S3 lands, observation entry points refuse with the sentinel and
// the status projection is never served from a zero value.
func TestPX1ObserveStubsFailClosed(t *testing.T) {
	if _, e := NewTracker(nil, TrackerConfig{ConfirmationsK: 2, ConflictBlocksN: 6}, nil); !errors.Is(e, ErrNotImplemented) {
		t.Fatal(e)
	}
	if _, e := NewCanary(nil, px1Operator().Canary); !errors.Is(e, ErrNotImplemented) {
		t.Fatal(e)
	}
	if _, e := NewFloatMonitor(nil, 2000000, 500000); !errors.Is(e, ErrNotImplemented) {
		t.Fatal(e)
	}
	if _, e := NewStartupReconciler(nil); !errors.Is(e, ErrNotImplemented) {
		t.Fatal(e)
	}
	if _, e := ProjectStatus(StatusInputs{}); !errors.Is(e, ErrNotImplemented) {
		t.Fatal(e)
	}
	if e := ServeStatus(context.Background(), nil, func() (StatusProjectionV1, error) { return px1StatusFixture(), nil }); !errors.Is(e, ErrNotImplemented) {
		t.Fatal(e)
	}
	NewLogAlertSink(func(string) { t.Fatal("stub sink must not write") }).Raise(Alert{Code: AlertCanarySpent})
}

// Claim: until S3 lands, the runtime seams refuse with the sentinel.
func TestPX1RuntimeSeamStubs(t *testing.T) {
	var s ActionService
	if !errors.Is(s.PX1Enqueue(TrackedPayment{}), ErrNotImplemented) || !errors.Is(s.PX1Tick(context.Background()), ErrNotImplemented) {
		t.Fatal("runtime seams")
	}
	if _, e := s.PX1Status(); !errors.Is(e, ErrNotImplemented) {
		t.Fatal(e)
	}
}
