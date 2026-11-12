package wallet

// Owner S2. STUB CONTRACT: replace these tests with T3/T5/T8/T9/T10/T16/T17
// coverage when the implementation lands.

import (
	"errors"
	"testing"
)

// Claim: until S2 lands, journal entry points refuse with the sentinel, the
// capacity rule can never be satisfied, and the read limiter refuses reads.
func TestPX1JournalStubsFailClosed(t *testing.T) {
	if j, e := OpenJournalV2(t.TempDir(), "journal.lock", JournalHeaderV2{Version: 2, Layer: JournalLayerWallet}, JournalLimitsV2{SpendCapacity: 2048}); j != nil || !errors.Is(e, ErrNotImplemented) {
		t.Fatal(e)
	}
	if RequiredSpendCapacity(5, 0, 86400*7) >= 0 {
		t.Fatal("stub capacity must be unsatisfiable")
	}
	if UTCDay(1794000000) != "" || UTCDaysSpanned(0, 86400) != 0 {
		t.Fatal("stub day helpers must be zero")
	}
	if _, e := FoldLedgerV2(nil); !errors.Is(e, ErrNotImplemented) {
		t.Fatal(e)
	}
	if _, e := NewClockGuard(func() int64 { return 1 }, 0); !errors.Is(e, ErrNotImplemented) {
		t.Fatal(e)
	}
	r := NewReadLimiter(DefaultReadRatePerHour)
	if !errors.Is(r.Admit(px1ExecutorKey, 1), ErrNotImplemented) || r.Tail() == nil {
		t.Fatal("read limiter stub")
	}
}

// Claim: until S2 lands, the service seams report the W2 profile (nil).
func TestPX1ServiceSeamStubs(t *testing.T) {
	var s ActionService
	if s.PX1ServiceJournal() != nil || s.PX1Profile() != nil {
		t.Fatal("service seams")
	}
}
