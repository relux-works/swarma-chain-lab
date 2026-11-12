package wallet

// PX1 stream S2 implementation file (owner S2). STUBS: every function returns
// ErrNotImplemented (or a zero value where the frozen signature has no error)
// until S2 lands. Signatures are frozen in px1_journal_api.go.

// OpenJournalV2 opens or creates one layer journal.
func OpenJournalV2(dir, lockName string, h JournalHeaderV2, l JournalLimitsV2) (JournalV2, error) {
	return nil, ErrNotImplemented
}

// RequiredSpendCapacity is the minimum journal spend capacity for a grant.
// STUB: returns -1, which no configured capacity can satisfy (fail closed).
func RequiredSpendCapacity(dayCountCap int, notBefore, notAfter int64) int { return -1 }

// UTCDay is the UTC calendar day key of a Unix time. STUB: returns "".
func UTCDay(unix int64) string { return "" }

// UTCDaysSpanned counts UTC calendar days intersecting [notBefore, notAfter).
// STUB: returns 0.
func UTCDaysSpanned(notBefore, notAfter int64) int { return 0 }

// FoldLedgerV2 folds a wallet-layer journal into the cap checker's view.
func FoldLedgerV2(j JournalV2) (LedgerView, error) { return nil, ErrNotImplemented }

// NewClockGuard returns the CLOCK_ROLLBACK guard.
func NewClockGuard(clock func() int64, lastTime int64) (ClockGuard, error) {
	return nil, ErrNotImplemented
}

type stubReadLimiter struct{}

// NewReadLimiter returns the per-grantee read limiter. STUB: refuses every read.
func NewReadLimiter(perHour int) ReadLimiter { return stubReadLimiter{} }

func (stubReadLimiter) Admit(string, int64) error { return ErrNotImplemented }
func (stubReadLimiter) Tail() []ReadAuditEntry    { return []ReadAuditEntry{} }
