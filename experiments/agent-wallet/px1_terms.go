package wallet

// PX1 stream S1 implementation file (owner S1). STUBS: every function returns
// ErrNotImplemented until S1 lands. Signatures are frozen in px1_terms_api.go.

// ParseTermsV2 parses and binds terms v2 bytes; see the refusal table in
// px1_terms_api.go.
func ParseTermsV2(raw []byte, pins TermsV2Pins) (TermsV2, error) {
	return TermsV2{}, ErrNotImplemented
}

// ValidateG2OperatorConfig validates the "g2" operator block.
func ValidateG2OperatorConfig(c G2OperatorConfig) error { return ErrNotImplemented }

// EffectiveLimitsFor computes min(terms, operator ceiling) for one grant.
func EffectiveLimitsFor(g Grant, t TermsV2, c G2OperatorConfig) (EffectiveLimits, error) {
	return EffectiveLimits{}, ErrNotImplemented
}

type stubCapChecker struct{}

// NewCapChecker returns the PX1 cap checker.
func NewCapChecker() CapChecker { return stubCapChecker{} }

func (stubCapChecker) CheckExecutor(TermsV2, string) error          { return ErrNotImplemented }
func (stubCapChecker) CheckRecipient(EffectiveLimits, string) error { return ErrNotImplemented }
func (stubCapChecker) CheckPrePlan(EffectiveLimits, SpendIntent, LedgerView) error {
	return ErrNotImplemented
}
func (stubCapChecker) CheckPostPlan(EffectiveLimits, SpendIntent, LedgerView) error {
	return ErrNotImplemented
}
