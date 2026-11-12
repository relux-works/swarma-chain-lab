package wallet

// Owner S1. STUB CONTRACT: replace these tests with T1/T2/T4/T6/T7/T12/T15
// coverage when the implementation lands.

import (
	"errors"
	"testing"
)

// Claim: until S1 lands, every terms/caps entry point refuses with the sentinel
// and none reports success.
func TestPX1TermsStubsFailClosed(t *testing.T) {
	if _, e := ParseTermsV2(canonical(px1TermsAllow()), TermsV2Pins{}); !errors.Is(e, ErrNotImplemented) {
		t.Fatal(e)
	}
	if !errors.Is(ValidateG2OperatorConfig(px1Operator()), ErrNotImplemented) {
		t.Fatal("operator config")
	}
	if _, e := EffectiveLimitsFor(Grant{}, px1TermsAllow(), px1Operator()); !errors.Is(e, ErrNotImplemented) {
		t.Fatal(e)
	}
	c := NewCapChecker()
	for _, e := range []error{c.CheckExecutor(px1TermsAllow(), px1ExecutorKey), c.CheckRecipient(EffectiveLimits{}, px1AllowA), c.CheckPrePlan(EffectiveLimits{}, SpendIntent{}, nil), c.CheckPostPlan(EffectiveLimits{}, SpendIntent{}, nil)} {
		if !errors.Is(e, ErrNotImplemented) {
			t.Fatal(e)
		}
	}
}

// Claim: until S1 lands, the wallet seams expose no journal and no ledger.
func TestPX1WalletSeamStubs(t *testing.T) {
	var w Wallet
	if w.PX1Journal() != nil {
		t.Fatal("journal seam")
	}
	if _, e := w.PX1Ledger(); !errors.Is(e, ErrNotImplemented) {
		t.Fatal(e)
	}
}
