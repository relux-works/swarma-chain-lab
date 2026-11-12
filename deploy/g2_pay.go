package deploy

// PX1 stream S5 implementation file (owner S5). STUBS: every entry point
// refuses with ErrG2NotImplemented until S5 lands. Signatures are frozen in
// g2_pay_api.go.

import (
	"context"
	"errors"
)

// ErrG2NotImplemented is the PX1 stub sentinel of this module.
var ErrG2NotImplemented = errors.New("PX1_NOT_IMPLEMENTED")

// ValidateG2PayParameters validates operator inputs.
func ValidateG2PayParameters(p G2PayParameters) error { return ErrG2NotImplemented }

// RenderG2PayTemplates renders the G2 pay file set.
func RenderG2PayTemplates(p G2PayParameters) (map[string][]byte, error) {
	return nil, ErrG2NotImplemented
}

// RunCustodyProbe runs the T18 probes as the agent UID.
func RunCustodyProbe(ctx context.Context, spec CustodySpecV1) (CustodyReportV1, error) {
	return CustodyReportV1{}, ErrG2NotImplemented
}

// VerifyCustodyReport checks a T18 report against its spec.
func VerifyCustodyReport(spec CustodySpecV1, report CustodyReportV1) error {
	return ErrG2NotImplemented
}
