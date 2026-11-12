package deploy

// Owner S5. STUB CONTRACT: replace with template and T18 tests when the
// implementation lands (a denied probe on ENOENT must fail; a report from
// another UID must be refused; the allowed socket is the positive control).

import (
	"context"
	"errors"
	"testing"
)

// Claim: until S5 lands, every G2 deploy entry point refuses with the sentinel
// and renders nothing.
func TestPX1G2DeployStubsFailClosed(t *testing.T) {
	p := G2PayParameters{Network: "main", FeeRateSatVB: 110, G2: px1OperatorParameters()}
	if !errors.Is(ValidateG2PayParameters(p), ErrG2NotImplemented) {
		t.Fatal("validate stub")
	}
	if files, e := RenderG2PayTemplates(p); files != nil || !errors.Is(e, ErrG2NotImplemented) {
		t.Fatal("render stub", e)
	}
	spec := CustodySpecV1{Version: 1, AgentUID: 1201, ServiceUID: 1101, AllowedSocket: "/run/swarma-wallet/wallet.sock"}
	if r, e := RunCustodyProbe(context.Background(), spec); r.Pass || !errors.Is(e, ErrG2NotImplemented) {
		t.Fatal("probe stub", e)
	}
	if !errors.Is(VerifyCustodyReport(spec, CustodyReportV1{Pass: true}), ErrG2NotImplemented) {
		t.Fatal("verify stub accepted a report")
	}
}
