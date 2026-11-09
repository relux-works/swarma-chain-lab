package signerservice

import (
	"context"
	rental "github.com/relux-works/swarma-chain-lab/experiments/rental"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// V2Issuer is the only multi-coin binding. P1 owns signed-wire decoding, trusted
// per-coin admission and K1 reservation/recovery; this service does not fork it.
type V2Issuer struct {
	Policy   rental.IssuerPolicyV2
	Identity su.Node
	Payments map[string]su.Node
	KeyPath  string
}

func (a V2Issuer) Inspect(r, p []byte, now int64) (Intent, error) {
	req, _, e := rental.VerifyIssuancePackageV2(a.Policy, r, p, now)
	if e != nil {
		return Intent{}, e
	}
	return Intent{req.BookingID, req.ContractSHA256, req.BudgetSat, req.PaymentCoin, req.PaymentNetwork, req.PaymentGenesis, req.PaymentTxID, req.PaymentVout}, nil
}
func (a V2Issuer) Check(ctx context.Context, r, p []byte, now int64) error {
	result := rental.AdmitIssuanceV2(ctx, a.Payments, a.Policy, r, p, now)
	if result.Verdict != "admit" {
		return fail(result.Reason)
	}
	return nil
}
func (a V2Issuer) Prepare(ctx context.Context, r, p []byte, seal rental.Point, s rental.PlanSpec, now int64) rental.GrantIssueResult {
	return rental.IssueGrantWithNodes(ctx, a.Identity, a.Payments, a.Policy, r, p, seal, s, a.KeyPath, now)
}
