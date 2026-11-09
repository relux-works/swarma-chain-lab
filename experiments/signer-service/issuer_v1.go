package signerservice

import (
	"context"
	rental "github.com/relux-works/swarma-chain-lab/experiments/rental"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// V1Issuer reuses the landed K1 engine for NMC. V2 admission is a separate
// binding and is unavailable until the real P1 implementation is linked.
type V1Issuer struct {
	Policy  rental.IssuerPolicy
	Node    su.Node
	KeyPath string
}

func (a V1Issuer) Inspect(r, p []byte, now int64) (Intent, error) {
	req, _, e := rental.VerifyIssuancePackage(a.Policy, r, p, now)
	if e != nil {
		return Intent{}, e
	}
	return Intent{req.BookingID, req.ContractSHA256, req.BudgetSat, "nmc", a.Policy.Policy.Network, a.Policy.Policy.Genesis, req.PaymentTxID, req.PaymentVout}, nil
}
func (a V1Issuer) Check(ctx context.Context, r, p []byte, now int64) error {
	if a.Node == nil {
		return fail("NODE_UNAVAILABLE")
	}
	result := rental.AdmitIssuance(ctx, a.Node, a.Policy, r, p, now)
	if result.Verdict != "admit" {
		return fail(result.Reason)
	}
	o := su.NewReadObservation(ctx, a.Node)
	defer o.Close()
	if e := o.Start(a.Policy.Policy.Network, a.Policy.Policy.Genesis); e != nil {
		return e
	}
	intent, e := a.Inspect(r, p, now)
	if e != nil {
		return e
	}
	v, _, e := o.PaymentTransaction(intent.PaymentTxID)
	if e != nil {
		return e
	}
	if v.Confirmations < 1 {
		return fail("PAYMENT_UNCONFIRMED")
	}
	if _, e = o.Confirmed(v); e != nil {
		return e
	}
	return o.Stable()
}
func (a V1Issuer) Prepare(ctx context.Context, r, p []byte, seal rental.Point, s rental.PlanSpec, now int64) rental.GrantIssueResult {
	return rental.IssueGrant(ctx, a.Node, a.Policy, r, p, seal, s, a.KeyPath, now)
}
