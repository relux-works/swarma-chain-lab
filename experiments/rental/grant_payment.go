package rental

import (
	"context"
	pc "github.com/relux-works/swarma-chain-lab/experiments/payment-chain"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// IssueGrantWithNodes keeps Namecoin identity, seals and funding on the explicit
// identity route. Signed v2 payment terms choose only a trusted payment route;
// they cannot inject credentials or redirect name operations. The grant/burn/
// recovery engine is shared with IssueGrant, preserving exact old v3 replays.
func IssueGrantWithNodes(ctx context.Context, identityNode su.Node, paymentNodes map[string]su.Node, p IssuerPolicyV2, request, publication []byte, pool Point, spec PlanSpec, keyPath string, now int64) GrantIssueResult {
	route := grantPaymentRoute{policies: map[string]PaymentAdmissionPolicy{}, nodes: map[string]su.Node{}}
	for coin, policy := range p.PaymentPolicies {
		route.policies[coin] = policy
	}
	for coin, node := range paymentNodes {
		route.nodes[coin] = node
	}
	return issueGrantRouted(ctx, identityNode, p.IssuerPolicy, request, publication, pool, spec, keyPath, now, nil, &route, readGrantKey)
}

type grantPaymentRoute struct {
	policies map[string]PaymentAdmissionPolicy
	nodes    map[string]su.Node
}

// This internal projection has no wire encoding and no authority by itself. The
// verifier consumes the original signed bytes; it never fabricates a v1 contract
// from v2 terms or changes the contract hash used for signatures and burns.
type grantIntent struct {
	BookingID, ContractSHA256, RenterPubkey string
	Scope                                   []string
	BudgetSat, NotBefore, NotAfter          int64
}
type grantIntentPackage struct {
	RenterName    string
	Consent       Event
	HoldExpiresAt int64
}

func intentV1(r IssuanceRequest) grantIntent {
	return grantIntent{r.BookingID, r.ContractSHA256, r.RenterPubkey, r.Scope, r.BudgetSat, r.NotBefore, r.NotAfter}
}
func intentV2(r IssuanceRequestV2) grantIntent {
	return grantIntent{r.BookingID, r.ContractSHA256, r.RenterPubkey, r.Scope, r.BudgetSat, r.NotBefore, r.NotAfter}
}
func decodeGrantIntent(raw []byte, v2 bool) (grantIntent, error) {
	if v2 {
		var r IssuanceRequestV2
		if canonical(raw, &r) != nil || r.Version != 2 {
			return grantIntent{}, bad("ISSUANCE_REQUEST")
		}
		return intentV2(r), nil
	}
	var r IssuanceRequest
	if canonical(raw, &r) != nil {
		return grantIntent{}, bad("ISSUANCE_REQUEST")
	}
	return intentV1(r), nil
}
func verifyGrantIntent(p IssuerPolicy, route *grantPaymentRoute, request, event []byte, now int64) (grantIntent, grantIntentPackage, error) {
	if route == nil {
		r, pack, e := VerifyIssuancePackage(p, request, event, now)
		if e != nil {
			return grantIntent{}, grantIntentPackage{}, e
		}
		return intentV1(r), grantIntentPackage{pack.Contract.RenterName, pack.Consent, pack.HoldExpiresAt}, nil
	}
	r, pack, e := VerifyIssuancePackageV2(IssuerPolicyV2{IssuerPolicy: p, PaymentPolicies: route.policies}, request, event, now)
	if e != nil {
		return grantIntent{}, grantIntentPackage{}, e
	}
	return intentV2(r), grantIntentPackage{pack.Contract.RenterName, pack.Consent, pack.HoldExpiresAt}, nil
}
func validStoredPaymentAdmission(a *AdmissionV2, request []byte) bool {
	var r IssuanceRequestV2
	if a == nil || canonical(request, &r) != nil || a.Verdict != "admit" || a.Reason != "PAYMENT_AND_PACKAGE_CURRENT" || a.BookingID != r.BookingID || a.ContractSHA256 != r.ContractSHA256 || a.Coin != r.PaymentCoin || a.Network != r.PaymentNetwork || a.Genesis != r.PaymentGenesis || a.CheckedAt <= 0 || a.Observation == nil {
		return false
	}
	profile, e := pc.ForNetwork(a.Coin, a.Network, a.Genesis)
	if e != nil || profile.Network != a.Network || profile.Genesis != a.Genesis {
		return false
	}
	o := a.Observation
	return o.Payment.TxID == r.PaymentTxID && o.Payment.Vout == r.PaymentVout && o.Payment.Height == r.PaymentHeight && o.Payment.BlockHash == r.PaymentBlockHash && o.Payment.ValueAtoms > 0 && o.Payment.ValueAtoms <= profile.MaxAtoms && o.Tip.Height >= o.Payment.Height && digest(o.Tip.Hash) && o.Confirmations == o.Tip.Height-o.Payment.Height+1 && o.Confirmations > 0 && o.SurplusAtoms >= 0
}
