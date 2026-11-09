package wallet

import (
	"context"
	"slices"

	rental "github.com/relux-works/swarma-chain-lab/experiments/rental"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

type Grant struct {
	ID, Agent, Grantee, Issuer, Contract string
	Kind, Landlord, Recipient            string
	Amount, FeeLimit                     int64
	Scope                                []string
	Budget, NotBefore, NotAfter          int64
	Seal                                 su.Point
}

// Authority is the single protocol migration seam. Product wiring always uses
// KernelAuthority; fixture doubles never establish real-Core acceptance.
type Authority interface {
	Parse([]byte) (Grant, error)
	Check(context.Context, []byte, string, int64) error
}
type KernelAuthority struct {
	Node   su.Node
	Policy rental.Policy
}

func (k KernelAuthority) Parse(raw []byte) (Grant, error) {
	e, err := rental.ParseGrantPresentation(raw)
	if err != nil {
		return Grant{}, fail("GRANT_INVALID")
	}
	c := e.SignedGrant.Grant
	return Grant{ID: e.SignedGrant.ID(), Landlord: c.LandlordName, Agent: c.AgentName, Grantee: c.GranteeKey, Issuer: c.IssuerKey, Contract: c.ContractSHA256, Scope: append([]string{}, c.Scope...), Budget: c.BudgetSat(), NotBefore: c.NotBefore, NotAfter: c.NotAfter, Seal: su.Point{TxID: c.Seal.TxID, Vout: c.Seal.Vout}}, nil
}
func (k KernelAuthority) Check(ctx context.Context, raw []byte, sender string, now int64) error {
	r := rental.Check(ctx, k.Node, k.Policy, raw, k.Policy.AgentName, sender, now)
	if r.Verdict != "live" {
		return fail("GRANT_" + r.Reason)
	}
	return nil
}
func bindRequest(g Grant, t Terms, s SignedRequest, now int64) error {
	r := s.Request
	if g.Kind == "single-use" {
		if r.Action != "pay" || r.Amount != g.Amount || r.Address != g.Recipient || r.FeeLimit > g.FeeLimit {
			return fail("ONEOFF_REQUEST_BINDING")
		}

	}
	if r.GrantID != g.ID || s.Event.Pubkey != g.Grantee {
		return fail("REQUEST_GRANTEE_BINDING")
	}
	if s.Event.CreatedAt < g.NotBefore || s.Event.CreatedAt >= g.NotAfter || s.Event.CreatedAt > now {
		return fail("REQUEST_TIME")
	}
	if !slices.Contains(g.Scope, r.Action) {
		return fail("GRANT_SCOPE")
	}
	if !slices.Contains(t.Recipients, r.Address) {
		return fail("ADDRESS_NOT_ALLOWED")
	}
	return nil
}

// KernelResolver delegates all landlord name/chain/mempool interpretation to K1.
type KernelResolver struct {
	Node   su.Node
	Policy rental.Policy
}

func (k KernelResolver) Resolve(ctx context.Context, name string) (string, rental.Anchor, error) {
	return rental.ResolveLandlordGrantKey(ctx, k.Node, k.Policy, name)
}
