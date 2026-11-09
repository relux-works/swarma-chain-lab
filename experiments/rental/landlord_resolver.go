package rental

import (
	"context"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// ResolveLandlordGrantKey returns a fresh, confirmed landlord key and raw-bound
// generation. Only Network, Genesis and LandlordName are policy inputs; it does
// not open StateDir, inspect a seal or authorize an effect. The caller must bind
// a grant's issuer and durably retain observed forward-rotation closure. A
// stateless current-name read cannot remember unseen rotations or rotate-back.
func ResolveLandlordGrantKey(ctx context.Context, node su.Node, p Policy, landlordName string) (string, Anchor, error) {
	refuse := func(e error) (string, Anchor, error) { return "", Anchor{}, e }
	if !su.NetworkPinned(p.Network, p.Genesis) {
		return refuse(bad("NETWORK_PIN"))
	}
	if !station(p.LandlordName) || landlordName != p.LandlordName {
		return refuse(bad("LANDLORD_POLICY"))
	}
	if node == nil {
		return refuse(bad("NODE_UNAVAILABLE"))
	}
	o := su.NewReadObservation(ctx, node)
	defer o.Close()
	if e := o.Start(p.Network, p.Genesis); e != nil {
		return refuse(e)
	}
	n, generation, e := readNameGeneration(o, landlordName)
	if e != nil {
		return refuse(e)
	}
	b, e := ParseLandlordValue(n.Value)
	if e != nil {
		return refuse(e)
	}
	pending := func() ([]string, error) {
		changed, ids, e := pendingIdentityTransition(o, n, func(value string) (bool, error) {
			next, e := ParseLandlordValue(value)
			return next.Grant != b.Grant, e
		})
		if e != nil {
			return nil, e
		}
		if changed {
			return nil, bad("PENDING_LANDLORD_ROTATION")
		}
		return ids, nil
	}
	before, e := pending()
	if e != nil {
		return refuse(e)
	}
	again, e := currentName(o, landlordName)
	if e != nil {
		return refuse(e)
	}
	if !sameName(n, again) {
		return refuse(bad("NAME_CHANGED"))
	}
	after, e := pending()
	if e != nil {
		return refuse(e)
	}
	if !sameJSON(before, after) {
		return refuse(bad("MEMPOOL_CHANGED"))
	}
	// Repeat after the second mempool scan: neither response set can replace
	// the final stable name/chain observation.
	again, e = currentName(o, landlordName)
	if e != nil {
		return refuse(e)
	}
	if !sameName(n, again) {
		return refuse(bad("NAME_CHANGED"))
	}
	if e = o.Stable(); e != nil {
		return refuse(e)
	}
	return b.Grant, generation, nil
}
