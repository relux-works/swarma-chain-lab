package grantstore

import (
	"context"
	"errors"
	"relux.works/swarma-chain-lab/experiments/rental"
)

// PutGrant stores exact canonical signed-grant bytes. Landlord and agent are
// caller-pinned Nostr/grant keys, not names resolved or trusted by this store.
// The issuance locator remains separate; storage is not a live grant verdict.
func (c *Client) PutGrant(ctx context.Context, server string, raw []byte, landlord, agent string) (Descriptor, error) {
	g, e := rental.ParseSignedGrant(raw)
	if e != nil {
		return Descriptor{}, errors.New("invalid signed grant")
	}
	if !key(landlord) || !key(agent) {
		return Descriptor{}, errors.New("invalid reader pin")
	}
	set := map[string]bool{g.Grant.GranteeKey: true, landlord: true, agent: true}
	readers := []string{}
	for k := range set {
		readers = append(readers, k)
	}
	return c.Put(ctx, server, raw, readers)
}
func (c *Client) GetGrant(ctx context.Context, server, id string) (rental.SignedGrant, error) {
	raw, e := c.Get(ctx, server, id)
	if e != nil {
		return rental.SignedGrant{}, e
	}
	g, e := rental.ParseSignedGrant(raw)
	if e != nil || g.ID() != id {
		return rental.SignedGrant{}, errors.New("invalid signed grant")
	}
	return g, nil
}
