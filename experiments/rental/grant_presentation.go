package rental

import (
	"context"
	"encoding/json"

	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/durable"
)

type cachedGrant struct {
	Sender       string          `json:"sender"`
	ID           string          `json:"id"`
	Presentation json.RawMessage `json:"presentation"`
}
type grantCache struct {
	Version int           `json:"version"`
	Entries []cachedGrant `json:"entries"`
}

func grantCacheName(p Policy) string {
	b, _ := json.Marshal(struct{ Network, Genesis, Agent, Landlord string }{p.Network, p.Genesis, p.AgentName, p.LandlordName})
	return "grant-presentations-" + Hash(b) + ".json"
}
func readGrantCache(store *durable.Store, p Policy) (grantCache, error) {
	c := grantCache{Version: 3, Entries: []cachedGrant{}}
	raw, e := store.Read(grantCacheName(p), PresentationBytes)
	if e != nil || raw == nil {
		return c, e
	}
	if su.StrictInput(raw, &c) != nil || c.Version != 3 || c.Entries == nil || len(c.Entries) > PresentationCapacity {
		return c, bad("PRESENTATION_CACHE_CORRUPT")
	}
	b, e := json.Marshal(c)
	if e != nil || string(b) != string(raw) {
		return c, bad("PRESENTATION_CACHE_CORRUPT")
	}
	seen := map[string]bool{}
	for _, entry := range c.Entries {
		proof, e := ParseGrantPresentation(entry.Presentation)
		g := proof.SignedGrant.Grant
		if e != nil || !pubkey(entry.Sender) || seen[entry.Sender] || entry.Sender != g.GranteeKey || entry.ID != proof.SignedGrant.ID() || g.Network != p.Network || g.Genesis != p.Genesis || g.AgentName != p.AgentName || g.LandlordName != p.LandlordName {
			return c, bad("PRESENTATION_CACHE_CORRUPT")
		}
		seen[entry.Sender] = true
	}
	return c, nil
}

// Present expects the stable signed grant id, NOT a hash of the locator-bearing
// transport bytes. Only a fresh live Check can insert or replace cached proof.
func Present(ctx context.Context, node su.Node, p Policy, raw []byte, id, agentName, sender string, now int64) Receipt {
	fail := Receipt{Version: 3, Verdict: "refused", GrantID: id, AgentName: agentName, LandlordName: p.LandlordName, CheckedAt: now}
	proof, e := ParseGrantPresentation(raw)
	if e != nil {
		fail.Reason = e.Error()
		return fail
	}
	if !digest(id) || id != proof.SignedGrant.ID() {
		fail.Reason = "PRESENTATION_ID"
		return fail
	}
	r := Check(ctx, node, p, raw, agentName, sender, now)
	if r.Verdict != "live" {
		return r
	}
	refuse := func(e error) Receipt { r.Verdict = "refused"; r.Reason = e.Error(); return r }
	store, e := durable.Open(p.StateDir, "rental.lock")
	if e != nil {
		return refuse(e)
	}
	defer store.Close()
	c, e := readGrantCache(store, p)
	if e != nil {
		return refuse(e)
	}
	replacement := cachedGrant{sender, id, append(json.RawMessage(nil), raw...)}
	index := -1
	for i, v := range c.Entries {
		if v.Sender == sender {
			index = i
			break
		}
	}
	if index >= 0 {
		c.Entries[index] = replacement
	} else {
		if len(c.Entries) >= PresentationCapacity {
			return refuse(bad("PRESENTATION_CACHE_FULL"))
		}
		c.Entries = append(c.Entries, replacement)
	}
	b, e := json.Marshal(c)
	if e != nil {
		return refuse(bad("PRESENTATION_ENCODING"))
	}
	if len(b) > PresentationBytes {
		return refuse(bad("PRESENTATION_CACHE_FULL"))
	}
	if e = store.Write(grantCacheName(p), b); e != nil {
		return refuse(e)
	}
	return r
}

// CachedGrant returns public proof bytes and stable id, never a live verdict.
func CachedGrant(p Policy, sender string) ([]byte, string, error) {
	if e := p.validateGrant(); e != nil {
		return nil, "", e
	}
	if !pubkey(sender) {
		return nil, "", bad("GRANTEE_MISMATCH")
	}
	store, e := durable.Open(p.StateDir, "rental.lock")
	if e != nil {
		return nil, "", e
	}
	defer store.Close()
	c, e := readGrantCache(store, p)
	if e != nil {
		return nil, "", e
	}
	for _, entry := range c.Entries {
		if entry.Sender == sender {
			return append([]byte(nil), entry.Presentation...), entry.ID, nil
		}
	}
	return nil, "", bad("PRESENTATION_ABSENT")
}
