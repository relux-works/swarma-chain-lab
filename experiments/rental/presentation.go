package rental

import (
	"context"
	"encoding/json"

	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/durable"
)

const PresentationCapacity = 64
const PresentationBytes = 60000

type cachedPresentation struct {
	Sender   string          `json:"sender"`
	ID       string          `json:"id"`
	Envelope json.RawMessage `json:"envelope"`
}
type presentationCache struct {
	Version int                  `json:"version"`
	Entries []cachedPresentation `json:"entries"`
}

func presentationName(p Policy) string {
	b, _ := json.Marshal(struct{ Network, Genesis, Agent string }{p.Network, p.Genesis, p.AgentName})
	return "presentations-" + Hash(b) + ".json"
}
func readPresentations(store *durable.Store, p Policy) (presentationCache, error) {
	cache := presentationCache{Version: 2, Entries: []cachedPresentation{}}
	raw, e := store.Read(presentationName(p), PresentationBytes)
	if e != nil {
		return cache, e
	}
	if raw == nil {
		return cache, nil
	}
	// The aggregate cache has a larger bound than one certificate. It still
	// uses StrictInput and a byte-for-byte canonical re-encoding comparison.
	if su.StrictInput(raw, &cache) != nil || cache.Version != 2 || cache.Entries == nil || len(cache.Entries) > PresentationCapacity {
		return cache, bad("PRESENTATION_CACHE_CORRUPT")
	}
	encoded, e := json.Marshal(cache)
	if e != nil || string(encoded) != string(raw) {
		return cache, bad("PRESENTATION_CACHE_CORRUPT")
	}
	seen := map[string]bool{}
	for _, entry := range cache.Entries {
		env, e := ParseDetachedEnvelope(entry.Envelope)
		if e != nil || !pubkey(entry.Sender) || seen[entry.Sender] || entry.Sender != env.Certificate.GranteeKey || !digest(entry.ID) || entry.ID != Hash(entry.Envelope) || env.Certificate.Network != p.Network || env.Certificate.Genesis != p.Genesis || env.Certificate.AgentName != p.AgentName {
			return cache, bad("PRESENTATION_CACHE_CORRUPT")
		}
		seen[entry.Sender] = true
	}
	return cache, nil
}

// Present accepts only inline bytes and an exact envelope id. It performs a
// fresh Check before changing the bounded sender cache. A cache hit is never
// authority; each subsequent message must still call Check against its node.
func PresentV2(ctx context.Context, node su.Node, p Policy, raw []byte, id, agentName, sender string, now int64) Receipt {
	fail := Receipt{Version: 2, Verdict: "refused", CertificateSHA256: id, StationName: agentName, CheckedAt: now}
	if len(raw) == 0 || len(raw) > 16384 || !digest(id) || Hash(raw) != id {
		fail.Reason = "PRESENTATION_ID"
		return fail
	}
	r := CheckV2(ctx, node, p, raw, agentName, sender, now)
	if r.Verdict != "live" {
		return r
	}
	refuse := func(e error) Receipt { r.Verdict = "refused"; r.Reason = e.Error(); return r }
	store, e := durable.Open(p.StateDir, "rental.lock")
	if e != nil {
		return refuse(e)
	}
	defer store.Close()
	cache, e := readPresentations(store, p)
	if e != nil {
		return refuse(e)
	}
	replacement := cachedPresentation{sender, id, append(json.RawMessage(nil), raw...)}
	index := -1
	for i, entry := range cache.Entries {
		if entry.Sender == sender {
			index = i
			break
		}
	}
	if index >= 0 {
		cache.Entries[index] = replacement
	} else {
		if len(cache.Entries) >= PresentationCapacity {
			return refuse(bad("PRESENTATION_CACHE_FULL"))
		}
		cache.Entries = append(cache.Entries, replacement)
	}
	encoded, e := json.Marshal(cache)
	if e != nil {
		return refuse(bad("PRESENTATION_ENCODING"))
	}
	if len(encoded) > PresentationBytes {
		return refuse(bad("PRESENTATION_CACHE_FULL"))
	}
	if e = store.Write(presentationName(p), encoded); e != nil {
		return refuse(e)
	}
	return r
}

// CachedCertificate returns public presentation bytes, not a cached verdict.
// Consumers MUST Check them freshly with their authenticated sender and clock.
func CachedCertificateV2(p Policy, sender string) ([]byte, string, error) {
	if e := p.validateDetached(); e != nil {
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
	cache, e := readPresentations(store, p)
	if e != nil {
		return nil, "", e
	}
	for _, entry := range cache.Entries {
		if entry.Sender == sender {
			return append([]byte(nil), entry.Envelope...), entry.ID, nil
		}
	}
	return nil, "", bad("PRESENTATION_ABSENT")
}
