package grantcheck

import (
	"bytes"
	"encoding/json"

	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernel"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/durable"
)

const maxCacheBytes = 60000
const maxStateBytes = 131072

type cachedProof struct {
	Peer    string          `json:"peer"`
	GrantID string          `json:"grant_id"`
	Bytes   json.RawMessage `json:"bytes"`
}

func (c *Checker) validCache(entries []cachedProof) bool {
	if len(entries) > MaxRecipients {
		return false
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		if !validKey(entry.Peer) || seen[entry.Peer] || len(entry.Bytes) > MaxPresentationBytes {
			return false
		}
		proof, err := rental.ParseGrantPresentation(entry.Bytes)
		g := proof.SignedGrant.Grant
		if err != nil || entry.GrantID != proof.SignedGrant.ID() || g.GranteeKey != entry.Peer || g.AgentName != c.config.AgentName || g.LandlordName != c.config.LandlordName || g.IssuerKey != c.config.IssuerPubkey || g.Network != "regtest" || g.Genesis != su.RegtestGenesis {
			return false
		}
		seen[entry.Peer] = true
	}
	raw, _ := json.Marshal(entries)
	return len(raw) <= maxCacheBytes
}

func cachedGrant(m state, peer string) ([]byte, error) {
	for _, entry := range m.Cache {
		if entry.Peer == peer {
			return bytes.Clone(entry.Bytes), nil
		}
	}
	return nil, kernel.ErrNoPresentation
}

// putCached is private and only called after every check (including the final
// trusted clock/freshness check) returns live. It changes a copy, never a refused cache.
func putCached(m *state, peer string, p Presentation) Code {
	entries := append([]cachedProof(nil), m.Cache...)
	found := false
	for i := range entries {
		if entries[i].Peer == peer {
			entries[i] = cachedProof{peer, p.GrantID, bytes.Clone(p.Bytes)}
			found = true
			break
		}
	}
	if !found {
		entries = append(entries, cachedProof{peer, p.GrantID, bytes.Clone(p.Bytes)})
	}
	raw, _ := json.Marshal(entries)
	if len(entries) > MaxRecipients || len(raw) > maxCacheBytes {
		return CodeStateUnavailable
	}
	m.Cache = entries
	return CodeLive
}

// cachedGrant is an internal diagnostic read; it returns bytes, never authority.
func (c *Checker) cachedGrant(peer string) ([]byte, error) {
	s, err := durable.Open(c.config.StateDir, "grantcheck.lock")
	if err != nil {
		return nil, ErrState
	}
	defer s.Close()
	m, err := c.load(s)
	if err != nil {
		return nil, err
	}
	return cachedGrant(m, peer)
}
