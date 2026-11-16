package grantcheck

import (
	"bytes"
	"encoding/json"

	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernel"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/durable"
)

const maxCacheBytes = 60000

// JSON punctuation, maximum digest widths, maximum timestamp and longest code.
const maxProvisionRecordBytes = len(`{"grant_id":"","hash":"","at":253402300799,"result":""}`) + 128 + len(CodeInvalidPresentation)
const maxProvisionBytes = 2 + MaxProvisionRecords*maxProvisionRecordBytes + MaxProvisionRecords - 1
const maxStateEnvelopeBytes = len(`{"version":1,"binding":"","high":253402300799,"provisioning":,"cache":}`) + 64
const maxStateBytes = maxStateEnvelopeBytes + maxCacheBytes + maxProvisionBytes

// encodeState preflights the complete candidate before any durable write. Cache
// and audit retain their independent capacities within the combined writer bound.
func encodeState(m state) ([]byte, Code) {
	cache, err := json.Marshal(m.Cache)
	raw, rawErr := json.Marshal(m)
	if err != nil || rawErr != nil || len(m.Cache) > MaxRecipients || len(cache) > maxCacheBytes || len(m.Provisioning) > MaxProvisionRecords || len(raw) > maxStateBytes || maxStateBytes > durable.MaxWriteBytes {
		return nil, CodeCapacityExceeded
	}
	return raw, CodeLive
}

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
		if err != nil || entry.GrantID != proof.SignedGrant.ID() || g.GranteeKey != entry.Peer || g.AgentName != c.config.AgentName || g.LandlordName != c.config.LandlordName || g.IssuerKey != c.config.IssuerPubkey || g.Network != c.network || g.Genesis != c.genesis {
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
		return CodeCapacityExceeded
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
