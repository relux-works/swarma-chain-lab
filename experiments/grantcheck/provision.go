package grantcheck

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"

	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/durable"
)

// MaxProvisionRecords bounds the durable audit ring. The newest 64 attempts
// survive restart; consumers must export observations if longer retention is needed.
const MaxProvisionRecords = 64

// ProvisionRecord contains public proof metadata, never proof contents or keys.
// Hash is SHA256 of the canonical presentation bytes; GrantID is the signed
// grant hash bound by the on-chain issuance commitment (the locator is unsigned).
type ProvisionRecord struct {
	GrantID string `json:"grant_id"`
	Hash    string `json:"hash"`
	At      int64  `json:"at"`
	Result  Code   `json:"result"`
}

func validDigest(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == s
}

func validProvisioning(records []ProvisionRecord) bool {
	if len(records) > MaxProvisionRecords {
		return false
	}
	for _, r := range records {
		if !validDigest(r.Hash) || r.At < 0 || r.At > maxUnix || (r.GrantID != "" && !validDigest(r.GrantID)) || route(r.Result, false, r.Result == CodeSealSpent || r.Result == CodeLandlordRotated || r.Result == CodeLandlordChanged).Code != r.Result {
			return false
		}
	}
	return true
}

// Provision is protected manual retrieval-by-hash for first-message bootstrap.
// Callers supply canonical public proof bytes, not a cached permission. The
// very same admission path verifies signed-grant/terms hashes, on-chain issuance,
// seal, names, executor and fresh own-node state before grantcheck may cache bytes.
// No transport assertion or prior inbound message is needed. Every subsequent
// admission/send rechecks the cache. A durable audit failure never returns Live.
func (c *Checker) Provision(ctx context.Context, p Presentation) Verdict {
	if c == nil || c.backend == nil {
		return route(CodeCheckFailed, false, false)
	}
	if ctx == nil || ctx.Err() != nil {
		return c.auditRefusal(p, route(CodeCancelled, false, false))
	}
	if len(p.Bytes) > MaxPresentationBytes {
		return c.auditRefusal(p, route(CodeOversize, false, false))
	}
	p.Bytes = bytes.Clone(p.Bytes)
	proof, err := rental.ParseGrantPresentation(p.Bytes)
	if err != nil {
		return c.auditRefusal(p, route(CodeInvalidPresentation, false, false))
	}
	return c.checkOperation(ctx, proof.SignedGrant.Grant.GranteeKey, &p, false, true)
}

func appendProvision(m *state, p Presentation, v Verdict, at int64) {
	id := p.GrantID
	if !validDigest(id) {
		id = ""
	}
	if at < 0 || at > maxUnix {
		at = m.High
	}
	m.Provisioning = append(m.Provisioning, ProvisionRecord{id, rental.Hash(p.Bytes), at, v.Code})
	if len(m.Provisioning) > MaxProvisionRecords {
		m.Provisioning = m.Provisioning[len(m.Provisioning)-MaxProvisionRecords:]
	}
}

// Early malformed/pin refusals still produce an audit when private state is
// available. Busy or unavailable state cannot promise a durable audit.
func (c *Checker) auditRefusal(p Presentation, v Verdict) Verdict {
	if !c.mu.TryLock() {
		return route(CodeBusy, false, false)
	}
	defer c.mu.Unlock()
	if c.poisoned || !canonicalRoot(c.config.StateDir) {
		return route(CodeStateUnavailable, false, false)
	}
	s, err := durable.Open(c.config.StateDir, "grantcheck.lock")
	if err != nil {
		return route(CodeStateUnavailable, false, false)
	}
	defer s.Close()
	m, err := c.load(s)
	if err != nil {
		return route(CodeStateUnavailable, false, false)
	}
	appendProvision(&m, p, v, c.config.Now().Unix())
	raw, _ := json.Marshal(m)
	if s.Write(stateName, raw) != nil {
		c.poisoned = true
		return route(CodeStateUnavailable, false, false)
	}
	return v
}
