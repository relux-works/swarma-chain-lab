package rental

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"time"

	"relux.works/swarma-chain-lab/experiments/rental/oplocator"
	su "relux.works/swarma-chain-lab/experiments/single-use"
	"relux.works/swarma-chain-lab/experiments/single-use/durable"
)

type grantState struct {
	Version      int    `json:"version"`
	Binding      string `json:"binding"`
	GrantID      string `json:"grant_id"`
	Agent        Anchor `json:"agent"`
	Landlord     Anchor `json:"landlord"`
	ClosedReason string `json:"closed_reason"`
}
type seenGrantSeal struct {
	Version int    `json:"version"`
	Network string `json:"network"`
	Genesis string `json:"genesis"`
	Seal    Point  `json:"seal"`
	GrantID string `json:"grant_id"`
}

func (p Policy) validateGrant() error {
	if e := p.validateDetached(); e != nil {
		return e
	}
	if !station(p.LandlordName) || p.LandlordName == p.AgentName {
		return bad("LANDLORD_POLICY")
	}
	if len(p.KnownPoolSeals) > 4096 {
		return bad("POOL_INVENTORY")
	}
	seen := map[Point]bool{}
	for _, point := range p.KnownPoolSeals {
		if !digest(point.TxID) || seen[point] {
			return bad("POOL_INVENTORY")
		}
		seen[point] = true
	}
	return nil
}
func validGeneration(a Anchor) bool { return digest(a.TxID) && digest(a.Block) && a.Height > 0 }

// Check admits v3 grants only. The unsigned locator is checked on this node;
// neither an issuer journal nor a cached verdict substitutes for chain state.
func Check(ctx context.Context, node su.Node, p Policy, raw []byte, agentName, sender string, now int64) (r Receipt) {
	started := time.Now()
	r = Receipt{Version: 3, Verdict: "refused", AgentName: agentName, LandlordName: p.LandlordName, CheckedAt: now}
	refuse := func(e error) Receipt { r.Reason = e.Error(); return r }
	if e := p.validateGrant(); e != nil {
		return refuse(e)
	}
	presentation, e := ParseGrantPresentation(raw)
	if e != nil {
		return refuse(e)
	}
	signed := presentation.SignedGrant
	g := signed.Grant
	r.GrantID = signed.ID()
	if g.Network != p.Network || g.Genesis != p.Genesis || g.AgentName != p.AgentName || agentName != p.AgentName || g.LandlordName != p.LandlordName {
		return refuse(bad("GRANT_POLICY"))
	}
	if sender != g.GranteeKey {
		return refuse(bad("GRANTEE_MISMATCH"))
	}
	script, e := GrantSealScript(g.IssuerKey)
	if e != nil || script != p.SealScript {
		return refuse(bad("SEAL_KEY_BINDING"))
	}
	if now < 0 {
		return refuse(bad("CLOCK_INPUT"))
	}
	if g.Consent.ConsentEvent.CreatedAt > now {
		return refuse(bad("CONSENT_FUTURE"))
	}
	r.Scope = append([]string{}, g.Scope...)
	r.BudgetSat = g.BudgetSat()
	store, e := durable.Open(p.StateDir, "rental.lock")
	if e != nil {
		return refuse(e)
	}
	defer store.Close()
	binding, _ := json.Marshal(struct{ Network, Genesis, Agent, Landlord, Script string }{p.Network, p.Genesis, p.AgentName, p.LandlordName, p.SealScript})
	state := grantState{Version: 3, Binding: Hash(binding), GrantID: r.GrantID}
	name := "grant-" + r.GrantID + ".json"
	saved, e := store.Read(name, 8192)
	if e != nil {
		return refuse(e)
	}
	if saved != nil {
		if canonical(saved, &state) != nil || state.Version != 3 || state.Binding != Hash(binding) || state.GrantID != r.GrantID || !validGeneration(state.Agent) || !validGeneration(state.Landlord) || (state.ClosedReason != "" && state.ClosedReason != "SEAL_SPENT" && state.ClosedReason != "LANDLORD_KEY_ROTATED" && state.ClosedReason != "AGENT_LANDLORD_CHANGED") {
			return refuse(bad("JOURNAL_CORRUPT"))
		}
		if state.ClosedReason != "" {
			r.Closed = true
			return refuse(bad(state.ClosedReason))
		}
	}
	sealName := sealIndexName(p, g.Seal)
	prior, e := store.Read(sealName, 4096)
	if e != nil {
		return refuse(e)
	}
	if prior != nil {
		var version struct {
			Version int `json:"version"`
		}
		if json.Unmarshal(prior, &version) != nil {
			return refuse(bad("SEAL_INDEX_CORRUPT"))
		}
		var oldID string
		switch version.Version {
		case 2: // Preserve one-ever memory across the explicit v2 regression profile.
			var old seenSeal
			if canonical(prior, &old) != nil || old.Network != p.Network || old.Genesis != p.Genesis || old.Seal != g.Seal || !digest(old.CertificateSHA256) {
				return refuse(bad("SEAL_INDEX_CORRUPT"))
			}
			oldID = old.CertificateSHA256
		case 3:
			var old seenGrantSeal
			if canonical(prior, &old) != nil || old.Network != p.Network || old.Genesis != p.Genesis || old.Seal != g.Seal || !digest(old.GrantID) {
				return refuse(bad("SEAL_INDEX_CORRUPT"))
			}
			oldID = old.GrantID
		default:
			return refuse(bad("SEAL_INDEX_CORRUPT"))
		}
		if oldID != r.GrantID {
			return refuse(bad("SEAL_ALREADY_SEEN"))
		}
	}
	if now < g.NotBefore {
		r.Verdict = "pending"
		return refuse(bad("NOT_YET_VALID"))
	}
	if now >= g.NotAfter {
		return refuse(bad("EXPIRED"))
	}
	if node == nil {
		return refuse(bad("NODE_UNAVAILABLE"))
	}
	o := su.NewReadObservation(ctx, node)
	defer o.Close()
	defer func() { r.Calls = o.Calls() }()
	if e = o.Start(p.Network, p.Genesis); e != nil {
		return refuse(e)
	}
	r.TipHash = o.Tip().Best
	closeGrant := func(reason string) Receipt {
		state.ClosedReason = reason
		b, _ := json.Marshal(state)
		if e := store.Write(name, b); e != nil {
			return refuse(e)
		}
		r.Closed = true
		return refuse(bad(reason))
	}
	agent, ag, e := readNameGeneration(o, p.AgentName)
	if e != nil {
		return refuse(e)
	}
	ab, e := ParseAgentBinding(agent.Value)
	if e != nil {
		return refuse(e)
	}
	stableNames := func(names ...su.NameView) error {
		for _, n := range names {
			again, e := currentName(o, n.Name)
			if e != nil {
				return e
			}
			if !sameName(n, again) {
				return bad("NAME_CHANGED")
			}
		}
		return o.Stable()
	}
	forward := func(old, next Anchor) error {
		if saved == nil || next.TxID == old.TxID || next.Height < old.Height {
			return bad("UNOBSERVED_ROTATION")
		}
		active, e := o.Active(old.Block)
		if e != nil {
			return e
		}
		if active.Height != old.Height {
			return bad("PRIOR_GENERATION_BINDING")
		}
		return nil
	}
	if ab.Landlord != g.LandlordName {
		if saved == nil || ag.TxID == state.Agent.TxID || ag.Height < state.Agent.Height {
			return refuse(bad("AGENT_LANDLORD_MISMATCH"))
		}
		if e = forward(state.Agent, ag); e != nil {
			return refuse(e)
		}
		if e = stableNames(agent); e != nil {
			return refuse(e)
		}
		return closeGrant("AGENT_LANDLORD_CHANGED")
	}
	landlord, lg, e := readNameGeneration(o, p.LandlordName)
	if e != nil {
		return refuse(e)
	}
	lb, e := ParseLandlordValue(landlord.Value)
	if e != nil {
		return refuse(e)
	}
	if lb.Grant != g.IssuerKey {
		if saved == nil || lg.TxID == state.Landlord.TxID || lg.Height < state.Landlord.Height {
			return refuse(bad("LANDLORD_KEY_MISMATCH"))
		}
		if e = forward(state.Landlord, lg); e != nil {
			return refuse(e)
		}
		if e = stableNames(agent, landlord); e != nil {
			return refuse(e)
		}
		return closeGrant("LANDLORD_KEY_ROTATED")
	}
	pending := func() ([]string, error) {
		return pendingGrantBinding(o, agent, landlord, g.LandlordName, g.IssuerKey)
	}
	poolBefore, e := pending()
	if e != nil {
		return refuse(e)
	}
	if e = checkIssuance(o, signed, presentation.Issuance); e != nil {
		if e.Error() == "ISSUANCE_UNCONFIRMED" {
			r.Verdict = "pending"
		}
		return refuse(e)
	}
	sv, tx, e := o.PaymentTransaction(g.Seal.TxID)
	if e != nil {
		return refuse(e)
	}
	if sv.Block == "" || sv.Confirmations <= 0 {
		r.Verdict = "pending"
		return refuse(bad("SEAL_UNCONFIRMED"))
	}
	sh, e := o.Confirmed(sv)
	if e != nil {
		return refuse(e)
	}
	if uint64(g.Seal.Vout) >= uint64(len(tx.Outputs)) {
		return refuse(bad("SEAL_OUTPUT"))
	}
	seal := tx.Outputs[g.Seal.Vout]
	if seal.Value <= 0 || hex.EncodeToString(seal.Script) != script {
		return refuse(bad("SEAL_BINDING"))
	}
	state.Agent = ag
	state.Landlord = lg
	for i := 0; i < 2; i++ {
		spent, e := sealSpent(o, g.Seal, seal, sh)
		if e != nil {
			return refuse(e)
		}
		if spent {
			if _, e = o.Active(sh.Hash); e != nil {
				return refuse(e)
			}
			if e = stableNames(agent, landlord); e != nil {
				return refuse(e)
			}
			return closeGrant("SEAL_SPENT")
		}
		if e = stableNames(agent, landlord); e != nil {
			return refuse(e)
		}
	}
	poolAfter, e := pending()
	if e != nil {
		return refuse(e)
	}
	if !sameJSON(poolBefore, poolAfter) {
		return refuse(bad("MEMPOOL_CHANGED"))
	}
	if e = stableNames(agent, landlord); e != nil {
		return refuse(e)
	}
	if now+int64(time.Since(started)/time.Second) >= g.NotAfter {
		return refuse(bad("EXPIRED"))
	}
	if prior == nil {
		b, _ := json.Marshal(seenGrantSeal{3, p.Network, p.Genesis, g.Seal, r.GrantID})
		if e = store.Write(sealName, b); e != nil {
			return refuse(e)
		}
	}
	b, _ := json.Marshal(state)
	if !bytes.Equal(saved, b) {
		if e = store.Write(name, b); e != nil {
			return refuse(e)
		}
	}
	if now+int64(time.Since(started)/time.Second) >= g.NotAfter {
		return refuse(bad("EXPIRED"))
	}
	r.Verdict = "live"
	r.Reason = "LIVE"
	return r
}

func checkIssuance(o *su.ReadObservation, s SignedGrant, proof IssuanceProof) error {
	v, tx, e := o.PaymentTransaction(proof.TxID)
	if e != nil {
		return e
	}
	if v.Block == "" || v.Confirmations <= 0 {
		return bad("ISSUANCE_UNCONFIRMED")
	}
	if _, e = o.Confirmed(v); e != nil {
		return e
	}
	commit, e := IssuanceCommitment(s)
	if e != nil {
		return e
	}
	returns, matches := 0, 0
	for _, in := range tx.Inputs {
		if in.Point == (su.Point{TxID: s.Grant.Seal.TxID, Vout: s.Grant.Seal.Vout}) {
			return bad("ISSUANCE_SPENDS_SEAL")
		}
	}
	for _, out := range tx.Outputs {
		if len(out.Script) > 0 && out.Script[0] == 0x6a {
			returns++
			if issuanceScriptMatches(out.Script, commit, s.ID()) && out.Value == 0 {
				matches++
			}
		}
	}
	if returns != 1 || matches != 1 {
		return bad("ISSUANCE_COMMITMENT")
	}
	return nil
}

// Bare legacy commitments already bind the grant ID through the LIP-0004 hash.
// Framed issuance additionally pins action, blob location and the presented ID.
func issuanceScriptMatches(script []byte, commitment, grantID string) bool {
	m, e := oplocator.Parse(script)
	if e != nil || hex.EncodeToString(m.Commitment[:]) != commitment {
		return false
	}
	if m.Legacy {
		return true
	}
	return m.Action == oplocator.ActionGrantIssuance && m.Locator.Type == oplocator.LocationBlob && hex.EncodeToString(m.Locator.Pointer) == grantID
}
