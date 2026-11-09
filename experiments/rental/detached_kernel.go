package rental

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"slices"
	"time"

	sw "relux.works/swarma-chain-lab/experiments/sealwatch"
	su "relux.works/swarma-chain-lab/experiments/single-use"
	"relux.works/swarma-chain-lab/experiments/single-use/durable"
)

type detachedState struct {
	Version           int    `json:"version"`
	Binding           string `json:"binding"`
	CertificateSHA256 string `json:"certificate_sha256"`
	Generation        Anchor `json:"generation"`
	ClosedReason      string `json:"closed_reason"`
}
type seenSeal struct {
	Version           int    `json:"version"`
	Network           string `json:"network"`
	Genesis           string `json:"genesis"`
	Seal              Point  `json:"seal"`
	CertificateSHA256 string `json:"certificate_sha256"`
}

func (p Policy) validateDetached() error {
	if p.Network != "regtest" || p.Genesis != su.RegtestGenesis {
		return bad("REGTEST_ONLY")
	}
	if !station(p.AgentName) || !p2pkh(p.SealScript) || !filepath.IsAbs(p.StateDir) || filepath.Clean(p.StateDir) != p.StateDir {
		return bad("DETACHED_POLICY")
	}
	return nil
}
func sealIndexName(p Policy, point Point) string {
	b, _ := json.Marshal(struct {
		Network, Genesis string
		Point            Point
	}{p.Network, p.Genesis, point})
	return "seen-seal-" + Hash(b) + ".json"
}

// CheckV2 verifies detached v2 certificates only. Policy pins the agent and chain;
// sender is already authenticated by the caller. nowUnix is the trusted local
// clock. No signing, broadcasting or external effect is performed here.
func CheckV2(ctx context.Context, node su.Node, p Policy, raw []byte, agentName, sender string, nowUnix int64) (r Receipt) {
	started := time.Now()
	r = Receipt{Version: 2, Verdict: "refused", CertificateSHA256: Hash(raw), StationName: agentName, CheckedAt: nowUnix}
	refuse := func(e error) Receipt { r.Reason = e.Error(); return r }
	if e := p.validateDetached(); e != nil {
		return refuse(e)
	}
	env, e := ParseDetachedEnvelope(raw)
	if e != nil {
		return refuse(e)
	}
	c := env.Certificate
	if c.Network != p.Network || c.Genesis != p.Genesis || c.AgentName != p.AgentName || agentName != p.AgentName {
		return refuse(bad("CERTIFICATE_POLICY"))
	}
	if sender != c.GranteeKey {
		return refuse(bad("GRANTEE_MISMATCH"))
	}
	expectedScript, e := GrantSealScript(c.IssuerKey)
	if e != nil || expectedScript != p.SealScript {
		return refuse(bad("SEAL_KEY_BINDING"))
	}
	r.Scope = append([]string{}, c.Scope...)
	r.BudgetSat = c.BudgetSat()
	store, e := durable.Open(p.StateDir, "rental.lock")
	if e != nil {
		return refuse(e)
	}
	defer store.Close()
	bindingBytes, _ := json.Marshal(struct{ Network, Genesis, Agent, Script string }{p.Network, p.Genesis, p.AgentName, p.SealScript})
	state := detachedState{Version: 2, Binding: Hash(bindingBytes), CertificateSHA256: r.CertificateSHA256}
	name := "detached-" + r.CertificateSHA256 + ".json"
	saved, e := store.Read(name, 8192)
	if e != nil {
		return refuse(e)
	}
	if saved != nil {
		if canonical(saved, &state) != nil || state.Version != 2 || state.Binding != Hash(bindingBytes) || state.CertificateSHA256 != r.CertificateSHA256 || !digest(state.Generation.TxID) || !digest(state.Generation.Block) || state.Generation.Height < 1 || (state.ClosedReason != "" && state.ClosedReason != "SEAL_SPENT" && state.ClosedReason != "GRANT_KEY_ROTATED") {
			return refuse(bad("JOURNAL_CORRUPT"))
		}
		if state.ClosedReason != "" {
			r.Closed = true
			return refuse(bad(state.ClosedReason))
		}
	}
	seenName := sealIndexName(p, c.Seal)
	priorSeal, e := store.Read(seenName, 4096)
	if e != nil {
		return refuse(e)
	}
	if priorSeal != nil {
		var old seenSeal
		if canonical(priorSeal, &old) != nil || old.Version != 2 || old.Network != p.Network || old.Genesis != p.Genesis || old.Seal != c.Seal || !digest(old.CertificateSHA256) {
			return refuse(bad("SEAL_INDEX_CORRUPT"))
		}
		if old.CertificateSHA256 != r.CertificateSHA256 {
			return refuse(bad("SEAL_ALREADY_SEEN"))
		}
	}
	if nowUnix < 0 {
		return refuse(bad("CLOCK_INPUT"))
	}
	if nowUnix < c.NotBefore {
		r.Verdict = "pending"
		return refuse(bad("NOT_YET_VALID"))
	}
	if nowUnix >= c.NotAfter {
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
	n, keys, generation, e := readAgentName(o, p.AgentName)
	if e != nil {
		return refuse(e)
	}
	if keys.Grant != c.IssuerKey {
		// A first observer or chain rollback does not prove a newly confirmed
		// rotation of this certificate's previously admitted generation.
		if saved == nil || generation.TxID == state.Generation.TxID || generation.Height < state.Generation.Height {
			return refuse(bad("GRANT_KEY_MISMATCH"))
		}
		old, e := o.Active(state.Generation.Block)
		if e != nil {
			return refuse(e)
		}
		if old.Height != state.Generation.Height {
			return refuse(bad("PRIOR_GENERATION_BINDING"))
		}
		again, e := currentName(o, p.AgentName)
		if e != nil {
			return refuse(e)
		}
		if !sameName(n, again) {
			return refuse(bad("NAME_CHANGED"))
		}
		if e = o.Stable(); e != nil {
			return refuse(e)
		}
		return closeGrant("GRANT_KEY_ROTATED")
	}
	pending, poolBefore, e := pendingAgentRotation(o, n, c.IssuerKey)
	if e != nil {
		return refuse(e)
	}
	if pending {
		return refuse(bad("PENDING_GRANT_ROTATION"))
	}
	sv, stx, e := o.PaymentTransaction(c.Seal.TxID)
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
	if uint64(c.Seal.Vout) >= uint64(len(stx.Outputs)) {
		return refuse(bad("SEAL_OUTPUT"))
	}
	seal := stx.Outputs[c.Seal.Vout]
	if seal.Value <= 0 || hex.EncodeToString(seal.Script) != expectedScript {
		return refuse(bad("SEAL_BINDING"))
	}
	// Record the current matching generation before a possible first-observation
	// spend closure; no anchor or block-time issuance bound exists in this profile.
	state.Generation = generation
	for i := 0; i < 2; i++ {
		spent, e := sealSpent(o, c.Seal, seal, sh)
		if e != nil {
			return refuse(e)
		}
		if spent {
			if _, e = o.Active(sh.Hash); e != nil {
				return refuse(e)
			}
			if e = o.Stable(); e != nil {
				return refuse(e)
			}
			return closeGrant("SEAL_SPENT")
		}
		again, e := currentName(o, p.AgentName)
		if e != nil {
			return refuse(e)
		}
		if !sameName(n, again) {
			return refuse(bad("NAME_CHANGED"))
		}
	}
	pending, poolAfter, e := pendingAgentRotation(o, n, c.IssuerKey)
	if e != nil {
		return refuse(e)
	}
	if pending {
		return refuse(bad("PENDING_GRANT_ROTATION"))
	}
	if !slices.Equal(poolBefore, poolAfter) {
		return refuse(bad("MEMPOOL_CHANGED"))
	}
	if e = o.Stable(); e != nil {
		return refuse(e)
	}
	if nowUnix+int64(time.Since(started)/time.Second) >= c.NotAfter {
		return refuse(bad("EXPIRED"))
	}
	// Never evict this index: presentation-cache eviction must not reset the
	// verifier's one-seal-ever memory. Cross-verifier equivocation remains possible.
	if priorSeal == nil {
		b, _ := json.Marshal(seenSeal{2, p.Network, p.Genesis, c.Seal, r.CertificateSHA256})
		if e = store.Write(seenName, b); e != nil {
			return refuse(e)
		}
	}
	b, _ := json.Marshal(state)
	if !bytes.Equal(saved, b) {
		if e = store.Write(name, b); e != nil {
			return refuse(e)
		}
	}
	if nowUnix+int64(time.Since(started)/time.Second) >= c.NotAfter {
		return refuse(bad("EXPIRED"))
	}
	r.Verdict = "live"
	r.Reason = "LIVE"
	return r
}

func readAgentName(o *su.ReadObservation, name string) (su.NameView, AgentKeys, Anchor, error) {
	var keys AgentKeys
	var anchor Anchor
	n, e := currentName(o, name)
	if e != nil {
		return n, keys, anchor, e
	}
	v, tx, e := o.PaymentTransaction(n.TxID)
	if e != nil {
		return n, keys, anchor, e
	}
	if v.Block == "" || v.Confirmations <= 0 {
		return n, keys, anchor, bad("AGENT_NAME_UNCONFIRMED")
	}
	h, e := o.Confirmed(v)
	if e != nil {
		return n, keys, anchor, e
	}
	if n.Height != h.Height || uint64(n.Vout) >= uint64(len(tx.Outputs)) {
		return n, keys, anchor, bad("AGENT_NAME_BINDING")
	}
	if e = bindAgentNameOutput(n.Name, n.Value, n.Vout, v, tx); e != nil {
		return n, keys, anchor, e
	}
	keys, e = ParseAgentValue(n.Value)
	if e != nil {
		return n, keys, anchor, e
	}
	return n, keys, Anchor{n.TxID, n.Vout, v.Block, h.Height}, nil
}

func pendingAgentRotation(o *su.ReadObservation, n su.NameView, issuer string) (bool, []string, error) {
	var ids []string
	if e := o.Call("getrawmempool", &ids); e != nil {
		return false, nil, e
	}
	slices.Sort(ids)
	for i, id := range ids {
		if !digest(id) || (i > 0 && id == ids[i-1]) {
			return false, nil, bad("MEMPOOL_PROJECTION")
		}
		var raw json.RawMessage
		if e := o.Call("getrawtransaction", &raw, id, true); e != nil {
			return false, nil, e
		}
		var txid string
		var vin []json.RawMessage
		if sw.ProjectJSON(raw, map[string]any{"txid": &txid, "vin": &vin}, nil) != nil || txid != id || len(vin) == 0 {
			return false, nil, bad("MEMPOOL_PROJECTION")
		}
		candidate := false
		for _, b := range vin {
			var point su.Point
			if sw.ProjectJSON(b, map[string]any{"txid": &point.TxID, "vout": &point.Vout}, nil) != nil || !digest(point.TxID) {
				return false, nil, bad("MEMPOOL_PROJECTION")
			}
			if point == (su.Point{TxID: n.TxID, Vout: n.Vout}) {
				candidate = true
			}
		}
		if !candidate {
			continue
		}
		// Only a name-spend candidate enters the full decoder. Unrelated witness
		// or large-input traffic is projected, not fed to the legacy decoder.
		v, tx, e := o.PaymentTransaction(id)
		if e != nil {
			return false, nil, e
		}
		bound := false
		for _, input := range tx.Inputs {
			if input.Point == (su.Point{TxID: n.TxID, Vout: n.Vout}) {
				bound = true
			}
		}
		if !bound {
			return false, nil, bad("PENDING_INPUT_BINDING")
		}
		matches := 0
		pending := false
		for _, out := range v.Vout {
			op := out.Script.Name
			if op == nil || op.Name != n.Name {
				continue
			}
			matches++
			if e := bindAgentNameOutput(n.Name, op.Value, out.N, v, tx); e != nil {
				return false, nil, e
			}
			keys, e := ParseAgentValue(op.Value)
			if e != nil {
				return false, nil, bad("PENDING_NAME_VALUE")
			}
			if keys.Grant != issuer {
				pending = true
			}
		}
		if matches != 1 {
			return false, nil, bad("PENDING_NAME_TRANSITION")
		}
		if pending {
			return true, ids, nil
		}
	}
	return false, ids, nil
}

func bindAgentNameOutput(name, value string, index uint32, v su.TransactionView, tx *su.Transaction) error {
	if uint64(index) >= uint64(len(tx.Outputs)) || uint64(index) >= uint64(len(v.Vout)) {
		return bad("RAW_AGENT_NAME")
	}
	out := tx.Outputs[index]
	op := v.Vout[index].Script.Name
	if out.Value != 1000000 || op == nil || op.Name != name || op.Value != value || op.NameEncoding != "ascii" || op.ValueEncoding != "ascii" || len(op.NameError) > 0 || len(op.ValueError) > 0 {
		return bad("RAW_AGENT_NAME")
	}
	prefix := su.NameUpdateScript(name, value, nil)
	if op.Op == "name_firstupdate" {
		b := out.Script
		if len(b) == 0 || b[0] != 0x52 {
			return bad("RAW_AGENT_NAME")
		}
		b = b[1:]
		nm, rest, ok := namePush(b)
		if !ok || string(nm) != name {
			return bad("RAW_AGENT_NAME")
		}
		rand, rest, ok := namePush(rest)
		if !ok || len(rand) != 20 {
			return bad("RAW_AGENT_NAME")
		}
		val, rest, ok := namePush(rest)
		if !ok || string(val) != value || len(rest) < 3 || rest[0] != 0x6d || rest[1] != 0x6d {
			return bad("RAW_AGENT_NAME")
		}
		return nil // Active Core validation authenticates the remaining owner script.
	}
	if op.Op != "name_update" || len(out.Script) <= len(prefix) || !bytes.HasPrefix(out.Script, prefix) {
		return bad("RAW_AGENT_NAME")
	}
	return nil
}
func namePush(b []byte) ([]byte, []byte, bool) {
	if len(b) == 0 {
		return nil, nil, false
	}
	n := int(b[0])
	offset := 1
	if n == 0x4c {
		if len(b) < 2 {
			return nil, nil, false
		}
		n = int(b[1])
		offset = 2
		if n < 76 {
			return nil, nil, false
		}
	} else if n == 0x4d {
		if len(b) < 3 {
			return nil, nil, false
		}
		n = int(b[1]) | int(b[2])<<8
		offset = 3
		if n <= 255 {
			return nil, nil, false
		}
	} else if n > 75 {
		return nil, nil, false
	}
	if n > 520 || n > len(b)-offset {
		return nil, nil, false
	}
	return b[offset : offset+n], b[offset+n:], true
}
