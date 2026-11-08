package rental

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"time"

	sw "relux.works/swarma-chain-lab/experiments/sealwatch"
	su "relux.works/swarma-chain-lab/experiments/single-use"
	"relux.works/swarma-chain-lab/experiments/single-use/durable"
)

type Policy struct {
	Network       string `json:"network"`
	Genesis       string `json:"genesis"`
	IssuerPubkey  string `json:"issuer_pubkey"`
	AgentPubkey   string `json:"agent_pubkey"`
	StationName   string `json:"station_name"`
	StationScript string `json:"station_script"`
	StateDir      string `json:"state_dir"`
	AgentName     string `json:"agent_name,omitempty"`
	SealScript    string `json:"seal_script,omitempty"`
}
type Anchor struct {
	TxID   string `json:"txid"`
	Vout   uint32 `json:"vout"`
	Block  string `json:"block"`
	Height int64  `json:"height"`
}
type Receipt struct {
	Version           int      `json:"version"`
	Verdict           string   `json:"verdict"`
	Reason            string   `json:"reason"`
	CertificateSHA256 string   `json:"certificate_sha256"`
	StationName       string   `json:"station_name"`
	CheckedAt         int64    `json:"checked_at"`
	Closed            bool     `json:"closed"`
	Anchor            *Anchor  `json:"anchor,omitempty"`
	TipHash           string   `json:"tip_hash,omitempty"`
	Calls             int      `json:"calls"`
	Scope             []string `json:"scope"`
	BudgetSat         int64    `json:"budget_sat"`
}
type kernelState struct {
	Version           int    `json:"version"`
	Binding           string `json:"binding"`
	CertificateSHA256 string `json:"certificate_sha256"`
	Anchor            Anchor `json:"anchor"`
	ClosedReason      string `json:"closed_reason"`
}

func (p Policy) validate() error {
	// M1 is regtest-only. Network support in a certificate is not runtime admission.
	if p.Network != "regtest" || p.Genesis != su.RegtestGenesis {
		return bad("REGTEST_ONLY")
	}
	if !pubkey(p.IssuerPubkey) || !pubkey(p.AgentPubkey) || !station(p.StationName) || !p2pkh(p.StationScript) || !filepath.IsAbs(p.StateDir) || filepath.Clean(p.StateDir) != p.StateDir {
		return bad("POLICY_INPUT")
	}
	return nil
}
func p2pkh(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && hex.EncodeToString(b) == s && len(b) == 25 && bytes.Equal(b[:3], []byte{0x76, 0xa9, 20}) && bytes.Equal(b[23:], []byte{0x88, 0xac})
}

// CheckLegacy authenticates a v1 rental against its station anchor. Only live
// admits; it does not authorize any action. Caller supplies the authenticated
// NIP-17 inner-seal key and a trusted UTC clock. Observation is not atomic with
// the chain after return; each effect requires a new check.
func CheckLegacy(ctx context.Context, node su.Node, p Policy, raw []byte, stationName, senderPubkey string, nowUnix int64) (r Receipt) {
	started := time.Now()
	r = Receipt{Version: 1, Verdict: "refused", CertificateSHA256: Hash(raw), StationName: stationName, CheckedAt: nowUnix}
	refuse := func(e error) Receipt { r.Reason = e.Error(); return r }
	if e := p.validate(); e != nil {
		return refuse(e)
	}
	env, e := ParseEnvelope(raw)
	if e != nil {
		return refuse(e)
	}
	c := env.Certificate
	if c.Network != p.Network || c.Genesis != p.Genesis || c.IssuerPubkey != p.IssuerPubkey || c.AgentPubkey != p.AgentPubkey || stationName != p.StationName || c.StationName != stationName {
		return refuse(bad("CERTIFICATE_POLICY"))
	}
	if senderPubkey != c.GranteePubkey {
		return refuse(bad("GRANTEE_MISMATCH"))
	}
	r.Scope = append([]string{}, c.Scope...)
	r.BudgetSat = c.BudgetSat
	store, e := durable.Open(p.StateDir, "rental.lock")
	if e != nil {
		return refuse(e)
	}
	defer store.Close()
	bindingBytes, _ := json.Marshal(struct{ Network, Genesis, Issuer, Agent, Station, Script string }{p.Network, p.Genesis, p.IssuerPubkey, p.AgentPubkey, p.StationName, p.StationScript})
	binding := Hash(bindingBytes)
	name := "certificate-" + r.CertificateSHA256 + ".json"
	state := kernelState{Version: 1, Binding: binding, CertificateSHA256: r.CertificateSHA256}
	saved, e := store.Read(name, 8192)
	if e != nil {
		return refuse(e)
	}
	if saved != nil {
		if canonical(saved, &state) != nil || state.Version != 1 || state.Binding != binding || state.CertificateSHA256 != r.CertificateSHA256 || !digest(state.Anchor.TxID) || !digest(state.Anchor.Block) || state.Anchor.Height < 1 || (state.ClosedReason != "" && state.ClosedReason != "SEAL_SPENT" && state.ClosedReason != "NAME_REPLACED") {
			return refuse(bad("JOURNAL_CORRUPT"))
		}
		r.Anchor = &state.Anchor
		if state.ClosedReason != "" {
			r.Closed = true
			return refuse(bad(state.ClosedReason))
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
	n, e := currentName(o, p.StationName)
	if e != nil {
		return refuse(e)
	}
	av, atx, e := o.Transaction(n.TxID)
	if e != nil {
		return refuse(e)
	}
	if av.Block == "" || av.Confirmations == 0 {
		r.Verdict = "pending"
		return refuse(bad("ANCHOR_UNCONFIRMED"))
	}
	if av.Confirmations < 0 {
		r.Verdict = "pending"
		return refuse(bad("ANCHOR_INACTIVE"))
	}
	ah, e := o.Confirmed(av)
	if e != nil {
		return refuse(e)
	}
	if n.Height != ah.Height || uint64(n.Vout) >= uint64(len(atx.Outputs)) {
		return refuse(bad("ANCHOR_BINDING"))
	}
	expected, _ := NameValue(c, r.CertificateSHA256)
	if n.Value != expected {
		if e = rawName(n, av, atx, ""); e != nil {
			return refuse(e)
		}
		// A different confirmed generation closes only when our previously accepted
		// generation remains in the active chain. A rollback alone is not replacement.
		if saved != nil && n.TxID != state.Anchor.TxID && ah.Height >= state.Anchor.Height {
			old, e := o.Active(state.Anchor.Block)
			if e != nil {
				return refuse(e)
			}
			if old.Height != state.Anchor.Height {
				return refuse(bad("PRIOR_ANCHOR_BINDING"))
			}
			again, e := currentName(o, p.StationName)
			if e != nil {
				return refuse(e)
			}
			if !sameName(n, again) {
				return refuse(bad("NAME_CHANGED"))
			}
			if e = o.Stable(); e != nil {
				return refuse(e)
			}
			return closeGrant("NAME_REPLACED")
		}
		return refuse(bad("NAME_VALUE"))
	}
	if e = rawName(n, av, atx, p.StationScript); e != nil {
		return refuse(e)
	}
	if e = su.RequestCommitment(atx, raw); e != nil {
		return refuse(bad("ANCHOR_COMMITMENT"))
	}
	anchor := Anchor{n.TxID, n.Vout, av.Block, ah.Height}
	r.Anchor = &anchor
	state.Anchor = anchor
	sv, stx, e := o.Transaction(c.Seal.TxID)
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
	if sh.Height >= ah.Height {
		return refuse(bad("SEAL_ANCHOR_ORDER"))
	}
	if uint64(c.Seal.Vout) >= uint64(len(stx.Outputs)) {
		return refuse(bad("SEAL_OUTPUT"))
	}
	seal := stx.Outputs[c.Seal.Vout]
	if seal.Value <= 0 || hex.EncodeToString(seal.Script) != p.StationScript {
		return refuse(bad("SEAL_BINDING"))
	}
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
		again, e := currentName(o, p.StationName)
		if e != nil {
			return refuse(e)
		}
		if !sameName(n, again) {
			return refuse(bad("NAME_CHANGED"))
		}
	}
	if e = o.Stable(); e != nil {
		return refuse(e)
	}
	if nowUnix+int64(time.Since(started)/time.Second) >= c.NotAfter {
		return refuse(bad("EXPIRED"))
	}
	if saved == nil || state.Anchor != anchor {
		state.Anchor = anchor
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
func currentName(o *su.ReadObservation, name string) (su.NameView, error) {
	var n su.NameView
	if e := o.Call("name_show", &n, name, map[string]string{"nameEncoding": "ascii", "valueEncoding": "ascii"}); e != nil {
		return n, e
	}
	if n.Name != name || !digest(n.TxID) || n.Expired || n.ExpiresIn <= 0 || n.NameEncoding != "ascii" || n.ValueEncoding != "ascii" || len(n.NameError) > 0 || len(n.ValueError) > 0 || len(n.Value) > 520 {
		return n, bad("CURRENT_NAME")
	}
	for _, b := range []byte(n.Value) {
		if b > 127 {
			return n, bad("NAME_VALUE_ENCODING")
		}
	}
	return n, nil
}
func sameName(a, b su.NameView) bool {
	return a.TxID == b.TxID && a.Vout == b.Vout && a.Height == b.Height && a.Value == b.Value
}
func rawName(n su.NameView, v su.TransactionView, tx *su.Transaction, script string) error {
	payment, _ := hex.DecodeString(script)
	if uint64(n.Vout) >= uint64(len(v.Vout)) {
		return bad("ANCHOR_BINDING")
	}
	op := v.Vout[n.Vout].Script.Name
	rawScript := tx.Outputs[n.Vout].Script
	bound := bytes.Equal(rawScript, su.NameUpdateScript(n.Name, n.Value, payment))
	if script == "" {
		// A proved replacement may transfer the name to a different destination.
		// That still closes the old certificate. Admission always pins the suffix.
		prefix := su.NameUpdateScript(n.Name, n.Value, nil)
		bound = len(rawScript) > len(prefix) && bytes.HasPrefix(rawScript, prefix)
	}
	if !bound || op == nil || op.Op != "name_update" || op.Name != n.Name || op.Value != n.Value || op.NameEncoding != "ascii" || op.ValueEncoding != "ascii" || len(op.NameError) > 0 || len(op.ValueError) > 0 {
		return bad("RAW_NAME_ANCHOR")
	}
	return nil
}
func sealSpent(o *su.ReadObservation, p Point, out su.Output, h su.Header) (bool, error) {
	var raw json.RawMessage
	if e := o.Call("gettxout", &raw, p.TxID, p.Vout, true); e != nil {
		return false, e
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return true, nil
	}
	var best string
	var confirms int64
	var script json.RawMessage
	var amount json.Number
	if e := sw.ProjectJSON(raw, map[string]any{"bestblock": &best, "confirmations": &confirms, "value": &amount, "scriptPubKey": &script}, nil); e != nil {
		return false, bad("NODE_PROJECTION")
	}
	var hexScript string
	if e := sw.ProjectJSON(script, map[string]any{"hex": &hexScript}, nil); e != nil {
		return false, bad("NODE_PROJECTION")
	}
	sat, e := su.ParseCoins(string(amount))
	if e != nil || best != o.Tip().Best || confirms != o.Tip().Blocks-h.Height+1 || sat != out.Value || hexScript != hex.EncodeToString(out.Script) {
		return false, bad("SEAL_UTXO_BINDING")
	}
	return false, nil
}
