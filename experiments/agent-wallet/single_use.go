package wallet

import (
	"context"
	"encoding/json"
	"strings"

	rental "relux.works/swarma-chain-lab/experiments/rental"
	su "relux.works/swarma-chain-lab/experiments/single-use"
	"relux.works/swarma-chain-lab/experiments/single-use/durable"
)

type OneoffGrant struct {
	Version   int      `json:"version"`
	Network   string   `json:"network"`
	Genesis   string   `json:"genesis"`
	Agent     string   `json:"agent_name"`
	Landlord  string   `json:"landlord_name"`
	Issuer    string   `json:"issuer_key"`
	Grantee   string   `json:"grantee_key"`
	Address   string   `json:"recipient"`
	Amount    int64    `json:"amount_sat"`
	FeeLimit  int64    `json:"fee_limit_sat"`
	NotBefore int64    `json:"not_before"`
	NotAfter  int64    `json:"not_after"`
	Seal      su.Point `json:"seal"`
}
type OneoffEnvelope struct {
	Grant     OneoffGrant `json:"oneoff_grant"`
	Signature string      `json:"signature"`
}

func OneoffDigest(g OneoffGrant) string {
	return Hash(append([]byte("swarma-wallet-oneoff-v1"), canonical(g)...))
}

// LandlordResolver is implemented by the K1 adapter, never by a grant-supplied
// key pin. Generation and pending/rotation checks come from the genuine kernel.
type LandlordResolver interface {
	Resolve(context.Context, string) (string, rental.Anchor, error)
}
type CombinedAuthority struct {
	Kernel                    KernelAuthority
	Resolver                  LandlordResolver
	Agent, Landlord, StateDir string
}

func parseOneoff(raw []byte) (OneoffEnvelope, error) {
	var env OneoffEnvelope
	if strict(raw, &env) != nil {
		return env, fail("ONEOFF_SCHEMA")
	}
	g := env.Grant
	if g.Version != 1 || g.Network != "regtest" || g.Genesis != su.RegtestGenesis || !strings.HasPrefix(g.Agent, "id/") || !strings.HasPrefix(g.Landlord, "id/") || !ascii(g.Agent, 255) || !ascii(g.Landlord, 255) || !hexN(g.Issuer, 32) || !hexN(g.Grantee, 32) || g.Issuer == g.Grantee || !hexN(g.Seal.TxID, 32) || g.NotBefore < 0 || g.NotAfter <= g.NotBefore || g.Amount < 1 || g.Amount > MaxMoney || g.FeeLimit < 1 || g.FeeLimit > MaxFee || g.Amount > MaxMoney-g.FeeLimit {
		return env, fail("ONEOFF_FIELDS")
	}
	if _, e := addressScript(g.Address); e != nil {
		return env, e
	}
	if _, _, e := su.SealScript("02"+g.Issuer, "02"+g.Grantee); e != nil {
		return env, fail("ONEOFF_KEYS")
	}
	if !rental.VerifySignature(g.Issuer, OneoffDigest(g), env.Signature) {
		return env, fail("ONEOFF_SIGNATURE")
	}
	return env, nil
}
func oneoffKind(raw []byte) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return false
	}
	_, ok := fields["oneoff_grant"]
	return ok
}
func (a CombinedAuthority) Parse(raw []byte) (Grant, error) {
	if !oneoffKind(raw) {
		return a.Kernel.Parse(raw)
	}
	env, e := parseOneoff(raw)
	if e != nil {
		return Grant{}, e
	}
	g := env.Grant
	if g.Agent != a.Agent || g.Landlord != a.Landlord {
		return Grant{}, fail("ONEOFF_POLICY")
	}
	return Grant{Kind: "single-use", ID: Hash(raw), Agent: g.Agent, Grantee: g.Grantee, Issuer: g.Issuer, Landlord: g.Landlord, Scope: []string{"pay"}, Budget: g.Amount + g.FeeLimit, NotBefore: g.NotBefore, NotAfter: g.NotAfter, Seal: g.Seal, Recipient: g.Address, Amount: g.Amount, FeeLimit: g.FeeLimit}, nil
}

type oneoffState struct {
	Version    int           `json:"version"`
	GrantID    string        `json:"grant_id"`
	Generation rental.Anchor `json:"generation"`
	Closed     bool          `json:"closed"`
}

func (a CombinedAuthority) Check(ctx context.Context, raw []byte, sender string, now int64) error {
	if !oneoffKind(raw) {
		return a.Kernel.Check(ctx, raw, sender, now)
	}
	g, e := a.Parse(raw)
	if e != nil {
		return e
	}
	if g.Grantee != sender {
		return fail("GRANT_GRANTEE_MISMATCH")
	}
	if now < g.NotBefore || now >= g.NotAfter {
		return fail("GRANT_TIME")
	}
	if a.Resolver == nil {
		return fail("GRANT_RESOLVER_REQUIRED")
	}
	store, e := durable.Open(a.StateDir, "oneoff.lock")
	if e != nil {
		return e
	}
	defer store.Close()
	name := "oneoff-" + g.ID + ".json"
	state := oneoffState{Version: 1, GrantID: g.ID}
	saved, e := store.Read(name, 4096)
	if e != nil {
		return e
	}
	if saved != nil {
		if strict(saved, &state) != nil || state.Version != 1 || state.GrantID != g.ID || !hexN(state.Generation.TxID, 32) || !hexN(state.Generation.Block, 32) || state.Generation.Height < 1 {
			return fail("ONEOFF_STATE")
		}
		if state.Closed {
			return fail("GRANT_KEY_ROTATED")
		}
	}
	key, generation, e := a.Resolver.Resolve(ctx, g.Landlord)
	if e != nil {
		return e
	}
	if !hexN(generation.TxID, 32) || !hexN(generation.Block, 32) || generation.Height < 1 {
		return fail("GRANT_GENERATION")
	}
	if key != g.Issuer {
		// A current mismatch refuses immediately, but only a forward confirmed
		// rotation from a still-active admitted generation is terminal.
		if saved == nil || generation.TxID == state.Generation.TxID || generation.Height <= state.Generation.Height {
			return fail("GRANT_KEY_MISMATCH")
		}
		observation := su.NewReadObservation(ctx, a.Kernel.Node)
		defer observation.Close()
		if e = observation.Start("regtest", su.RegtestGenesis); e != nil {
			return e
		}
		old, err := observation.Active(state.Generation.Block)
		if err != nil || old.Height != state.Generation.Height {
			return fail("GRANT_PRIOR_GENERATION_UNAVAILABLE")
		}
		againKey, againGeneration, err := a.Resolver.Resolve(ctx, g.Landlord)
		if err != nil {
			return err
		}
		if againKey != key || againGeneration != generation {
			return fail("GRANT_GENERATION_CHANGED")
		}
		if e = observation.Stable(); e != nil {
			return e
		}
		state.Closed = true
		if e = store.Write(name, canonical(state)); e != nil {
			return e
		}
		return fail("GRANT_KEY_ROTATED")
	}
	if saved != nil && generation != state.Generation && generation.Height <= state.Generation.Height {
		return fail("GRANT_GENERATION_ROLLBACK")
	}
	state.Generation = generation
	if e = store.Write(name, canonical(state)); e != nil {
		return e
	}
	return nil
}
func termsFor(g Grant, raw []byte) (Terms, error) {
	if g.Kind == "single-use" {
		if len(raw) != 0 {
			return Terms{}, fail("ONEOFF_EXTRA_TERMS")
		}
		return Terms{Version: 1, Recipients: []string{g.Recipient}, SpendCap: g.Budget}, nil
	}
	if Hash(raw) != g.Contract {
		return Terms{}, fail("CONTRACT_HASH")
	}
	return ParseTerms(raw, g.Budget)
}

// checkUse reuses W3's raw signature attribution and exact request commitment.
// A caller-provided txid is only a locator; confirmed own-node proof decides.
func (w *Wallet) checkUse(ctx context.Context, g Grant, request []byte, txid string) error {
	if !hexN(txid, 32) {
		return fail("USE_PROOF_REQUIRED")
	}
	o := su.NewReadObservation(ctx, w.node)
	defer o.Close()
	if e := o.Start("regtest", su.RegtestGenesis); e != nil {
		return e
	}
	funding, ftx, e := o.Transaction(g.Seal.TxID)
	if e != nil {
		return e
	}
	fh, e := o.Confirmed(funding)
	if e != nil {
		return e
	}
	_, script, e := su.SealScript("02"+g.Issuer, "02"+g.Grantee)
	if e != nil {
		return e
	}
	if int(g.Seal.Vout) >= len(ftx.Outputs) || ftx.Outputs[g.Seal.Vout].Value <= 0 || string(ftx.Outputs[g.Seal.Vout].Script) != string(script) {
		return fail("USE_FUNDING_BINDING")
	}
	view, tx, e := o.Transaction(txid)
	if e != nil {
		return e
	}
	who, e := su.Attribute(tx, g.Seal, "02"+g.Issuer, "02"+g.Grantee)
	if e != nil {
		return e
	}
	if who != "grantee" {
		return fail("USE_ISSUER_REVOKED")
	}
	if e = su.RequestCommitment(tx, request); e != nil {
		return e
	}
	if view.Confirmations < 1 {
		return fail("USE_PENDING")
	}
	h, e := o.Confirmed(view)
	if e != nil {
		return e
	}
	if h.Height <= fh.Height {
		return fail("USE_HEIGHT_ORDER")
	}
	return o.Stable()
}
