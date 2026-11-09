package rental

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

type unavailableNode struct{}

func (unavailableNode) Call(context.Context, string, ...any) (json.RawMessage, error) {
	return nil, errors.New("offline")
}

type aliasNode struct {
	base    su.Node
	applied int
}

func (n *aliasNode) Call(ctx context.Context, m string, args ...any) (json.RawMessage, error) {
	b, e := n.base.Call(ctx, m, args...)
	if e == nil && m == "getblockchaininfo" && n.applied == 0 {
		changed := bytes.Replace(b, []byte(`"chain"`), []byte(`"Chain"`), 1)
		if !bytes.Equal(b, changed) {
			n.applied++
			b = changed
		}
	}
	return b, e
}
func noCertificateRecord(t *testing.T, p Policy) {
	t.Helper()
	files, e := filepath.Glob(filepath.Join(p.StateDir, "certificate-*"))
	if e != nil || len(files) != 0 {
		t.Fatal("refusal wrote certificate state", files, e)
	}
}
func (l *coreLab) revoke(pool PoolOutput, mine bool) string {
	p := l.policy("revoke-planner")
	plan, e := MakeLegacyPlan(IssuerPolicy{Policy: p}, PlanSpec{Kind: "revoke", Inputs: []su.PlanInput{{Point: su.Point{TxID: pool.Point.TxID, Vout: pool.Point.Vout}, ValueSat: pool.ValueSat, Script: pool.Script, Role: "seal"}}, ChangeScript: l.script, Pool: pool}, nil, nil, nil, 500)
	if e != nil {
		l.t.Fatal(e)
	}
	return l.sendPlan(plan, mine)
}
func (l *coreLab) manualAnchor(c Certificate, raw []byte) string {
	l.t.Helper()
	var n su.NameView
	if e := json.Unmarshal(l.rpc("", "name_show", l.station), &n); e != nil {
		l.t.Fatal(e)
	}
	fund := l.fund()
	payment, _ := hex.DecodeString(l.script)
	value, _ := NameValue(c, Hash(raw))
	commit, _ := hex.DecodeString(Hash(raw))
	tx := su.Transaction{Version: 0x7100, Inputs: []su.Input{{Point: su.Point{TxID: n.TxID, Vout: n.Vout}, Sequence: 0xfffffffe}, {Point: fund.Point, Sequence: 0xfffffffe}}, Outputs: []su.Output{{Value: 1000000, Script: su.NameUpdateScript(l.station, value, payment)}, {Value: 0, Script: append([]byte{0x6a, 32}, commit...)}, {Value: fund.ValueSat - 200000, Script: payment}}}
	return l.send(hex.EncodeToString(tx.Bytes()), false)
}

// Every row has a genuine-Core valid neighbor and a precise denial/state
// assertion. Alias and unavailable-route rows are explicitly transport controls;
// other chain mutations are real transactions, mining or reorgs in Core 28.
func TestCoreMatrix(t *testing.T) {
	l := newCore(t)
	passed := []string{}
	run := func(name string, fn func()) {
		t.Run(name, func(tt *testing.T) {
			old := l.t
			l.t = tt
			defer func() { l.t = old }()
			fn()
			passed = append(passed, name)
		})
	}
	// name_firstupdate is genuinely confirmed, but cannot stand in for the
	// required name_update anchor. The following real update is the neighbor.
	p := l.policy("firstupdate")
	pool := l.pool(p, true)
	c := testCertificate()
	c.Seal = pool.Point
	raw := signTest(t, c, 1)
	run("anchor-not-name-update", func() {
		l.check("firstupdate-denied", l.observer, p, raw, c.GranteePubkey, 500, "refused", "RAW_NAME_ANCHOR", false)
		noCertificateRecord(l.t, p)
		l.anchor(c, raw, "", nil, true)
		l.check("firstupdate-neighbor", l.observer, p, raw, c.GranteePubkey, 500, "live", "LIVE", false)
	})
	baseC, baseRaw := c, raw
	neighbor := func(label string) {
		p := l.policy(label + "-neighbor")
		l.check(label+"-neighbor", l.observer, p, baseRaw, baseC.GranteePubkey, 500, "live", "LIVE", false)
	}
	simple := []struct {
		name, reason string
		change       func(*Certificate, *[]byte, *string, *int64, *Policy)
	}{
		{"wrong-grantee", "GRANTEE_MISMATCH", func(_ *Certificate, _ *[]byte, s *string, _ *int64, _ *Policy) { _, *s = testKey(5) }},
		{"outer-wrap-key-only", "GRANTEE_MISMATCH", func(_ *Certificate, _ *[]byte, s *string, _ *int64, _ *Policy) { _, *s = testKey(6) }},
		{"foreign-signature", "ISSUER_SIGNATURE", func(c *Certificate, r *[]byte, _ *string, _ *int64, _ *Policy) { *r = signTest(l.t, *c, 4) }},
		{"foreign-pinned-issuer", "CERTIFICATE_POLICY", func(c *Certificate, r *[]byte, _ *string, _ *int64, _ *Policy) {
			_, c.IssuerPubkey = testKey(4)
			*r = signTest(l.t, *c, 4)
		}},
		{"alter-contract", "ISSUER_SIGNATURE", func(c *Certificate, r *[]byte, _ *string, _ *int64, _ *Policy) {
			*r = bytes.Replace(*r, []byte(c.ContractSHA256), []byte(strings.Repeat("c", 64)), 1)
		}},
		{"alter-expiry", "ISSUER_SIGNATURE", func(_ *Certificate, r *[]byte, _ *string, _ *int64, _ *Policy) {
			*r = bytes.Replace(*r, []byte(`"not_after":1000`), []byte(`"not_after":1001`), 1)
		}},
		{"alter-seal", "ISSUER_SIGNATURE", func(c *Certificate, r *[]byte, _ *string, _ *int64, _ *Policy) {
			*r = bytes.Replace(*r, []byte(c.Seal.TxID), []byte(strings.Repeat("d", 64)), 1)
		}},
		{"alter-scope", "ISSUER_SIGNATURE", func(_ *Certificate, r *[]byte, _ *string, _ *int64, _ *Policy) {
			*r = bytes.Replace(*r, []byte(`["deliver","pay"]`), []byte(`["deliver"]`), 1)
		}},
		{"unknown-scope", "CERTIFICATE_SCOPE", func(_ *Certificate, r *[]byte, _ *string, _ *int64, _ *Policy) {
			*r = bytes.Replace(*r, []byte(`"pay"`), []byte(`"pay.nmc"`), 1)
		}},
		{"expired-exact-boundary", "EXPIRED", func(_ *Certificate, _ *[]byte, _ *string, n *int64, _ *Policy) { *n = 1000 }},
		{"not-yet-valid", "NOT_YET_VALID", func(_ *Certificate, _ *[]byte, _ *string, n *int64, _ *Policy) { *n = 99 }},
		{"wrong-agent-policy", "CERTIFICATE_POLICY", func(_ *Certificate, _ *[]byte, _ *string, _ *int64, p *Policy) { _, p.AgentPubkey = testKey(5) }},
		{"canonical-alias", "CANONICAL_ENCODING", func(_ *Certificate, r *[]byte, _ *string, _ *int64, _ *Policy) {
			*r = bytes.Replace(*r, []byte(`"budget_sat"`), []byte(`"Budget_Sat"`), 1)
		}},
	}
	for _, tc := range simple {
		run(tc.name, func() {
			p := l.policy(tc.name)
			c := baseC
			r := bytes.Clone(baseRaw)
			sender := c.GranteePubkey
			now := int64(500)
			tc.change(&c, &r, &sender, &now, &p)
			verdict := "refused"
			if tc.reason == "NOT_YET_VALID" {
				verdict = "pending"
			}
			l.check(tc.name, l.observer, p, r, sender, now, verdict, tc.reason, false)
			noCertificateRecord(l.t, p)
			neighbor(tc.name)
		})
	}
	run("node-unavailable", func() {
		p := l.policy("offline")
		l.check("offline", unavailableNode{}, p, baseRaw, baseC.GranteePubkey, 500, "refused", "NODE_UNAVAILABLE", false)
		noCertificateRecord(l.t, p)
		l.check("offline-recovery", l.observer, p, baseRaw, baseC.GranteePubkey, 500, "live", "LIVE", false)
	})
	run("node-fold-alias", func() {
		p := l.policy("alias")
		n := &aliasNode{base: l.observer}
		l.check("alias", n, p, baseRaw, baseC.GranteePubkey, 500, "refused", "NODE_PROJECTION", false)
		if n.applied != 1 {
			l.t.Fatal("alias plant not applied")
		}
		noCertificateRecord(l.t, p)
		neighbor("alias")
	})
	value, _ := NameValue(baseC, Hash(baseRaw))
	values := map[string]string{
		"name-extra":        strings.Replace(value, `"swarma":{`, `"swarma":{"extra":1,`, 1),
		"name-missing":      strings.Replace(value, `"rental_issuer_pubkey":"`+baseC.IssuerPubkey+`",`, "", 1),
		"name-alias":        strings.Replace(value, "rental_issuer_pubkey", "Rental_issuer_pubkey", 1),
		"name-wrong-issuer": strings.Replace(value, baseC.IssuerPubkey, baseC.AgentPubkey, 1),
	}
	// Explicit order keeps evidence and state progression reproducible.
	for _, name := range []string{"name-extra", "name-missing", "name-alias", "name-wrong-issuer"} {
		run(name, func() {
			p := l.policy(name)
			l.anchor(baseC, baseRaw, values[name], nil, true)
			l.check(name, l.observer, p, baseRaw, baseC.GranteePubkey, 500, "refused", "NAME_VALUE", false)
			noCertificateRecord(l.t, p)
			l.anchor(baseC, baseRaw, "", nil, true)
			neighbor(name)
		})
	}
	for _, mode := range []string{"two-commitments", "wrong-commitment"} {
		run(mode, func() {
			p := l.policy(mode)
			l.anchor(baseC, baseRaw, "", func(tx *su.Transaction) {
				for i, out := range tx.Outputs {
					if len(out.Script) == 34 && out.Script[0] == 0x6a {
						if mode == "two-commitments" {
							tx.Outputs = append(tx.Outputs, out)
						} else {
							tx.Outputs[i].Script = bytes.Clone(out.Script)
							tx.Outputs[i].Script[2] ^= 1
						}
						break
					}
				}
			}, true)
			l.check(mode, l.observer, p, baseRaw, baseC.GranteePubkey, 500, "refused", "ANCHOR_COMMITMENT", false)
			noCertificateRecord(l.t, p)
			l.anchor(baseC, baseRaw, "", nil, true)
			neighbor(mode)
		})
	}
	run("anchor-unconfirmed", func() {
		p := l.policy("unconfirmed-anchor")
		pool := l.pool(p, true)
		c := testCertificate()
		c.Seal = pool.Point
		raw := signTest(l.t, c, 1)
		l.anchor(c, raw, "", nil, false)
		l.check("unconfirmed-anchor", l.observer, p, raw, c.GranteePubkey, 500, "refused", "NAME_VALUE", false)
		noCertificateRecord(l.t, p)
		l.mine(1)
		l.check("confirmed-anchor-neighbor", l.observer, p, raw, c.GranteePubkey, 500, "live", "LIVE", false)
	})
	run("anchor-reorg", func() {
		p, c, raw, _ := l.fixture("anchor-reorg")
		r := l.check("pre-reorg-live", l.observer, p, raw, c.GranteePubkey, 500, "live", "LIVE", false)
		l.rpc("", "invalidateblock", r.Anchor.Block)
		l.check("reorg-denied", l.observer, p, raw, c.GranteePubkey, 500, "refused", "NAME_VALUE", false)
		l.rpc("", "reconsiderblock", r.Anchor.Block)
		l.check("reorg-restored", l.observer, p, raw, c.GranteePubkey, 500, "live", "LIVE", false)
	})
	run("seal-same-height", func() {
		p := l.policy("same-height")
		pool := l.pool(p, false)
		c := testCertificate()
		c.Seal = pool.Point
		raw := signTest(l.t, c, 1)
		l.anchor(c, raw, "", nil, true)
		l.check("same-height", l.observer, p, raw, c.GranteePubkey, 500, "refused", "SEAL_ANCHOR_ORDER", false)
		noCertificateRecord(l.t, p)
		p, c, raw, _ = l.fixture("same-height-valid")
		l.check("same-height-neighbor", l.observer, p, raw, c.GranteePubkey, 500, "live", "LIVE", false)
	})
	run("seal-unconfirmed", func() {
		p := l.policy("seal-unconfirmed")
		pool := l.pool(p, false)
		c := testCertificate()
		c.Seal = pool.Point
		raw := signTest(l.t, c, 1)
		id := l.manualAnchor(c, raw)
		l.rpc("", "generateblock", l.address, []string{id})
		l.check("seal-unconfirmed", l.observer, p, raw, c.GranteePubkey, 500, "pending", "SEAL_UNCONFIRMED", false)
		noCertificateRecord(l.t, p)
		l.mine(1)
		p, c, raw, _ = l.fixture("seal-unconfirmed-valid")
		l.check("seal-unconfirmed-neighbor", l.observer, p, raw, c.GranteePubkey, 500, "live", "LIVE", false)
	})
	run("name-generation-replaced", func() {
		p, c, raw, _ := l.fixture("replacement")
		l.check("replacement-before", l.observer, p, raw, c.GranteePubkey, 500, "live", "LIVE", false)
		idle, _ := IdleValue(c.IssuerPubkey)
		l.anchor(c, raw, idle, nil, true)
		l.check("replacement-closed", l.observer, p, raw, c.GranteePubkey, 500, "refused", "NAME_REPLACED", true)
		l.anchor(c, raw, "", nil, true)
		l.check("replacement-restored-still-closed", l.observer, p, raw, c.GranteePubkey, 500, "refused", "NAME_REPLACED", true)
	})
	run("seal-spent-in-block", func() {
		p, c, raw, pool := l.fixture("block-spent")
		l.check("block-spent-before", l.observer, p, raw, c.GranteePubkey, 500, "live", "LIVE", false)
		l.revoke(pool, true)
		fresh := l.policy("block-spent-first-observation")
		l.check("block-spent", l.observer, fresh, raw, c.GranteePubkey, 500, "refused", "SEAL_SPENT", true)
	})
	run("replacement-transfers-name", func() {
		p, c, raw, _ := l.fixture("transfer-replacement")
		l.check("transfer-before", l.observer, p, raw, c.GranteePubkey, 500, "live", "LIVE", false)
		address := text(l.t, l.rpc("issuer", "getnewaddress", "", "legacy"))
		script := text(l.t, object(l.t, l.rpc("issuer", "getaddressinfo", address))["scriptPubKey"])
		payment, _ := hex.DecodeString(script)
		idle, _ := IdleValue(c.IssuerPubkey)
		l.anchor(c, raw, idle, func(tx *su.Transaction) {
			for i, out := range tx.Outputs {
				if len(out.Script) > 0 && out.Script[0] == 0x53 {
					tx.Outputs[i].Script = su.NameUpdateScript(l.station, idle, payment)
				}
			}
		}, true)
		l.check("transfer-closed", l.observer, p, raw, c.GranteePubkey, 500, "refused", "NAME_REPLACED", true)
		l.anchor(c, raw, "", nil, true)
		l.check("transfer-restored-closed", l.observer, p, raw, c.GranteePubkey, 500, "refused", "NAME_REPLACED", true)
	})
	run("unrelated-witness-mempool-and-block", func() {
		p, c, raw, _ := l.fixture("witness")
		l.check("witness-before", l.observer, p, raw, c.GranteePubkey, 500, "live", "LIVE", false)
		l.rpc("", "createwallet", "noise")
		address := text(l.t, l.rpc("noise", "getnewaddress", "", "bech32"))
		l.rpc("issuer", "sendtoaddress", address, su.Coins(200000000))
		l.mine(1)
		id := text(l.t, l.rpc("noise", "sendtoaddress", l.address, su.Coins(100000000)))
		view := object(l.t, l.rpc("", "getrawtransaction", id, true))
		hexRaw := text(l.t, view["hex"])
		if len(hexRaw) < 12 || hexRaw[8:12] != "0001" {
			l.t.Fatal("not witness traffic")
		}
		l.check("witness-mempool", l.observer, p, raw, c.GranteePubkey, 500, "live", "LIVE", false)
		l.mine(1)
		l.check("witness-block", l.observer, p, raw, c.GranteePubkey, 500, "live", "LIVE", false)
	})
	run("seal-spend-dropped-still-closed", func() {
		p, c, raw, pool := l.fixture("drop")
		l.check("drop-before", l.observer, p, raw, c.GranteePubkey, 500, "live", "LIVE", false)
		l.revoke(pool, false)
		l.check("drop-mempool-closed", l.observer, p, raw, c.GranteePubkey, 500, "refused", "SEAL_SPENT", true)
		l.stop()
		l.noWalletBroadcast = true
		l.start()
		utxo := l.rpc("", "gettxout", pool.Point.TxID, pool.Point.Vout, true)
		if bytes.Equal(bytes.TrimSpace(utxo), []byte("null")) || string(utxo) == `""` {
			l.t.Fatal("spend did not drop")
		}
		l.check("drop-restored-still-closed", l.observer, p, raw, c.GranteePubkey, 500, "refused", "SEAL_SPENT", true)
	})
	if len(passed) < 25 {
		t.Fatalf("only %d matrix rows", len(passed))
	}
	l.save("matrix-result.json", map[string]any{"status": "PASS", "count": len(passed), "cases": passed, "all_valid_neighbors": true, "node_reply_mutations": []string{"node-fold-alias"}, "transport_failures": []string{"node-unavailable"}})
}
