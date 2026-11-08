package rental

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	su "relux.works/swarma-chain-lab/experiments/single-use"
)

// This table uses actual confirmed Core name/seal fixtures; authentication and
// time failures happen before RPC by design. Transport faults are labelled.
// Every denial keeps closure false and is followed by the unchanged live case.
func TestCoreDetachedMatrix(t *testing.T) {
	l := newCore(t)
	l.agentValue(1, 3, true)
	seal := l.detachedPool(1, true)
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
	cases := []struct {
		name, reason, verdict string
		change                func(*Policy, *DetachedCertificate, *[]byte, *string, *int64)
	}{
		{"wrong-agent", "CERTIFICATE_POLICY", "refused", func(p *Policy, c *DetachedCertificate, b *[]byte, s *string, n *int64) {
			c.AgentName = "id/foreign"
			*b = signDetachedTest(l.t, *c, 1)
		}},
		{"foreign-network", "CERTIFICATE_POLICY", "refused", func(p *Policy, c *DetachedCertificate, b *[]byte, s *string, n *int64) {
			c.Network = "main"
			c.Genesis = su.MainGenesis
			*b = signDetachedTest(l.t, *c, 1)
		}},
		{"policy-genesis", "REGTEST_ONLY", "refused", func(p *Policy, c *DetachedCertificate, b *[]byte, s *string, n *int64) { p.Genesis = su.MainGenesis }},
		{"wrong-grant-key", "GRANT_KEY_MISMATCH", "refused", func(p *Policy, c *DetachedCertificate, b *[]byte, s *string, n *int64) {
			_, c.IssuerKey = testKey(5)
			p.SealScript, _ = GrantSealScript(c.IssuerKey)
			*b = signDetachedTest(l.t, *c, 5)
		}},
		{"nostr-signature", "ISSUER_SIGNATURE", "refused", func(p *Policy, c *DetachedCertificate, b *[]byte, s *string, n *int64) {
			*b = signDetachedTest(l.t, *c, 3)
		}},
		{"other-presenter", "GRANTEE_MISMATCH", "refused", func(p *Policy, c *DetachedCertificate, b *[]byte, s *string, n *int64) { _, *s = testKey(4) }},
		{"foreign-grantee-certificate", "GRANTEE_MISMATCH", "refused", func(p *Policy, c *DetachedCertificate, b *[]byte, s *string, n *int64) {
			_, c.GranteeKey = testKey(4)
			*b = signDetachedTest(l.t, *c, 1)
		}},
		{"not-yet-valid", "NOT_YET_VALID", "pending", func(p *Policy, c *DetachedCertificate, b *[]byte, s *string, n *int64) { *n = c.NotBefore - 1 }},
		{"expired-exact", "EXPIRED", "refused", func(p *Policy, c *DetachedCertificate, b *[]byte, s *string, n *int64) { *n = c.NotAfter }},
		{"negative-clock", "CLOCK_INPUT", "refused", func(p *Policy, c *DetachedCertificate, b *[]byte, s *string, n *int64) { *n = -1 }},
		{"seal-script-policy", "SEAL_KEY_BINDING", "refused", func(p *Policy, c *DetachedCertificate, b *[]byte, s *string, n *int64) { p.SealScript = l.script }},
		{"missing-output", "SEAL_OUTPUT", "refused", func(p *Policy, c *DetachedCertificate, b *[]byte, s *string, n *int64) {
			c.Seal.Vout = 63
			*b = signDetachedTest(l.t, *c, 1)
		}},
		{"extra-certificate-field", "CANONICAL_ENCODING", "refused", func(p *Policy, c *DetachedCertificate, b *[]byte, s *string, n *int64) {
			*b = bytes.Replace(*b, []byte(`"version":2`), []byte(`"version":2,"extra":0`), 1)
		}},
		{"null-budget", "CANONICAL_ENCODING", "refused", func(p *Policy, c *DetachedCertificate, b *[]byte, s *string, n *int64) {
			*b = bytes.Replace(*b, []byte(`"seal":`), []byte(`"budget":null,"seal":`), 1)
		}},
	}
	for _, tc := range cases {
		run(tc.name, func() {
			p, c, raw := l.detached(tc.name, seal, 2)
			baseline := p
			baseC := c
			baseRaw := append([]byte(nil), raw...)
			sender := c.GranteeKey
			now := int64(500)
			tc.change(&p, &c, &raw, &sender, &now)
			r := Check(context.Background(), l.observer, p, raw, p.AgentName, sender, now)
			l.save(tc.name+".json", r)
			if r.Verdict != tc.verdict || r.Reason != tc.reason || r.Closed {
				l.t.Fatalf("want %s/%s unclosed got %+v", tc.verdict, tc.reason, r)
			}
			assertNoIssuerBurn(l.t, baseline.StateDir)
			l.checkDetached(tc.name+"-valid", baseline, baseC, baseRaw, 500, "live", "LIVE", false)
		})
	}
	for _, mode := range []string{"extra", "missing", "alias", "malformed"} {
		run("name-"+mode, func() {
			p, c, raw := l.detached("name-"+mode, seal, 2)
			l.checkDetached("name-"+mode+"-before", p, c, raw, 500, "live", "LIVE", false)
			_, issuer := testKey(1)
			_, nostr := testKey(3)
			value, _ := AgentValue(AgentKeys{nostr, issuer})
			switch mode {
			case "extra":
				value = strings.TrimSuffix(value, "}") + `,"extra":1}`
			case "missing":
				value = `{"swarma":{"agent":{"nostr":"` + nostr + `"}}}`
			case "alias":
				value = strings.Replace(value, `"grant":`, `"issuer":`, 1)
			case "malformed":
				value = "not-json"
			}
			l.rpc("issuer", "name_update", l.station, value)
			l.mine(1)
			l.checkDetached("name-"+mode+"-refusal", p, c, raw, 500, "refused", "AGENT_NAME_VALUE", false)
			l.agentValue(1, 3, true)
			l.checkDetached("name-"+mode+"-valid", p, c, raw, 500, "live", "LIVE", false)
		})
	}
	run("read-unavailable", func() {
		p, c, raw := l.detached("unavailable", seal, 2)
		r := Check(context.Background(), unavailableNode{}, p, raw, p.AgentName, c.GranteeKey, 500)
		if r.Reason != "NODE_UNAVAILABLE" || r.Closed {
			l.t.Fatal(r)
		}
		assertNoIssuerBurn(l.t, p.StateDir)
		l.checkDetached("read-unavailable-valid", p, c, raw, 500, "live", "LIVE", false)
	})
	run("malformed-node-projection", func() {
		p, c, raw := l.detached("projection", seal, 2)
		n := &aliasNode{base: l.observer}
		r := Check(context.Background(), n, p, raw, p.AgentName, c.GranteeKey, 500)
		if n.applied != 1 || r.Reason != "NODE_PROJECTION" || r.Closed {
			l.t.Fatal(r, n.applied)
		}
		assertNoIssuerBurn(l.t, p.StateDir)
		l.checkDetached("projection-valid", p, c, raw, 500, "live", "LIVE", false)
	})
	run("seal-unconfirmed", func() {
		s := l.detachedPool(1, false)
		p, c, raw := l.detached("unconfirmed", s, 2)
		l.checkDetached("unconfirmed-seal", p, c, raw, 500, "pending", "SEAL_UNCONFIRMED", false)
		assertNoIssuerBurn(l.t, p.StateDir)
		l.mine(1)
		l.checkDetached("unconfirmed-seal-valid", p, c, raw, 500, "live", "LIVE", false)
	})
	run("seal-foreign-owner", func() {
		s := l.detachedPool(5, true)
		p, c, raw := l.detached("foreign-seal", s, 2)
		l.checkDetached("foreign-seal", p, c, raw, 500, "refused", "SEAL_BINDING", false)
		assertNoIssuerBurn(l.t, p.StateDir)
		c.Seal = seal
		raw = signDetachedTest(l.t, c, 1)
		l.checkDetached("foreign-seal-valid", p, c, raw, 500, "live", "LIVE", false)
	})
	run("seen-seal-reuse", func() {
		p, c, raw := l.detached("seen-seal", seal, 2)
		l.checkDetached("seen-seal-first", p, c, raw, 500, "live", "LIVE", false)
		other := c
		_, other.GranteeKey = testKey(4)
		otherRaw := signDetachedTest(l.t, other, 1)
		l.checkDetached("seen-seal-second", p, other, otherRaw, 500, "refused", "SEAL_ALREADY_SEEN", false)
		l.checkDetached("seen-seal-first-valid", p, c, raw, 500, "live", "LIVE", false)
	})
	run("seal-spent-before-first-check", func() {
		s := l.detachedPool(1, true)
		p, c, raw := l.detached("spent-block", s, 2)
		l.revokeDetached(s, true)
		l.checkDetached("spent-first-observation", p, c, raw, 500, "refused", "SEAL_SPENT", true)
		fresh, fc, fr := l.detached("spent-block-valid", seal, 2)
		l.checkDetached("spent-block-valid", fresh, fc, fr, 500, "live", "LIVE", false)
	})
	run("unrelated-witness-noise", func() {
		p, c, raw := l.detached("witness-noise", seal, 2)
		address := text(l.t, l.rpc("issuer", "getnewaddress", "", "bech32"))
		funding := text(l.t, l.rpc("issuer", "sendtoaddress", address, su.Coins(2000000)))
		l.mine(1)
		var view su.TransactionView
		if e := json.Unmarshal(l.rpc("", "getrawtransaction", funding, true), &view); e != nil {
			l.t.Fatal(e)
		}
		var point Point
		found := false
		for _, o := range view.Vout {
			if o.Script.Address == address {
				point = Point{funding, o.N}
				found = true
				break
			}
		}
		if !found {
			l.t.Fatal("witness input")
		}
		unsigned := text(l.t, l.rpc("", "createrawtransaction", []Point{point}, []map[string]any{{l.address: su.Coins(1950000)}}))
		l.send(unsigned, false)
		l.checkDetached("witness-mempool-live", p, c, raw, 500, "live", "LIVE", false)
		l.mine(1)
		l.checkDetached("witness-block-live", p, c, raw, 500, "live", "LIVE", false)
	})
	run("name-expired-at-chain-height", func() {
		p, c, raw := l.detached("expiry", seal, 2)
		l.checkDetached("name-expiry-before", p, c, raw, 500, "live", "LIVE", false)
		var n su.NameView
		if e := json.Unmarshal(l.rpc("", "name_show", l.station), &n); e != nil {
			l.t.Fatal(e)
		}
		if n.ExpiresIn < 1 || n.ExpiresIn > 50000 {
			l.t.Fatalf("unexpected bounded regtest expiry %d", n.ExpiresIn)
		}
		l.mine(int(n.ExpiresIn))
		tip := text(l.t, l.rpc("", "getbestblockhash"))
		// Core's default name_show refuses the expired lookup. The read boundary
		// reports NODE_UNAVAILABLE rather than inventing an expiry verdict from
		// an RPC error; the chain-height transition is controlled by this test.
		l.checkDetached("name-expired", p, c, raw, 500, "refused", "NODE_UNAVAILABLE", false)
		l.rpc("", "invalidateblock", tip)
		l.checkDetached("name-expiry-reorg-valid", p, c, raw, 500, "live", "LIVE", false)
	})
	if len(passed) < 25 {
		t.Fatalf("only %d cases", len(passed))
	}
	l.save("matrix.json", map[string]any{"status": "PASS", "cases": passed, "transport_controls": []string{"read-unavailable", "malformed-node-projection"}, "count": len(passed)})
}

// A pending name update can disappear without closing anything. Conversely,
// a seen mempool seal spend stays closed even after restart drops that spend.
func TestCoreDetachedDroppedTransactions(t *testing.T) {
	l := newCore(t)
	l.agentValue(1, 3, true)
	seal := l.detachedPool(1, true)
	neighborSeal := l.detachedPool(1, true)
	p, c, raw := l.detached("pending-drop", seal, 2)
	l.checkDetached("before-pending", p, c, raw, 500, "live", "LIVE", false)
	l.agentValue(5, 3, false)
	l.checkDetached("pending", p, c, raw, 500, "refused", "PENDING_GRANT_ROTATION", false)
	l.stop()
	l.noWalletBroadcast = true
	l.start()
	l.rpc("", "loadwallet", "issuer")
	var ids []string
	if e := json.Unmarshal(l.rpc("", "getrawmempool"), &ids); e != nil || len(ids) != 0 {
		t.Fatal("restart did not drop pending tx", e)
	}
	l.checkDetached("dropped-rotation-live", p, c, raw, 500, "live", "LIVE", false)
	l.revokeDetached(seal, false)
	l.checkDetached("mempool-seal-closed", p, c, raw, 500, "refused", "SEAL_SPENT", true)
	l.stop()
	l.start()
	l.checkDetached("dropped-spend-still-closed", p, c, raw, 500, "refused", "SEAL_SPENT", true)
	fresh, fc, fr := l.detached("dropped-neighbor", neighborSeal, 2)
	l.checkDetached("dropped-spend-neighbor", fresh, fc, fr, 500, "live", "LIVE", false)
}

// A reorg back to an older, different grant-key generation is refusal without
// closure, and restoring the accepted generation restores live.
func TestCoreDetachedRollback(t *testing.T) {
	l := newCore(t)
	l.agentValue(5, 3, true)
	seal := l.detachedPool(1, true)
	id := l.agentValue(1, 3, true)
	v := object(t, l.rpc("", "getrawtransaction", id, true))
	block := text(t, v["blockhash"])
	p, c, raw := l.detached("rollback", seal, 2)
	l.checkDetached("rollback-before", p, c, raw, 500, "live", "LIVE", false)
	l.rpc("", "invalidateblock", block)
	l.checkDetached("older-key-refuses", p, c, raw, 500, "refused", "GRANT_KEY_MISMATCH", false)
	l.rpc("", "reconsiderblock", block)
	l.checkDetached("restored-generation-live", p, c, raw, 500, "live", "LIVE", false)
}

func cacheBytes(t *testing.T, p Policy) []byte {
	t.Helper()
	b, e := os.ReadFile(filepath.Join(p.StateDir, presentationName(p)))
	if e != nil {
		t.Fatal(e)
	}
	return b
}
