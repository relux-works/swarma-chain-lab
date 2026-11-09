package rental

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"math/big"
	"testing"

	su "relux.works/swarma-chain-lab/experiments/single-use"
)

// Public deterministic laboratory WIF only; never production custody material.
func testWIF(n byte) string {
	raw := make([]byte, 34)
	raw[0] = 0xef
	raw[32] = n
	raw[33] = 1
	a := sha256.Sum256(raw)
	b := sha256.Sum256(a[:])
	raw = append(raw, b[:4]...)
	number := new(big.Int).SetBytes(raw)
	base := big.NewInt(58)
	mod := new(big.Int)
	var out []byte
	alphabet := "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	for number.Sign() > 0 {
		number.DivMod(number, base, mod)
		out = append(out, alphabet[mod.Int64()])
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}
func (l *coreLab) agentValue(grant, nostr byte, mine bool) string {
	_, g := testKey(grant)
	_, n := testKey(nostr)
	value, e := AgentValue(AgentKeys{Nostr: n, Grant: g})
	if e != nil {
		l.t.Fatal(e)
	}
	id := text(l.t, l.rpc("issuer", "name_update", l.station, value))
	if mine {
		l.mine(1)
	}
	return id
}
func (l *coreLab) detachedPool(key byte, mine bool) Point {
	l.rpc("issuer", "importprivkey", testWIF(key), "", false)
	_, pub := testKey(key)
	descriptor := object(l.t, l.rpc("", "getdescriptorinfo", "pkh(02"+pub+")"))
	var addresses []string
	if e := json.Unmarshal(l.rpc("", "deriveaddresses", text(l.t, descriptor["descriptor"])), &addresses); e != nil || len(addresses) != 1 {
		l.t.Fatal("fixture descriptor")
	}
	id := text(l.t, l.rpc("issuer", "sendtoaddress", addresses[0], su.Coins(1000000)))
	if mine {
		l.mine(1)
	}
	var tx su.TransactionView
	if e := json.Unmarshal(l.rpc("", "getrawtransaction", id, true), &tx); e != nil {
		l.t.Fatal(e)
	}
	script, e := GrantSealScript(pub)
	if e != nil {
		l.t.Fatal(e)
	}
	for _, o := range tx.Vout {
		if o.Script.Hex == script && int64(o.Value) == 1000000 {
			point := Point{id, o.N}
			l.rpc("issuer", "lockunspent", false, []Point{point})
			return point
		}
	}
	l.t.Fatal("fixture seal absent")
	return Point{}
}
func (l *coreLab) detached(label string, seal Point, grantee byte) (Policy, DetachedCertificate, []byte) {
	p := l.policy(label)
	p.AgentName = l.station
	p.SealScript, _ = GrantSealScript(p.IssuerPubkey)
	c := testDetached()
	c.AgentName = l.station
	c.Seal = seal
	_, c.GranteeKey = testKey(grantee)
	return p, c, signDetachedTest(l.t, c, 1)
}
func (l *coreLab) checkDetached(label string, p Policy, c DetachedCertificate, raw []byte, now int64, want, reason string, closed bool) Receipt {
	l.t.Helper()
	r := CheckV2(context.Background(), l.observer, p, raw, p.AgentName, c.GranteeKey, now)
	l.save(label+".json", r)
	if r.Verdict != want || r.Reason != reason || r.Closed != closed {
		l.t.Fatalf("%s: want %s/%s closed=%v; got %+v", label, want, reason, closed, r)
	}
	return r
}
func (l *coreLab) revokeDetached(seal Point, mine bool) string {
	unsigned := text(l.t, l.rpc("", "createrawtransaction", []Point{seal}, []map[string]any{{l.address: su.Coins(950000)}}))
	return l.send(unsigned, mine)
}

// Genuine Core: two detached certificates under one name are simultaneously
// live without anchors; a mempool seal spend closes only its grant, survives
// mining and restart, while the other grant and its separate seal stay live.
func TestCoreDetachedLifecycle(t *testing.T) {
	l := newCore(t)
	l.agentValue(1, 3, true)
	a := l.detachedPool(1, true)
	b := l.detachedPool(1, true)
	p, c, raw := l.detached("parallel", a, 2)
	other := c
	other.Seal = b
	_, other.GranteeKey = testKey(4)
	otherRaw := signDetachedTest(t, other, 1)
	l.checkDetached("grant-a-live", p, c, raw, 500, "live", "LIVE", false)
	l.checkDetached("grant-b-live", p, other, otherRaw, 500, "live", "LIVE", false)
	l.revokeDetached(a, false)
	l.checkDetached("grant-a-mempool-closed", p, c, raw, 500, "refused", "SEAL_SPENT", true)
	l.checkDetached("grant-b-still-live", p, other, otherRaw, 500, "live", "LIVE", false)
	l.mine(1)
	l.checkDetached("grant-a-mined-closed", p, c, raw, 500, "refused", "SEAL_SPENT", true)
	l.stop()
	l.start()
	r := l.checkDetached("grant-a-restart-closed", p, c, raw, 500, "refused", "SEAL_SPENT", true)
	if r.Calls != 0 {
		t.Fatal("durable closure rereads node")
	}
	l.checkDetached("grant-b-restart-live", p, other, otherRaw, 500, "live", "LIVE", false)
	l.save("result.json", map[string]any{"status": "PASS", "parallel_grants": 2, "per_grant_anchor": false})
}

// Genuine Core name rotations distinguish pending refusal from confirmed,
// permanent closure. A nostr-only generation is a live positive neighbor;
// neither a reorg of the observed rotation nor rotate-back reopens closure.
func TestCoreDetachedRotation(t *testing.T) {
	l := newCore(t)
	l.agentValue(1, 3, true)
	seal := l.detachedPool(1, true)
	p, c, raw := l.detached("rotation", seal, 2)
	l.checkDetached("initial-live", p, c, raw, 500, "live", "LIVE", false)
	l.agentValue(1, 4, true)
	l.checkDetached("nostr-rotation-live", p, c, raw, 500, "live", "LIVE", false)
	id := l.agentValue(5, 4, false)
	l.checkDetached("pending-refuses", p, c, raw, 500, "refused", "PENDING_GRANT_ROTATION", false)
	l.mine(1)
	l.checkDetached("confirmed-closes", p, c, raw, 500, "refused", "GRANT_KEY_ROTATED", true)
	v := object(t, l.rpc("", "getrawtransaction", id, true))
	block := text(t, v["blockhash"])
	l.rpc("", "invalidateblock", block)
	l.checkDetached("reorg-stays-closed", p, c, raw, 500, "refused", "GRANT_KEY_ROTATED", true)
	l.rpc("", "reconsiderblock", block)
	l.agentValue(1, 3, true)
	l.checkDetached("rotate-back-stays-closed", p, c, raw, 500, "refused", "GRANT_KEY_ROTATED", true)
	fresh, fc, fr := l.detached("fresh-neighbor", l.detachedPool(1, true), 2)
	l.checkDetached("new-certificate-live", fresh, fc, fr, 500, "live", "LIVE", false)
	l.save("result.json", map[string]any{"status": "PASS", "observed_rotation_permanent": true})
}
