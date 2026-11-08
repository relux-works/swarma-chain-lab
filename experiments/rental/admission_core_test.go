package rental

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"testing"

	su "relux.works/swarma-chain-lab/experiments/single-use"
)

func (l *coreLab) payment(amount int64, script string, mine bool) (string, su.Transaction) {
	f := l.fund()
	dest, _ := hex.DecodeString(script)
	change, _ := hex.DecodeString(l.script)
	tx := su.Transaction{Version: 2, Inputs: []su.Input{{Point: f.Point, Sequence: 0xfffffffe}}, Outputs: []su.Output{{Value: amount, Script: dest}, {Value: f.ValueSat - amount - 100000, Script: change}}}
	return l.send(hex.EncodeToString(tx.Bytes()), mine), tx
}
func (l *coreLab) requestFor(c Certificate, id, policy string) (Certificate, []byte, []byte) {
	var v su.TransactionView
	if e := json.Unmarshal(l.rpc("", "getrawtransaction", id, true), &v); e != nil {
		l.t.Fatal(e)
	}
	var height int64
	if v.Block != "" {
		var h su.Header
		if e := json.Unmarshal(l.rpc("", "getblockheader", v.Block), &h); e != nil {
			l.t.Fatal(e)
		}
		height = h.Height
	}
	c, r, event := packageFixture(l.t, c, l.address, Point{id, 0}, height, v.Block, policy)
	request, _ := json.Marshal(r)
	return c, request, eventBytes(event)
}
func (l *coreLab) issueSpec(pool PoolOutput) PlanSpec {
	var n su.NameView
	if e := json.Unmarshal(l.rpc("", "name_show", l.station), &n); e != nil {
		l.t.Fatal(e)
	}
	var v su.TransactionView
	if e := json.Unmarshal(l.rpc("", "getrawtransaction", n.TxID, true), &v); e != nil {
		l.t.Fatal(e)
	}
	out := v.Vout[n.Vout]
	return PlanSpec{Kind: "issue", Inputs: []su.PlanInput{{Point: su.Point{TxID: n.TxID, Vout: n.Vout}, ValueSat: int64(out.Value), Script: out.Script.Hex, Role: "name"}, l.fund()}, ChangeScript: l.script, Pool: pool}
}

// Admission rechecks real payment state, including non-signalling full-RBF,
// mined/reorged payments, exact amount/address, and signed hold expiry. Pool
// refusal controls use actual confirmed/unconfirmed Core prevouts and nearby
// valid plans. Wire authentication is separately cross-checked with M3.
func TestCoreIssuanceAndPool(t *testing.T) {
	l := newCore(t)
	p := l.policy("issuer-admission")
	_, provider := testKey(4)
	ip := IssuerPolicy{p, provider}
	passed := []string{}
	check := func(label string, request, event []byte, now int64, verdict, reason string) {
		t.Helper()
		a := AdmitIssuance(context.Background(), l.observer, ip, request, event, now)
		l.save(label+".json", a)
		if a.Verdict != verdict || a.Reason != reason {
			t.Fatalf("%s: %+v", label, a)
		}
		passed = append(passed, label)
	}
	id, _ := l.payment(1000000, l.script, true)
	_, req, event := l.requestFor(testCertificate(), id, "advance")
	check("advance-valid", req, event, 500, "admit", "PAYMENT_AND_PACKAGE_CURRENT")
	check("expired-hold", req, event, 900, "refused", "hold_expired_at_admission")
	check("hold-valid-neighbor", req, event, 899, "admit", "PAYMENT_AND_PACKAGE_CURRENT")
	var view su.TransactionView
	if e := json.Unmarshal(l.rpc("", "getrawtransaction", id, true), &view); e != nil {
		t.Fatal(e)
	}
	l.rpc("", "invalidateblock", view.Block)
	check("advance-reorg", req, event, 500, "refused", "PAYMENT_UNCONFIRMED")
	l.rpc("", "reconsiderblock", view.Block)
	check("advance-restored", req, event, 500, "admit", "PAYMENT_AND_PACKAGE_CURRENT")
	wrong, _ := l.payment(1000001, l.script, true)
	_, badReq, badEvent := l.requestFor(testCertificate(), wrong, "advance")
	check("wrong-payment-amount", badReq, badEvent, 500, "refused", "PAYMENT_BINDING")
	check("amount-neighbor", req, event, 500, "admit", "PAYMENT_AND_PACKAGE_CURRENT")
	other := text(t, l.rpc("issuer", "getnewaddress", "", "legacy"))
	otherScript := text(t, object(t, l.rpc("issuer", "getaddressinfo", other))["scriptPubKey"])
	wrong, _ = l.payment(1000000, otherScript, true)
	_, badReq, badEvent = l.requestFor(testCertificate(), wrong, "advance")
	check("wrong-payment-address", badReq, badEvent, 500, "refused", "PAYMENT_BINDING")
	check("address-neighbor", req, event, 500, "admit", "PAYMENT_AND_PACKAGE_CURRENT")
	mem, tx := l.payment(1000000, l.script, false)
	_, memReq, memEvent := l.requestFor(testCertificate(), mem, "start_now")
	check("start-now-valid", memReq, memEvent, 500, "admit", "PAYMENT_AND_PACKAGE_CURRENT")
	check("start-now-expired-hold", memReq, memEvent, 900, "refused", "hold_expired_at_admission")
	if tx.Inputs[0].Sequence < 0xfffffffe {
		t.Fatal("replacement control signalled RBF")
	}
	tx.Outputs[1].Value -= 100000
	replacement := l.send(hex.EncodeToString(tx.Bytes()), false)
	if replacement == mem {
		t.Fatal("replacement unchanged")
	}
	var ids []string
	if e := json.Unmarshal(l.rpc("", "getrawmempool"), &ids); e != nil {
		t.Fatal(e)
	}
	hasReplacement := false
	for _, x := range ids {
		if x == mem {
			t.Fatal("original not replaced")
		}
		hasReplacement = hasReplacement || x == replacement
	}
	if !hasReplacement {
		t.Fatal("replacement absent")
	}
	check("original-payment-replaced", memReq, memEvent, 500, "refused", "NODE_UNAVAILABLE")
	l.mine(1)
	check("replacement-does-not-reissue", memReq, memEvent, 500, "refused", "NODE_UNAVAILABLE")
	check("replacement-neighbor", req, event, 500, "admit", "PAYMENT_AND_PACKAGE_CURRENT")
	for _, mode := range []string{"foreign-pool", "unconfirmed-pool", "reuse-pool"} {
		p := l.policy(mode)
		ip := IssuerPolicy{p, provider}
		pool := l.pool(p, mode != "unconfirmed-pool")
		c := testCertificate()
		c.Seal = pool.Point
		c, r, e := l.requestFor(c, id, "advance")
		raw := signTest(t, c, 1)
		s := l.issueSpec(pool)
		if mode == "foreign-pool" {
			foreign, _ := l.payment(1000000, otherScript, true)
			var fv su.TransactionView
			if err := json.Unmarshal(l.rpc("", "getrawtransaction", foreign, true), &fv); err != nil {
				t.Fatal(err)
			}
			var fh su.Header
			if err := json.Unmarshal(l.rpc("", "getblockheader", fv.Block), &fh); err != nil {
				t.Fatal(err)
			}
			s.Pool = PoolOutput{Point: Point{foreign, 0}, ValueSat: 1000000, Script: fv.Vout[0].Script.Hex, Height: fh.Height, Block: fv.Block}
			c.Seal = s.Pool.Point
			raw = signTest(t, c, 1)
			if _, e := MakePlan(ip, s, raw, r, e, 500); e == nil || e.Error() != "POOL_STATION_BINDING" {
				t.Fatal(mode, e)
			}
			s.Pool = pool
			c.Seal = pool.Point
			raw = signTest(t, c, 1)
		}
		if mode == "unconfirmed-pool" {
			if _, err := MakePlan(ip, s, raw, r, e, 500); err == nil || err.Error() != "POOL_UNCONFIRMED" {
				t.Fatal(mode, err)
			}
			l.mine(1)
			var v su.TransactionView
			_ = json.Unmarshal(l.rpc("", "getrawtransaction", pool.Point.TxID, true), &v)
			var h su.Header
			_ = json.Unmarshal(l.rpc("", "getblockheader", v.Block), &h)
			s.Pool.Height = h.Height
			s.Pool.Block = v.Block
		}
		plan, err := MakePlan(ip, s, raw, r, e, 500)
		if err != nil {
			t.Fatal("pool valid neighbor", err)
		}
		l.save(mode+"-valid-plan.json", plan)
		if mode == "reuse-pool" {
			c.NotAfter++
			c, r, e = l.requestFor(c, id, "advance")
			raw = signTest(t, c, 1)
			if _, err := MakePlan(ip, s, raw, r, e, 500); err == nil || err.Error() != "POOL_ALREADY_RESERVED" {
				t.Fatal(mode, err)
			}
		}
		passed = append(passed, mode)
	}
	dropped, _ := l.payment(1000000, l.script, false)
	_, dropReq, dropEvent := l.requestFor(testCertificate(), dropped, "start_now")
	check("drop-before-valid", dropReq, dropEvent, 500, "admit", "PAYMENT_AND_PACKAGE_CURRENT")
	l.stop()
	l.noWalletBroadcast = true
	l.start()
	rawPool := l.rpc("", "getrawmempool")
	if bytes.Contains(rawPool, []byte(dropped)) {
		t.Fatal("payment did not drop")
	}
	check("dropped-payment", dropReq, dropEvent, 500, "refused", "NODE_UNAVAILABLE")
	check("drop-valid-neighbor", req, event, 500, "admit", "PAYMENT_AND_PACKAGE_CURRENT")
	l.save("admission-result.json", map[string]any{"status": "PASS", "cases": passed, "replacement_signalled_rbf": false, "replacement_txid": replacement})
}
