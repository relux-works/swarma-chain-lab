package wallet

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"

	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// A response corrupter is only a negative fault injector; its underlying
// funding/signing RPC and every authority check run against genuine Core.
type corruptWallet struct {
	node  su.Node
	mode  string
	point su.Point
}

func (c corruptWallet) Call(ctx context.Context, method string, args ...any) (json.RawMessage, error) {
	raw, e := c.node.Call(ctx, method, args...)
	if e != nil {
		return nil, e
	}
	if method != "fundrawtransaction" && method != "signrawtransactionwithwallet" {
		return raw, nil
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return nil, fail("TEST_RESPONSE")
	}
	var encoded string
	json.Unmarshal(fields["hex"], &encoded)
	tx, e := decodeWire(encoded)
	if e != nil {
		return nil, e
	}
	changed := false
	if method == "fundrawtransaction" {
		switch c.mode {
		case "seal-funding":
			h, e := chainhash.NewHashFromStr(c.point.TxID)
			if e != nil {
				return nil, e
			}
			tx.TxIn = []*wire.TxIn{wire.NewTxIn(wire.NewOutPoint(h, c.point.Vout), nil, nil)}
			tx.TxOut[1].Value = 1000000 - tx.TxOut[0].Value - 50000
			fields["fee"] = json.RawMessage("0.00050000")
			changed = true
		case "target":
			tx.TxOut[0].Value++
			changed = true
		case "change":
			tx.TxOut[1].PkScript, _ = addressScript(testAddress(4))
			changed = true
		case "version":
			tx.Version = 1
			changed = true
		case "fee-quote":
			fields["fee"] = json.RawMessage("0.00000001")
		}
	} else {
		switch c.mode {
		case "signed-output":
			tx.TxOut[0].Value++
			changed = true
		case "signature":
			tx.TxIn[0].SignatureScript[5] ^= 1
			changed = true
		}
	}
	if changed {
		fields["hex"] = canonical(rawTx(tx))
	}
	return canonical(fields), nil
}

// Changed fund/sign replies cannot redirect value, alter the agreed transaction
// or evade fee checks; positive control afterward is an actual valid spend.
func TestCorePlanControls(t *testing.T) {
	l := newCore(t)
	terms := Terms{Version: 1, Recipients: []string{testAddress(3)}, SpendCap: 1000000}
	raw, c := l.grant(terms, []string{"pay"}, 1000000)
	w, e := Open(c)
	if e != nil {
		t.Fatal(e)
	}
	defer w.Close()
	w.clock = func() int64 { return 500 }
	r := testRequest()
	r.GrantID = grantID(t, raw)
	r.Amount = 100000
	r.FeeLimit = 100000
	req := signRequest(t, r, 2)
	real := w.wallet
	pool := string(l.rpc("", "getrawmempool"))
	for _, tc := range []struct{ mode, want string }{{"target", "PLAN_TARGET"}, {"change", "PLAN_CHANGE"}, {"version", "PLAN_SHAPE"}, {"fee-quote", "FEE_LIMIT"}, {"signed-output", "SIGNED_PLAN_CHANGED"}, {"signature", "SIGNED_INPUT_INVALID"}} {
		t.Run(tc.mode, func(t *testing.T) {
			w.wallet = corruptWallet{node: real, mode: tc.mode}
			got := w.Execute(context.Background(), raw, canonical(terms), req, "")
			w.wallet = real
			if got.Status != "refused" || got.Reason != tc.want {
				t.Fatalf("want %s got %+v", tc.want, got)
			}
			if _, e := os.Stat(filepath.Join(c.StateDir, "wallet.json")); !os.IsNotExist(e) || pool != string(l.rpc("", "getrawmempool")) {
				t.Fatal("corrupt plan changed state/effects")
			}
		})
	}
	low := r
	low.FeeLimit = 1
	got := w.Execute(context.Background(), raw, canonical(terms), signRequest(t, low, 2), "")
	if got.Reason != "FEE_LIMIT" {
		t.Fatalf("actual fee limit %+v", got)
	}
	got = w.Execute(context.Background(), raw, canonical(terms), req, "")
	if got.Status != "executed" {
		t.Fatalf("positive plan %+v", got)
	}
	l.save("plan-positive.json", got)
}

// Even if the demo wallet accidentally holds the grant issuer key, neither the
// current seal nor an unrelated UTXO at that seal script can fund a payment.
// The injected plan would otherwise sign and be consensus-valid on this node.
func TestCoreSealFunding(t *testing.T) {
	l := newCore(t)
	k, _ := testKey(1)
	wif, _ := btcutil.NewWIF(k, &chaincfg.RegressionNetParams, true)
	l.rpc("agent", "importprivkey", wif.String(), "", false)
	terms := Terms{Version: 1, Recipients: []string{testAddress(3)}, SpendCap: 1000000}
	raw, c := l.grant(terms, []string{"pay"}, 1000000)
	w, e := Open(c)
	if e != nil {
		t.Fatal(e)
	}
	defer w.Close()
	w.clock = func() int64 { return 500 }
	g, e := w.Grant(raw)
	if e != nil {
		t.Fatal(e)
	}
	l.rpc("agent", "lockunspent", false, []su.Point{g.Seal})
	id := text(t, l.rpc("issuer", "sendtoaddress", testAddress(1), su.Coins(1000000)))
	l.mine(1)
	var tx su.TransactionView
	if json.Unmarshal(l.rpc("", "getrawtransaction", id, true), &tx) != nil {
		t.Fatal("pool funding")
	}
	script, _ := addressScript(testAddress(1))
	stray := su.Point{}
	for _, o := range tx.Vout {
		if o.Script.Hex == hex.EncodeToString(script) && int64(o.Value) == 1000000 {
			stray = su.Point{TxID: id, Vout: o.N}
		}
	}
	if stray.TxID == "" {
		t.Fatal("stray seal-script funding absent")
	}
	l.rpc("agent", "lockunspent", false, []su.Point{stray})
	r := testRequest()
	r.GrantID = g.ID
	r.Amount = 100000
	r.FeeLimit = 100000
	req := signRequest(t, r, 2)
	real := w.wallet
	pool := string(l.rpc("", "getrawmempool"))
	for _, tc := range []struct {
		name, want string
		point      su.Point
	}{{"current", "PLAN_RESERVED_INPUT", g.Seal}, {"stray", "PLAN_SEAL_SCRIPT_INPUT", stray}} {
		t.Run(tc.name, func(t *testing.T) {
			w.wallet = corruptWallet{node: real, mode: "seal-funding", point: tc.point}
			got := w.Execute(context.Background(), raw, canonical(terms), req, "")
			w.wallet = real
			if got.Status != "refused" || got.Reason != tc.want {
				t.Fatalf("seal funding want %s got %+v", tc.want, got)
			}
			if _, e := os.Stat(filepath.Join(c.StateDir, "wallet.json")); !os.IsNotExist(e) || pool != string(l.rpc("", "getrawmempool")) {
				t.Fatal("seal funding wrote state/effect")
			}
		})
	}
	got := w.Execute(context.Background(), raw, canonical(terms), req, "")
	if got.Status != "executed" {
		t.Fatalf("separate wallet funding %+v", got)
	}
	l.save("separate-funding.json", got)
}
