package wallet

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	rental "github.com/relux-works/swarma-chain-lab/experiments/rental"
)

func (l *coreLab) revoke(raw []byte) {
	l.t.Helper()
	p, e := rental.ParseGrantPresentation(raw)
	if e != nil {
		l.t.Fatal(e)
	}
	g := p.SignedGrant.Grant
	h, e := chainhash.NewHashFromStr(g.Seal.TxID)
	if e != nil {
		l.t.Fatal(e)
	}
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(h, g.Seal.Vout), nil, nil))
	payment, _ := addressScript(l.address)
	tx.AddTxOut(wire.NewTxOut(970000, payment))
	scriptHex, e := rental.GrantSealScript(g.IssuerKey)
	if e != nil {
		l.t.Fatal(e)
	}
	script, _ := hex.DecodeString(scriptHex)
	k, _ := testKey(1)
	tx.TxIn[0].SignatureScript, e = txscript.SignatureScript(tx, 0, script, txscript.SigHashAll, k, true)
	if e != nil {
		l.t.Fatal(e)
	}
	l.rpc("", "sendrawtransaction", rawTx(tx))
}

// A real rental-seal spend prevents a fresh payment and prevents revealing an
// already-funded name. Confirmed revocation remains closed across reopening.
func TestCoreRevocation(t *testing.T) {
	l := newCore(t)
	terms := Terms{Version: 1, Recipients: []string{testAddress(3)}, SpendCap: 1000000, NameCap: DefaultNameBudget, NameCount: 3}
	raw, c := l.grant(terms, []string{"names.register", "pay"}, 4000000)
	w, e := Open(c)
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if w != nil {
			w.Close()
		}
	}()
	w.clock = func() int64 { return 500 }
	r := testRequest()
	r.GrantID = grantID(t, raw)
	r.Action = "names.register"
	r.Amount = 0
	r.Name = "d/revoked-name-test"
	r.Value = "fixture"
	r.FeeLimit = 100000
	request := signRequest(t, r, 2)
	ctx := context.Background()
	got := w.Execute(ctx, raw, canonical(terms), request, "")
	if got.Status != "pending" {
		t.Fatalf("positive name commit %+v", got)
	}
	l.mine(12)
	l.revoke(raw)
	check := func(label string, req []byte) {
		t.Helper()
		before, _ := os.ReadFile(filepath.Join(c.StateDir, "wallet.json"))
		pool := string(l.rpc("", "getrawmempool"))
		got := w.Execute(ctx, raw, canonical(terms), req, "")
		if got.Status != "refused" || got.Reason != "GRANT_SEAL_SPENT" {
			t.Fatalf("%s revoked %+v", label, got)
		}
		after, _ := os.ReadFile(filepath.Join(c.StateDir, "wallet.json"))
		if string(before) != string(after) || pool != string(l.rpc("", "getrawmempool")) {
			t.Fatal("revoked request changed effects")
		}
		l.save(label+".json", got)
	}
	check("pending-revoke-name", request)
	x := testRequest()
	x.GrantID = r.GrantID
	x.FeeLimit = 100000
	x.Nonce = Hash([]byte("fresh-pay"))
	check("pending-revoke-pay", signRequest(t, x, 2))
	l.mine(1)
	w.Close()
	w = nil
	w, e = Open(c)
	if e != nil {
		t.Fatal(e)
	}
	w.clock = func() int64 { return 500 }
	check("confirmed-revoke-reopen", request)
}
