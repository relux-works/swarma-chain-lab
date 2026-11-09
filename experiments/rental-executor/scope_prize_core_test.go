package executor

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	"testing"
)

// Empty scope refuses all effects while a real live grant still verifies.
// Explicitly scoped local stubs work, but even scoped secret.release refuses.
// The watcher identifies a deliberate isolated prize spend by exact outpoint.
func TestCoreScopeAndPrize(t *testing.T) {
	l := newCore(t)
	ctx := context.Background()
	c := testCertificate()
	c.Scope = []string{}
	p, c, raw, _ := l.issueFixture("empty", c)
	x, b, _, _ := l.executor(p, raw, 1)
	live := rental.Check(ctx, l.observer, p, raw, p.StationName, c.GranteePubkey, 500)
	if live.Verdict != "live" {
		t.Fatal("empty live neighbour", live)
	}
	for _, action := range []string{"pay", "deliver", "publish", "repository.push", "secret.release"} {
		event := requestFor(c, "empty-"+action, action, 1000)
		switch action {
		case "deliver":
			tagSet(&event, "target", "sha256:"+Hash(nil))
		case "repository.push":
			tagSet(&event, "target", "https://example.com/repo")
		}
		event = signEvent(event, testKey(2))
		want := "ACTION_SCOPE"
		if action == "secret.release" {
			want = "SECRET_RELEASE_FORBIDDEN"
		}
		expectResult(t, x.Execute(ctx, canonical(event), nil), "refused", want)
	}
	if b.calls != 0 || len(x.journal.Reservations) != 0 {
		t.Fatal("empty scope effect")
	}
	x.Close()
	c = testCertificate()
	c.Scope = []string{"deliver", "pay", "publish", "repository.push", "secret.release"}
	p, c, raw, _ = l.issueFixture("wide", c)
	x, b, _, _ = l.executor(p, raw, 2)
	for _, action := range []string{"publish", "repository.push"} {
		event := requestFor(c, action, action, 0)
		if action == "repository.push" {
			tagSet(&event, "target", "https://example.com/repo")
		}
		event = signEvent(event, testKey(2))
		expectResult(t, x.Execute(ctx, canonical(event), nil), "executed", "LIVE_RENTER_REQUEST")
	}
	expectResult(t, x.Execute(ctx, canonical(requestFor(c, "secret-scoped", "secret.release", 0)), nil), "refused", "SECRET_RELEASE_FORBIDDEN")
	prize := x.config.Prize
	observation, e := WatchPrize(ctx, l.observer, prize)
	if e != nil || observation.Status != "unspent" {
		t.Fatal("unspent prize neighbour", e)
	}
	expectResult(t, x.Execute(ctx, canonical(requestFor(c, "budget-prize-control", "pay", 1000)), nil), "executed", "LIVE_RENTER_REQUEST")
	observation, e = WatchPrize(ctx, l.observer, prize)
	if e != nil || observation.Status != "unspent" {
		t.Fatal("budget touched prize", e)
	}
	// Deliberate violation plant spends only this test's disposable regtest prize.
	// It bypasses the executor to demonstrate watcher detection, not prevention.
	h, _ := chainhash.NewHashFromStr(prize.Point.TxID)
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(h, prize.Point.Vout), nil, nil))
	out, _ := addressScript(keyAddress(testKey(32)))
	tx.AddTxOut(wire.NewTxOut(970000, out))
	script, _ := addressScript(prize.Address)
	key, _ := privateKey(prize.Key)
	sig, e := txscript.SignatureScript(tx, 0, script, txscript.SigHashAll, key, true)
	if e != nil {
		t.Fatal(e)
	}
	tx.TxIn[0].SignatureScript = sig
	var buf bytes.Buffer
	_ = tx.Serialize(&buf)
	id := text(t, l.rpc("", "sendrawtransaction", hex.EncodeToString(buf.Bytes())))
	observation, e = WatchPrize(ctx, l.observer, prize)
	if e != nil || observation.Status != "spent" || observation.SpendTxID != id || observation.Block != "" {
		t.Fatal("mempool prize spend not detected", e, observation)
	}
	l.save("prize-mempool.json", observation)
	l.mine(1)
	observation, e = WatchPrize(ctx, l.observer, prize)
	if e != nil || observation.Status != "spent" || observation.SpendTxID != id || observation.Block == "" {
		t.Fatal("confirmed prize spend not detected", e, observation)
	}
	l.save("prize-confirmed.json", observation)
	// A prize can be funded and spent in one block; include its funding block.
	fundingID := text(t, l.rpc("issuer", "sendtoaddress", prize.Address, json.Number("0.01000000")))
	var funding struct {
		Vout []struct {
			N      uint32      `json:"n"`
			Value  json.Number `json:"value"`
			Script struct {
				Address string `json:"address"`
			} `json:"scriptPubKey"`
		} `json:"vout"`
	}
	if json.Unmarshal(l.rpc("", "getrawtransaction", fundingID, true), &funding) != nil {
		t.Fatal("same-block funding")
	}
	found := false
	for _, output := range funding.Vout {
		if output.Script.Address == prize.Address && output.Value.String() == "0.01000000" {
			prize.Point = Point{fundingID, output.N}
			found = true
			break
		}
	}
	if !found {
		t.Fatal("same-block prize missing")
	}
	h, _ = chainhash.NewHashFromStr(prize.Point.TxID)
	tx.TxIn[0].PreviousOutPoint = *wire.NewOutPoint(h, prize.Point.Vout)
	tx.TxIn[0].SignatureScript = nil
	sig, e = txscript.SignatureScript(tx, 0, script, txscript.SigHashAll, key, true)
	if e != nil {
		t.Fatal(e)
	}
	tx.TxIn[0].SignatureScript = sig
	buf.Reset()
	_ = tx.Serialize(&buf)
	sameID := text(t, l.rpc("", "sendrawtransaction", hex.EncodeToString(buf.Bytes())))
	l.mine(1)
	observation, e = WatchPrize(ctx, l.observer, prize)
	if e != nil || observation.Status != "spent" || observation.SpendTxID != sameID || observation.Block == "" {
		t.Fatal("same-block prize spend not detected", e, observation)
	}
	l.save("prize-same-block.json", observation)
	if _, e = WatchPrize(ctx, failingNode{}, prize); e == nil {
		t.Fatal("node outage claimed prize result")
	}
}
