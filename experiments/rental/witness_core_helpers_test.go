package rental

import (
	"encoding/hex"
	"encoding/json"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// W fixtures explicitly spend one confirmed native coin; ordinary wallet
// selection may choose legacy name change. Historical v0/v2 helpers stay legacy.
func (l *coreLab) witnessPool(key byte, mine bool) Point {
	l.t.Helper()
	l.rpc("issuer", "importprivkey", testWIF(key), "", false)
	nativeAddress := text(l.t, l.rpc("issuer", "getnewaddress", "", "bech32"))
	nativeScript := text(l.t, object(l.t, l.rpc("issuer", "getaddressinfo", nativeAddress))["scriptPubKey"])
	seed := text(l.t, l.rpc("issuer", "sendtoaddress", nativeAddress, su.Coins(2000000)))
	l.mine(1)
	var view su.TransactionView
	if e := json.Unmarshal(l.rpc("", "getrawtransaction", seed, true), &view); e != nil {
		l.t.Fatal(e)
	}
	var point su.Point
	found := false
	for _, out := range view.Vout {
		if out.Script.Hex == nativeScript && int64(out.Value) == 2000000 {
			point = su.Point{TxID: seed, Vout: out.N}
			found = true
		}
	}
	if !found {
		l.t.Fatal("native fixture funding")
	}
	_, pub := testKey(key)
	script, e := GrantSealScript(pub)
	if e != nil {
		l.t.Fatal(e)
	}
	if key == 7 {
		script = testFundingScript()
	}
	tx := su.Transaction{Version: 2, Inputs: []su.Input{{Point: point, Sequence: 0xfffffffe}}, Outputs: []su.Output{{Value: 1000000, Script: mustDecodeKey(script)}, {Value: 900000, Script: mustDecodeKey(nativeScript)}}}
	id := l.send(hex.EncodeToString(tx.Bytes()), mine)
	result := Point{TxID: id, Vout: 0}
	l.rpc("issuer", "lockunspent", false, []Point{result})
	return result
}
