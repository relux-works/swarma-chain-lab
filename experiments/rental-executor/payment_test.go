package executor

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"github.com/btcsuite/btcd/wire"
	"strings"
	"testing"
)

type coinNode struct {
	script string
	absent bool
}

func (n coinNode) Call(_ context.Context, method string, _ ...any) (json.RawMessage, error) {
	if method != "gettxout" {
		return nil, fail("method")
	}
	if n.absent {
		return []byte("null"), nil
	}
	return canonical(map[string]any{"value": json.Number("0.01000000"), "confirmations": 1, "coinbase": false, "scriptPubKey": map[string]any{"hex": n.script}}), nil
}
func walletFixture() (Wallet, PrizeA, coinNode) {
	key := testKey(30)
	script, _ := addressScript(keyAddress(key))
	w := Wallet{hex.EncodeToString(key.Serialize()), []Point{{strings.Repeat("1", 64), 0}}, 30000}
	p := PrizeA{Point{strings.Repeat("2", 64), 0}, keyAddress(testKey(31)), hex.EncodeToString(testKey(31).Serialize())}
	return w, p, coinNode{script: hex.EncodeToString(script)}
}

// A valid explicit input builds a signed payment; forbidden prize points or
// addresses, exhausted inputs and wrong UTXO scripts never produce a plan.
func TestPaymentIsolation(t *testing.T) {
	w, p, n := walletFixture()
	build := func(w Wallet, p PrizeA, n coinNode, used map[string]bool) (paymentPlan, error) {
		return buildPayment(context.Background(), n, w, p, keyAddress(testKey(32)), 10000, used)
	}
	good, e := build(w, p, n, nil)
	if e != nil {
		t.Fatal(e)
	}
	var tx wire.MsgTx
	if tx.Deserialize(bytes.NewReader(good.Raw)) != nil || len(tx.TxIn) != 1 || tx.TxIn[0].PreviousOutPoint.Hash.String() != w.Inputs[0].TxID || len(tx.TxIn[0].SignatureScript) == 0 {
		t.Fatal("positive transaction")
	}
	for _, mode := range []string{"prize-point", "prize-address", "spent", "reserved", "script"} {
		t.Run(mode, func(t *testing.T) {
			w, p, n := walletFixture()
			used := map[string]bool{}
			want := "PRIZE_ISOLATION"
			switch mode {
			case "prize-point":
				p.Point = w.Inputs[0]
			case "prize-address":
				p.Address = keyAddress(testKey(30))
			case "spent":
				n.absent = true
				want = "BUDGET_EXHAUSTED"
			case "reserved":
				used[w.Inputs[0].key()] = true
				want = "BUDGET_EXHAUSTED"
			case "script":
				n.script = "00"
				want = "BUDGET_SCRIPT"
			}
			plan, e := build(w, p, n, used)
			if e == nil || e.Error() != want || len(plan.Raw) != 0 {
				t.Fatalf("isolation %s: %v", mode, e)
			}
		})
	}
}

// Amount parsing is exact and bounded; malformed fractions, exponent notation
// and money overflow cannot silently round or wrap into a valid payment.
func TestAtomBoundaries(t *testing.T) {
	if n, e := atoms("1.00000001"); e != nil || n != 100000001 {
		t.Fatal(n, e)
	}
	for _, s := range []string{"1e1", "-1", "1.000000001", "21000000.00000001", "00.1", "0"} {
		if _, e := atoms(json.Number(s)); e == nil {
			t.Fatal("invalid atoms", s)
		}
	}
}
