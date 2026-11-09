package paymentchain

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
)

// Synthetic own-node replies establish main chain/genesis/raw-payment binding;
// reciprocal wrong-chain/genesis plants refuse with no returned admission.
// No real mainnet node is queried and no consensus claim follows from this test.
func TestMainPaymentObservation(t *testing.T) {
	for _, mode := range []string{"valid", "wrong-chain", "wrong-genesis"} {
		t.Run(mode, func(t *testing.T) {
			n, terms, payment := nodeFixture(t, "nmc")
			params := chaincfg.MainNetParams
			params.PubKeyHashAddrID = 52
			address, _ := btcutil.NewAddressPubKeyHash(make([]byte, 20), &params)
			terms.Network, terms.Genesis, terms.Address = "main", NamecoinMainGenesis, address.EncodeAddress()
			n.mutate = func(method string, args []any, raw json.RawMessage) json.RawMessage {
				if method == "getblockchaininfo" && mode != "wrong-chain" {
					return rewrite(raw, "chain", "main")
				}
				if method == "getblockhash" && args[0] == 0 && mode != "wrong-genesis" {
					return canonical(NamecoinMainGenesis)
				}
				return raw
			}
			got, err := Admit(context.Background(), n, Limits{2016, 10000, 10000, 64 << 20}, terms, payment, 100, 1300, 60, 1, 101)
			if mode == "valid" {
				if err != nil || got.Payment.TxID != payment.TxID || got.Confirmations != 2 {
					t.Fatal(got, err)
				}
				return
			}
			want := "NODE_CHAIN"
			if mode == "wrong-genesis" {
				want = "NODE_GENESIS"
			}
			if err == nil || err.Error() != want || got != (Admission{}) {
				t.Fatal(mode, got, err)
			}
		})
	}
}
