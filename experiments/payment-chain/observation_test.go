package paymentchain

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

type fixtureNode struct {
	t           *testing.T
	coin        string
	tx          wire.MsgTx
	calls       []string
	mutate      func(string, []any, json.RawMessage) json.RawMessage
	unavailable string
}

func (n *fixtureNode) Call(_ context.Context, m string, args ...any) (json.RawMessage, error) {
	n.calls = append(n.calls, m)
	if !readMethods[m] {
		n.t.Fatalf("forbidden RPC %s", m)
	}
	if m == n.unavailable {
		return nil, errors.New("deliberate node failure")
	}
	p, _ := ForCoin(n.coin)
	var v any
	block := strings.Repeat("b", 64)
	id := n.tx.TxHash().String()
	switch m {
	case "getnetworkinfo":
		v = map[string]any{"subversion": map[string]string{"btc": "/Satoshi:32.1.0/", "ltc": "/LitecoinCore:0.21.5.8/", "nmc": "/Satoshi:28.0.0/"}[n.coin], "protocolversion": map[string]int64{"btc": 70017, "ltc": 70017, "nmc": 110016}[n.coin]}
	case "getblockchaininfo":
		v = map[string]any{"chain": "regtest", "bestblockhash": block, "blocks": int64(20), "headers": int64(20), "initialblockdownload": false}
	case "getblockhash":
		if args[0] == 0 {
			v = p.Genesis
		} else {
			v = block
		}
	case "getblock":
		v = map[string]any{"hash": block, "height": int64(19), "confirmations": int64(2), "tx": []string{id}}
	case "getrawtransaction":
		if len(args) != 3 || args[2] != block {
			n.t.Fatal("historical admission must derive active block argument")
		}
		var b bytes.Buffer
		if e := n.tx.Serialize(&b); e != nil {
			n.t.Fatal(e)
		}
		v = map[string]any{"txid": id, "hex": hex.EncodeToString(b.Bytes()), "blockhash": block, "confirmations": int64(2)}
	default:
		n.t.Fatalf("unexpected RPC %s", m)
	}
	b := canonical(v)
	if n.mutate != nil {
		b = n.mutate(m, args, b)
	}
	return b, nil
}
func nodeFixture(t *testing.T, coin string) (*fixtureNode, Terms, Payment) {
	t.Helper()
	p, _ := ForCoin(coin)
	params := chaincfg.RegressionNetParams
	params.Bech32HRPSegwit = p.HRP
	var address string
	if coin == "nmc" {
		a, _ := btcutil.NewAddressPubKeyHash(make([]byte, 20), &params)
		address = a.EncodeAddress()
	} else {
		a, _ := btcutil.NewAddressWitnessPubKeyHash(make([]byte, 20), &params)
		address = a.EncodeAddress()
	}
	script, _ := p.Script(address)
	scriptBytes, _ := hex.DecodeString(script)
	tx := wire.NewMsgTx(2)
	h := chainhash.Hash{1}
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&h, 0), nil, wire.TxWitness{[]byte{1, 2, 3}}))
	tx.AddTxOut(wire.NewTxOut(1001000, scriptBytes))
	n := &fixtureNode{t: t, coin: coin, tx: *tx}
	terms := Terms{Coin: coin, Network: p.Network, Genesis: p.Genesis, PriceUSDCents: 1, USDMicrosPerCoin: 1000000, RateAsOf: 100, MaxRateAgeSeconds: 60, AmountAtoms: 1000000, Address: address, MinConfirmations: 2}
	payment := Payment{tx.TxHash().String(), 0, 1001000, 19, strings.Repeat("b", 64)}
	return n, terms, payment
}
func rewrite(raw json.RawMessage, field string, v any) json.RawMessage {
	var m map[string]json.RawMessage
	if e := json.Unmarshal(raw, &m); e != nil {
		panic(e)
	}
	m[field] = canonical(v)
	return canonical(m)
}

// Controlled RPC mutations prove each declared rejection and a zero returned
// admission, with the same independent literal quote/raw transaction accepted
// beside every mutation. These are observer contract tests, not consensus proofs.
func TestAdmissionBoundaries(t *testing.T) {
	for _, coin := range []string{"btc", "ltc", "nmc"} {
		t.Run(coin, func(t *testing.T) {
			cases := []struct {
				name, method, field string
				value               any
				reason              string
			}{
				{"wrong_product", "getnetworkinfo", "subversion", "/WrongCore:1/", "NODE_PRODUCT"},
				{"unknown_protocol", "getnetworkinfo", "protocolversion", int64(1), "NODE_PRODUCT"},
				{"main_chain", "getblockchaininfo", "chain", "main", "NODE_CHAIN"},
				{"ibd", "getblockchaininfo", "initialblockdownload", true, "NODE_CHAIN"},
				{"wrong_raw_id", "getrawtransaction", "txid", strings.Repeat("a", 64), "PAYMENT_RAW_BINDING"},
				{"wrong_raw_bytes", "getrawtransaction", "hex", "00000000000000000000", "PAYMENT_RAW"},
				{"raw_trailing", "getrawtransaction", "hex", nil, "PAYMENT_RAW"},
				{"raw_different_transaction", "getrawtransaction", "hex", nil, "PAYMENT_RAW_BINDING"},
				{"wrong_tx_block", "getrawtransaction", "blockhash", strings.Repeat("a", 64), "PAYMENT_RAW_BINDING"},
				{"missing_member", "getblock", "tx", []string{strings.Repeat("a", 64)}, "PAYMENT_MEMBERSHIP"},
				{"duplicate_member", "getblock", "tx", nil, "PAYMENT_BLOCK_BINDING"},
				{"block_confirmations", "getblock", "confirmations", int64(1), "PAYMENT_BLOCK_BINDING"},
				{"pruned_block", "getblock", "", nil, "NODE_UNAVAILABLE"},
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					n, terms, p := nodeFixture(t, coin)
					n.mutate = func(m string, _ []any, b json.RawMessage) json.RawMessage {
						if m != tc.method {
							return b
						}
						v := tc.value
						if tc.name == "raw_trailing" {
							var x map[string]any
							_ = json.Unmarshal(b, &x)
							v = x["hex"].(string) + "00"
						}
						if tc.name == "raw_different_transaction" {
							tx := n.tx.Copy()
							tx.TxOut[0].Value++
							var buf bytes.Buffer
							if err := tx.Serialize(&buf); err != nil {
								t.Fatal(err)
							}
							v = hex.EncodeToString(buf.Bytes())
						}
						if tc.name == "duplicate_member" {
							v = []string{p.TxID, p.TxID}
						}
						return rewrite(b, tc.field, v)
					}
					if tc.name == "pruned_block" {
						n.unavailable = "getblock"
					}
					a, e := Admit(context.Background(), n, testLimits, terms, p, 100, 200, 60, 1, 110)
					if e == nil || e.Error() != tc.reason || a != (Admission{}) {
						t.Fatalf("want %s got %+v %v", tc.reason, a, e)
					}
					n.mutate = nil
					n.unavailable = ""
					a, e = Admit(context.Background(), n, testLimits, terms, p, 100, 200, 60, 1, 110)
					if e != nil || a.SurplusAtoms != 1000 || a.Confirmations != 2 {
						t.Fatalf("valid %+v %v", a, e)
					}
				})
			}
			t.Run("wrong_genesis", func(t *testing.T) {
				n, terms, p := nodeFixture(t, coin)
				n.mutate = func(m string, args []any, b json.RawMessage) json.RawMessage {
					if m == "getblockhash" && args[0] == 0 {
						return canonical(strings.Repeat("a", 64))
					}
					return b
				}
				a, e := Admit(context.Background(), n, testLimits, terms, p, 100, 200, 60, 1, 110)
				if e == nil || e.Error() != "NODE_GENESIS" || a != (Admission{}) {
					t.Fatal(a, e)
				}
			})
			t.Run("raw_underpayment", func(t *testing.T) {
				n, terms, p := nodeFixture(t, coin)
				n.tx.TxOut[0].Value = terms.AmountAtoms - 1
				p.TxID = n.tx.TxHash().String()
				a, e := Admit(context.Background(), n, testLimits, terms, p, 100, 200, 60, 1, 110)
				if e == nil || e.Error() != "PAYMENT_BINDING" || a != (Admission{}) {
					t.Fatal("underpayment must refuse PAYMENT_BINDING with zero admission", a, e)
				}
			})
			t.Run("raw_wrong_script", func(t *testing.T) {
				n, terms, p := nodeFixture(t, coin)
				n.tx.TxOut[0].PkScript = []byte{0x51}
				p.TxID = n.tx.TxHash().String()
				a, e := Admit(context.Background(), n, testLimits, terms, p, 100, 200, 60, 1, 110)
				if e == nil || e.Error() != "PAYMENT_BINDING" || a != (Admission{}) {
					t.Fatal("wrong script must refuse PAYMENT_BINDING with zero admission", a, e)
				}
			})
			t.Run("expired", func(t *testing.T) {
				n, terms, p := nodeFixture(t, coin)
				a, e := Admit(context.Background(), n, testLimits, terms, p, 100, 200, 60, 1, 200)
				if e == nil || e.Error() != "HOLD_EXPIRED" || a != (Admission{}) || len(n.calls) != 0 {
					t.Fatal(a, e)
				}
			})
			t.Run("many_inputs_witness", func(t *testing.T) {
				n, terms, p := nodeFixture(t, coin)
				for i := 0; i < 100; i++ {
					h := chainhash.Hash{byte(i + 2)}
					n.tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&h, 0), nil, wire.TxWitness{[]byte{1}}))
				}
				p.TxID = n.tx.TxHash().String()
				a, e := Admit(context.Background(), n, testLimits, terms, p, 100, 200, 60, 1, 110)
				if e != nil || a.SurplusAtoms != 1000 {
					t.Fatal(a, e)
				}
			})
			t.Run("bounded", func(t *testing.T) {
				n, terms, p := nodeFixture(t, coin)
				limits := testLimits
				limits.MaxCalls = 1
				a, e := Admit(context.Background(), n, limits, terms, p, 100, 200, 60, 1, 110)
				if e == nil || e.Error() != "OBSERVATION_BOUND" || a != (Admission{}) || len(n.calls) != 1 {
					t.Fatal(a, e)
				}
			})
		})
	}
}
