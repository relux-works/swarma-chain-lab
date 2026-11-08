package executor

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"relux.works/swarma-chain-lab/experiments/sealwatch"
	"relux.works/swarma-chain-lab/experiments/single-use"
)

type Point struct {
	TxID string `json:"txid"`
	Vout uint32 `json:"vout"`
}

func (p Point) key() string { return p.TxID + ":" + strconv.FormatUint(uint64(p.Vout), 10) }
func (p Point) valid() bool { return hexN(p.TxID, 32) }

type Wallet struct {
	Key    string  `json:"private_key"`
	Inputs []Point `json:"inputs"`
	Fee    int64   `json:"fee_sat"`
}
type PrizeA struct {
	Point   Point  `json:"outpoint"`
	Address string `json:"address"`
	Key     string `json:"private_key"`
}
type paymentPlan struct {
	Raw    []byte
	TxID   string
	Inputs []Point
	Debit  int64
}

func privateKey(s string) (*btcec.PrivateKey, error) {
	if !hexN(s, 32) {
		return nil, fail("WALLET_KEY")
	}
	raw, _ := hex.DecodeString(s)
	var v btcec.ModNScalar
	if v.SetByteSlice(raw) || v.IsZero() {
		return nil, fail("WALLET_KEY")
	}
	k, _ := btcec.PrivKeyFromBytes(raw)
	return k, nil
}
func keyAddress(key *btcec.PrivateKey) string {
	a, _ := btcutil.NewAddressPubKeyHash(btcutil.Hash160(key.PubKey().SerializeCompressed()), &chaincfg.RegressionNetParams)
	return a.EncodeAddress()
}
func addressScript(s string) ([]byte, error) {
	a, e := btcutil.DecodeAddress(s, &chaincfg.RegressionNetParams)
	if e != nil || !a.IsForNet(&chaincfg.RegressionNetParams) {
		return nil, fail("PAY_TARGET")
	}
	if _, ok := a.(*btcutil.AddressPubKeyHash); !ok || a.EncodeAddress() != s {
		return nil, fail("PAY_TARGET")
	}
	return txscript.PayToAddrScript(a)
}
func (w Wallet) validate(prize PrizeA) error {
	key, e := privateKey(w.Key)
	if e != nil {
		return e
	}
	if len(w.Inputs) == 0 || len(w.Inputs) > 64 || w.Fee < 1000 || w.Fee > 100000 {
		return fail("WALLET_CONFIG")
	}
	if keyAddress(key) == prize.Address {
		return fail("PRIZE_ISOLATION")
	}
	seen := map[string]bool{}
	for _, p := range w.Inputs {
		if !p.valid() || seen[p.key()] {
			return fail("WALLET_INPUTS")
		}
		if p == prize.Point {
			return fail("PRIZE_ISOLATION")
		}
		seen[p.key()] = true
	}
	return nil
}

// atoms accepts exact fixed-point JSON amounts without floating-point rounding.
func atoms(n json.Number) (int64, error) {
	s := n.String()
	if len(s) == 0 || len(s) > 24 {
		return 0, fail("UTXO_VALUE")
	}
	parts := strings.Split(s, ".")
	if len(parts) > 2 {
		return 0, fail("UTXO_VALUE")
	}
	whole, e := strconv.ParseInt(parts[0], 10, 64)
	if e != nil || whole < 0 || whole > 21000000 || strconv.FormatInt(whole, 10) != parts[0] {
		return 0, fail("UTXO_VALUE")
	}
	frac := ""
	if len(parts) == 2 {
		frac = parts[1]
		if len(frac) == 0 || len(frac) > 8 {
			return 0, fail("UTXO_VALUE")
		}
	}
	for _, c := range frac {
		if c < '0' || c > '9' {
			return 0, fail("UTXO_VALUE")
		}
	}
	frac += strings.Repeat("0", 8-len(frac))
	f, _ := strconv.ParseInt(frac, 10, 64)
	v := whole*100000000 + f
	if v <= 0 || v > MaxMoney {
		return 0, fail("UTXO_VALUE")
	}
	return v, nil
}
func readCoin(ctx context.Context, node singleuse.Node, p Point) (int64, string, error) {
	raw, e := node.Call(ctx, "gettxout", p.TxID, p.Vout, true)
	if e != nil {
		return 0, "", fail("PAY_NODE_UNAVAILABLE")
	}
	if string(bytes.TrimSpace(raw)) == "null" {
		return 0, "", fail("BUDGET_INPUT_UNAVAILABLE")
	}
	var value json.Number
	var script json.RawMessage
	var confirmations int64
	var coinbase bool
	if sealwatch.ProjectJSON(raw, map[string]any{"value": &value, "scriptPubKey": &script, "confirmations": &confirmations, "coinbase": &coinbase}, nil) != nil {
		return 0, "", fail("UTXO_SCHEMA")
	}
	var scriptHex string
	if sealwatch.ProjectJSON(script, map[string]any{"hex": &scriptHex}, nil) != nil || confirmations < 1 || (coinbase && confirmations <= 100) {
		return 0, "", fail("UTXO_CONFIRMATION")
	}
	v, e := atoms(value)
	return v, scriptHex, e
}

// buildPayment has no general-wallet fallback. Only configured, unreserved,
// confirmed ordinary P2PKH inputs can be signed, always excluding prize A.
func buildPayment(ctx context.Context, node singleuse.Node, w Wallet, prize PrizeA, target string, amount int64, used map[string]bool) (paymentPlan, error) {
	var plan paymentPlan
	if e := w.validate(prize); e != nil {
		return plan, e
	}
	outScript, e := addressScript(target)
	if e != nil {
		return plan, e
	}
	key, _ := privateKey(w.Key)
	script, _ := addressScript(keyAddress(key))
	if amount < 546 || amount > MaxMoney-w.Fee {
		return plan, fail("PAY_AMOUNT")
	}
	need := amount + w.Fee
	total := int64(0)
	tx := wire.NewMsgTx(2)
	points := []Point{}
	for _, p := range w.Inputs {
		if used[p.key()] {
			continue
		}
		if p == prize.Point {
			return plan, fail("PRIZE_ISOLATION")
		}
		value, got, e := readCoin(ctx, node, p)
		if e != nil {
			if e.Error() == "BUDGET_INPUT_UNAVAILABLE" {
				continue
			}
			return plan, e
		}
		if got != hex.EncodeToString(script) {
			return plan, fail("BUDGET_SCRIPT")
		}
		if total > MaxMoney-value {
			return plan, fail("UTXO_VALUE")
		}
		h, _ := chainhash.NewHashFromStr(p.TxID)
		tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(h, p.Vout), nil, nil))
		total += value
		points = append(points, p)
		if total >= need && (total == need || total-need >= 546) {
			break
		}
		if len(points) >= 16 {
			return plan, fail("BUDGET_INPUT_LIMIT")
		}
	}
	if total < need {
		return plan, fail("BUDGET_EXHAUSTED")
	}
	if total > need && total-need < 546 {
		return plan, fail("BUDGET_CHANGE_DUST")
	}
	tx.AddTxOut(wire.NewTxOut(amount, outScript))
	if total > need {
		tx.AddTxOut(wire.NewTxOut(total-need, script))
	}
	for i, p := range points {
		if p == prize.Point {
			return plan, fail("PRIZE_ISOLATION")
		}
		sig, e := txscript.SignatureScript(tx, i, script, txscript.SigHashAll, key, true)
		if e != nil {
			return plan, fail("PAY_SIGN")
		}
		tx.TxIn[i].SignatureScript = sig
	}
	var buf bytes.Buffer
	if tx.Serialize(&buf) != nil {
		return plan, fail("PAY_SERIALIZE")
	}
	return paymentPlan{buf.Bytes(), tx.TxHash().String(), points, need}, nil
}

// ObservePrize reports a pinned outpoint's current unspent/unavailable state.
// Unavailable is not itself proof of theft: a caller must inspect a spend tx or
// chain reorg before reporting a confirmed prize spend.
func ObservePrize(ctx context.Context, node singleuse.Node, prize PrizeA) (string, error) {
	if !prize.Point.valid() {
		return "", fail("PRIZE_CONFIG")
	}
	value, script, e := readCoin(ctx, node, prize.Point)
	if e != nil {
		if e.Error() == "BUDGET_INPUT_UNAVAILABLE" {
			return "unavailable-investigate-spend", nil
		}
		return "", e
	}
	expected, e := addressScript(prize.Address)
	if e != nil || script != hex.EncodeToString(expected) || value <= 0 {
		return "", fail("PRIZE_BINDING")
	}
	return "unspent", nil
}
