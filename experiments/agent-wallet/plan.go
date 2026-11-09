package wallet

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	rental "github.com/relux-works/swarma-chain-lab/experiments/rental"
	sw "github.com/relux-works/swarma-chain-lab/experiments/sealwatch"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

type plan struct {
	Raw        string
	TxID       string
	Fee        int64
	Inputs     []su.Point
	NameScript string
	Salt       string
	NameVout   uint32
}
type coin struct {
	Value  int64
	Script []byte
}

func readCoin(ctx context.Context, node su.Node, p su.Point) (coin, error) {
	var c coin
	raw, e := node.Call(ctx, "gettxout", p.TxID, p.Vout, true)
	if e != nil {
		return c, fail("UTXO_UNAVAILABLE")
	}
	var confirmations int64
	var value json.Number
	var coinbase bool
	var script struct {
		Hex string `json:"hex"`
	}
	if sw.ProjectJSON(raw, map[string]any{"confirmations": &confirmations, "value": &value, "coinbase": &coinbase, "scriptPubKey": &script}, nil) != nil {
		return c, fail("UTXO_UNAVAILABLE")
	}
	if confirmations < 1 || (coinbase && confirmations < 100) {
		return c, fail("UTXO_IMMATURE")
	}
	c.Value, e = su.ParseCoins(value.String())
	if e != nil || c.Value <= 0 {
		return c, fail("UTXO_AMOUNT")
	}
	c.Script, e = hex.DecodeString(script.Hex)
	if e != nil || len(c.Script) > 1024 {
		return c, fail("UTXO_SCRIPT")
	}
	return c, nil
}
func nameScript(action, name, value, salt string, payment []byte) ([]byte, error) {
	r, e := hex.DecodeString(salt)
	if e != nil || len(r) != 20 {
		return nil, fail("NAME_SALT")
	}
	b := txscript.NewScriptBuilder()
	switch action {
	case "name_new":
		h := btcutil.Hash160(append(append([]byte{}, r...), []byte(name)...))
		b.AddOp(txscript.OP_1).AddData(h).AddOp(txscript.OP_2DROP)
	case "name_firstupdate":
		b.AddOp(txscript.OP_2).AddData([]byte(name)).AddData(r).AddData([]byte(value)).AddOp(txscript.OP_2DROP).AddOp(txscript.OP_2DROP)
	default:
		return nil, fail("NAME_OPERATION")
	}
	prefix, e := b.Script()
	if e != nil {
		return nil, fail("NAME_SCRIPT")
	}
	return append(prefix, payment...), nil
}
func rawTx(tx *wire.MsgTx) string {
	var b bytes.Buffer
	if tx.Serialize(&b) != nil {
		panic("internal transaction")
	}
	return hex.EncodeToString(b.Bytes())
}
func decodeWire(s string) (*wire.MsgTx, error) {
	b, e := hex.DecodeString(s)
	if e != nil || len(b) > 100000 {
		return nil, fail("TX_ENCODING")
	}
	tx := wire.NewMsgTx(2)
	r := bytes.NewReader(b)
	if tx.Deserialize(r) != nil || r.Len() != 0 {
		return nil, fail("TX_ENCODING")
	}
	return tx, nil
}
func sameUnsigned(a, b *wire.MsgTx) bool {
	if a.Version != b.Version || a.LockTime != b.LockTime || len(a.TxIn) != len(b.TxIn) || len(a.TxOut) != len(b.TxOut) {
		return false
	}
	for i, x := range a.TxIn {
		if x.PreviousOutPoint != b.TxIn[i].PreviousOutPoint || x.Sequence != b.TxIn[i].Sequence {
			return false
		}
	}
	for i, x := range a.TxOut {
		if x.Value != b.TxOut[i].Value || !bytes.Equal(x.PkScript, b.TxOut[i].PkScript) {
			return false
		}
	}
	return true
}

// buildPlan never broadcasts or locks wallet inputs. The final signed bytes
// are checked against their own-node prevouts and the exact approved outputs.
func (w *Wallet) buildPlan(ctx context.Context, g Grant, t Terms, r Request, prior *Record) (plan, error) {
	var p plan
	recipient, e := addressScriptForNetwork(r.Address, w.config.Network, w.config.Genesis)
	if e != nil {
		return p, e
	}
	change, e := addressScriptForNetwork(w.config.ChangeAddress, w.config.Network, w.config.Genesis)
	if e != nil {
		return p, e
	}
	tx := wire.NewMsgTx(2)
	target := recipient
	value := r.Amount
	nameOp := ""
	if r.Action == "names.register" {
		tx.Version = 0x7100
		value = NameDeposit
		if prior == nil {
			salt := make([]byte, 20)
			if _, e = rand.Read(salt); e != nil {
				return p, fail("ENTROPY")
			}
			p.Salt = hex.EncodeToString(salt)
			nameOp = "name_new"
			target = change
		} else {
			p.Salt = prior.Salt
			nameOp = "name_firstupdate"
			h, e := chainhash.NewHashFromStr(prior.NewTxID)
			if e != nil {
				return p, fail("JOURNAL_CORRUPT")
			}
			tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(h, prior.NameVout), nil, nil))
		}
		target, e = nameScript(nameOp, r.Name, r.Value, p.Salt, target)
		if e != nil {
			return p, e
		}
		p.NameScript = hex.EncodeToString(target)
	}
	tx.AddTxOut(wire.NewTxOut(value, target))
	// The name operation is built locally so the fee/budget gate precedes any
	// wallet name RPC that would otherwise broadcast immediately.
	var funded struct {
		Hex    string      `json:"hex"`
		Fee    json.Number `json:"fee"`
		Change int         `json:"changepos"`
	}
	opts := map[string]any{"changeAddress": w.config.ChangeAddress, "changePosition": 1, "fee_rate": w.config.FeeRate, "minconf": 1, "include_unsafe": false, "includeWatching": false, "lockUnspents": false, "replaceable": false}
	if e = call(ctx, w.wallet, "fundrawtransaction", &funded, rawTx(tx), opts); e != nil {
		return p, e
	}
	fundedTx, e := decodeWire(funded.Hex)
	if e != nil {
		return p, e
	}
	if fundedTx.Version != tx.Version || fundedTx.LockTime != 0 || len(fundedTx.TxIn) < 1 || len(fundedTx.TxIn) > 16 || len(fundedTx.TxOut) < 1 || len(fundedTx.TxOut) > 2 {
		return p, fail("PLAN_SHAPE")
	}
	if fundedTx.TxOut[0].Value != value || !bytes.Equal(fundedTx.TxOut[0].PkScript, target) {
		return p, fail("PLAN_TARGET")
	}
	if len(fundedTx.TxOut) == 2 {
		if funded.Change != 1 || !bytes.Equal(fundedTx.TxOut[1].PkScript, change) || fundedTx.TxOut[1].Value < 546 {
			return p, fail("PLAN_CHANGE")
		}
	} else if funded.Change != -1 {
		return p, fail("PLAN_CHANGE")
	}
	expectedName := su.Point{}
	if prior != nil {
		expectedName = su.Point{TxID: prior.NewTxID, Vout: prior.NameVout}
	}
	fetcher := txscript.NewMultiPrevOutFetcher(nil)
	coins := map[su.Point]coin{}
	inputTotal := int64(0)
	hasName := false
	for _, in := range fundedTx.TxIn {
		point := su.Point{TxID: in.PreviousOutPoint.Hash.String(), Vout: in.PreviousOutPoint.Index}
		if _, ok := coins[point]; ok {
			return p, fail("PLAN_DUPLICATE_INPUT")
		}
		if point == g.Seal || w.inputReserved(point) {
			return p, fail("PLAN_RESERVED_INPUT")
		}
		c, e := readCoin(ctx, w.node, point)
		if e != nil {
			return p, e
		}
		issuerScript, err := rental.GrantSealScript(g.Issuer)
		if err != nil || hex.EncodeToString(c.Script) == issuerScript || hex.EncodeToString(c.Script) == w.config.Policy.SealScript {
			return p, fail("PLAN_SEAL_SCRIPT_INPUT")
		}
		if prior != nil && point == expectedName {
			if hex.EncodeToString(c.Script) != prior.NewScript || c.Value != NameDeposit {
				return p, fail("NAME_PREVOUT")
			}
			hasName = true
		} else if !txscript.IsPayToPubKeyHash(c.Script) {
			return p, fail("PLAN_INPUT_PROFILE")
		}
		if inputTotal > MaxMoney-c.Value {
			return p, fail("PLAN_AMOUNT")
		}
		inputTotal += c.Value
		coins[point] = c
		fetcher.AddPrevOut(in.PreviousOutPoint, wire.NewTxOut(c.Value, c.Script))
		p.Inputs = append(p.Inputs, point)
	}
	if prior != nil && !hasName {
		return p, fail("NAME_PREVOUT")
	}
	outputTotal := int64(0)
	for _, o := range fundedTx.TxOut {
		if o.Value < 0 || o.Value > MaxMoney-outputTotal {
			return p, fail("PLAN_AMOUNT")
		}
		outputTotal += o.Value
	}
	p.Fee = inputTotal - outputTotal
	quoted, e := su.ParseCoins(funded.Fee.String())
	if e != nil || p.Fee < 1 || p.Fee != quoted || p.Fee > r.FeeLimit {
		return p, fail("FEE_LIMIT")
	}
	if e = w.authority.Check(ctx, w.grantRaw, g.Grantee, w.clock()); e != nil {
		return p, e
	}
	var signed struct {
		Hex      string          `json:"hex"`
		Complete bool            `json:"complete"`
		Errors   json.RawMessage `json:"errors"`
	}
	if e = call(ctx, w.wallet, "signrawtransactionwithwallet", &signed, funded.Hex, []any{}, "ALL"); e != nil {
		return p, e
	}
	if !signed.Complete || len(signed.Errors) > 0 {
		return p, fail("SIGNING_INCOMPLETE")
	}
	signedTx, e := decodeWire(signed.Hex)
	if e != nil || !sameUnsigned(fundedTx, signedTx) {
		return p, fail("SIGNED_PLAN_CHANGED")
	}
	hashes := txscript.NewTxSigHashes(signedTx, fetcher)
	for i, in := range signedTx.TxIn {
		point := su.Point{TxID: in.PreviousOutPoint.Hash.String(), Vout: in.PreviousOutPoint.Index}
		c := coins[point]
		// All supported wallet inputs end in P2PKH; require SIGHASH_ALL explicitly.
		sig := in.SignatureScript
		if len(in.Witness) != 0 || len(sig) < 2 || int(sig[0]) >= len(sig) || sig[0] < 9 || sig[sig[0]] != 1 {
			return p, fail("SIGNED_INPUT_PROFILE")
		}
		vm, e := txscript.NewEngine(c.Script, signedTx, i, txscript.StandardVerifyFlags, nil, hashes, c.Value, fetcher)
		if e != nil || vm.Execute() != nil {
			return p, fail("SIGNED_INPUT_INVALID")
		}
	}
	p.Raw = signed.Hex
	p.TxID = signedTx.TxHash().String()
	p.NameVout = 0
	return p, nil
}
func containsPoint(ps []su.Point, p su.Point) bool {
	for _, x := range ps {
		if x == p {
			return true
		}
	}
	return false
}
