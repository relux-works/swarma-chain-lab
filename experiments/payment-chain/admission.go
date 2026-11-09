package paymentchain

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/btcsuite/btcd/wire"
	"github.com/relux-works/swarma-chain-lab/experiments/sealwatch"
)

// Admission is an own-node observation, never a spending or issuance authority.
type Admission struct {
	Tip           Tip     `json:"tip"`
	Payment       Payment `json:"payment"`
	Confirmations int64   `json:"confirmations"`
	SurplusAtoms  int64   `json:"surplus_atoms"`
}

// Admit re-reads a claimed payment through the issuer's separately configured
// read-only node. The height is only a lookup hint: active hash, block membership,
// raw transaction, output and confirmations are independently bound twice.
// Explicit block lookup works without txindex; missing pruned data refuses.
// Callers authenticate terms and hold bounds before invoking this predicate.
func Admit(ctx context.Context, node Node, limits Limits, terms Terms, claimed Payment, holdCreated, holdExpires, maxRateAge, minConfirmations, now int64) (Admission, error) {
	started := time.Now()
	deny := func(code string) (Admission, error) { return Admission{}, refuse(code) }
	if e := terms.ValidateAt(holdCreated, maxRateAge, minConfirmations); e != nil {
		return Admission{}, e
	}
	if holdCreated <= 0 || holdExpires <= holdCreated || now < holdCreated || now >= holdExpires {
		return deny("HOLD_EXPIRED")
	}
	p, _ := ForCoin(terms.Coin)
	if node == nil || !limits.valid() {
		return deny("NODE_CONFIG")
	}
	if !hexSize(claimed.TxID, 32) || claimed.Height <= 0 || !hexSize(claimed.BlockHash, 32) {
		return deny("PAYMENT_LOCATOR")
	}
	o := observation{ctx: ctx, node: node, profile: p, limits: limits}
	tip, e := o.tip()
	if e != nil {
		return Admission{}, e
	}
	if claimed.Height > tip.Height || tip.Height-claimed.Height+1 < terms.MinConfirmations {
		return deny("PAYMENT_CONFIRMATIONS")
	}
	wantScript, _ := p.Script(terms.Address)
	var admitted Payment
	for pass := 0; pass < 2; pass++ {
		b, e := o.read("getblockhash", claimed.Height)
		if e != nil {
			return Admission{}, e
		}
		var block string
		if json.Unmarshal(b, &block) != nil || block != claimed.BlockHash {
			return deny("PAYMENT_ACTIVE_BLOCK")
		}
		b, e = o.read("getblock", block, 1)
		if e != nil {
			return Admission{}, e
		}
		var got string
		var height, confirmations int64
		var txids []string
		if sealwatch.ProjectJSON(b, map[string]any{"hash": &got, "height": &height, "confirmations": &confirmations, "tx": &txids}, nil) != nil || got != block || height != claimed.Height || confirmations != tip.Height-height+1 || len(txids) == 0 {
			return deny("PAYMENT_BLOCK_BINDING")
		}
		count := 0
		seen := map[string]bool{}
		for _, id := range txids {
			if !hexSize(id, 32) || seen[id] {
				return deny("PAYMENT_BLOCK_BINDING")
			}
			seen[id] = true
			if id == claimed.TxID {
				count++
			}
		}
		if count != 1 {
			return deny("PAYMENT_MEMBERSHIP")
		}
		b, e = o.read("getrawtransaction", claimed.TxID, true, block)
		if e != nil {
			return Admission{}, e
		}
		var id, rawHex, txBlock string
		var conf int64
		if sealwatch.ProjectJSON(b, map[string]any{"txid": &id, "hex": &rawHex, "blockhash": &txBlock, "confirmations": &conf}, nil) != nil || id != claimed.TxID || txBlock != block || conf != confirmations {
			return deny("PAYMENT_RAW_BINDING")
		}
		raw, err := hex.DecodeString(rawHex)
		if err != nil || len(raw) < 10 || len(raw) > 4<<20 || hex.EncodeToString(raw) != rawHex {
			return deny("PAYMENT_RAW")
		}
		var tx wire.MsgTx
		r := bytes.NewReader(raw)
		if tx.Deserialize(r) != nil || r.Len() != 0 || len(tx.TxIn) == 0 || len(tx.TxOut) == 0 {
			return deny("PAYMENT_RAW")
		}
		var encoded bytes.Buffer
		if tx.Serialize(&encoded) != nil || !bytes.Equal(raw, encoded.Bytes()) || tx.TxHash().String() != id {
			return deny("PAYMENT_RAW_BINDING")
		}
		if len(tx.TxIn) == 1 && tx.TxIn[0].PreviousOutPoint.Index == 0xffffffff && tx.TxIn[0].PreviousOutPoint.Hash.String() == "0000000000000000000000000000000000000000000000000000000000000000" {
			return deny("PAYMENT_COINBASE")
		}
		var total int64
		for _, output := range tx.TxOut {
			if output.Value < 0 || output.Value > p.MaxAtoms-total {
				return deny("PAYMENT_AMOUNT")
			}
			total += output.Value
		}
		if uint64(claimed.Vout) >= uint64(len(tx.TxOut)) {
			return deny("PAYMENT_OUTPUT")
		}
		output := tx.TxOut[claimed.Vout]
		if output.Value < terms.AmountAtoms || hex.EncodeToString(output.PkScript) != wantScript {
			return deny("PAYMENT_BINDING")
		}
		current := Payment{claimed.TxID, claimed.Vout, output.Value, claimed.Height, block}
		if pass > 0 && current != admitted {
			return deny("NODE_CHANGED")
		}
		admitted = current
	}
	end, e := o.tip()
	if e != nil {
		return Admission{}, e
	}
	if end != tip {
		return deny("NODE_CHANGED")
	}
	if now+int64(time.Since(started)/time.Second) >= holdExpires {
		return deny("HOLD_EXPIRED")
	}
	return Admission{tip, admitted, tip.Height - admitted.Height + 1, admitted.ValueAtoms - terms.AmountAtoms}, nil
}
