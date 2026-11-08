package executor

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"github.com/btcsuite/btcd/wire"
	"relux.works/swarma-chain-lab/experiments/sealwatch"
	"relux.works/swarma-chain-lab/experiments/single-use"
	"slices"
)

type PrizeObservation struct {
	Status    string `json:"status"`
	SpendTxID string `json:"spend_txid"`
	Block     string `json:"block"`
	Tip       string `json:"tip"`
}

// WatchPrize scans at most 256 active blocks since the pinned confirmed prize
// funding and a bounded stable mempool. A spend verdict names a raw transaction
// whose decoded input spends the exact point. Read/bound failures are unknown,
// never a theft verdict. This watcher reports; it cannot prevent a spend.
func WatchPrize(ctx context.Context, node singleuse.Node, p PrizeA) (PrizeObservation, error) {
	var result PrizeObservation
	if node == nil || !p.Point.valid() {
		return result, fail("PRIZE_CONFIG")
	}
	o := singleuse.NewReadObservation(ctx, node)
	defer o.Close()
	if e := o.Start("regtest", singleuse.RegtestGenesis); e != nil {
		return result, fail("PRIZE_NODE")
	}
	result.Tip = o.Tip().Best
	var funding json.RawMessage
	if e := o.Call("getrawtransaction", &funding, p.Point.TxID, true); e != nil {
		return result, fail("PRIZE_NODE")
	}
	var fundingHex, block string
	if sealwatch.ProjectJSON(funding, map[string]any{"hex": &fundingHex, "blockhash": &block}, nil) != nil {
		return result, fail("PRIZE_FUNDING")
	}
	decode := func(rawHex string, id string) (*wire.MsgTx, error) {
		raw, e := hex.DecodeString(rawHex)
		if e != nil || len(raw) > 1<<20 {
			return nil, fail("PRIZE_TX")
		}
		r := bytes.NewReader(raw)
		var tx wire.MsgTx
		if tx.Deserialize(r) != nil || r.Len() != 0 || tx.TxHash().String() != id {
			return nil, fail("PRIZE_TX")
		}
		return &tx, nil
	}
	origin, e := decode(fundingHex, p.Point.TxID)
	if e != nil {
		return result, e
	}
	script, e := addressScript(p.Address)
	if e != nil || int(p.Point.Vout) >= len(origin.TxOut) || !bytes.Equal(origin.TxOut[p.Point.Vout].PkScript, script) {
		return result, fail("PRIZE_BINDING")
	}
	h, e := o.Active(block)
	if e != nil || h.Height < 1 || o.Tip().Blocks-h.Height+1 > 256 {
		return result, fail("PRIZE_SCAN_BOUND")
	}
	inspect := func(raw json.RawMessage, expected, block string) error {
		var id string
		var inputs []json.RawMessage
		if sealwatch.ProjectJSON(raw, map[string]any{"txid": &id, "vin": &inputs}, nil) != nil || !hexN(id, 32) || (expected != "" && expected != id) {
			return fail("PRIZE_TX")
		}
		candidate := false
		for _, input := range inputs {
			var txid string
			var vout uint32
			if sealwatch.ProjectJSON(input, nil, map[string]any{"txid": &txid, "vout": &vout}) != nil {
				return fail("PRIZE_TX")
			}
			if txid == p.Point.TxID && vout == p.Point.Vout {
				candidate = true
			}
		}
		if !candidate {
			return nil
		}
		var rawHex string
		if e := o.Call("getrawtransaction", &raw, id, true); e != nil {
			return fail("PRIZE_NODE")
		}
		if sealwatch.ProjectJSON(raw, map[string]any{"hex": &rawHex}, nil) != nil {
			return fail("PRIZE_TX")
		}
		tx, e := decode(rawHex, id)
		if e != nil {
			return e
		}
		found := false
		for _, in := range tx.TxIn {
			if in.PreviousOutPoint.Hash.String() == p.Point.TxID && in.PreviousOutPoint.Index == p.Point.Vout {
				found = true
			}
		}
		if !found || result.SpendTxID != "" {
			return fail("PRIZE_INCONSISTENT")
		}
		result.Status = "spent"
		result.SpendTxID = id
		result.Block = block
		return nil
	}
	var previous string
	if o.Call("getblockhash", &previous, h.Height-1) != nil {
		return result, fail("PRIZE_NODE")
	}
	for height := h.Height; height <= o.Tip().Blocks; height++ {
		var hash string
		if o.Call("getblockhash", &hash, height) != nil {
			return result, fail("PRIZE_NODE")
		}
		var raw json.RawMessage
		if o.Call("getblock", &raw, hash, 2) != nil {
			return result, fail("PRIZE_NODE")
		}
		var got, parent string
		var gotHeight, conf int64
		var txs []json.RawMessage
		if sealwatch.ProjectJSON(raw, map[string]any{"hash": &got, "previousblockhash": &parent, "height": &gotHeight, "confirmations": &conf, "tx": &txs}, nil) != nil || got != hash || parent != previous || gotHeight != height || conf != o.Tip().Blocks-height+1 {
			return result, fail("PRIZE_BLOCK")
		}
		previous = hash
		for _, tx := range txs {
			if e := inspect(tx, "", hash); e != nil {
				return result, e
			}
		}
	}
	if previous != o.Tip().Best {
		return result, fail("PRIZE_BLOCK")
	}
	var pool []string
	if o.Call("getrawmempool", &pool) != nil || pool == nil || len(pool) > 512 {
		return result, fail("PRIZE_MEMPOOL_BOUND")
	}
	slices.Sort(pool)
	for i, id := range pool {
		if !hexN(id, 32) || (i > 0 && pool[i-1] == id) {
			return result, fail("PRIZE_MEMPOOL")
		}
		var raw json.RawMessage
		if o.Call("getrawtransaction", &raw, id, true) != nil {
			return result, fail("PRIZE_NODE")
		}
		if e := inspect(raw, id, ""); e != nil {
			return result, e
		}
	}
	var again []string
	if o.Call("getrawmempool", &again) != nil || again == nil {
		return result, fail("PRIZE_NODE")
	}
	slices.Sort(again)
	if !slices.Equal(pool, again) || o.Stable() != nil {
		return result, fail("PRIZE_CHANGED")
	}
	if result.SpendTxID == "" {
		state, e := ObservePrize(ctx, node, p)
		if e != nil || state != "unspent" {
			return result, fail("PRIZE_UNKNOWN")
		}
		result.Status = "unspent"
	}
	return result, nil
}
