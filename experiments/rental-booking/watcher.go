package booking

import (
	"context"
	"encoding/json"
	"math/big"
	"sort"
	"strings"

	"github.com/relux-works/swarma-chain-lab/experiments/sealwatch"
	singleuse "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

type Node = singleuse.Node

type Limits struct {
	MaxBlocks  int64 `json:"max_blocks"`
	MaxMempool int   `json:"max_mempool"`
	MaxCalls   int   `json:"max_calls"`
	MaxBytes   int   `json:"max_bytes"`
}

func (l Limits) valid() bool {
	return l.MaxBlocks > 0 && l.MaxBlocks <= 2016 && l.MaxMempool > 0 && l.MaxMempool <= 100000 && l.MaxCalls > 0 && l.MaxCalls <= 200000 && l.MaxBytes > 0 && l.MaxBytes <= 512<<20
}

type Tip struct {
	Hash   string `json:"hash"`
	Height int64  `json:"height"`
}
type observation struct {
	ctx          context.Context
	node         Node
	limits       Limits
	calls, bytes int
}

func (o *observation) read(method string, args ...any) (json.RawMessage, error) {
	if o.ctx.Err() != nil || o.calls >= o.limits.MaxCalls {
		return nil, refuse("OBSERVATION_BOUND")
	}
	o.calls++
	raw, e := o.node.Call(o.ctx, method, args...)
	if e != nil {
		return nil, refuse("NODE_UNAVAILABLE")
	}
	o.bytes += len(raw)
	if len(raw) > 8<<20 || o.bytes > o.limits.MaxBytes {
		return nil, refuse("OBSERVATION_BOUND")
	}
	return raw, nil
}
func (o *observation) tip() (Tip, error) {
	b, e := o.read("getblockchaininfo")
	if e != nil {
		return Tip{}, e
	}
	var chain, best string
	var height, headers int64
	var ibd bool
	// Core 28 can report headers below blocks after reconsiderblock. Header
	// progress is not an active-chain proof; bind observations to block hashes.
	if sealwatch.ProjectJSON(b, map[string]any{"chain": &chain, "bestblockhash": &best, "blocks": &height, "headers": &headers, "initialblockdownload": &ibd}, nil) != nil || chain != "regtest" || !hexSize(best, 32) || height < 0 || headers < 0 || ibd {
		return Tip{}, refuse("NODE_CHAIN")
	}
	b, e = o.read("getblockhash", 0)
	if e != nil {
		return Tip{}, e
	}
	var genesis string
	if json.Unmarshal(b, &genesis) != nil || genesis != singleuse.RegtestGenesis {
		return Tip{}, refuse("NODE_GENESIS")
	}
	return Tip{best, height}, nil
}
func ReadTip(ctx context.Context, node Node, limits Limits) (Tip, error) {
	if node == nil || !limits.valid() {
		return Tip{}, refuse("NODE_CONFIG")
	}
	o := observation{ctx: ctx, node: node, limits: limits}
	return o.tip()
}

type Payment struct {
	TxID      string `json:"txid"`
	Vout      uint32 `json:"vout"`
	ValueSat  int64  `json:"value_sat"`
	Height    int64  `json:"height"`
	BlockHash string `json:"block_hash"`
}

func (p Payment) point() string { return p.TxID + ":" + string(canonical(p.Vout)) }

type WatchTarget struct {
	Script      string
	AfterHeight int64
}
type Snapshot struct {
	Tip      Tip
	Payments map[string][]Payment
}

func amountSat(raw []byte) (int64, error) {
	s := string(raw)
	if len(s) > 32 || strings.ContainsAny(s, "eE+-") {
		return 0, refuse("PAYMENT_AMOUNT")
	}
	r, ok := new(big.Rat).SetString(s)
	if !ok || r.Sign() < 0 {
		return 0, refuse("PAYMENT_AMOUNT")
	}
	r.Mul(r, big.NewRat(100000000, 1))
	if !r.IsInt() || !r.Num().IsInt64() || r.Num().Int64() > 21000000*100000000 {
		return 0, refuse("PAYMENT_AMOUNT")
	}
	return r.Num().Int64(), nil
}

// Discover reads only output scripts of unrelated transactions. It validates
// amount/index/coinbase status only for outputs addressed to a watched booking;
// witness encoding and input-count limits of legacy seal spends do not apply.
func Discover(ctx context.Context, node Node, limits Limits, targets map[string]WatchTarget) (Snapshot, error) {
	if node == nil || !limits.valid() {
		return Snapshot{}, refuse("NODE_CONFIG")
	}
	o := observation{ctx: ctx, node: node, limits: limits}
	tip, e := o.tip()
	if e != nil {
		return Snapshot{}, e
	}
	out := Snapshot{tip, map[string][]Payment{}}
	byScript := map[string]string{}
	first := tip.Height + 1
	for id, t := range targets {
		if t.Script == "" || t.AfterHeight < 0 {
			return Snapshot{}, refuse("WATCH_TARGET")
		}
		if _, ok := byScript[t.Script]; ok {
			return Snapshot{}, refuse("WATCH_TARGET")
		}
		byScript[t.Script] = id
		if t.AfterHeight+1 < first {
			first = t.AfterHeight + 1
		}
	}
	if tip.Height-first+1 > limits.MaxBlocks {
		return Snapshot{}, refuse("OBSERVATION_BOUND")
	}
	parse := func(raw json.RawMessage, height int64, hash, expected string) error {
		var txid string
		var outputs []json.RawMessage
		if sealwatch.ProjectJSON(raw, map[string]any{"txid": &txid, "vout": &outputs}, nil) != nil || !hexSize(txid, 32) || expected != "" && txid != expected {
			return refuse("TX_PROJECTION")
		}
		for index, v := range outputs {
			var script json.RawMessage
			var scriptHex string
			if sealwatch.ProjectJSON(v, map[string]any{"scriptPubKey": &script}, nil) != nil || sealwatch.ProjectJSON(script, map[string]any{"hex": &scriptHex}, nil) != nil {
				return refuse("OUTPUT_PROJECTION")
			}
			id, match := byScript[scriptHex]
			if !match || height > 0 && height <= targets[id].AfterHeight {
				continue
			}
			var n uint32
			var value json.RawMessage
			if sealwatch.ProjectJSON(v, map[string]any{"n": &n, "value": &value}, nil) != nil || int(n) != index {
				return refuse("CANDIDATE_OUTPUT")
			}
			sat, err := amountSat(value)
			if err != nil {
				return err
			}
			var inputs []json.RawMessage
			if sealwatch.ProjectJSON(raw, map[string]any{"vin": &inputs}, nil) != nil || len(inputs) == 0 {
				return refuse("CANDIDATE_INPUT")
			}
			var coinbase json.RawMessage
			if sealwatch.ProjectJSON(inputs[0], nil, map[string]any{"coinbase": &coinbase}) != nil {
				return refuse("CANDIDATE_INPUT")
			}
			if len(coinbase) != 0 {
				continue
			} // Immature/minted outputs are not renter payments.
			out.Payments[id] = append(out.Payments[id], Payment{txid, n, sat, height, hash})
		}
		return nil
	}
	previous := ""
	if first <= tip.Height {
		b, err := o.read("getblockhash", first-1)
		if err != nil {
			return Snapshot{}, err
		}
		if json.Unmarshal(b, &previous) != nil || !hexSize(previous, 32) {
			return Snapshot{}, refuse("BLOCK_HASH")
		}
	}
	for height := first; height <= tip.Height; height++ {
		b, err := o.read("getblockhash", height)
		if err != nil {
			return Snapshot{}, err
		}
		var hash string
		if json.Unmarshal(b, &hash) != nil || !hexSize(hash, 32) {
			return Snapshot{}, refuse("BLOCK_HASH")
		}
		b, err = o.read("getblock", hash, 2)
		if err != nil {
			return Snapshot{}, err
		}
		var got, parent string
		var h, conf int64
		var txs []json.RawMessage
		if sealwatch.ProjectJSON(b, map[string]any{"hash": &got, "previousblockhash": &parent, "height": &h, "confirmations": &conf, "tx": &txs}, nil) != nil || got != hash || parent != previous || h != height || conf != tip.Height-height+1 {
			return Snapshot{}, refuse("BLOCK_BINDING")
		}
		previous = got
		for _, tx := range txs {
			if err = parse(tx, height, hash, ""); err != nil {
				return Snapshot{}, err
			}
		}
	}
	if previous != "" && previous != tip.Hash {
		return Snapshot{}, refuse("BLOCK_BINDING")
	}
	b, e := o.read("getrawmempool")
	if e != nil {
		return Snapshot{}, e
	}
	var pool []string
	if sealwatch.DecodeJSON(b, &pool) != nil || pool == nil || len(pool) > limits.MaxMempool {
		return Snapshot{}, refuse("MEMPOOL_BOUND")
	}
	sort.Strings(pool)
	for i, id := range pool {
		if !hexSize(id, 32) || i > 0 && pool[i-1] == id {
			return Snapshot{}, refuse("MEMPOOL_SCHEMA")
		}
		raw, err := o.read("getrawtransaction", id, true)
		if err != nil {
			return Snapshot{}, err
		}
		if err = parse(raw, 0, "", id); err != nil {
			return Snapshot{}, err
		}
	}
	// A changing mempool or tip invalidates the whole observation. It is not a
	// disappearance verdict, and no partially observed state may be committed.
	b, e = o.read("getrawmempool")
	if e != nil {
		return Snapshot{}, e
	}
	var pool2 []string
	if sealwatch.DecodeJSON(b, &pool2) != nil || pool2 == nil {
		return Snapshot{}, refuse("MEMPOOL_SCHEMA")
	}
	sort.Strings(pool2)
	if string(canonical(pool)) != string(canonical(pool2)) {
		return Snapshot{}, refuse("NODE_CHANGED")
	}
	end, e := o.tip()
	if e != nil {
		return Snapshot{}, e
	}
	if end != tip {
		return Snapshot{}, refuse("NODE_CHANGED")
	}
	for id, list := range out.Payments {
		sort.Slice(list, func(i, j int) bool {
			a, b := list[i], list[j]
			if a.Height != b.Height {
				if a.Height == 0 {
					return false
				}
				if b.Height == 0 {
					return true
				}
				return a.Height < b.Height
			}
			return a.point() < b.point()
		})
		out.Payments[id] = list
	}
	return out, nil
}
func CheckRenterName(ctx context.Context, node Node, limits Limits, name, key string) error {
	if !identifier(name) || !strings.HasPrefix(name, "id/") || !pubkey(key) {
		return refuse("RENTER_NAME")
	}
	o := observation{ctx: ctx, node: node, limits: limits}
	tip, e := o.tip()
	if e != nil {
		return e
	}
	b, e := o.read("name_show", name)
	if e != nil {
		return e
	}
	var got, value string
	var expired bool
	var remaining int64
	if sealwatch.ProjectJSON(b, map[string]any{"name": &got, "value": &value, "expired": &expired, "expires_in": &remaining}, nil) != nil || got != name || expired || remaining <= 0 {
		return refuse("RENTER_NAME")
	}
	var swarma json.RawMessage
	var pub string
	if sealwatch.ProjectJSON([]byte(value), map[string]any{"swarma": &swarma}, nil) != nil || sealwatch.ProjectJSON(swarma, map[string]any{"nostr_pubkey": &pub}, nil) != nil || pub != key {
		return refuse("RENTER_NAME_KEY")
	}
	end, e := o.tip()
	if e != nil {
		return e
	}
	if end != tip {
		return refuse("NODE_CHANGED")
	}
	return nil
}
