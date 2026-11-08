package singleuse

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"relux.works/swarma-chain-lab/experiments/sealwatch"
)

const RegtestGenesis = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
const MainGenesis = "000000000062b72c5e2ceb45fbc8587e807c155b0da735e6483dfba2f0a9c770"

// NetworkPinned has no implicit/default network or genesis.
func NetworkPinned(network, genesis string) bool {
	return (network == "regtest" && genesis == RegtestGenesis) || (network == "main" && genesis == MainGenesis)
}

var errNodeProjection = errors.New("NODE_PROJECTION")

var readMethods = map[string]bool{"getblockchaininfo": true, "getblockhash": true, "getblockheader": true, "getrawtransaction": true, "gettxout": true, "name_show": true, "getrawmempool": true, "getblock": true}

type Node interface {
	Call(context.Context, string, ...any) (json.RawMessage, error)
}
type Route struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
}
type RPC struct {
	route  Route
	client *http.Client
}

func NewRPC(r Route) (*RPC, error) {
	ip := net.ParseIP(r.Host)
	if ip == nil || !ip.IsLoopback() || r.Port < 1 || r.Port > 65535 || r.Username != "w3-observer" || len(r.Password) < 16 || len(r.Password) > 256 {
		return nil, fail("READ_ONLY_ROUTE")
	}
	return &RPC{r, &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil, MaxIdleConns: 2}, CheckRedirect: func(*http.Request, []*http.Request) error { return fail("REDIRECT") }}}, nil
}
func (n *RPC) Call(ctx context.Context, method string, args ...any) (json.RawMessage, error) {
	if !readMethods[method] {
		return nil, fail("READ_ONLY_METHOD")
	}
	if args == nil {
		args = []any{}
	}
	b, e := json.Marshal(map[string]any{"jsonrpc": "1.0", "id": 1, "method": method, "params": args})
	if e != nil {
		return nil, fail("RPC_INPUT")
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+net.JoinHostPort(n.route.Host, strconv.Itoa(n.route.Port))+"/", bytes.NewReader(b))
	if e != nil {
		return nil, fail("RPC_REQUEST")
	}
	req.SetBasicAuth(n.route.Username, n.route.Password)
	req.Header.Set("Content-Type", "application/json")
	res, e := n.client.Do(req)
	if e != nil {
		return nil, fail("RPC_UNAVAILABLE")
	}
	defer res.Body.Close()
	b, e = io.ReadAll(io.LimitReader(res.Body, 8<<20+1))
	if e != nil || len(b) > 8<<20 || res.StatusCode != 200 {
		return nil, fail("RPC_RESPONSE")
	}
	var id int
	var result, rpcError json.RawMessage
	if e = sealwatch.ProjectJSON(b, map[string]any{"id": &id}, map[string]any{"result": &result, "error": &rpcError}); e != nil || id != 1 || len(result) == 0 || len(rpcError) == 0 {
		return nil, errNodeProjection
	}
	if string(bytes.TrimSpace(rpcError)) != "null" {
		return nil, fail("RPC_REMOTE_ERROR")
	}
	return result, nil
}

type chainInfo struct {
	Chain           string
	Blocks, Headers int64
	Best            string
	IBD             bool
}

func (v *chainInfo) UnmarshalJSON(b []byte) error {
	return sealwatch.ProjectJSON(b, map[string]any{"chain": &v.Chain, "blocks": &v.Blocks, "headers": &v.Headers, "bestblockhash": &v.Best, "initialblockdownload": &v.IBD}, nil)
}

type header struct {
	Hash                  string
	Height, Confirmations int64
}

func (v *header) UnmarshalJSON(b []byte) error {
	return sealwatch.ProjectJSON(b, map[string]any{"hash": &v.Hash, "height": &v.Height, "confirmations": &v.Confirmations}, nil)
}

type rpcBlock struct {
	Hash   string
	Height int64
	Tx     []string
}

func (v *rpcBlock) UnmarshalJSON(b []byte) error {
	return sealwatch.ProjectJSON(b, map[string]any{"hash": &v.Hash, "height": &v.Height, "tx": &v.Tx}, nil)
}
func (v *Point) UnmarshalJSON(b []byte) error {
	return sealwatch.ProjectJSON(b, map[string]any{"txid": &v.TxID, "vout": &v.Vout}, nil)
}

type rpcInput struct {
	TxID     string
	Vout     uint32
	Coinbase string
	Script   struct{ Hex string }
}

func (v *rpcInput) UnmarshalJSON(b []byte) error {
	var script json.RawMessage
	if e := sealwatch.ProjectJSON(b, nil, map[string]any{"txid": &v.TxID, "vout": &v.Vout, "coinbase": &v.Coinbase, "scriptSig": &script}); e != nil {
		return e
	}
	if v.Coinbase == "" {
		var p Point
		if e := sealwatch.ProjectJSON(b, map[string]any{"txid": &p.TxID, "vout": &p.Vout}, nil); e != nil {
			return e
		}
		if !digestHex(p.TxID) || len(script) == 0 {
			return fail("TX_INPUT")
		}
		return sealwatch.ProjectJSON(script, map[string]any{"hex": &v.Script.Hex}, nil)
	}
	return nil
}

type nameOp struct {
	Op, Name, Value, NameEncoding, ValueEncoding string
	NameError, ValueError                        json.RawMessage
}

func (v *nameOp) UnmarshalJSON(b []byte) error {
	return sealwatch.ProjectJSON(b, nil, map[string]any{"op": &v.Op, "name": &v.Name, "value": &v.Value, "name_encoding": &v.NameEncoding, "value_encoding": &v.ValueEncoding, "name_error": &v.NameError, "value_error": &v.ValueError})
}

type rpcScript struct {
	Hex, Address string
	Name         *nameOp
}

func (v *rpcScript) UnmarshalJSON(b []byte) error {
	return sealwatch.ProjectJSON(b, map[string]any{"hex": &v.Hex}, map[string]any{"address": &v.Address, "nameOp": &v.Name})
}

type amount int64

func (v *amount) UnmarshalJSON(b []byte) error {
	if len(b) > 32 {
		return fail("AMOUNT")
	}
	n, e := coins(string(b))
	*v = amount(n)
	return e
}

type rpcOutput struct {
	N      uint32
	Value  amount
	Script rpcScript
}

func (v *rpcOutput) UnmarshalJSON(b []byte) error {
	return sealwatch.ProjectJSON(b, map[string]any{"n": &v.N, "value": &v.Value, "scriptPubKey": &v.Script}, nil)
}

type rpcTx struct {
	TxID, Hex, Block string
	Confirmations    int64
	Vin              []rpcInput
	Vout             []rpcOutput
}

func (v *rpcTx) UnmarshalJSON(b []byte) error {
	return sealwatch.ProjectJSON(b, map[string]any{"txid": &v.TxID, "hex": &v.Hex, "vin": &v.Vin, "vout": &v.Vout}, map[string]any{"blockhash": &v.Block, "confirmations": &v.Confirmations})
}

type nameShow struct {
	Name, Value, TxID, NameEncoding, ValueEncoding string
	Vout                                           uint32
	Height, ExpiresIn                              int64
	Expired                                        bool
	NameError, ValueError                          json.RawMessage
}

func (v *nameShow) UnmarshalJSON(b []byte) error {
	return sealwatch.ProjectJSON(b, map[string]any{"name": &v.Name, "value": &v.Value, "txid": &v.TxID, "vout": &v.Vout, "height": &v.Height, "expired": &v.Expired, "expires_in": &v.ExpiresIn, "name_encoding": &v.NameEncoding, "value_encoding": &v.ValueEncoding}, map[string]any{"name_error": &v.NameError, "value_error": &v.ValueError})
}

type observation struct {
	ctx          context.Context
	node         Node
	calls, bytes int
	tip          chainInfo
	spendBlock   string
}

func (o *observation) call(method string, out any, args ...any) error {
	if !readMethods[method] || o.calls >= 1024 || o.ctx.Err() != nil {
		return fail("OBSERVATION_BOUND")
	}
	o.calls++
	raw, e := o.node.Call(o.ctx, method, args...)
	if e != nil {
		if errors.Is(e, errNodeProjection) {
			return errNodeProjection
		}
		return fail("NODE_UNAVAILABLE")
	}
	o.bytes += len(raw)
	if len(raw) > 8<<20 || o.bytes > 32<<20 {
		return fail("OBSERVATION_BYTES")
	}
	if e = sealwatch.DecodeJSON(raw, out); e != nil {
		return fail("NODE_PROJECTION")
	}
	return nil
}
func (o *observation) active(block string) (header, error) {
	var h header
	if !digestHex(block) {
		return h, fail("BLOCK_HASH")
	}
	if e := o.call("getblockheader", &h, block); e != nil {
		return h, e
	}
	if h.Hash != block || h.Height < 0 || h.Height > o.tip.Blocks || h.Confirmations != o.tip.Blocks-h.Height+1 {
		return h, fail("ACTIVE_HEADER")
	}
	var canonical string
	if e := o.call("getblockhash", &canonical, h.Height); e != nil || canonical != block {
		return h, fail("ACTIVE_BLOCK")
	}
	return h, nil
}
func (o *observation) block(block string, height int64) (rpcBlock, error) {
	var b rpcBlock
	if e := o.call("getblock", &b, block, 1); e != nil {
		return b, e
	}
	if b.Hash != block || b.Height != height || len(b.Tx) == 0 || len(b.Tx) > 10000 {
		return b, fail("BLOCK_PROJECTION")
	}
	seen := map[string]bool{}
	for _, id := range b.Tx {
		if !digestHex(id) || seen[id] {
			return b, fail("BLOCK_TXIDS")
		}
		seen[id] = true
	}
	return b, nil
}
func (o *observation) transaction(id string) (rpcTx, *Transaction, error) {
	var view rpcTx
	if !digestHex(id) {
		return view, nil, fail("TXID")
	}
	if e := o.call("getrawtransaction", &view, id, true); e != nil {
		return view, nil, e
	}
	raw, e := hex.DecodeString(view.Hex)
	if e != nil || hex.EncodeToString(raw) != view.Hex || view.TxID != id {
		return view, nil, fail("TX_HEX")
	}
	tx, e := DecodeTransaction(raw)
	if e != nil {
		return view, nil, e
	}
	if tx.ID() != id || len(tx.Inputs) != len(view.Vin) || len(tx.Outputs) != len(view.Vout) {
		return view, nil, fail("RAW_TX_BINDING")
	}
	for i, in := range tx.Inputs {
		v := view.Vin[i]
		if v.Coinbase != "" || in.TxID != v.TxID || in.Vout != v.Vout || hex.EncodeToString(in.Script) != v.Script.Hex {
			return view, nil, fail("RAW_INPUT_BINDING")
		}
	}
	for i, out := range tx.Outputs {
		v := view.Vout[i]
		if v.N != uint32(i) || int64(v.Value) != out.Value || v.Script.Hex != hex.EncodeToString(out.Script) {
			return view, nil, fail("RAW_OUTPUT_BINDING")
		}
	}
	return view, tx, nil
}
func (o *observation) confirmed(view rpcTx) (header, error) {
	h, e := o.active(view.Block)
	if e != nil {
		return h, e
	}
	if view.Confirmations != o.tip.Blocks-h.Height+1 {
		return h, fail("TX_CONFIRMATIONS")
	}
	b, e := o.block(view.Block, h.Height)
	if e != nil {
		return h, e
	}
	found := false
	for _, id := range b.Tx {
		if id == view.TxID {
			found = true
		}
	}
	if !found {
		return h, fail("BLOCK_MEMBERSHIP")
	}
	return h, nil
}

// NameUpdateScript constructs the exact historical Namecoin OP_NAME_UPDATE
// serialization. Matching its bytes binds decoded name/value claims to raw txid.
func NameUpdateScript(name, value string, payment []byte) []byte {
	b := []byte{0x53}
	b = appendPush(b, []byte(name))
	b = appendPush(b, []byte(value))
	b = append(b, 0x6d, 0x75)
	return append(b, payment...)
}
func appendPush(dst, data []byte) []byte {
	switch {
	case len(data) < 76:
		dst = append(dst, byte(len(data)))
	case len(data) <= 255:
		dst = append(dst, 0x4c, byte(len(data)))
	default:
		dst = append(dst, 0x4d, byte(len(data)), byte(len(data)>>8))
	}
	return append(dst, data...)
}
func (o *observation) stable() error {
	var after chainInfo
	if e := o.call("getblockchaininfo", &after); e != nil {
		return e
	}
	if after != o.tip {
		return fail("TIP_CHANGED")
	}
	return nil
}
func (o *observation) start(network, pinnedGenesis string) error {
	if !NetworkPinned(network, pinnedGenesis) {
		return fail("GENESIS")
	}
	if e := o.call("getblockchaininfo", &o.tip); e != nil {
		return e
	}
	// Core28 reconsiderblock can restore blocks above its cached best-header
	// counter. That counter supplies no authority: verify the active hash,
	// height, confirmations and transaction membership independently below.
	if o.tip.Chain != network || o.tip.IBD || o.tip.Blocks < 0 || o.tip.Blocks > 2147483647 || o.tip.Headers < 0 || o.tip.Headers > 2147483647 || !digestHex(o.tip.Best) {
		return fail("CHAIN_STATE")
	}
	var genesis string
	if e := o.call("getblockhash", &genesis, 0); e != nil || genesis != pinnedGenesis {
		return fail("GENESIS")
	}
	_, e := o.active(o.tip.Best)
	return e
}
func publicError(e error) string {
	if e == nil {
		return ""
	}
	return fmt.Sprint(e)
}
