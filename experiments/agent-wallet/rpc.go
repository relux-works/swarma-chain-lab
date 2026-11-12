package wallet

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	sw "github.com/relux-works/swarma-chain-lab/experiments/sealwatch"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

type WalletRoute struct {
	Route  su.Route `json:"route"`
	Wallet string   `json:"wallet"`
}
type RPC struct {
	route    su.Route
	endpoint string
	methods  map[string]bool
	client   *http.Client
	// noSuchTx is set only on the S3 transaction lookup route
	// (newTxLookupRPC). No wallet or broadcast route sets it, so their answers
	// are unchanged.
	noSuchTx bool
}

// CodeNoSuchTx is the transaction lookup route's answer when Core states that
// it knows the transaction neither in its mempool nor in its chain. It is the
// only node answer the S3 tracker reads as "absent".
const CodeNoSuchTx = "RPC_NO_SUCH_TX"

// coreNoSuchTxMessage is Namecoin Core 28's getrawtransaction message with a
// ready transaction index. The other -5 messages of that call (no index, index
// still syncing, block hash given) cannot rule out a mined transaction, so
// they stay RPC_RESPONSE.
const coreNoSuchTxMessage = "No such mempool or blockchain transaction. Use gettransaction for wallet transactions."

var walletMethods = map[string]bool{"getbalances": true, "getnewaddress": true, "listtransactions": true, "fundrawtransaction": true, "signrawtransactionwithwallet": true}
var broadcastMethods = map[string]bool{"sendrawtransaction": true}

func newRPC(r su.Route, path, user string, methods map[string]bool) (*RPC, error) {
	ip := net.ParseIP(r.Host)
	if ip == nil || !ip.IsLoopback() || r.Port < 1 || r.Port > 65535 || r.Username != user || len(r.Password) < 16 || len(r.Password) > 256 {
		return nil, fail("RPC_ROUTE")
	}
	return &RPC{route: r, endpoint: "http://" + net.JoinHostPort(r.Host, strconv.Itoa(r.Port)) + path, methods: methods, client: &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil, MaxIdleConns: 2}, CheckRedirect: func(*http.Request, []*http.Request) error { return fail("RPC_REDIRECT") }}}, nil
}
func NewWalletRPC(r WalletRoute) (*RPC, error) {
	if r.Wallet == "" || len(r.Wallet) > 64 || strings.ContainsAny(r.Wallet, "/\\.%") || !ascii(r.Wallet, 64) {
		return nil, fail("WALLET_ENDPOINT")
	}
	return newRPC(r.Route, "/wallet/"+url.PathEscape(r.Wallet), "w1-wallet", walletMethods)
}
func NewBroadcasterRPC(r su.Route) (*RPC, error) {
	return newRPC(r, "/", "w1-broadcast", broadcastMethods)
}

// newTxLookupRPC is the S3 tracker's getrawtransaction client on the observer
// route (the same route, user and node as the wallet's observer).
func newTxLookupRPC(r su.Route) (*RPC, error) {
	n, e := newRPC(r, "/", "w3-observer", map[string]bool{"getrawtransaction": true})
	if e != nil {
		return nil, e
	}
	n.noSuchTx = true
	return n, nil
}

// coreNoSuchTx reports Core's JSON-RPC 1.0 error reply to getrawtransaction for
// a transaction it does not know: exactly {"result":null,"error":{"code":-5,
// "message":coreNoSuchTxMessage},"id":1}. Anything else is not this answer.
func coreNoSuchTx(b []byte) bool {
	var reply map[string]json.RawMessage
	if sw.DecodeJSON(b, &reply) != nil || len(reply) != 3 {
		return false
	}
	if string(bytes.TrimSpace(reply["result"])) != "null" || string(bytes.TrimSpace(reply["id"])) != "1" {
		return false
	}
	var remote map[string]json.RawMessage
	if sw.DecodeJSON(reply["error"], &remote) != nil || len(remote) != 2 {
		return false
	}
	var message string
	return string(bytes.TrimSpace(remote["code"])) == "-5" && json.Unmarshal(remote["message"], &message) == nil && message == coreNoSuchTxMessage
}

// px1ObserverNode is the S3 observers' own-node client: getrawtransaction goes
// to the transaction lookup route, every other read to the wallet's observer
// node unchanged.
type px1ObserverNode struct {
	su.Node
	tx su.Node
}

func (o px1ObserverNode) Call(ctx context.Context, method string, args ...any) (json.RawMessage, error) {
	if method == "getrawtransaction" {
		return o.tx.Call(ctx, method, args...)
	}
	return o.Node.Call(ctx, method, args...)
}
func (n *RPC) Call(ctx context.Context, method string, args ...any) (json.RawMessage, error) {
	if !n.methods[method] {
		return nil, fail("RPC_METHOD_FORBIDDEN")
	}
	if args == nil {
		args = []any{}
	}
	b, e := json.Marshal(map[string]any{"jsonrpc": "1.0", "id": 1, "method": method, "params": args})
	if e != nil || len(b) > 1<<20 {
		return nil, fail("RPC_INPUT")
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, n.endpoint, bytes.NewReader(b))
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
	b, e = io.ReadAll(io.LimitReader(res.Body, 2<<20+1))
	if e != nil || len(b) > 2<<20 || res.StatusCode != 200 {
		if e == nil && len(b) <= 2<<20 && n.noSuchTx && res.StatusCode == http.StatusInternalServerError && coreNoSuchTx(b) {
			return nil, fail(CodeNoSuchTx)
		}
		return nil, fail("RPC_RESPONSE")
	}
	var id int
	var result, remote json.RawMessage
	if sw.ProjectJSON(b, map[string]any{"id": &id}, map[string]any{"result": &result, "error": &remote}) != nil || id != 1 || len(result) == 0 || !bytes.Equal(bytes.TrimSpace(remote), []byte("null")) {
		return nil, fail("RPC_REMOTE_REFUSAL")
	}
	return result, nil
}
func call(ctx context.Context, node su.Node, method string, out any, args ...any) error {
	if node == nil {
		return fail("RPC_UNAVAILABLE")
	}
	raw, e := node.Call(ctx, method, args...)
	if e != nil {
		return e
	}
	if len(raw) > 2<<20 || sw.DecodeJSON(raw, out) != nil {
		return fail("RPC_RESULT")
	}
	return nil
}
