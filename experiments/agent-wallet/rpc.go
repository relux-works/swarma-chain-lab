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
}

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
