package paymentchain

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"relux.works/swarma-chain-lab/experiments/sealwatch"
	"strconv"
	"time"
)

var readMethods = map[string]bool{"getnetworkinfo": true, "getblockchaininfo": true, "getblockhash": true, "getblockheader": true, "getblock": true, "getrawtransaction": true, "getrawmempool": true}

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

// NewRPC opens the watcher's read-only principal.
func NewRPC(r Route) (*RPC, error) { return newRPC(r, "payment-observer") }

// NewIssuerRPC requires a separately provisioned issuer principal and secret.
// Both principals are read-only; neither accepts the node wallet credential.
func NewIssuerRPC(r Route) (*RPC, error) { return newRPC(r, "payment-issuer") }
func newRPC(r Route, username string) (*RPC, error) {
	ip := net.ParseIP(r.Host)
	if ip == nil || !ip.IsLoopback() || r.Port < 1 || r.Port > 65535 || r.Username != username || len(r.Password) < 16 || len(r.Password) > 256 {
		return nil, refuse("READ_ONLY_ROUTE")
	}
	return &RPC{r, &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil, MaxIdleConns: 2}, CheckRedirect: func(*http.Request, []*http.Request) error { return refuse("REDIRECT") }}}, nil
}
func (n *RPC) Call(ctx context.Context, method string, args ...any) (json.RawMessage, error) {
	if !readMethods[method] {
		return nil, refuse("READ_ONLY_METHOD")
	}
	if args == nil {
		args = []any{}
	}
	b, e := json.Marshal(map[string]any{"jsonrpc": "1.0", "id": 1, "method": method, "params": args})
	if e != nil {
		return nil, refuse("RPC_INPUT")
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+net.JoinHostPort(n.route.Host, strconv.Itoa(n.route.Port))+"/", bytes.NewReader(b))
	if e != nil {
		return nil, refuse("RPC_REQUEST")
	}
	req.SetBasicAuth(n.route.Username, n.route.Password)
	req.Header.Set("Content-Type", "application/json")
	res, e := n.client.Do(req)
	if e != nil {
		return nil, refuse("RPC_UNAVAILABLE")
	}
	defer res.Body.Close()
	b, e = io.ReadAll(io.LimitReader(res.Body, 8<<20+1))
	if e != nil || len(b) > 8<<20 || res.StatusCode != 200 {
		return nil, refuse("RPC_RESPONSE")
	}
	var id int
	var result, rpcError json.RawMessage
	if e = sealwatch.ProjectJSON(b, map[string]any{"id": &id}, map[string]any{"result": &result, "error": &rpcError}); e != nil || id != 1 || len(result) == 0 || len(rpcError) == 0 {
		return nil, refuse("NODE_PROJECTION")
	}
	if string(bytes.TrimSpace(rpcError)) != "null" {
		return nil, refuse("RPC_REMOTE_ERROR")
	}
	return result, nil
}
