package signerservice

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	su "relux.works/swarma-chain-lab/experiments/single-use"
)

// RPCBroadcast has one write method and a distinct least-privilege principal.
// The daemon must whitelist sendrawtransaction only for sg1-broadcaster. It
// never imports a key, asks a wallet to sign, mines, or follows a remote route.
type RPCBroadcast struct {
	route  su.Route
	read   su.Node
	client *http.Client
}

func NewRPCBroadcast(route su.Route, observerRoute su.Route) (*RPCBroadcast, error) {
	node, e := su.NewRPC(observerRoute)
	if e != nil || route.Host != observerRoute.Host || route.Port != observerRoute.Port {
		return nil, fail("BROADCAST_NODE_PIN")
	}
	ip := net.ParseIP(route.Host)
	if ip == nil || !ip.IsLoopback() || route.Port < 1 || route.Port > 65535 || route.Username != "sg1-broadcaster" || len(route.Password) < 16 || len(route.Password) > 256 || node == nil {
		return nil, fail("BROADCAST_ROUTE")
	}
	return &RPCBroadcast{route, node, &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return fail("REDIRECT") }}}, nil
}
func (b *RPCBroadcast) Send(ctx context.Context, raw []byte) (string, error) {
	tx, e := su.DecodeTransaction(raw)
	if e != nil || len(raw) > 16384 {
		return "", fail("BROADCAST_ENCODING")
	}
	o := su.NewReadObservation(ctx, b.read)
	defer o.Close()
	if e = o.Start("regtest", su.RegtestGenesis); e != nil {
		return "", e
	}
	// Observation also recovers an already accepted tx after a lost ACK. Equality
	// checks original serialization; a matching requested ID alone is insufficient.
	if _, seen, e := o.PaymentTransaction(tx.ID()); e == nil && bytes.Equal(seen.Bytes(), raw) {
		return tx.ID(), nil
	}
	body := encode(map[string]any{"jsonrpc": "1.0", "id": 1, "method": "sendrawtransaction", "params": []any{hex.EncodeToString(raw)}})
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+net.JoinHostPort(b.route.Host, strconv.Itoa(b.route.Port))+"/", bytes.NewReader(body))
	if e != nil {
		return "", fail("BROADCAST_REQUEST")
	}
	req.SetBasicAuth(b.route.Username, b.route.Password)
	req.Header.Set("Content-Type", "application/json")
	resp, e := b.client.Do(req)
	if e != nil {
		return "", fail("BROADCAST_UNCERTAIN")
	}
	defer resp.Body.Close()
	data, e := io.ReadAll(io.LimitReader(resp.Body, 4097))
	if e != nil || len(data) > 4096 || resp.StatusCode != 200 {
		return "", fail("BROADCAST_UNCERTAIN")
	}
	var result struct {
		ID     int             `json:"id"`
		Result string          `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if json.Unmarshal(data, &result) != nil || result.ID != 1 || !bytes.Equal(result.Error, []byte("null")) || result.Result != tx.ID() {
		return "", fail("BROADCAST_UNCERTAIN")
	}
	return result.Result, nil
}

// String and GoString never expose route credentials through diagnostics.
func (*RPCBroadcast) String() string   { return "RPCBroadcast(redacted)" }
func (*RPCBroadcast) GoString() string { return "RPCBroadcast(redacted)" }
