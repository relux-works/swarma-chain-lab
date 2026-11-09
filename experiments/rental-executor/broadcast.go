package executor

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/relux-works/swarma-chain-lab/experiments/sealwatch"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"
)

type RPCBroadcaster struct {
	route  singleuse.Route
	client *http.Client
}

// NewBroadcaster requires a separate sendrawtransaction-only loopback RPC user.
// It holds no wallet RPC capability. Core config must enforce the same whitelist.
func NewBroadcaster(r singleuse.Route) (*RPCBroadcaster, error) {
	ip := net.ParseIP(r.Host)
	if ip == nil || !ip.IsLoopback() || r.Port < 1 || r.Port > 65535 || r.Username != "m4a-broadcast" || len(r.Password) < 32 || len(r.Password) > 256 {
		return nil, fail("BROADCAST_ROUTE")
	}
	return &RPCBroadcaster{r, &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return fail("REDIRECT") }}}, nil
}
func (b *RPCBroadcaster) Broadcast(ctx context.Context, raw []byte) (string, error) {
	if len(raw) == 0 || len(raw) > 100000 {
		return "", fail("BROADCAST_INPUT")
	}
	body := canonical(map[string]any{"jsonrpc": "1.0", "id": 1, "method": "sendrawtransaction", "params": []any{hex.EncodeToString(raw), json.Number("0.01000000")}})
	req, e := http.NewRequestWithContext(ctx, "POST", "http://"+net.JoinHostPort(b.route.Host, strconv.Itoa(b.route.Port))+"/", bytes.NewReader(body))
	if e != nil {
		return "", fail("BROADCAST_REQUEST")
	}
	req.SetBasicAuth(b.route.Username, b.route.Password)
	req.Header.Set("Content-Type", "application/json")
	resp, e := b.client.Do(req)
	if e != nil {
		return "", fail("BROADCAST_UNAVAILABLE")
	}
	defer resp.Body.Close()
	data, e := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if e != nil || len(data) > 65536 {
		return "", fail("BROADCAST_RESPONSE")
	}
	if resp.StatusCode != 200 {
		var response struct {
			Error struct {
				Code int `json:"code"`
			} `json:"error"`
		}
		_ = json.Unmarshal(data, &response)
		return "", fmt.Errorf("BROADCAST_HTTP_%d_RPC_%d", resp.StatusCode, response.Error.Code)
	}
	var id int
	var result string
	var rpcError json.RawMessage
	if sealwatch.ProjectJSON(data, map[string]any{"id": &id, "result": &result}, map[string]any{"error": &rpcError}) != nil || id != 1 || string(bytes.TrimSpace(rpcError)) != "null" || !hexN(result, 32) {
		return "", fail("BROADCAST_RESPONSE")
	}
	return result, nil
}
