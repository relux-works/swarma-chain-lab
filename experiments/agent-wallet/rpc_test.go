package wallet

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// The client admits its fixed method set on the pinned wallet path and rejects
// forbidden methods before I/O. No argument-controlled URL or method escape.
func TestWalletRPCBoundary(t *testing.T) {
	var count atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		if r.URL.Path != "/wallet/agent" {
			t.Error("wallet path changed")
		}
		user, password, ok := r.BasicAuth()
		if !ok || user != "w1-wallet" || password != strings.Repeat("x", 32) {
			t.Error("fixture auth mismatch")
		}
		json.NewEncoder(w).Encode(map[string]any{"id": 1, "result": map[string]any{"mine": map[string]any{"trusted": 1, "untrusted_pending": 0, "immature": 0}}, "error": nil})
	}))
	defer s.Close()
	u, _ := url.Parse(s.URL)
	host, p, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(p)
	route := WalletRoute{Route: su.Route{Host: host, Port: port, Username: "w1-wallet", Password: strings.Repeat("x", 32)}, Wallet: "agent"}
	rpc, e := NewWalletRPC(route)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = rpc.Call(context.Background(), "getbalances"); e != nil {
		t.Fatal(e)
	}
	before := count.Load()
	for _, method := range []string{"dumpprivkey", "sendtoaddress", "name_new", "name_firstupdate", "importprivkey", "stop", "getbalances/../dumpwallet"} {
		if _, e = rpc.Call(context.Background(), method); e == nil || e.Error() != "RPC_METHOD_FORBIDDEN" {
			t.Fatalf("method %s bypassed allowlist", method)
		}
	}
	if count.Load() != before {
		t.Fatal("forbidden method reached server")
	}
	for _, bad := range []string{"../issuer", "agent/issuer", "%2e%2e", "", strings.Repeat("a", 65)} {
		r := route
		r.Wallet = bad
		if _, e := NewWalletRPC(r); e == nil {
			t.Fatal("invalid wallet endpoint admitted")
		}
	}
	r := route
	r.Route.Host = "example.invalid"
	if _, e := NewWalletRPC(r); e == nil {
		t.Fatal("remote route admitted")
	}
}

// A malformed/mismatched JSON-RPC response cannot become a successful result;
// the negative path reports bounded codes without echoing server data.
func TestRPCResponseControls(t *testing.T) {
	for _, body := range []string{`{"id":2,"result":{},"error":null}`, `{"id":1,"result":{},"error":{"secret":"must-not-escape"}}`, `{"id":1,"id":1,"result":{},"error":null}`} {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
		u, _ := url.Parse(s.URL)
		host, p, _ := net.SplitHostPort(u.Host)
		port, _ := strconv.Atoi(p)
		rpc, e := NewWalletRPC(WalletRoute{Route: su.Route{Host: host, Port: port, Username: "w1-wallet", Password: strings.Repeat("x", 32)}, Wallet: "agent"})
		if e != nil {
			t.Fatal(e)
		}
		_, e = rpc.Call(context.Background(), "getbalances")
		s.Close()
		if e == nil || strings.Contains(e.Error(), "must-not-escape") {
			t.Fatal("RPC response admitted or leaked body")
		}
	}
}
