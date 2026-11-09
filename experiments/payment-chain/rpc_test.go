package paymentchain

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

// The transport refuses unauthorized methods before making a request, accepts
// every authorized read method, and never returns node response/error bodies.
// Server-side credential restriction is a separate node configuration contract.
func TestRPCReadOnly(t *testing.T) {
	var calls atomic.Int64
	var mode atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		u, p, ok := r.BasicAuth()
		if !ok || u != "payment-observer" || p != "synthetic-public-fixture-password" {
			t.Error("authentication contract")
		}
		switch mode.Load() {
		case 1:
			w.WriteHeader(500)
			fmt.Fprint(w, "private-node-error-marker")
			return
		case 2:
			http.Redirect(w, r, "http://127.0.0.1:1/private", 302)
			return
		case 3:
			fmt.Fprint(w, `{"id":1,"result":null,"error":{"message":"private-node-error-marker"}}`)
			return
		}
		var in struct {
			Method string `json:"method"`
		}
		if e := json.NewDecoder(r.Body).Decode(&in); e != nil || !readMethods[in.Method] {
			t.Error("method escaped")
		}
		fmt.Fprint(w, `{"id":1,"result":{"read":true},"error":null}`)
	}))
	defer srv.Close()
	host, portText, e := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if e != nil {
		t.Fatal(e)
	}
	port, _ := strconv.Atoi(portText)
	route := Route{host, port, "payment-observer", "synthetic-public-fixture-password"}
	node, e := NewRPC(route)
	if e != nil {
		t.Fatal(e)
	}
	ctx := context.Background()
	for _, method := range []string{"sendrawtransaction", "stop", "getwalletinfo", "name_show", "importdescriptors"} {
		before := calls.Load()
		b, e := node.Call(ctx, method)
		if e == nil || e.Error() != "READ_ONLY_METHOD" || b != nil || calls.Load() != before {
			t.Fatal("forbidden request emitted", method, e)
		}
	}
	for method := range readMethods {
		b, e := node.Call(ctx, method)
		if e != nil || string(b) != `{"read":true}` {
			t.Fatal("allowed read refused", method, e)
		}
	}
	for i, want := range []string{"RPC_RESPONSE", "RPC_UNAVAILABLE", "RPC_REMOTE_ERROR"} {
		mode.Store(int64(i + 1))
		b, e := node.Call(ctx, "getnetworkinfo")
		if e == nil || e.Error() != want || b != nil || strings.Contains(e.Error(), "private-node-error-marker") {
			t.Fatal("response refusal/leak", e)
		}
	}
	bad := route
	bad.Host = "192.0.2.1"
	if _, e = NewRPC(bad); e == nil || e.Error() != "READ_ONLY_ROUTE" {
		t.Fatal("external route accepted")
	}
	bad = route
	bad.Username = "admin"
	if _, e = NewRPC(bad); e == nil || e.Error() != "READ_ONLY_ROUTE" {
		t.Fatal("operator credential accepted")
	}
}

// Issuer and watcher factories require distinct principal names. Both retain
// the same local read-only guard; separate secrets are provisioned at the node.
func TestRPCPrincipals(t *testing.T) {
	route := Route{"127.0.0.1", 12345, "payment-observer", "synthetic-public-fixture-password"}
	if _, e := NewIssuerRPC(route); e == nil || e.Error() != "READ_ONLY_ROUTE" {
		t.Fatal("watcher principal accepted by issuer", e)
	}
	route.Username = "payment-issuer"
	if _, e := NewRPC(route); e == nil || e.Error() != "READ_ONLY_ROUTE" {
		t.Fatal("issuer principal accepted by watcher", e)
	}
	node, e := NewIssuerRPC(route)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = node.Call(context.Background(), "name_show", "id/forbidden"); e == nil || e.Error() != "READ_ONLY_METHOD" {
		t.Fatal("name route escaped", e)
	}
}
