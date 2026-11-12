package wallet

// Item T10 tracker defect: the S3 tracker's getrawtransaction route
// (newTxLookupRPC in rpc.go) and px1oRemoteNo. Core 28 answers a JSON-RPC 1.0
// error with HTTP 500 and an error object; only its definitive "no such
// transaction" answer may read as absent. Every other answer keeps the
// error the tracker got before (RPC_RESPONSE for any non-200).

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

const px1rNoSuchTxBody = `{"result":null,"error":{"code":-5,"message":"No such mempool or blockchain transaction. Use gettransaction for wallet transactions."},"id":1}`

// px1rServer answers every request with status and body, and returns a route
// to it for user.
func px1rServer(t *testing.T, status int, body, user string) su.Route {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	host, port, e := net.SplitHostPort(srv.Listener.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	p, _ := strconv.Atoi(port)
	return su.Route{Host: host, Port: p, Username: user, Password: "observer-password-0123"}
}

func px1rCode(e error) string {
	if e == nil {
		return ""
	}
	return e.Error()
}

// Claim: the lookup route maps exactly Core's HTTP 500 reply {"result":null,
// "error":{"code":-5,"message":<no such mempool or blockchain transaction>},
// "id":1} to CodeNoSuchTx, and px1oTxDepth reads it as absent with no error;
// every neighbour (another code with the same message, another -5 message,
// another id, a non-null result, extra or missing fields, a non-JSON or
// malformed body, the same body on 401/503/404, a refused login or a busy
// node) keeps RPC_RESPONSE and px1oTxDepth fails with it. A 200 reply keeps
// its result. Limit: a local HTTP server stands in for Core here; the Core
// layer is TestPX1CoreS2Crash.
func TestPX1TxLookupNoSuchTx(t *testing.T) {
	txid := px1oHex('a', 1)
	cases := []struct {
		name   string
		status int
		body   string
		want   string // "" = result returned
		absent bool
	}{
		{"core-no-such-tx", 500, px1rNoSuchTxBody, CodeNoSuchTx, true},
		{"code-8", 500, `{"result":null,"error":{"code":-8,"message":"No such mempool or blockchain transaction. Use gettransaction for wallet transactions."},"id":1}`, "RPC_RESPONSE", false},
		{"code-1", 500, `{"result":null,"error":{"code":-1,"message":"No such mempool or blockchain transaction. Use gettransaction for wallet transactions."},"id":1}`, "RPC_RESPONSE", false},
		{"code-5-string", 500, `{"result":null,"error":{"code":"-5","message":"No such mempool or blockchain transaction. Use gettransaction for wallet transactions."},"id":1}`, "RPC_RESPONSE", false},
		{"code-5-index-syncing", 500, `{"result":null,"error":{"code":-5,"message":"No such mempool transaction. Blockchain transactions are still in the process of being indexed. Use gettransaction for wallet transactions."},"id":1}`, "RPC_RESPONSE", false},
		{"code-5-no-index", 500, `{"result":null,"error":{"code":-5,"message":"No such mempool transaction. Use -txindex or provide a block hash to enable blockchain transaction queries. Use gettransaction for wallet transactions."},"id":1}`, "RPC_RESPONSE", false},
		{"code-5-other-id", 500, `{"result":null,"error":{"code":-5,"message":"No such mempool or blockchain transaction. Use gettransaction for wallet transactions."},"id":2}`, "RPC_RESPONSE", false},
		{"code-5-result-not-null", 500, `{"result":{},"error":{"code":-5,"message":"No such mempool or blockchain transaction. Use gettransaction for wallet transactions."},"id":1}`, "RPC_RESPONSE", false},
		{"code-5-extra-field", 500, `{"result":null,"error":{"code":-5,"message":"No such mempool or blockchain transaction. Use gettransaction for wallet transactions."},"id":1,"x":1}`, "RPC_RESPONSE", false},
		{"code-5-no-result", 500, `{"error":{"code":-5,"message":"No such mempool or blockchain transaction. Use gettransaction for wallet transactions."},"id":1}`, "RPC_RESPONSE", false},
		{"code-5-duplicate-code", 500, `{"result":null,"error":{"code":-5,"code":-8,"message":"No such mempool or blockchain transaction. Use gettransaction for wallet transactions."},"id":1}`, "RPC_RESPONSE", false},
		{"500-no-json", 500, "Internal Server Error", "RPC_RESPONSE", false},
		{"500-empty", 500, "", "RPC_RESPONSE", false},
		{"500-malformed-json", 500, `{"result":null,"error":{"code":-5,`, "RPC_RESPONSE", false},
		{"401", 401, "", "RPC_RESPONSE", false},
		{"401-with-no-such-body", 401, px1rNoSuchTxBody, "RPC_RESPONSE", false},
		{"503-work-queue", 503, "Work queue depth exceeded", "RPC_RESPONSE", false},
		{"503-with-no-such-body", 503, px1rNoSuchTxBody, "RPC_RESPONSE", false},
		{"404-with-no-such-body", 404, px1rNoSuchTxBody, "RPC_RESPONSE", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n, e := newTxLookupRPC(px1rServer(t, tc.status, tc.body, "w3-observer"))
			if e != nil {
				t.Fatal(e)
			}
			_, e = n.Call(context.Background(), "getrawtransaction", txid, true)
			if got := px1rCode(e); got != tc.want {
				t.Fatalf("lookup %s: got %q, want %q", tc.name, got, tc.want)
			}
			present, depth, e := px1oTxDepth(context.Background(), n, txid)
			if tc.absent {
				if e != nil || present || depth != 0 {
					t.Fatalf("no-such-tx not read as absent: present=%v depth=%d err=%v", present, depth, e)
				}
				return
			}
			if px1rCode(e) != tc.want || present {
				t.Fatalf("%s read as absent or lost its error: present=%v err=%v", tc.name, present, e)
			}
		})
	}
	// Positive control: a 200 reply is returned unchanged and is present.
	ok := px1rServer(t, 200, `{"result":{"txid":"`+txid+`","hex":"00"},"error":null,"id":1}`, "w3-observer")
	n, _ := newTxLookupRPC(ok)
	if present, depth, e := px1oTxDepth(context.Background(), n, txid); e != nil || !present || depth != 0 {
		t.Fatalf("mempool transaction: present=%v depth=%d err=%v", present, depth, e)
	}
	// The route carries only getrawtransaction and the observer user.
	if _, e := n.Call(context.Background(), "gettxout", txid, 0, true); px1rCode(e) != "RPC_METHOD_FORBIDDEN" {
		t.Fatalf("lookup route method set: %v", e)
	}
	if _, e := newTxLookupRPC(su.Route{Host: "127.0.0.1", Port: 1, Username: "w1-wallet", Password: "observer-password-0123"}); px1rCode(e) != "RPC_ROUTE" {
		t.Fatalf("lookup route user: %v", e)
	}
}

// Claim: the classification is the lookup route's alone: the wallet and
// broadcast routes of rpc.go still answer RPC_RESPONSE to Core's no-such-tx
// reply (and to every other non-200), as before this change; their 200
// replies are unchanged.
func TestPX1TxLookupOtherRoutesUnchanged(t *testing.T) {
	for _, status := range []int{500, 401, 503} {
		w, e := NewWalletRPC(WalletRoute{Route: px1rServer(t, status, px1rNoSuchTxBody, "w1-wallet"), Wallet: "hot"})
		if e != nil {
			t.Fatal(e)
		}
		if _, e = w.Call(context.Background(), "getbalances"); px1rCode(e) != "RPC_RESPONSE" {
			t.Fatalf("wallet route %d: %v", status, e)
		}
		b, e := NewBroadcasterRPC(px1rServer(t, status, px1rNoSuchTxBody, "w1-broadcast"))
		if e != nil {
			t.Fatal(e)
		}
		if _, e = b.Call(context.Background(), "sendrawtransaction", "00"); px1rCode(e) != "RPC_RESPONSE" {
			t.Fatalf("broadcast route %d: %v", status, e)
		}
	}
	w, _ := NewWalletRPC(WalletRoute{Route: px1rServer(t, 200, `{"result":{"mine":{}},"error":null,"id":1}`, "w1-wallet"), Wallet: "hot"})
	if raw, e := w.Call(context.Background(), "getbalances"); e != nil || string(raw) != `{"mine":{}}` {
		t.Fatalf("wallet route 200: %s %v", raw, e)
	}
}

// px1rNode records the methods it is asked for.
type px1rNode struct{ calls []string }

func (n *px1rNode) Call(_ context.Context, method string, _ ...any) (json.RawMessage, error) {
	n.calls = append(n.calls, method)
	return json.RawMessage(`null`), nil
}

// Claim: the S3 observers' node sends getrawtransaction, and only it, to the
// lookup route; every other read stays on the wallet's observer node. A
// wallet built without OpenWallet (no lookup route) keeps its node as is.
// Limit: that the production wallet carries the route is shown at the Core
// layer (TestPX1CoreS2Crash before the broadcast).
func TestPX1ObserverNodeRouting(t *testing.T) {
	base, tx := &px1rNode{}, &px1rNode{}
	w := &Wallet{node: base, txLookup: tx}
	o := w.px1Observer()
	for _, m := range []string{"getblockchaininfo", "getrawtransaction", "gettxout", "getblockhash", "getblock"} {
		o.Call(context.Background(), m)
	}
	if len(tx.calls) != 1 || tx.calls[0] != "getrawtransaction" || len(base.calls) != 4 {
		t.Fatalf("routing: lookup %v, observer %v", tx.calls, base.calls)
	}
	if bare := (&Wallet{node: base}).px1Observer(); bare != su.Node(base) {
		t.Fatal("a wallet without a lookup route must keep its observer node")
	}
}
