package notarycheck

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These finite fake-RPC cases isolate view, registration and failure handling;
// the separately recorded regtest run establishes the real Core wire behavior.
// Expiry <= 0 refuses even if expired=false; the live positive uses expiry 1000.
func TestNodeReaderBoundsAndNames(t *testing.T) {
	hash := strings.Repeat("ab", 32)
	for _, tc := range []struct{ name, expected string }{
		{"positive", ""}, {"height", "NODE_TIP_MISMATCH"}, {"hash", "NODE_TIP_MISMATCH"}, {"blockhash", "NODE_TIP_MISMATCH"}, {"network", "NODE_NETWORK"}, {"missing", "NODE_NAME_UNREGISTERED"}, {"rpc", "NODE_RPC_FAILURE"}, {"malformed", "NODE_NAME_VALUE"}, {"history", "NODE_NAME_HISTORY"}, {"update", ""}, {"reregister", ""}, {"expiry-before", ""}, {"expiry-at", ""}, {"expiry-after", ""}, {"zero-expiry", "NODE_NAME_UNREGISTERED"}, {"negative-expiry", "NODE_NAME_UNREGISTERED"}, {"mid-read-tip", "NODE_TIP_MISMATCH"}, {"timeout", "NODE_RPC_FAILURE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			views := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var q struct {
					Method string `json:"method"`
				}
				_ = json.NewDecoder(r.Body).Decode(&q)
				var value any
				var rpcError any
				switch q.Method {
				case "getblockchaininfo":
					views++
					height := int64(100)
					best := hash
					chain := "regtest"
					if tc.name == "height" || tc.name == "mid-read-tip" && views > 1 {
						height++
					}
					if tc.name == "hash" {
						best = strings.Repeat("00", 32)
					}
					if tc.name == "network" {
						chain = "main"
					}
					value = map[string]any{"blocks": height, "bestblockhash": best, "chain": chain}
				case "getblockhash":
					value = hash
					if tc.name == "blockhash" {
						value = strings.Repeat("00", 32)
					}
				case "name_show", "name_history":
					n := nodeName{Name: "id/reader", Value: `{"swarma":{"landlord":{"grant":"` + strings.Repeat("11", 32) + `"}}}`, TxID: strings.Repeat("11", 32), Height: 1, ExpiresIn: 1000, NameEncoding: "utf8", ValueEncoding: "utf8"}
					if tc.name == "malformed" {
						n.Value = "{"
					}
					if tc.name == "update" || tc.name == "reregister" || strings.HasPrefix(tc.name, "expiry-") {
						n.Height = 50
						n.TxID = strings.Repeat("22", 32)
					}
					if tc.name == "zero-expiry" {
						n.ExpiresIn = 0
					}
					if tc.name == "negative-expiry" {
						n.ExpiresIn = -1
					}
					value = n
					if q.Method == "name_history" {
						history := []nodeName{n}
						if tc.name == "history" {
							history = []nodeName{}
						}
						if tc.name == "update" || tc.name == "reregister" || strings.HasPrefix(tc.name, "expiry-") {
							prev := n
							prev.TxID = strings.Repeat("11", 32)
							prev.Height = 1
							prev.ExpiresIn = 1000
							if tc.name == "reregister" {
								prev.ExpiresIn = -60
							}
							// Claim: at tip 100, height 50 is a fresh registration exactly
							// when the prior stretch expires at 50; 49 is new, 51 is not.
							if tc.name == "expiry-before" {
								prev.ExpiresIn = -51
							}
							if tc.name == "expiry-at" {
								prev.ExpiresIn = -50
							}
							if tc.name == "expiry-after" {
								prev.ExpiresIn = -49
							}
							history = []nodeName{prev, n}
						}
						value = history
					}
					if tc.name == "missing" {
						rpcError = map[string]any{"code": -4, "message": "sensitive diagnostic"}
					}
				}
				if tc.name == "rpc" {
					rpcError = map[string]any{"code": -1, "message": "sensitive diagnostic"}
				}
				if tc.name == "timeout" {
					select {
					case <-r.Context().Done():
						return
					case <-time.After(time.Second):
						return
					}
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"id": 1, "result": value, "error": rpcError})
			}))
			defer srv.Close()
			path := filepath.Join(t.TempDir(), "credential")
			if os.WriteFile(path, []byte("test-user:test-password"), 0600) != nil {
				t.Fatal("credential")
			}
			n, e := NewNodeNameReader(srv.URL, path)
			if e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			n = n.WithContext(ctx)
			got, e := n.Lookup("id/reader", 100, hash)
			code := ""
			if e != nil {
				code = e.Error()
			}
			if code != tc.expected {
				t.Fatalf("got %s want %s", code, tc.expected)
			}
			if code != "" {
				if len(got.Value) > 0 || got.Registration.TxID != "" {
					t.Fatal("partial observation")
				}
				return
			}
			want := strings.Repeat("11", 32)
			if tc.name == "reregister" || tc.name == "expiry-before" || tc.name == "expiry-at" {
				want = strings.Repeat("22", 32)
			}
			if got.Height != 100 || got.BlockHash != hash || got.Registration.TxID != want {
				t.Fatal("view/registration")
			}
		})
	}
}

// The zero-value adapter still fails closed, and configuration cannot send
// credentials to non-loopback endpoints, redirects, URLs with embedded auth or
// a file-backed source. A valid loopback URL is covered above.
func TestNodeReaderNoFallback(t *testing.T) {
	var zero NodeNameReader
	if _, e := zero.Lookup("id/x", 1, strings.Repeat("00", 32)); e != Refusal("MVP_CHAIN_READ_REQUIRED") {
		t.Fatal(e)
	}
	for _, endpoint := range []string{"file:///names.json", "http://192.0.2.1:8336", "http://user:pass@127.0.0.1:1234", "https://127.0.0.1:1234", "http://127.0.0.1:1234?x=1"} {
		if _, e := NewNodeNameReader(endpoint, "absent"); e != Refusal("NODE_CONFIG") {
			t.Fatal(endpoint, e)
		}
	}
}

type refusedNodeSource Refusal

func (n refusedNodeSource) Lookup(string, int64, string) (NameObservation, error) {
	return NameObservation{}, Refusal(n)
}

// Running MVP accepts only the concrete configured reader, never an injected
// fixture; missing readers retain the original required-chain-read refusal.
// Named reader failures survive the checker boundary without partial output.
func TestMVPNodeRefusalPassthrough(t *testing.T) {
	var in Input
	found := false
	for _, v := range readCorpus(t).Vectors {
		if v.Name == "positive-mvp-issuer-owner" {
			in = v.input()
			found = true
			break
		}
	}
	if !found {
		t.Fatal("positive control missing")
	}
	if _, e := Check(in); e != nil {
		t.Fatal("positive fixture control", e)
	}
	if _, e := CheckRunningWithNode(in, nil); e != Refusal("MVP_CHAIN_READ_REQUIRED") {
		t.Fatal("fixture injection accepted", e)
	}
	in.Names = nil
	if _, e := CheckRunningWithNode(in, nil); e != Refusal("MVP_CHAIN_READ_REQUIRED") {
		t.Fatal("missing reader accepted", e)
	}
	for _, code := range []Refusal{"NODE_RPC_FAILURE", "NODE_TIP_MISMATCH", "NODE_NETWORK", "NODE_NAME_UNREGISTERED", "NODE_NAME_VALUE", "NODE_NAME_HISTORY"} {
		t.Run(string(code), func(t *testing.T) {
			in.Names = refusedNodeSource(code)
			r, e := Check(in)
			if e != code || r.Digest != "" || len(r.Attestation) > 0 {
				t.Fatal("reader refusal changed", e)
			}
		})
	}
}
