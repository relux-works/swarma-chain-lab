package singleuse

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Explicit main and regtest pins are accepted; absence, cross-network genesis
// and unsupported network names refuse before any observation or state writes.
func TestNetworkAdmission(t *testing.T) {
	for _, tc := range []struct {
		name, network, genesis string
		ok                     bool
	}{{"main", "main", "000000000062b72c5e2ceb45fbc8587e807c155b0da735e6483dfba2f0a9c770", true}, {"regtest", "regtest", RegtestGenesis, true}, {"missing-network", "", RegtestGenesis, false}, {"missing-main-pin", "main", "", false}, {"wrong-main-pin", "main", RegtestGenesis, false}, {"wrong-regtest-pin", "regtest", "000000000062b72c5e2ceb45fbc8587e807c155b0da735e6483dfba2f0a9c770", false}, {"unsupported", "testnet", RegtestGenesis, false}} {
		t.Run(tc.name, func(t *testing.T) {
			s := exampleSpec(t, "use")
			_, script, e := SealScript(s.IssuerKey, s.GranteeKey)
			if e != nil {
				t.Fatal(e)
			}
			cert, req := []byte("certificate"), []byte("request")
			p := Policy{Network: tc.network, Genesis: tc.genesis, Seal: s.Seal, SealScript: hexString(script), IssuerKey: s.IssuerKey, GranteeKey: s.GranteeKey, Anchor: Anchor{TxID: strings.Repeat("44", 32), Block: strings.Repeat("55", 32), Height: 2}, OwnerName: "id/test", OwnerPaymentScript: s.ChangeScript, OwnerSPKI: "owner", RequesterSPKI: "requester", CertificateHash: Hash(cert), VerifierPath: "/pinned/public-verifier", VerifierHash: strings.Repeat("66", 32), StateDir: "/private/state"}
			e = p.validate(cert, req)
			if tc.ok && e != nil {
				t.Fatal(e)
			}
			if !tc.ok && publicError(e) != "POLICY_BINDING" {
				t.Fatalf("want POLICY_BINDING, got %v", e)
			}
		})
	}
}
func hexString(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[2*i] = digits[v>>4]
		out[2*i+1] = digits[v&15]
	}
	return string(out)
}

// Policy and route use the same bounded public-file reader. Readable public
// files are allowed, but group/world write permissions refuse without mutation.
func TestWritablePublicFileRefused(t *testing.T) {
	for _, mode := range []os.FileMode{0600, 0644, 0620, 0602, 0666} {
		t.Run(mode.String(), func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "input.json")
			body := []byte(`{"network":"main"}`)
			if e := os.WriteFile(p, body, 0600); e != nil {
				t.Fatal(e)
			}
			if e := os.Chmod(p, mode); e != nil {
				t.Fatal(e)
			}
			_, e := PublicFile(p, 1000)
			if mode&0022 != 0 {
				if publicError(e) != "PUBLIC_FILE" {
					t.Fatalf("writable input admitted: %v", e)
				}
			} else if e != nil {
				t.Fatal(e)
			}
			after, _ := os.ReadFile(p)
			if string(after) != string(body) {
				t.Fatal("input changed")
			}
		})
	}
}

// A case alias nested in a policy remains an exact-projection failure.
func TestAdmissionPolicySpelling(t *testing.T) {
	var p Policy
	if StrictInput([]byte(`{"network":"main","Genesis":"x"}`), &p) == nil {
		t.Fatal("alias admitted")
	}
	if StrictInput([]byte(`{"network":"main","genesis":"x"}`), &p) != nil {
		t.Fatal("official input projection")
	}
	_, _ = json.Marshal(p)
}

type admissionNode struct{ network, genesis string }

func (n admissionNode) Call(_ context.Context, method string, args ...any) (json.RawMessage, error) {
	switch method {
	case "getblockchaininfo":
		return json.Marshal(map[string]any{"chain": n.network, "blocks": 1, "headers": 1, "bestblockhash": strings.Repeat("aa", 32), "initialblockdownload": false})
	case "getblockhash":
		if len(args) == 1 && args[0] == 0 {
			return json.Marshal(n.genesis)
		}
		return json.Marshal(strings.Repeat("aa", 32))
	default:
		return json.Marshal(map[string]any{"hash": strings.Repeat("aa", 32), "height": 1, "confirmations": 1})
	}
}

// The observed node must match the pinned network/genesis, independently of
// accepting a policy. These are offline reply fixtures, not mainnet evidence.
func TestObservedNetworkMismatch(t *testing.T) {
	for _, tc := range []struct{ network, genesis, want string }{{"main", MainGenesis, ""}, {"regtest", RegtestGenesis, "CHAIN_STATE"}, {"main", RegtestGenesis, "GENESIS"}} {
		o := observation{ctx: context.Background(), node: admissionNode{tc.network, tc.genesis}}
		if e := o.start("main", MainGenesis); publicError(e) != tc.want {
			t.Fatal(e)
		}
	}
}
