package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

func serverOptions(t *testing.T, chain, genesis string) (options, *[]string) {
	t.Helper()
	calls := []string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
		}
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			t.Error("request JSON")
			return
		}
		calls = append(calls, req.Method)
		var result any
		switch req.Method {
		case "getblockchaininfo":
			result = map[string]any{"chain": chain}
		case "getblockhash":
			result = genesis
		default:
			json.NewEncoder(w).Encode(map[string]any{"result": nil, "error": map[string]any{"code": -99}})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"result": result, "error": nil})
	}))
	t.Cleanup(srv.Close)
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	n, _ := strconv.Atoi(port)
	root := t.TempDir()
	cookie := filepath.Join(root, "cookie")
	if err := os.WriteFile(cookie, []byte("fixture-user:fixture-password"), 0600); err != nil {
		t.Fatal(err)
	}
	k, _ := btcec.PrivKeyFromBytes([]byte{7})
	address, err := btcutil.NewAddressPubKeyHash(btcutil.Hash160(k.PubKey().SerializeCompressed()), &chaincfg.RegressionNetParams)
	if err != nil {
		t.Fatal(err)
	}
	return options{host: host, port: n, cookie: cookie, wallet: "fixture", out: filepath.Join(root, "out"), agent: agentName, landlord: landlordName, executor: hex.EncodeToString(schnorr.SerializePubKey(k.PubKey())), recipient: address.EncodeAddress(), allowance: 20000, fee: 30000, validFor: 24 * time.Hour}, &calls
}
func arguments(o options) []string {
	return []string{"--rpc-host", o.host, "--rpc-port", strconv.Itoa(o.port), "--rpc-cookie", o.cookie, "--wallet", o.wallet, "--out-dir", o.out, "--agent-name", o.agent, "--landlord-name", o.landlord, "--executor-key", o.executor, "--recipient", o.recipient}
}

// Claim: main/test chains (even with a regtest genesis) and a mismatched genesis refuse before keys, directories or any write RPC; the exact regtest pair passes the same gate.
func TestRegtestGate(t *testing.T) {
	for _, tc := range []struct {
		name, chain, genesis, want string
		calls                      []string
	}{
		{"main", "main", su.MainGenesis, "REGTEST_REQUIRED", []string{"getblockchaininfo"}},
		{"test", "test", su.RegtestGenesis, "REGTEST_REQUIRED", []string{"getblockchaininfo"}},
		{"main-regtest-genesis", "main", su.RegtestGenesis, "REGTEST_REQUIRED", []string{"getblockchaininfo"}},
		{"wrong-genesis", "regtest", su.MainGenesis, "REGTEST_GENESIS_REQUIRED", []string{"getblockchaininfo", "getblockhash"}},
		{"valid-neighbour", "regtest", su.RegtestGenesis, "", []string{"getblockchaininfo", "getblockhash"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o, calls := serverOptions(t, tc.chain, tc.genesis)
			if tc.want == "" {
				r, e := newRPC(o)
				if e != nil {
					t.Fatal(e)
				}
				defer r.client.CloseIdleConnections()
				if e = r.regtest(context.Background()); e != nil {
					t.Fatal(e)
				}
			} else {
				var out, diag bytes.Buffer
				if run(arguments(o), &out, &diag) != 1 || out.Len() != 0 || diag.String() != "rt-grant-fixture: "+tc.want+"\n" {
					t.Fatal("CHAIN_REFUSAL: expected sanitized exit 1 and no stdout")
				}
			}
			if !reflect.DeepEqual(*calls, tc.calls) {
				t.Fatalf("CHAIN_REFUSAL: unexpected RPC sequence %v", *calls)
			}
			if _, err := os.Lstat(o.out); !os.IsNotExist(err) {
				t.Fatal("chain refusal created output")
			}
		})
	}
}

// Claim: unsafe hosts, either non-fixture name and existing output refuse locally with no RPC and preserve existing contents; valid fixed names and numeric loopbacks pass local validation.
func TestLocalRefusals(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		change     func(*options)
	}{
		{"remote-ip", "LOOPBACK_REQUIRED", func(o *options) { o.host = "192.0.2.1" }},
		{"dns-name", "LOOPBACK_REQUIRED", func(o *options) { o.host = "localhost.example" }},
		{"mapped-remote", "LOOPBACK_REQUIRED", func(o *options) { o.host = "::ffff:192.0.2.1" }},
		{"url-host", "LOOPBACK_REQUIRED", func(o *options) { o.host = "127.0.0.1@192.0.2.1" }},
		{"agent", "FIXED_NAMES_REQUIRED", func(o *options) { o.agent = "id/other" }},
		{"landlord", "FIXED_NAMES_REQUIRED", func(o *options) { o.landlord = "id/other" }},
		{"existing-dir", "OUT_DIR_EXISTS_OR_UNAVAILABLE", func(o *options) {
			os.Mkdir(o.out, 0700)
			os.WriteFile(filepath.Join(o.out, "sentinel"), []byte("keep"), 0600)
		}},
		{"existing-file", "OUT_DIR_EXISTS_OR_UNAVAILABLE", func(o *options) { os.WriteFile(o.out, []byte("keep"), 0600) }},
		{"existing-symlink", "OUT_DIR_EXISTS_OR_UNAVAILABLE", func(o *options) { os.Symlink("absent", o.out) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o, calls := serverOptions(t, "regtest", su.RegtestGenesis)
			tc.change(&o)
			before, _ := os.ReadFile(o.out)
			var out, diag bytes.Buffer
			if run(arguments(o), &out, &diag) != 1 || out.Len() != 0 || diag.String() != "rt-grant-fixture: "+tc.code+"\n" || len(*calls) != 0 {
				t.Fatal("local refusal failed or contacted node")
			}
			after, _ := os.ReadFile(o.out)
			if !bytes.Equal(before, after) {
				t.Fatal("existing output changed")
			}
			if tc.name == "existing-dir" {
				b, e := os.ReadFile(filepath.Join(o.out, "sentinel"))
				if e != nil || string(b) != "keep" {
					t.Fatal("existing directory changed")
				}
			}
		})
	}
	o, _ := serverOptions(t, "regtest", su.RegtestGenesis)
	for _, host := range []string{"127.0.0.1", "127.1.2.3", "::1", "::ffff:127.0.0.1"} {
		o.host = host
		if err := o.validate(); err != nil {
			t.Fatal("valid loopback neighbour", err)
		}
	}
}

// Claim: generated keys are 0600, never overwritten and normalized to the even-y seal key.
func TestPrivateOutput(t *testing.T) {
	dir := t.TempDir()
	s, err := makeKey(dir, "issuer.key")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "issuer.key")
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("key mode")
	}
	before, err := os.ReadFile(path)
	if err != nil || s.key.PubKey().SerializeCompressed()[0] != 2 {
		t.Fatal("key normalization")
	}
	if _, err = makeKey(dir, "issuer.key"); err == nil {
		t.Fatal("overwrote key")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("key changed")
	}
}

// Claim: flags reject unsafe numeric/terms bounds before RPC, while supported custom amounts produce fee-inclusive caps without changing the fixed network or names.
func TestParameterBounds(t *testing.T) {
	for _, flags := range [][]string{
		{"--allowance-sat", "19999"}, {"--allowance-sat", "9223372036854775807"},
		{"--fee-limit-sat", "0"}, {"--fee-limit-sat", "1000001"},
		{"--valid-for", "59s"}, {"--valid-for", "25h"},
		{"--rpc-port", "0"}, {"--rpc-port", "65536"},
		{"--executor-key", "invalid"}, {"--recipient", "invalid"},
	} {
		o, calls := serverOptions(t, "regtest", su.RegtestGenesis)
		var out, diag bytes.Buffer
		if run(append(arguments(o), flags...), &out, &diag) != 1 || out.Len() != 0 || len(*calls) != 0 {
			t.Fatal("unsafe parameter reached RPC")
		}
		if _, err := os.Lstat(o.out); !os.IsNotExist(err) {
			t.Fatal("invalid parameters created output")
		}
	}
	o, calls := serverOptions(t, "main", su.RegtestGenesis)
	var out, diag bytes.Buffer
	if run(append(arguments(o), "--allowance-sat", "40000", "--fee-limit-sat", "25000", "--valid-for", "2h"), &out, &diag) != 1 || diag.String() != "rt-grant-fixture: REGTEST_REQUIRED\n" || !reflect.DeepEqual(*calls, []string{"getblockchaininfo"}) {
		t.Fatal("valid custom flags did not reach chain gate")
	}
	o.allowance, o.fee = 40000, 25000
	terms := o.terms()
	if terms.SpendCap != 65000 || terms.TransferCap != 65000 || terms.DayCap != 65000 || terms.FeeCap != 25000 || terms.Network != "regtest" || terms.Genesis != su.RegtestGenesis {
		t.Fatal("custom cap derivation")
	}
}
