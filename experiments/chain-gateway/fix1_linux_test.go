package chaingateway

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every Core network-key form refuses each unsafe setting before HTTP and keeps
// previous bytes/inode/mtime, beside a full loopback publication control. The
// whitelist independently refuses includes, including those in inactive scopes.
func TestNodeConfigNetworkForms(t *testing.T) {
	forms := []struct{ name, header, prefix string }{{"bare", "", ""}}
	for _, network := range []string{"main", "test", "testnet4", "signet", "regtest"} {
		forms = append(forms, struct{ name, header, prefix string }{network + "_prefix", "", network + "."})
		forms = append(forms, struct{ name, header, prefix string }{network + "_section", "[" + network + "]\n", ""})
	}
	for _, form := range forms {
		t.Run(form.name, func(t *testing.T) {
			for _, kind := range []string{"loopback_control", "rpcbind", "rpcallowip", "includeconf"} {
				t.Run(kind, func(t *testing.T) {
					x := makeFixture(t, "rpcauth-user")
					old, previous := x.previous(t)
					extra := form.prefix + "rpcbind=127.0.0.1\n" + form.prefix + "rpcallowip=127.0.0.1\n"
					switch kind {
					case "rpcbind":
						extra = form.prefix + "rpcbind=192.0.2.10\n"
					case "rpcallowip":
						extra = form.prefix + "rpcallowip=192.0.2.0/24\n"
					case "includeconf":
						extra = form.prefix + "includeconf=other.conf\n"
					}
					config := loopbackPolicy + "rpcwhitelistdefault=1\nrpcwhitelist=snapshot-observer:" + verifierMethods + "\n" + form.header + extra
					if e := os.WriteFile(x.c.NodeConfig, []byte(config), 0600); e != nil {
						t.Fatal(e)
					}
					want := map[string]string{"rpcbind": "node bind", "rpcallowip": "node allow", "includeconf": "included node config"}[kind]
					e := verifyNodeLoopback(x.c, x.p)
					if kind == "loopback_control" {
						if e != nil {
							t.Fatal(e)
						}
					} else if e == nil || e.Error() != want {
						t.Fatalf("node policy refusal: got %v want %s", e, want)
					}
					e = verifyWhitelist(x.c, x.p)
					if kind == "includeconf" {
						if e == nil || e.Error() != "uninspected included config" {
							t.Fatalf("whitelist include refusal: %v", e)
						}
					} else if e != nil {
						t.Fatal(e)
					}
					code, _ := x.execute()
					if kind == "loopback_control" {
						if code != 0 {
							t.Fatalf("loopback control exit %d", code)
						}
					} else {
						if code != 11 {
							t.Fatalf("unsafe policy exit %d want 11", code)
						}
						x.unchanged(t, old, previous)
						if len(x.rpc.methods) != 0 {
							t.Fatal("HTTP before policy proof")
						}
					}
				})
			}
		})
	}
}

// Active dotted/section policies can independently supply both required values;
// inactive-only values cannot, and nested section+prefix includes never escape.
func TestNodeConfigScopeAndBoundaries(t *testing.T) {
	for _, tc := range []struct{ name, config, refusal string }{
		{"active_prefix", "regtest.rpcbind=127.0.0.1\nregtest.rpcallowip=127.0.0.1\n", ""},
		{"active_section", "[regtest]\nrpcbind=::1\nrpcallowip=::1/128\n", ""},
		{"inactive_only", "main.rpcbind=127.0.0.1\nmain.rpcallowip=127.0.0.1\n", "explicit node loopback policy"},
		{"nested_include", loopbackPolicy + "[test]\nregtest.includeconf=other.conf\n", "included node config"},
		{"valueless_include", loopbackPolicy + "signet.includeconf\n", "included node config"},
		{"ipv4_range", "rpcbind=127.0.0.1:1234\nrpcallowip=127.0.0.0/8\n", ""},
		{"broad_ipv4", "rpcbind=127.0.0.1\nrpcallowip=127.0.0.1/7\n", "node allow"},
		{"broad_ipv6", "rpcbind=::1\nrpcallowip=::1/127\n", "node allow"},
		{"malformed_section", loopbackPolicy + "[regtest]]\n", "config section"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := makeFixture(t, "cookie")
			if e := os.WriteFile(x.c.NodeConfig, []byte(tc.config), 0600); e != nil {
				t.Fatal(e)
			}
			e := verifyNodeLoopback(x.c, x.p)
			if tc.refusal == "" {
				if e != nil {
					t.Fatal(e)
				}
			} else if e == nil || e.Error() != tc.refusal {
				t.Fatalf("policy got %v want %s", e, tc.refusal)
			}
		})
	}
}

// Reserved crash-temp basenames are refused before lock/cleanup can remove a
// configured output or held lock. Nearby nonmatching names publish normally.
func TestReservedSnapshotPaths(t *testing.T) {
	for _, field := range []string{"output", "lock"} {
		for _, reserved := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%t", field, reserved), func(t *testing.T) {
				x := makeFixture(t, "cookie")
				name := ".snapshot-" + strings.Repeat("a", 24)
				if !reserved {
					name += "-kept"
				}
				path := filepath.Join(x.root, name)
				if field == "output" {
					x.c.Output = path
				} else {
					x.c.Lock = path
				}
				old, previous := x.previous(t)
				x.config(t)
				_, e := loadConfig(x.path, x.p)
				if reserved && (e == nil || e.Error() != "reserved snapshot temp name") {
					t.Fatalf("reserved path refusal: %v", e)
				}
				code, _ := x.execute()
				if reserved {
					if code != 11 {
						t.Fatalf("reserved path exit %d", code)
					}
					x.unchanged(t, old, previous)
					if len(x.rpc.methods) != 0 {
						t.Fatal("RPC before path refusal")
					}
				} else if e != nil || code != 0 {
					t.Fatalf("nonreserved control: %v exit %d", e, code)
				}
			})
		}
	}
}

// Only the closing blockchain-info response carries the wrong network; a full
// valid control publishes, while the closing refusal preserves the prior file.
func TestClosingBracketNetwork(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		t.Run(fmt.Sprint(invalid), func(t *testing.T) {
			x := makeFixture(t, "cookie")
			old, previous := x.previous(t)
			if invalid {
				x.rpc.invalid = "closing_network"
			}
			code, _ := x.execute()
			if !invalid {
				if code != 0 {
					t.Fatalf("closing control exit %d", code)
				}
				return
			}
			if code != 11 || x.rpc.tipCalls != 2 {
				t.Fatalf("closing refusal exit %d brackets %d", code, x.rpc.tipCalls)
			}
			x.unchanged(t, old, previous)
		})
	}
}

// The greatest qualified signed vout is dispatched unchanged and published;
// TestUnqualifiedHighVoutKeepsPrevious covers the adjacent forbidden value.
func TestQualifiedVoutBoundary(t *testing.T) {
	x := makeFixture(t, "cookie")
	x.rpc.flexible = true
	x.c.Seals[0].Vout = 2147483647
	x.config(t)
	if code, _ := x.execute(); code != 0 {
		t.Fatalf("qualified boundary exit %d", code)
	}
	raw, e := os.ReadFile(x.c.Output)
	if e != nil {
		t.Fatal(e)
	}
	snapshot, e := parse(raw, 65536)
	if e != nil {
		t.Fatal(e)
	}
	point := snapshot["seals"].([]any)[0].(map[string]any)
	if uintValue(point["vout"]) != 2147483647 {
		t.Fatal("boundary vout changed")
	}
	calls := 0
	for _, method := range x.rpc.methods {
		if method == "gettxout" {
			calls++
		}
	}
	if calls != 2 {
		t.Fatalf("boundary fixed-view calls %d", calls)
	}
}
