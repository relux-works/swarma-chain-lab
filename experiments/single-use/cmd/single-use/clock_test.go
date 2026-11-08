package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Mainnet backdating, including an explicit empty override, must be a CLI
// rejection before any route construction, RPC, journal or public verifier call.
// Regtest keeps accepting a syntactically valid override (later policy refuses).
func TestMainClockOverride(t *testing.T) {
	for _, tc := range []struct {
		network, flag string
		want          int
	}{{"main", "--test-at=2026-11-08T00:00:00Z", 2}, {"main", "--test-at=", 2}, {"regtest", "--test-at=2026-11-08T00:00:00Z", 1}} {
		t.Run(tc.network+tc.flag, func(t *testing.T) {
			d := t.TempDir()
			genesis := "000000000062b72c5e2ceb45fbc8587e807c155b0da735e6483dfba2f0a9c770"
			if tc.network == "regtest" {
				genesis = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
			}
			b, _ := json.Marshal(map[string]any{"network": tc.network, "genesis": genesis})
			for name, raw := range map[string][]byte{"policy": b, "route": []byte(`{"host":"127.0.0.1","port":1,"username":"w3-observer","password":"test-only-not-a-real-secret"}`), "certificate": []byte("public-certificate"), "request": []byte("public-request")} {
				if e := os.WriteFile(filepath.Join(d, name), raw, 0600); e != nil {
					t.Fatal(e)
				}
			}
			old := os.Args
			defer func() { os.Args = old }()
			os.Args = []string{"single-use", "--policy", d + "/policy", "--route", d + "/route", "--certificate", d + "/certificate", "--request", d + "/request", tc.flag}
			if got := run(); got != tc.want {
				t.Fatalf("clock route got exit%d want%d", got, tc.want)
			}
		})
	}
}

// Both CLI input paths reject writable mode before observation. The same
// non-writable inputs reach ordinary policy validation (exit1, no node calls).
func TestWritableRouteAndPolicyCLI(t *testing.T) {
	for _, which := range []string{"none", "policy", "route"} {
		t.Run(which, func(t *testing.T) {
			d := t.TempDir()
			files := map[string]string{"policy": `{"network":"regtest","genesis":"0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"}`, "route": `{"host":"127.0.0.1","port":1,"username":"w3-observer","password":"test-only-not-a-real-secret"}`, "certificate": "public-certificate", "request": "public-request"}
			for name, b := range files {
				if e := os.WriteFile(d+"/"+name, []byte(b), 0600); e != nil {
					t.Fatal(e)
				}
			}
			want := 1
			if which != "none" {
				want = 2
				if e := os.Chmod(d+"/"+which, 0620); e != nil {
					t.Fatal(e)
				}
			}
			old := os.Args
			defer func() { os.Args = old }()
			os.Args = []string{"single-use", "--policy", d + "/policy", "--route", d + "/route", "--certificate", d + "/certificate", "--request", d + "/request"}
			if got := run(); got != want {
				t.Fatalf("%s got%d want%d", which, got, want)
			}
		})
	}
}
