package deploy

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func validPolicy(service string) Policy {
	p := Policy{Version: 1, Network: "regtest", Service: service, ReleaseVersion: "v0.1.0-regtest", Commit: strings.Repeat("a", 40), BinarySHA256: strings.Repeat("b", 64), StateDir: "/var/lib/swarma-" + service, Config: "/etc/swarma/" + service + "/service.json", Listen: "127.0.0.1:8091"}
	if service == "booking" {
		p.Listen = "127.0.0.1:18819"
		p.Profile = "/etc/swarma/booking/profile.bin"
		p.ProviderKey = "/var/lib/swarma-booking/provider.hex"
		p.Route = "/etc/swarma/booking/operator-route.json"
		p.NodeCLI = "/opt/namecoin/28.0/bin/namecoin-cli"
		p.NodeCLISHA256 = strings.Repeat("c", 64)
		p.RPCConfig = "/var/lib/swarma-booking/rpc/namecoin.conf"
		p.RPCClientDataDir = "/var/lib/swarma-booking/rpc/client"
		p.RPCEndpoint = "127.0.0.1:18443"
		p.Relay = "ws://127.0.0.1:18818"
	}
	if service == "gateway" {
		p.Listen = "127.0.0.1:9444"
		p.ManagerListen = "127.0.0.1:9443"
		p.Screening = "off"
		p.StationDriver = "manager"
	}
	if service == "relay" {
		p.Listen = "127.0.0.1:18818"
	}
	return p
}
func encoded(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

// Complete public regtest policies accept without opening referenced custody
// files. Mainnet, unresolved values, wrong routes and foreign writable roots
// reject with fixed error classes beside those valid neighbours.
func TestPolicy(t *testing.T) {
	for _, service := range []string{"booking", "store", "gateway", "relay"} {
		t.Run(service, func(t *testing.T) {
			p := validPolicy(service)
			if got, e := Validate(encoded(t, p)); e != nil || got != p {
				t.Fatal("complete regtest policy refused")
			}
			for _, tc := range []struct {
				name   string
				change func(*Policy)
				err    error
			}{
				{"mainnet", func(p *Policy) { p.Network = "main"; p.BinarySHA256 = "PLACEHOLDER" }, ErrNetwork},
				{"mainnet-complete", func(p *Policy) { p.Network = "main" }, ErrNetwork},
				{"placeholder", func(p *Policy) { p.BinarySHA256 = "PLACEHOLDER_HASH" }, ErrPlaceholder},
				{"version", func(p *Policy) { p.Version = 2 }, ErrPolicy},
				{"release-path", func(p *Policy) { p.ReleaseVersion = "../../escape" }, ErrPolicy},
				{"hash", func(p *Policy) { p.BinarySHA256 = strings.Repeat("Z", 64) }, ErrPolicy},
				{"short-commit", func(p *Policy) { p.Commit = "abcdef" }, ErrPolicy},
				{"wildcard-listen", func(p *Policy) { p.Listen = "0.0.0.0:8091" }, ErrPolicy},
				{"foreign-state", func(p *Policy) { p.StateDir = "/var/lib/namecoind-regtest" }, ErrPolicy},
				{"foreign-config", func(p *Policy) { p.Config = "/tmp/config" }, ErrPolicy},
				{"unknown-service", func(p *Policy) { p.Service = "unknown" }, ErrPolicy},
			} {
				t.Run(tc.name, func(t *testing.T) {
					x := p
					tc.change(&x)
					got, e := Validate(encoded(t, x))
					if e != tc.err || got != (Policy{}) {
						t.Fatalf("invalid policy accepted or wrong refusal: %v", e)
					}
				})
			}
		})
	}
}

// Public node routing cannot point to mainnet, network credentials in a URL,
// another service's secrets, or the node wallet datadir.
func TestBookingRoute(t *testing.T) {
	for _, change := range []func(*Policy){
		func(p *Policy) { p.RPCEndpoint = "127.0.0.1:8336" }, func(p *Policy) { p.Relay = "ws://user:secret@127.0.0.1:18818" },
		func(p *Policy) { p.RPCConfig = "/var/lib/swarma-store/key" }, func(p *Policy) { p.RPCClientDataDir = "/var/lib/namecoind-regtest" },
		func(p *Policy) { p.NodeCLI = "/tmp/namecoin-cli" }, func(p *Policy) { p.NodeCLISHA256 = "" }, func(p *Policy) { p.Relay = "ws://example.com:18818" },
	} {
		p := validPolicy("booking")
		change(&p)
		if _, e := Validate(encoded(t, p)); e != ErrPolicy {
			t.Fatal("invalid route accepted")
		}
	}
	p := validPolicy("store")
	p.ProviderKey = "/var/lib/swarma-store/unused-key"
	if _, e := Validate(encoded(t, p)); e != ErrPolicy {
		t.Fatal("store was assigned a signing key")
	}
}

// Duplicate/unknown fields, trailing JSON and excess bytes cannot change the
// interpretation of network or refs; raw sensitive text is never echoed.
func TestPolicyFraming(t *testing.T) {
	valid := string(encoded(t, validPolicy("store")))
	for _, raw := range []string{strings.Replace(valid, `"network":"regtest"`, `"network":"main","network":"regtest"`, 1), strings.TrimSuffix(valid, "}") + `,"secret":"sensitive-marker"}`, valid + valid, strings.Repeat(" ", 16385), `null`, `{}`} {
		_, e := Validate([]byte(raw))
		if e == nil || strings.Contains(e.Error(), "sensitive-marker") {
			t.Fatal("malformed policy accepted or input leaked")
		}
	}
}

// Shipped templates stay inert until their public pins are supplied. There is
// all supported units retain the requested hardening and contain no secrets.
func TestTemplates(t *testing.T) {
	for _, service := range []string{"booking", "store", "gateway", "relay"} {
		raw, e := os.ReadFile("templates/" + service + "/deploy.json")
		if e != nil {
			t.Fatal(e)
		}
		if _, e = Validate(raw); e != ErrPlaceholder {
			t.Fatal("unfilled template accepted")
		}
		unit, e := os.ReadFile("templates/systemd/swarma-" + service + ".service.in")
		if e != nil {
			t.Fatal(e)
		}
		for _, required := range []string{"User=swarma-" + service, "ProtectSystem=strict", "NoNewPrivileges=true", "PrivateTmp=true", "MemoryMax=", "ReadWritePaths=/var/lib/swarma-" + service, "IPAddressDeny=any", "IPAddressAllow=127.0.0.1/32"} {
			if !strings.Contains(string(unit), required) {
				t.Fatalf("unit missing %s", required)
			}
		}
		for _, forbidden := range []string{"/Users/", "/home/", "rpcpassword", "rpcuser", "stub-verdict", "Environment="} {
			if strings.Contains(string(unit), forbidden) {
				t.Fatal("forbidden unit credential/path/stub")
			}
		}
	}
}

// Gateway policy requires the real manager and explicit screening off. Separate
// pinned listener inputs cannot be replaced by wildcards, shared endpoints or
// a test driver, while an operator-selected literal host address is accepted.
func TestGatewayPolicy(t *testing.T) {
	base := validPolicy("gateway")
	for _, change := range []func(*Policy){
		func(p *Policy) { p.Screening = "stub" }, func(p *Policy) { p.Screening = "" }, func(p *Policy) { p.StationDriver = "local-test" },
		func(p *Policy) { p.ManagerListen = p.Listen }, func(p *Policy) { p.ManagerListen = "0.0.0.0:9443" }, func(p *Policy) { p.Listen = "localhost:9444" },
		func(p *Policy) { p.ProviderKey = "/var/lib/swarma-gateway/key" },
	} {
		p := base
		change(&p)
		if _, e := Validate(encoded(t, p)); e != ErrPolicy {
			t.Fatal("gateway policy guard missing")
		}
	}
	base.Listen = "192.0.2.10:9444"
	base.ManagerListen = "192.0.2.10:9443"
	if _, e := Validate(encoded(t, base)); e != nil {
		t.Fatal("literal gateway host refused", e)
	}
}

// Supplemental native JSON checks cannot overlook nested placeholders, network
// mismatches, duplicate keys or inline credentials; ordinary public pins pass.
func TestPublicJSON(t *testing.T) {
	if e := ValidatePublicJSON([]byte(`{"Network":"regtest","NodeConfig":"/var/lib/swarma-booking/rpc/namecoin.conf"}`)); e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		raw  string
		want error
	}{
		{`{"Network":"main"}`, ErrNetwork},
		{`{"writers":["PLACEHOLDER_KEY"]}`, ErrPlaceholder},
		{`{"rpcpassword":"sensitive-marker"}`, ErrPolicy},
		{`{"nested":{"private_key":"sensitive-marker"}}`, ErrPolicy},
		{`{"Network":"main","Network":"regtest"}`, ErrPolicy},
		{`null`, ErrPolicy},
	} {
		if e := ValidatePublicJSON([]byte(tc.raw)); e != tc.want {
			t.Fatalf("public config guard: %v", e)
		}
	}
}
