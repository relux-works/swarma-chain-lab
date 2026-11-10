package deploy

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func newPolicy(service string) Policy {
	p := Policy{Version: 1, Network: "regtest", Service: service, ReleaseVersion: "fixture-regtest", Commit: strings.Repeat("a", 40), BinarySHA256: strings.Repeat("b", 64)}
	if service != "payload" {
		p.StateDir = "/var/lib/swarma-" + service
		p.Config = "/etc/swarma/" + service + "/service.json"
	}
	if service == "model" {
		p.Listen = "127.0.0.1:8443"
	}
	return p
}
func modelFixture() modelConfig {
	uid := uint32(1001)
	c := modelConfig{StateDir: "/var/lib/swarma-model", Listen: "127.0.0.1:8443", TLSCert: "/etc/swarma/model/tls.pem", TLSKey: "/etc/swarma/model/tls.key", AdminSocket: "/run/swarma-model/admin.sock", CallerUID: &uid, Upstream: "https://upstream.invalid/v1/messages", APIKeyFile: "/etc/swarma/model/api.key", Models: map[string]modelSpec{"fixture-model": {ContextTokens: 100, InputNanoUSD: 1, OutputNanoUSD: 2, Source: "synthetic test prices, not an operator approval"}}}
	c.Endpoint.URL = "https://model.invalid:8443"
	c.Endpoint.CertSHA256 = strings.Repeat("a", 64)
	return c
}
func stationsFixture() stationsConfig {
	return stationsConfig{StateDir: "/var/lib/swarma-stations", Socket: "/run/swarma-slotd-demo/sock", SlotMin: 1, SlotMax: 2, PayloadID: "scripted-station-v1", PayloadSHA256: strings.Repeat("a", 64), Endpoint: "https://192.0.2.10:9443/v1/station-manager/poll", GatewayCertSHA256: strings.Repeat("b", 64), ClientCert: "/etc/swarma/stations/client.pem", ClientKey: "/etc/swarma/stations/client.key", ServerCA: "/etc/swarma/stations/gateway-ca.pem"}
}
func issuerFixture() issuerConfig {
	var f issuerConfig
	f.PaymentRouteFiles = map[string]string{"nmc": "/etc/swarma/issuer/payment-nmc.json"}
	f.Config.PresentationDir = "/var/lib/swarma-issuer/presentations"
	f.Config.Profile = "v2"
	f.Config.PaymentPolicies = map[string]paymentPolicy{"nmc": {MaxRateAgeSeconds: 60, MinConfirmations: 1, Limits: paymentLimits{MaxBlocks: 100, MaxMempool: 100, MaxCalls: 1000, MaxBytes: 1000000}}}
	seal := "76a914" + strings.Repeat("a", 40) + "88ac"
	fund := "0014" + strings.Repeat("b", 40)
	f.Config.Policy.Policy = issuerPolicy{ConstructionProfile: "W", Network: "regtest", Genesis: regtestGenesis, IssuerPubkey: strings.Repeat("a", 64), AgentPubkey: strings.Repeat("b", 64), StationName: "id/fixture-agent", StationScript: seal, StateDir: "/var/lib/swarma-issuer/issuance", AgentName: "id/fixture-agent", SealScript: seal, LandlordName: "id/fixture-landlord", FundingScript: fund}
	f.Config.Policy.ProviderPubkey = strings.Repeat("c", 64)
	f.Config.StateDir = "/var/lib/swarma-issuer/ledger"
	f.Config.GrantKeyPath = "/etc/swarma/issuer/grant.key"
	f.Config.FundingKeyPath = "/etc/swarma/issuer/funding.key"
	// Synthetic caps only. No test fixture supplies approval or template defaults.
	f.Config.Caps = issuerCaps{FeePerTx: 1000, CountHour: 1, CountDay: 2, BudgetHour: 3000000, BudgetDay: 6000000, RefillCount: 1, SealValue: 100000, RefillValue: 200000, LowWater: 1}
	f.ReadRouteFile = "/etc/swarma/issuer/read-route.json"
	f.BroadcastRouteFile = "/etc/swarma/issuer/broadcast-route.json"
	f.BookingOutbox = "/var/lib/swarma-issuer/intake/booking"
	f.OperatorOutbox = "/var/lib/swarma-issuer/intake/operator"
	f.StoreURL = "http://127.0.0.1:8091"
	f.StoreLandlordReader = strings.Repeat("a", 64)
	f.StoreAgentReader = strings.Repeat("b", 64)
	f.IntervalSeconds = 2
	return f
}
func nativeFixture(t *testing.T, service string) []byte {
	switch service {
	case "issuer":
		return encoded(t, issuerFixture())
	case "model":
		return encoded(t, modelFixture())
	case "stations":
		return encoded(t, stationsFixture())
	}
	return nil
}

// Complete new regtest descriptors are accepted; mainnet (even with resolved
// pins), foreign paths, omitted hashes and inherited gateway-only fields refuse.
// Payload has no invented state directory, listener, native config or unit.
func TestNewServicePolicies(t *testing.T) {
	for _, service := range []string{"issuer", "model", "stations", "payload"} {
		t.Run(service, func(t *testing.T) {
			p := newPolicy(service)
			if got, e := Validate(encoded(t, p)); e != nil || got != p {
				t.Fatal("valid descriptor refused", e)
			}
			for _, tc := range []struct {
				name   string
				change func(*Policy)
				want   error
			}{
				{"mainnet", func(p *Policy) { p.Network = "main" }, ErrNetwork},
				{"mainnet-placeholder", func(p *Policy) { p.Network = "main"; p.BinarySHA256 = "PLACEHOLDER" }, ErrNetwork},
				{"missing-binary", func(p *Policy) { p.BinarySHA256 = "" }, ErrPolicy},
				{"placeholder", func(p *Policy) { p.BinarySHA256 = "PLACEHOLDER" }, ErrPlaceholder},
				{"foreign-state", func(p *Policy) { p.StateDir = "/var/lib/unrelated" }, ErrPolicy},
				{"gateway-field", func(p *Policy) { p.StationDriver = "manager" }, ErrPolicy},
				{"foreign-config", func(p *Policy) { p.Config = "/tmp/config" }, ErrPolicy},
				{"wildcard", func(p *Policy) { p.Listen = "0.0.0.0:8443" }, ErrPolicy},
			} {
				t.Run(tc.name, func(t *testing.T) {
					bad := p
					tc.change(&bad)
					if got, e := Validate(encoded(t, bad)); e != tc.want || got != (Policy{}) {
						t.Fatal("descriptor guard missing", e)
					}
				})
			}
			var inputs [][]byte
			if service != "payload" {
				inputs = [][]byte{nativeFixture(t, service)}
			} else {
				c := modelFixture()
				inputs = [][]byte{encoded(t, payloadPair{"messages", "fixture-model", 10, c.Endpoint.URL, c.Endpoint.CertSHA256}), encoded(t, c)}
			}
			if e := ValidateServiceInputs(p, inputs); e != nil {
				t.Fatal("complete native input refused", e)
			}
			if service == "payload" {
				if e := ValidateServiceInputs(p, [][]byte{[]byte(`{}`)}); e != ErrPolicy {
					t.Fatal("invented payload config accepted")
				}
			} else {
				for _, bad := range [][][]byte{nil, {inputs[0], inputs[0]}} {
					if e := ValidateServiceInputs(p, bad); e != ErrPolicy {
						t.Fatal("missing or ambiguous native file accepted")
					}
				}
			}
		})
	}
}

// Fixed public validation rejects exact wrong values without opening any path.
// These controls do not claim native key/curve validation or filesystem checks.
func TestModelConfigBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*modelConfig)
	}{
		{"tls-key", func(c *modelConfig) { c.TLSKey = "" }}, {"api-key", func(c *modelConfig) { c.APIKeyFile = "/etc/swarma/issuer/grant.key" }},
		{"uid-absent", func(c *modelConfig) { c.CallerUID = nil }}, {"root-caller", func(c *modelConfig) { v := uint32(0); c.CallerUID = &v }},
		{"partial-endpoint", func(c *modelConfig) { c.Endpoint.CertSHA256 = "" }}, {"endpoint-port", func(c *modelConfig) { c.Endpoint.URL = "https://model.invalid" }},
		{"upstream-credentials", func(c *modelConfig) { c.Upstream = "https://user:private-marker@upstream.invalid/v1/messages" }},
		{"upstream-redirect-path", func(c *modelConfig) { c.Upstream = "https://upstream.invalid/other" }},
		{"foreign-socket", func(c *modelConfig) { c.AdminSocket = "/run/swarma-slotd-demo/sock" }},
		{"models-absent", func(c *modelConfig) { c.Models = nil }},
		{"missing-price", func(c *modelConfig) {
			m := c.Models["fixture-model"]
			m.InputNanoUSD = 0
			c.Models["fixture-model"] = m
		}},
		{"price-overflow", func(c *modelConfig) {
			m := c.Models["fixture-model"]
			m.InputNanoUSD = ^uint64(0)
			c.Models["fixture-model"] = m
		}},
		{"price-add-overflow", func(c *modelConfig) { c.Models["fixture-model"] = modelSpec{1, ^uint64(0), 1, "fixture"} }},
		{"missing-source", func(c *modelConfig) { m := c.Models["fixture-model"]; m.Source = ""; c.Models["fixture-model"] = m }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := modelFixture()
			if e := ValidateServiceInputs(newPolicy("model"), [][]byte{encoded(t, c)}); e != nil {
				t.Fatal(e)
			}
			tc.change(&c)
			if e := ValidateServiceInputs(newPolicy("model"), [][]byte{encoded(t, c)}); e != ErrPolicy {
				t.Fatal("model guard missing", e)
			}
		})
	}
}

// Manager policy binds its credential paths, exact poll route, slot range and
// payload identity. No fictitious helper policy or bootstrap field is accepted.
func TestStationsConfigBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*stationsConfig)
	}{
		{"key", func(c *stationsConfig) { c.ClientKey = "" }}, {"ca", func(c *stationsConfig) { c.ServerCA = "" }},
		{"pin", func(c *stationsConfig) { c.GatewayCertSHA256 = "" }}, {"payload", func(c *stationsConfig) { c.PayloadSHA256 = "" }},
		{"slot-reversed", func(c *stationsConfig) { c.SlotMin = 3 }}, {"slot-bound", func(c *stationsConfig) { c.SlotMax = 10000 }},
		{"socket", func(c *stationsConfig) { c.Socket = "/run/other/sock" }},
		{"poll-path", func(c *stationsConfig) { c.Endpoint = "https://192.0.2.10:9443/other" }},
		{"poll-hostname", func(c *stationsConfig) { c.Endpoint = "https://gateway.invalid:9443/v1/station-manager/poll" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := stationsFixture()
			if e := ValidateServiceInputs(newPolicy("stations"), [][]byte{encoded(t, c)}); e != nil {
				t.Fatal(e)
			}
			tc.change(&c)
			if e := ValidateServiceInputs(newPolicy("stations"), [][]byte{encoded(t, c)}); e != ErrPolicy {
				t.Fatal("manager guard missing", e)
			}
		})
	}
}

// Signer references stay separated and bounded; complete v2 synthetic policy
// is the positive control beside missing keys/routes, incomplete caps and coins.
func TestIssuerConfigBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*issuerConfig)
		want   error
	}{
		{"missing-W", func(f *issuerConfig) { f.Config.Policy.Policy.ConstructionProfile = "" }, ErrPolicy},
		{"legacy-funding", func(f *issuerConfig) {
			f.Config.Policy.Policy.FundingScript = "76a914" + strings.Repeat("b", 40) + "88ac"
		}, ErrPolicy},
		{"grant-key", func(f *issuerConfig) { f.Config.GrantKeyPath = "" }, ErrPolicy},
		{"funding-key", func(f *issuerConfig) { f.Config.FundingKeyPath = f.Config.GrantKeyPath }, ErrPolicy},
		{"read-route", func(f *issuerConfig) { f.ReadRouteFile = "" }, ErrPolicy},
		{"broadcast-route", func(f *issuerConfig) { f.BroadcastRouteFile = f.ReadRouteFile }, ErrPolicy},
		{"v1", func(f *issuerConfig) { f.Config.Profile = "v1-nmc" }, ErrPolicy},
		{"missing-coin-route", func(f *issuerConfig) { delete(f.PaymentRouteFiles, "nmc") }, ErrPolicy},
		{"foreign-coin-route", func(f *issuerConfig) { f.PaymentRouteFiles["nmc"] = "/etc/swarma/booking/rpc.json" }, ErrPolicy},
		{"partial-caps", func(f *issuerConfig) { f.Config.Caps.BudgetDay = 0 }, ErrPolicy},
		{"cap-count", func(f *issuerConfig) { f.Config.Caps.CountDay = 65 }, ErrPolicy},
		{"refill-overflow", func(f *issuerConfig) { f.Config.Caps.SealValue = maxMoney; f.Config.Caps.RefillCount = 16 }, ErrPolicy},
		{"missing-provider", func(f *issuerConfig) { f.Config.Policy.ProviderPubkey = "" }, ErrPolicy},
		{"wrong-genesis", func(f *issuerConfig) { f.Config.Policy.Policy.Genesis = strings.Repeat("a", 64) }, ErrNetwork},
		{"mainnet", func(f *issuerConfig) { f.Config.Policy.Policy.Network = "main" }, ErrNetwork},
		{"shared-ledger", func(f *issuerConfig) { f.Config.StateDir = f.Config.Policy.Policy.StateDir }, ErrPolicy},
		{"cross-user-intake", func(f *issuerConfig) { f.BookingOutbox = "/var/lib/swarma-booking" }, ErrPolicy},
		{"unavailable-remote-store", func(f *issuerConfig) { f.StoreURL = "https://store.invalid" }, ErrPolicy},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := issuerFixture()
			if e := ValidateServiceInputs(newPolicy("issuer"), [][]byte{encoded(t, f)}); e != nil {
				t.Fatal(e)
			}
			tc.change(&f)
			if e := ValidateServiceInputs(newPolicy("issuer"), [][]byte{encoded(t, f)}); e != tc.want {
				t.Fatal("issuer guard missing", e)
			}
		})
	}
}

// Closed fields, duplicate/aliased keys and missing sections cannot pass the
// shared reader. Canonical native model/manager configs reject pretty JSON;
// the signer deliberately permits whitespace because its loader does.
func TestNewNativeFraming(t *testing.T) {
	for _, service := range []string{"issuer", "model", "stations"} {
		t.Run(service, func(t *testing.T) {
			raw := nativeFixture(t, service)
			p := newPolicy(service)
			for _, bad := range [][]byte{[]byte(`{}`), []byte(`null`), append(append([]byte{}, raw...), raw...), append([]byte(`{"unknown":"private-marker",`), raw[1:]...), bytes.Replace(raw, []byte(`"state_dir":`), []byte(`"State_dir":`), 1), bytes.Replace(raw, []byte(`"state_dir":`), []byte(`"state_dir":"/bad","state_dir":`), 1)} {
				if e := ValidateServiceInputs(p, [][]byte{bad}); e != ErrPolicy || strings.Contains(e.Error(), "private-marker") {
					t.Fatal("framing accepted or reflected", e)
				}
			}
			var pretty bytes.Buffer
			if e := json.Indent(&pretty, raw, "", "  "); e != nil {
				t.Fatal(e)
			}
			e := ValidateServiceInputs(p, [][]byte{pretty.Bytes()})
			if service == "issuer" {
				if e != nil {
					t.Fatal("valid signer whitespace refused", e)
				}
			} else if e != ErrPolicy {
				t.Fatal("noncanonical native input accepted", e)
			}
			if e := ValidateServiceInputs(p, [][]byte{[]byte(`{"network":"main","key":"PLACEHOLDER"}`)}); e != ErrNetwork && e != ErrPlaceholder {
				t.Fatal("mainnet placeholder input accepted", e)
			}
		})
	}
}

// Public templates remain unusable until pins and owner-approved values are
// supplied. Every new service has only its own writable roots and credential
// references; the payload policy is explicitly non-installable documentation.
func TestDK2Templates(t *testing.T) {
	for _, service := range []string{"issuer", "model", "stations", "payload"} {
		b, e := os.ReadFile("templates/" + service + "/deploy.json")
		if e != nil {
			t.Fatal(e)
		}
		if _, e = Validate(b); e != ErrPlaceholder {
			t.Fatal("unfinished descriptor accepted", service, e)
		}
		if service == "payload" {
			if _, e = os.Stat("templates/systemd/swarma-payload.service.in"); !os.IsNotExist(e) {
				t.Fatal("payload got standalone unit")
			}
			b, e = os.ReadFile("templates/payload/POLICY-NEEDS.md")
			if e != nil || !bytes.Contains(b, []byte("not** an installable")) {
				t.Fatal("missing policy disclaimer")
			}
			continue
		}
		b, e = os.ReadFile("templates/" + service + "/service.json")
		if e != nil {
			t.Fatal(e)
		}
		if e = ValidateServiceInputs(newPolicy(service), [][]byte{b}); e != ErrPlaceholder {
			t.Fatal("unfinished native accepted", service, e)
		}
		b, e = os.ReadFile("templates/systemd/swarma-" + service + ".service.in")
		if e != nil {
			t.Fatal(e)
		}
		for _, s := range []string{"User=swarma-" + service, "Group=swarma-" + service, "ProtectSystem=strict", "NoNewPrivileges=true", "ReadOnlyPaths=/etc/swarma/" + service, "ReadWritePaths=/var/lib/swarma-" + service, "StateDirectoryMode=0700", "IPAddressDeny=any", "CapabilityBoundingSet=\n"} {
			if !bytes.Contains(b, []byte(s)) {
				t.Fatal("unit missing boundary", service, s)
			}
		}
		for _, s := range []string{"/Users/", "/home/", "Environment=", "slotdfake", "rm -"} {
			if bytes.Contains(b, []byte(s)) {
				t.Fatal("unsafe unit directive", service)
			}
		}
	}
}

// Unit write grants are closed to the named state root and the model's one
// runtime socket directory. A required safe line cannot hide an extra grant.
func TestDK2UnitWritePaths(t *testing.T) {
	for _, service := range []string{"issuer", "model", "stations"} {
		raw, e := os.ReadFile("templates/systemd/swarma-" + service + ".service.in")
		if e != nil {
			t.Fatal(e)
		}
		seen := map[string]bool{}
		for _, line := range strings.Split(string(raw), "\n") {
			if !strings.HasPrefix(line, "ReadWritePaths=") {
				continue
			}
			for _, path := range strings.Fields(strings.TrimPrefix(line, "ReadWritePaths=")) {
				if seen[path] || path != "/var/lib/swarma-"+service && !(service == "model" && path == "/run/swarma-model") {
					t.Fatal("foreign or duplicate writable path", service)
				}
				seen[path] = true
			}
		}
		if !seen["/var/lib/swarma-"+service] || service == "model" && !seen["/run/swarma-model"] {
			t.Fatal("missing writable root", service)
		}
	}
}
