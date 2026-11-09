package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/exchange"
	"strings"
	"testing"

	"relux.works/swarma-chain-lab/experiments/rental"
	booking "relux.works/swarma-chain-lab/experiments/rental-booking"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/nostr"
	su "relux.works/swarma-chain-lab/experiments/single-use"
)

func testRoot(t *testing.T) string {
	t.Helper()
	p, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(p, 0700); e != nil {
		t.Fatal(e)
	}
	return p
}
func testConfig(t *testing.T) serveConfig {
	t.Helper()
	root := testRoot(t)
	key, e := nostr.GeneratePrivKey()
	if e != nil {
		t.Fatal(e)
	}
	seal, e := rental.GrantSealScript(key.PubKeyHex())
	if e != nil {
		t.Fatal(e)
	}
	return serveConfig{Version: 1, Mode: "test", AgentKeyFile: filepath.Join(root, "agent.key"), AgentPubkey: key.PubKeyHex(), RelayURL: "ws://127.0.0.1:7777", JournalDir: filepath.Join(root, "journal"), StationSocket: filepath.Join(root, "s.sock"), Screening: "off",
		Kernel:   kernelConfig{Kind: "real", Network: "regtest", Genesis: su.RegtestGenesis, AgentName: "id/test-agent", LandlordName: "id/test-landlord", IssuerPubkey: key.PubKeyHex(), SealScript: seal, StateDir: filepath.Join(root, "kernel"), RPCHost: "127.0.0.1", RPCPort: 18443, RPCRouteFile: filepath.Join(root, "route.json")},
		Exchange: exchangeConfig{BookingVersion: 2, PaymentCoins: []exchange.Coin{exchange.NMC}, StateDir: filepath.Join(root, "exchange"), BookingURL: "http://127.0.0.1:18819", PresentationsDir: filepath.Join(root, "presentations"), PrivacySHA256: booking.Hash([]byte(booking.PrivacyNotice)), TemplateSHA256: booking.Hash([]byte("template fixture")), ProfileSHA256: booking.Hash([]byte("profile fixture")), PowBits: 4, MaxClients: 8, QueueSize: 8, Burst: 4, MaxReplay: 8, RefillSeconds: 1, KnownSeconds: 600, MessageAgeSeconds: 300, PollMilliseconds: 20, CallMilliseconds: 2000},
		Station:  stationConfig{Driver: "local-test", Root: filepath.Join(root, "stations")},
	}
}

// Bad pins/modes/bounds refuse before filesystem or network effects. Adjacent
// valid real-kernel/off config succeeds only under explicitly permitted test mode.
func TestConfigBoundary(t *testing.T) {
	base := testConfig(t)
	if e := base.validate(true); e != nil {
		t.Fatal("valid config", e)
	}
	cases := []struct {
		name   string
		change func(*serveConfig)
		want   error
	}{
		{"version", func(c *serveConfig) { c.Version = 0 }, errConfig},
		{"mode", func(c *serveConfig) { c.Mode = "production" }, errConfig},
		{"mainnet", func(c *serveConfig) { c.Kernel.Network = "main" }, errConfig},
		{"genesis", func(c *serveConfig) { c.Kernel.Genesis = strings.Repeat("0", 64) }, errConfig},
		{"issuer", func(c *serveConfig) { c.Kernel.IssuerPubkey = "" }, errConfig},
		{"seal", func(c *serveConfig) { c.Kernel.SealScript = "00" }, errConfig},
		{"agent", func(c *serveConfig) { c.Kernel.AgentName = "" }, errConfig},
		{"landlord", func(c *serveConfig) { c.Kernel.LandlordName = c.Kernel.AgentName }, errConfig},
		{"agent-key", func(c *serveConfig) { c.AgentPubkey = "" }, errConfig},
		{"rpc-host", func(c *serveConfig) { c.Kernel.RPCHost = "example.com" }, errConfig},
		{"rpc-port", func(c *serveConfig) { c.Kernel.RPCPort = 0 }, errConfig},
		{"rpc-path", func(c *serveConfig) { c.Kernel.RPCRouteFile = "relative" }, errConfig},
		{"relay", func(c *serveConfig) { c.RelayURL = "ws://example.com:7777" }, errConfig},
		{"relay-page-small", func(c *serveConfig) { c.RelayReplayLimit = 1 }, errConfig},
		{"relay-page-large", func(c *serveConfig) { c.RelayReplayLimit = 4097 }, errConfig},
		{"booking-userinfo", func(c *serveConfig) { c.Exchange.BookingURL = "http://user@127.0.0.1:18819" }, errConfig},
		{"privacy", func(c *serveConfig) { c.Exchange.PrivacySHA256 = strings.Repeat("0", 64) }, errConfig},
		{"template", func(c *serveConfig) { c.Exchange.TemplateSHA256 = "" }, errConfig},
		{"profile", func(c *serveConfig) { c.Exchange.ProfileSHA256 = "" }, errConfig},
		{"state-overlap", func(c *serveConfig) { c.Exchange.StateDir = c.Kernel.StateDir }, errConfig},
		{"pow", func(c *serveConfig) { c.Exchange.PowBits = 0 }, errConfig},
		{"queue", func(c *serveConfig) { c.Exchange.QueueSize = 129 }, errConfig},
		{"replay", func(c *serveConfig) { c.Exchange.MaxReplay = 1 }, errConfig},
		{"timeout", func(c *serveConfig) { c.Exchange.CallMilliseconds = 5001 }, errConfig},
		{"implicit-stub", func(c *serveConfig) { c.Kernel.StubVerdict = "live" }, errConfig},
		{"screening-missing", func(c *serveConfig) { c.Screening = "" }, errConfig},
		{"regtest-local", func(c *serveConfig) { c.Mode = "regtest" }, errMode},
		{"regtest-stub-kernel", func(c *serveConfig) {
			c.Mode = "regtest"
			c.Station.Driver = "manager"
			c.Kernel.Kind = "stub"
			c.Kernel.StubVerdict = "live"
		}, errMode},
		{"regtest-stub-screen", func(c *serveConfig) { c.Mode = "regtest"; c.Station.Driver = "manager"; c.Screening = "stub" }, errMode},
		{"regtest-stub-agent", func(c *serveConfig) { c.Mode = "regtest"; c.Station.Driver = "manager"; c.Station.StubAgent = true }, errMode},
		{"manager-missing", func(c *serveConfig) { c.Mode = "regtest"; c.Station.Driver = "manager" }, errConfig},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := base
			tc.change(&c)
			if !errors.Is(c.validate(true), tc.want) || !errors.Is(serve(context.Background(), c), tc.want) {
				t.Fatal("config guard missing")
			}
			entries, e := os.ReadDir(filepath.Dir(base.AgentKeyFile))
			if e != nil || len(entries) != 0 {
				t.Fatal("invalid config caused effects")
			}
		})
	}
	if !errors.Is(base.validate(false), errMode) {
		t.Fatal("deployment validator accepted test mode")
	}
	demo := base
	demo.Kernel.Kind = "stub"
	demo.Kernel.StubVerdict = "live"
	demo.Screening = "stub"
	demo.Station.StubAgent = true
	if e := demo.validate(true); e != nil {
		t.Fatal("explicit test stub neighbor", e)
	}
}

// Strict JSON rejects duplicates/aliases/unknown fields/trailing documents and
// bounds before construction; protected-file/symlink refusals have valid controls.
func TestConfigFiles(t *testing.T) {
	c := testConfig(t)
	root := filepath.Dir(c.AgentKeyFile)
	raw, _ := json.Marshal(c)
	file := filepath.Join(root, "config.json")
	for _, bad := range [][]byte{append(append([]byte{}, raw...), raw...), []byte(strings.Replace(string(raw), `"version":1`, `"version":1,"version":1`, 1)), []byte(strings.Replace(string(raw), `"version"`, `"Version"`, 1)), []byte(strings.Replace(string(raw), `"version":1`, `"version":1,"unknown":"marker"`, 1)), []byte(strings.Repeat("x", 65537))} {
		if e := os.WriteFile(file, bad, 0600); e != nil {
			t.Fatal(e)
		}
		if _, e := loadConfig(file, true); !errors.Is(e, errConfig) {
			t.Fatal("strict config accepted")
		}
	}
	os.WriteFile(file, raw, 0600)
	if _, e := loadConfig(file, true); e != nil {
		t.Fatal(e)
	}
	link := filepath.Join(root, "alias")
	os.Symlink(file, link)
	if _, e := loadConfig(link, true); e == nil {
		t.Fatal("symlink config accepted")
	}
	os.Chmod(file, 0666)
	if _, e := loadConfig(file, true); e == nil {
		t.Fatal("writable config accepted")
	}
	os.Chmod(file, 0600)
	if _, e := readFile(file, 65536, 0400); e == nil {
		t.Fatal("wrong secret mode accepted")
	}
	os.Chmod(file, 0400)
	if _, e := readFile(file, 65536, 0400); e != nil {
		t.Fatal(e)
	}
	for _, args := range [][]string{{"-stub-verdict", "live"}, {"-config", file, "extra"}, {"-key", file}} {
		if _, _, e := configArgs(args, false); e == nil {
			t.Fatal("legacy override accepted")
		}
	}
}

func remoteConfig(t *testing.T) serveConfig {
	t.Helper()
	c := testConfig(t)
	c.Mode = "regtest"
	c.StationSocket = ""
	root := filepath.Dir(c.AgentKeyFile)
	c.Station = stationConfig{Driver: "manager", Manager: &managerConfig{
		StateDir: filepath.Join(root, "broker"), PayloadID: "rented-agent-v1", PayloadSHA256: booking.Hash([]byte("payload fixture")), SlotMin: 1, SlotMax: 64, StartMilliseconds: 2000,
		Listen: "127.0.0.1:9443", PayloadListen: "127.0.0.1:9444",
		TLS: gatewayTLSConfig{CertFile: filepath.Join(root, "server.pem"), KeyFile: filepath.Join(root, "server.key"), ManagerCAFile: filepath.Join(root, "manager-ca.pem"), CertSHA256: booking.Hash([]byte("server fixture")), ManagerCertSHA256: booking.Hash([]byte("manager fixture"))},
	}}
	return c
}

// A complete remote regtest config is deployment-valid; missing authority,
// local-test knobs and invalid listener/range bounds refuse before any effects.
func TestConfigRemote(t *testing.T) {
	c := remoteConfig(t)
	if e := c.validate(false); e != nil {
		t.Fatal("valid remote config", e)
	}
	cases := []struct {
		name   string
		change func(*serveConfig)
	}{
		{"missing-manager", func(c *serveConfig) { c.Station.Manager = nil }},
		{"local-root", func(c *serveConfig) { c.Station.Root = "/tmp/local" }},
		{"local-socket", func(c *serveConfig) { c.StationSocket = "/tmp/local.sock" }},
		{"stub-agent", func(c *serveConfig) { c.Station.StubAgent = true }},
		{"stub-kernel", func(c *serveConfig) { c.Kernel.Kind = "stub"; c.Kernel.StubVerdict = "live" }},
		{"stub-screen", func(c *serveConfig) { c.Screening = "stub" }},
		{"missing-payload", func(c *serveConfig) { c.Station.Manager.PayloadSHA256 = "" }},
		{"payload-id", func(c *serveConfig) { c.Station.Manager.PayloadID = "../payload" }},
		{"payload-label", func(c *serveConfig) { c.Station.Manager.PayloadID = "Payload.V1" }},
		{"negative-slot", func(c *serveConfig) { c.Station.Manager.SlotMin = -1 }},
		{"slot-overflow", func(c *serveConfig) { c.Station.Manager.SlotMax = 10000 }},
		{"slot-order", func(c *serveConfig) { c.Station.Manager.SlotMin = 65 }},
		{"unbounded-start", func(c *serveConfig) { c.Station.Manager.StartMilliseconds = 5001 }},
		{"missing-pin", func(c *serveConfig) { c.Station.Manager.TLS.ManagerCertSHA256 = "" }},
		{"missing-server-pin", func(c *serveConfig) { c.Station.Manager.TLS.CertSHA256 = "" }},
		{"relative-key", func(c *serveConfig) { c.Station.Manager.TLS.KeyFile = "key" }},
		{"wildcard", func(c *serveConfig) { c.Station.Manager.Listen = "0.0.0.0:9443" }},
		{"hostname", func(c *serveConfig) { c.Station.Manager.Listen = "localhost:9443" }},
		{"shared-port", func(c *serveConfig) { c.Station.Manager.PayloadListen = c.Station.Manager.Listen }},
		{"zero-port", func(c *serveConfig) { c.Station.Manager.PayloadListen = "127.0.0.1:0" }},
		{"state-overlap", func(c *serveConfig) { c.Station.Manager.StateDir = c.JournalDir }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bad := c
			m := *c.Station.Manager
			bad.Station.Manager = &m
			tc.change(&bad)
			if bad.validate(false) == nil || serve(context.Background(), bad) == nil {
				t.Fatal("remote config guard missing")
			}
			entries, e := os.ReadDir(filepath.Dir(c.AgentKeyFile))
			if e != nil || len(entries) != 0 {
				t.Fatal("invalid remote config caused effects")
			}
		})
	}
}

// The shipped public gateway template matches the native schema and remains
// inert until all public pins are supplied; filling pins never enables stubs.
func TestConfigDeployTemplate(t *testing.T) {
	root, e := os.Getwd()
	if e != nil {
		t.Fatal(e)
	}
	var raw []byte
	for i := 0; i < 6; i++ {
		raw, e = os.ReadFile(filepath.Join(root, "deploy/templates/gateway/service.json"))
		if e == nil {
			break
		}
		root = filepath.Dir(root)
	}
	if e != nil {
		t.Fatal("gateway template unavailable", e)
	}
	var c serveConfig
	if booking.Strict(raw, &c) != nil {
		t.Fatal("template schema mismatch")
	}
	if c.validate(false) == nil {
		t.Fatal("unfilled template accepted")
	}
	base := remoteConfig(t)
	replacements := map[string]string{
		"PLACEHOLDER_AGENT_PUBKEY": base.AgentPubkey, "PLACEHOLDER_AGENT_NAME": base.Kernel.AgentName, "PLACEHOLDER_LANDLORD_NAME": base.Kernel.LandlordName,
		"PLACEHOLDER_ISSUER_PUBKEY": base.Kernel.IssuerPubkey, "PLACEHOLDER_SEAL_SCRIPT": base.Kernel.SealScript, "PLACEHOLDER_PRIVACY_SHA256": base.Exchange.PrivacySHA256,
		"PLACEHOLDER_TEMPLATE_SHA256": base.Exchange.TemplateSHA256, "PLACEHOLDER_PROFILE_SHA256": base.Exchange.ProfileSHA256,
		"PLACEHOLDER_PAYLOAD_ID": base.Station.Manager.PayloadID, "PLACEHOLDER_PAYLOAD_SHA256": base.Station.Manager.PayloadSHA256,
		"PLACEHOLDER_GATEWAY_IP": "192.0.2.10", "PLACEHOLDER_GATEWAY_CERT_SHA256": base.Station.Manager.TLS.CertSHA256, "PLACEHOLDER_MANAGER_CERT_SHA256": base.Station.Manager.TLS.ManagerCertSHA256,
	}
	filled := string(raw)
	for k, v := range replacements {
		filled = strings.ReplaceAll(filled, k, v)
	}
	if strings.Contains(filled, "PLACEHOLDER") || booking.Strict([]byte(filled), &c) != nil || c.validate(false) != nil {
		t.Fatal("filled native template refused")
	}
}

// Deployment never selects V1 implicitly or explicitly. Closed nonempty coins
// are required even in tests; explicit V1 is confined to the existing test gate.
func TestConfigBookingVersion(t *testing.T) {
	c := remoteConfig(t)
	if e := c.validate(false); e != nil {
		t.Fatal("real V2 neighbor", e)
	}
	for _, version := range []int{0, 1, 3} {
		v := c
		v.Mode = "regtest"
		v.Exchange.BookingVersion = version
		if v.validate(true) == nil {
			t.Fatal("V1 deployed", version)
		}
	}
	c.Mode = "test"
	c.Exchange.BookingVersion = 1
	if e := c.validate(true); e != nil {
		t.Fatal("legacy test neighbor", e)
	}
	if c.validate(false) == nil {
		t.Fatal("legacy bypassed test mode")
	}
	c.Exchange.BookingVersion = 2
	for _, coins := range [][]exchange.Coin{nil, {}, {"eth"}, {"NMC"}, {exchange.NMC, exchange.NMC}} {
		v := c
		v.Exchange.PaymentCoins = coins
		if v.validate(true) == nil {
			t.Fatal("coin config accepted", coins)
		}
	}
	if e := c.validate(true); e != nil {
		t.Fatal("V2 neighbor", e)
	}
}
