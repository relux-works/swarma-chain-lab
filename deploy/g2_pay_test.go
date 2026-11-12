package deploy

// Owner S5 (PX1): G2 pay parameters, the templates/g2-pay render and the T18
// different-UID custody probe. Unit tests run as the test UID; the Core test
// (W1_REGTEST=1) starts a genuine Namecoin Core regtest node from the rendered
// node policy. A real cross-UID T18 run needs owner-provisioned users and is
// not claimed by any test here.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// BIP-340 x-only keys: x(G), x(2G); x = 5 is not on the curve.
const (
	g2KeyG     = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	g2Key2G    = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
	g2KeyOff   = "0000000000000000000000000000000000000000000000000000000000000005"
	g2Datadir  = "/var/lib/namecoind-main"
	g2SvcUID   = 1101
	g2Agent    = "cedar"
	g2KeyFile  = "/srv/agent/action.key"
	g2HotName  = "swarma-g2-hot"
	g2MainPort = 8336
)

func g2Params() G2PayParameters {
	return G2PayParameters{Network: "main", Genesis: mainGenesis, AgentUID: 1201, AgentSocketGID: 1301, OperatorGID: 1401, ServiceUID: g2SvcUID, AgentUser: g2Agent, AgentKeyFile: g2KeyFile, NodeDataDir: g2Datadir, Grantee: g2KeyG, ReceiptPubkey: g2Key2G, FeeRateSatVB: 110, HotWalletName: g2HotName, NodeRPCPort: g2MainPort, G2: px1OperatorParameters()}
}

func g2MainWalletPolicy() Policy {
	return Policy{Version: 1, Network: "main", Genesis: mainGenesis, Service: "wallet", ReleaseVersion: "fixture-main", Commit: strings.Repeat("a", 40), BinarySHA256: strings.Repeat("b", 64), StateDir: "/var/lib/swarma-wallet", Config: "/etc/swarma/wallet/service.json"}
}

// Claim: the launch fixture validates, and every pin, UID, account-name, path,
// key, fee-rate, wallet-name, port, node-datadir and operator-ceiling
// violation is refused with the frozen sentinel (ErrNetwork for chain pins,
// ErrPolicy otherwise); the identity domain's ErrPolicy wins over a pin error
// (amendment 1: ValidateG2PayIdentityDomain first). Each refusal row
// re-checks its valid neighbour, and boundary values are accepted.
func TestPX1S5ParametersRefusalTable(t *testing.T) {
	if e := ValidateG2PayParameters(g2Params()); e != nil {
		t.Fatal("launch fixture refused", e)
	}
	accept := map[string]func(*G2PayParameters){
		"regtest-explicit": func(p *G2PayParameters) { p.Network, p.Genesis = "regtest", regtestGenesis },
		"fee-rate-100":     func(p *G2PayParameters) { p.FeeRateSatVB = 100 },
		"fee-rate-1000":    func(p *G2PayParameters) { p.FeeRateSatVB = 1000 },
		"transfer-eq-day":  func(p *G2PayParameters) { p.G2.MaxTransferSat = p.G2.MaxDaySat },
		"capacity-minimum": func(p *G2PayParameters) { p.G2.JournalSpendCapacity = p.G2.MaxDayCount + 64 },
		"canary-dust":      func(p *G2PayParameters) { p.G2.Canary.ValueSat = 546 },
		"low-float-zero":   func(p *G2PayParameters) { p.G2.LowFloatSat = 0 },
		"socket-gid-65533": func(p *G2PayParameters) { p.AgentSocketGID = 65533 },
		"socket-gid-65536": func(p *G2PayParameters) { p.AgentSocketGID = 65536 },
		"operator-65533":   func(p *G2PayParameters) { p.OperatorGID = 65533 },
		"operator-65536":   func(p *G2PayParameters) { p.OperatorGID = 65536 },
		"service-65533":    func(p *G2PayParameters) { p.ServiceUID = 65533 },
		"service-65536":    func(p *G2PayParameters) { p.ServiceUID = 65536 },
		"agent-65536":      func(p *G2PayParameters) { p.AgentUID = 65536 },
		"user-31-bytes":    func(p *G2PayParameters) { p.AgentUser = "a" + strings.Repeat("b", 30) },
		"user-underscore":  func(p *G2PayParameters) { p.AgentUser = "_cedar-2" },
		"user-swarma":      func(p *G2PayParameters) { p.AgentUser = "swarma-agent" },
		"datadir-srv":      func(p *G2PayParameters) { p.NodeDataDir = "/srv/namecoind" },
		"datadir-var-lib":  func(p *G2PayParameters) { p.NodeDataDir = "/var/lib/swarma-walletx" },
	}
	for name, mut := range accept {
		p := g2Params()
		mut(&p)
		if e := ValidateG2PayParameters(p); e != nil {
			t.Fatal("boundary refused", name, e)
		}
	}
	refuse := []struct {
		name string
		want error
		mut  func(*G2PayParameters)
	}{
		{"testnet", ErrNetwork, func(p *G2PayParameters) { p.Network = "test" }},
		{"main-empty-genesis", ErrNetwork, func(p *G2PayParameters) { p.Genesis = "" }},
		{"regtest-main-genesis", ErrNetwork, func(p *G2PayParameters) { p.Network = "regtest" }},
		{"regtest-empty-genesis", ErrNetwork, func(p *G2PayParameters) { p.Network, p.Genesis = "regtest", "" }},
		{"agent-root", ErrPolicy, func(p *G2PayParameters) { p.AgentUID = 0 }},
		{"agent-nobody", ErrPolicy, func(p *G2PayParameters) { p.AgentUID = 65534 }},
		{"agent-minus-one", ErrPolicy, func(p *G2PayParameters) { p.AgentUID = math.MaxUint32 }},
		{"agent-65535", ErrPolicy, func(p *G2PayParameters) { p.AgentUID = 65535 }},
		{"service-root", ErrPolicy, func(p *G2PayParameters) { p.ServiceUID = 0 }},
		{"service-nobody", ErrPolicy, func(p *G2PayParameters) { p.ServiceUID = 65534 }},
		{"service-65535", ErrPolicy, func(p *G2PayParameters) { p.ServiceUID = 65535 }},
		{"service-minus-one", ErrPolicy, func(p *G2PayParameters) { p.ServiceUID = math.MaxUint32 }},
		{"service-is-agent", ErrPolicy, func(p *G2PayParameters) { p.ServiceUID = p.AgentUID }},
		{"domain-before-pin", ErrPolicy, func(p *G2PayParameters) { p.Network, p.ServiceUID = "test", p.AgentUID }},
		{"user-empty", ErrPolicy, func(p *G2PayParameters) { p.AgentUser = "" }},
		{"user-root", ErrPolicy, func(p *G2PayParameters) { p.AgentUser = "root" }},
		{"user-nobody", ErrPolicy, func(p *G2PayParameters) { p.AgentUser = "nobody" }},
		{"user-service", ErrPolicy, func(p *G2PayParameters) { p.AgentUser = "swarma-wallet" }},
		{"user-peer-group", ErrPolicy, func(p *G2PayParameters) { p.AgentUser = "swarma-wallet-peer" }},
		{"user-digit-first", ErrPolicy, func(p *G2PayParameters) { p.AgentUser = "1cedar" }},
		{"user-32-bytes", ErrPolicy, func(p *G2PayParameters) { p.AgentUser = "a" + strings.Repeat("b", 31) }},
		{"user-dot", ErrPolicy, func(p *G2PayParameters) { p.AgentUser = "ce.dar" }},
		{"key-relative", ErrPolicy, func(p *G2PayParameters) { p.AgentKeyFile = "srv/agent/action.key" }},
		{"key-unclean", ErrPolicy, func(p *G2PayParameters) { p.AgentKeyFile = "/srv/agent/../action.key" }},
		{"key-root", ErrPolicy, func(p *G2PayParameters) { p.AgentKeyFile = "/" }},
		{"datadir-relative", ErrPolicy, func(p *G2PayParameters) { p.NodeDataDir = "var/lib/namecoind" }},
		{"datadir-trailing-slash", ErrPolicy, func(p *G2PayParameters) { p.NodeDataDir = g2Datadir + "/" }},
		{"datadir-is-key", ErrPolicy, func(p *G2PayParameters) { p.NodeDataDir = p.AgentKeyFile }},
		{"datadir-in-state", ErrPolicy, func(p *G2PayParameters) { p.NodeDataDir = "/var/lib/swarma-wallet/node" }},
		{"datadir-state-root", ErrPolicy, func(p *G2PayParameters) { p.NodeDataDir = "/var/lib/swarma-wallet" }},
		{"datadir-etc-swarma", ErrPolicy, func(p *G2PayParameters) { p.NodeDataDir = "/etc/swarma/node" }},
		{"datadir-run", ErrPolicy, func(p *G2PayParameters) { p.NodeDataDir = "/run/namecoind" }},
		{"datadir-long", ErrPolicy, func(p *G2PayParameters) { p.NodeDataDir = "/" + strings.Repeat("d", 1024) }},
		{"socket-gid-root", ErrPolicy, func(p *G2PayParameters) { p.AgentSocketGID = 0 }},
		{"operator-gid-root", ErrPolicy, func(p *G2PayParameters) { p.OperatorGID = 0 }},
		{"socket-gid-65535", ErrPolicy, func(p *G2PayParameters) { p.AgentSocketGID = 65535 }},
		{"operator-gid-65535", ErrPolicy, func(p *G2PayParameters) { p.OperatorGID = 65535 }},
		{"operator-is-agent-group", ErrPolicy, func(p *G2PayParameters) { p.OperatorGID = p.AgentSocketGID }},
		{"grantee-empty", ErrPolicy, func(p *G2PayParameters) { p.Grantee = "" }},
		{"grantee-upper", ErrPolicy, func(p *G2PayParameters) { p.Grantee = strings.ToUpper(g2KeyG) }},
		{"grantee-off-curve", ErrPolicy, func(p *G2PayParameters) { p.Grantee = g2KeyOff }},
		{"grantee-ge-p", ErrPolicy, func(p *G2PayParameters) { p.Grantee = strings.Repeat("f", 64) }},
		{"receipt-off-curve", ErrPolicy, func(p *G2PayParameters) { p.ReceiptPubkey = g2KeyOff }},
		{"receipt-is-grantee", ErrPolicy, func(p *G2PayParameters) { p.ReceiptPubkey = p.Grantee }},
		{"fee-rate-99", ErrPolicy, func(p *G2PayParameters) { p.FeeRateSatVB = 99 }},
		{"fee-rate-1001", ErrPolicy, func(p *G2PayParameters) { p.FeeRateSatVB = 1001 }},
		{"wallet-default", ErrPolicy, func(p *G2PayParameters) { p.HotWalletName = "" }},
		{"wallet-traversal", ErrPolicy, func(p *G2PayParameters) { p.HotWalletName = "../hot" }},
		{"wallet-slash", ErrPolicy, func(p *G2PayParameters) { p.HotWalletName = "a/b" }},
		{"wallet-hidden", ErrPolicy, func(p *G2PayParameters) { p.HotWalletName = ".hot" }},
		{"wallet-upper", ErrPolicy, func(p *G2PayParameters) { p.HotWalletName = "Hot" }},
		{"rpc-port-zero", ErrPolicy, func(p *G2PayParameters) { p.NodeRPCPort = 0 }},
		{"terms-v1", ErrPolicy, func(p *G2PayParameters) { p.G2.RequireTermsVersion = 1 }},
		{"single-use", ErrPolicy, func(p *G2PayParameters) { p.G2.AllowSingleUse = true }},
		{"any-recipients", ErrPolicy, func(p *G2PayParameters) { p.G2.AllowAnyRecipients = true }},
		{"transfer-zero", ErrPolicy, func(p *G2PayParameters) { p.G2.MaxTransferSat = 0 }},
		{"transfer-over-day", ErrPolicy, func(p *G2PayParameters) { p.G2.MaxTransferSat = p.G2.MaxDaySat + 1 }},
		{"day-count-zero", ErrPolicy, func(p *G2PayParameters) { p.G2.MaxDayCount = 0 }},
		{"day-count-1001", ErrPolicy, func(p *G2PayParameters) { p.G2.MaxDayCount = 1001 }},
		{"fee-zero", ErrPolicy, func(p *G2PayParameters) { p.G2.MaxFeeSat = 0 }},
		{"fee-over-max", ErrPolicy, func(p *G2PayParameters) { p.G2.MaxFeeSat = 1000001 }},
		{"float-under-day", ErrPolicy, func(p *G2PayParameters) { p.G2.MaxFloatSat = p.G2.MaxDaySat - 1 }},
		{"low-float-at-ceiling", ErrPolicy, func(p *G2PayParameters) { p.G2.LowFloatSat = p.G2.MaxFloatSat }},
		{"low-float-negative", ErrPolicy, func(p *G2PayParameters) { p.G2.LowFloatSat = -1 }},
		{"canary-txid-zero", ErrPolicy, func(p *G2PayParameters) { p.G2.Canary.Outpoint.TxID = strings.Repeat("0", 64) }},
		{"canary-txid-short", ErrPolicy, func(p *G2PayParameters) { p.G2.Canary.Outpoint.TxID = "cc" }},
		{"canary-dust", ErrPolicy, func(p *G2PayParameters) { p.G2.Canary.ValueSat = 545 }},
		{"k-zero", ErrPolicy, func(p *G2PayParameters) { p.G2.ConfirmationsK = 0 }},
		{"k-seven", ErrPolicy, func(p *G2PayParameters) { p.G2.ConfirmationsK = 7 }},
		{"n-under-k", ErrPolicy, func(p *G2PayParameters) { p.G2.ConflictBlocksN = p.G2.ConfirmationsK - 1 }},
		{"read-rate-zero", ErrPolicy, func(p *G2PayParameters) { p.G2.ReadRatePerHour = 0 }},
		{"capacity-short", ErrPolicy, func(p *G2PayParameters) { p.G2.JournalSpendCapacity = p.G2.MaxDayCount + 63 }},
	}
	for _, row := range refuse {
		t.Run(row.name, func(t *testing.T) {
			p := g2Params()
			row.mut(&p)
			if e := ValidateG2PayParameters(p); e != row.want {
				t.Fatalf("G2_PARAMS_GUARD %s: got %v want %v", row.name, e, row.want)
			}
			if files, e := RenderG2PayTemplates(p); files != nil || e != row.want {
				t.Fatalf("G2_RENDER_GUARD %s rendered invalid parameters", row.name)
			}
			if e := ValidateG2PayParameters(g2Params()); e != nil {
				t.Fatal("neighbour refused", e)
			}
		})
	}
}

// Claim: the canonical parameters file round-trips through
// ParseG2PayParameters; reordered members, unknown members, duplicate keys and
// placeholders are refused (positive control first).
func TestPX1S5ParametersFile(t *testing.T) {
	raw, _ := json.Marshal(g2Params())
	if p, e := ParseG2PayParameters(raw); e != nil || !reflect.DeepEqual(p, g2Params()) {
		t.Fatal("canonical parameters refused", e)
	}
	for name, bad := range map[string][]byte{
		"reordered":   bytes.Replace(raw, []byte(`{"network":"main","genesis":"`+mainGenesis+`"`), []byte(`{"genesis":"`+mainGenesis+`","network":"main"`), 1),
		"unknown":     bytes.Replace(raw, []byte(`"network":"main"`), []byte(`"network":"main","rpcpassword":"x"`), 1),
		"duplicate":   bytes.Replace(raw, []byte(`"network":"main"`), []byte(`"network":"main","network":"main"`), 1),
		"placeholder": bytes.Replace(raw, []byte(g2HotName), []byte("PLACEHOLDER_WALLET"), 1),
		"invalid":     bytes.Replace(raw, []byte(`"fee_rate_sat_vb":110`), []byte(`"fee_rate_sat_vb":200000`), 1),
	} {
		if bytes.Equal(bad, raw) {
			t.Fatal("fixture edit did not apply", name)
		}
		if _, e := ParseG2PayParameters(bad); e == nil {
			t.Fatal("G2_PARAMS_FILE accepted", name)
		}
	}
}

// Claim: the render is exactly the frozen G2File* set, deterministic, and its
// service.json passes the main wallet deploy validator with the operator block
// byte-equal to the frozen golden; client.json and custody-spec.json carry no
// placeholder and decode to the parameter values (service UID, key file, node
// datadir) with the status directory denied.
func TestPX1S5RenderFileSet(t *testing.T) {
	p := g2Params()
	files, e := RenderG2PayTemplates(p)
	if e != nil {
		t.Fatal(e)
	}
	var names []string
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	want := []string{G2FileClientConfig, G2FileCustodySpec, G2FileRPCWhitelist, G2FileServiceConfig, G2FileSysusers, G2FileTmpfiles}
	sort.Strings(want)
	if !reflect.DeepEqual(names, want) {
		t.Fatal("G2_RENDER_SET", names)
	}
	again, _ := RenderG2PayTemplates(p)
	if !reflect.DeepEqual(files, again) {
		t.Fatal("render not deterministic")
	}
	service := bytes.TrimSuffix(files[G2FileServiceConfig], []byte("\n"))
	if e := ValidateServiceInputs(g2MainWalletPolicy(), [][]byte{service}); e != nil {
		t.Fatal("G2_SERVICE_INVALID", e)
	}
	if !bytes.HasSuffix(service, []byte(`,"g2":`+px1OperatorGolden+`}`)) {
		t.Fatal("G2_OPERATOR_BYTES", string(service))
	}
	var svc walletServiceConfig
	if json.Unmarshal(service, &svc) != nil || svc.PeerUID != p.AgentUID || svc.SocketGID != p.AgentSocketGID || svc.Grantee != p.Grantee || svc.Network != "main" {
		t.Fatal("service pins", string(service))
	}
	for _, name := range []string{G2FileClientConfig, G2FileCustodySpec} {
		if e := ValidatePublicJSON(files[name]); e != nil {
			t.Fatal("G2_RENDER_UNRESOLVED rendered file refused", name, e)
		}
	}
	var client struct {
		Network    string `json:"network"`
		Genesis    string `json:"genesis"`
		Version    int    `json:"version"`
		Service    string `json:"service"`
		Socket     string `json:"socket"`
		ServiceUID uint32 `json:"service_uid"`
		ReceiptKey string `json:"receipt_key"`
		KeyFile    string `json:"key_file"`
	}
	d := json.NewDecoder(bytes.NewReader(files[G2FileClientConfig]))
	d.DisallowUnknownFields()
	if d.Decode(&client) != nil || client.ServiceUID != 1101 || client.Socket != "/run/swarma-wallet/wallet.sock" || client.Network != "main" || client.Genesis != mainGenesis || client.Version != 1 || client.Service != "wallet.nmc" || client.ReceiptKey != p.ReceiptPubkey || client.KeyFile != g2KeyFile {
		t.Fatal("client pins", string(files[G2FileClientConfig]))
	}
	if !bytes.Contains(files[G2FileClientConfig], []byte(`"service_uid":1101,"receipt_key":"`+p.ReceiptPubkey+`","key_file":"`+g2KeyFile+`"}`)) {
		t.Fatal("client receipt key", string(files[G2FileClientConfig]))
	}
	spec, e := ParseCustodySpec(bytes.TrimSuffix(files[G2FileCustodySpec], []byte("\n")))
	if e != nil {
		t.Fatal("resolved spec refused", e)
	}
	if e := ValidateG2CustodyLaunchSpec(spec); e != nil {
		t.Fatal("G2_LAUNCH_SPEC", e)
	}
	cookie, wallet := G2NodeCustodyPaths("main", g2Datadir, g2HotName)
	if spec.AgentUID != p.AgentUID || spec.ServiceUID != 1101 || spec.AllowedSocket != "/run/swarma-wallet/wallet.sock" || !reflect.DeepEqual(spec.DeniedRPC, []string{"127.0.0.1:8336"}) || spec.DeniedReads[6] != "/run/swarma-wallet-status" || spec.DeniedReads[7] != cookie || spec.DeniedReads[8] != wallet || cookie != "/var/lib/namecoind-main/.cookie" || wallet != "/var/lib/namecoind-main/wallets/swarma-g2-hot/wallet.dat" {
		t.Fatalf("spec content %+v", spec)
	}
}

// Claim: no rendered file carries a credential directive, a host-home path or
// a private-key member; the agent user joins only swarma-wallet-peer (never
// swarma-wallet or swarma-wallet-status); tmpfiles has exactly the seven
// private directories, the status directory included.
// Limit: a pattern scan, not a proof that no secret could be encoded.
func TestPX1S5RenderNoSecrets(t *testing.T) {
	for _, network := range []string{"main", "regtest"} {
		p := g2Params()
		if network == "regtest" {
			p.Network, p.Genesis = "regtest", regtestGenesis
		}
		files, e := RenderG2PayTemplates(p)
		if e != nil {
			t.Fatal(e)
		}
		for name, b := range files {
			for _, forbidden := range []string{"rpcauth=", "rpcpassword", "rpcuser", "password", "private_key", "secret", "/home/", "/Users/", "/tmp/", "Environment="} {
				if bytes.Contains(bytes.ToLower(b), []byte(strings.ToLower(forbidden))) {
					t.Fatal("G2_RENDER_SECRET", name, forbidden)
				}
			}
		}
		sys := string(files[G2FileSysusers])
		if strings.Contains(sys, "m "+g2Agent+" swarma-wallet\n") || strings.Contains(sys, "m "+g2Agent+" swarma-wallet-status") || !strings.Contains(sys, "m "+g2Agent+" swarma-wallet-peer\n") {
			t.Fatal("G2_AGENT_GROUP", sys)
		}
		if !strings.Contains(sys, "g swarma-wallet-peer 1301\n") || !strings.Contains(sys, "g swarma-wallet-status 1401\n") {
			t.Fatal("G2_GROUP_PINS", sys)
		}
		tmp := string(files[G2FileTmpfiles])
		for _, line := range []string{"d /etc/swarma/wallet 0750 root swarma-wallet -\n", "d /var/lib/swarma-wallet 0700 swarma-wallet swarma-wallet -\n", "d /var/lib/swarma-wallet/service 0700 swarma-wallet swarma-wallet -\n", "d /var/lib/swarma-wallet/wallet 0700 swarma-wallet swarma-wallet -\n", "d /var/lib/swarma-wallet/kernel 0700 swarma-wallet swarma-wallet -\n", "d /var/lib/swarma-wallet/objects 0700 swarma-wallet swarma-wallet -\n", "d /run/swarma-wallet-status 0750 swarma-wallet swarma-wallet-status -\n"} {
			if !strings.Contains(tmp, line) {
				t.Fatal("G2_TMPFILES", line)
			}
		}
		if strings.Count(tmp, "\nd ") != 7 {
			t.Fatal("unexpected tmpfiles entry", tmp)
		}
	}
}

// Claim: the node policy grants exactly the three README route method sets,
// sets rpcwhitelistdefault=0, binds RPC to loopback only, disables P2P listen
// and scopes every option to the pinned chain's section.
func TestPX1S5RenderNodeConf(t *testing.T) {
	readme, e := os.ReadFile("../experiments/agent-wallet/README.md")
	if e != nil {
		t.Fatal(e)
	}
	for _, network := range []string{"main", "regtest"} {
		p := g2Params()
		if network == "regtest" {
			p.Network, p.Genesis = "regtest", regtestGenesis
		}
		files, _ := RenderG2PayTemplates(p)
		var lines []string
		for _, l := range strings.Split(strings.TrimSpace(string(files[G2FileRPCWhitelist])), "\n") {
			if !strings.HasPrefix(l, "#") {
				lines = append(lines, l)
			}
		}
		want := []string{"chain=" + network, "[" + network + "]", "server=1", "listen=0", "txindex=1", "rpcbind=127.0.0.1", "rpcallowip=127.0.0.1/32", "rpcport=8336", "rpcwhitelistdefault=0",
			"rpcwhitelist=w3-observer:getblockchaininfo,getblockhash,getblockheader,getrawtransaction,gettxout,name_show,getrawmempool,getblock",
			"rpcwhitelist=w1-wallet:getbalances,getnewaddress,listtransactions,fundrawtransaction,signrawtransactionwithwallet",
			"rpcwhitelist=w1-broadcast:sendrawtransaction",
			"wallet=" + g2HotName}
		if !reflect.DeepEqual(lines, want) {
			t.Fatalf("G2_NODE_CONF\n got %q\nwant %q", lines, want)
		}
		for _, l := range lines {
			if route, methods, ok := strings.Cut(strings.TrimPrefix(l, "rpcwhitelist="), ":"); ok && strings.HasPrefix(l, "rpcwhitelist=") {
				if !bytes.Contains(readme, []byte("| `"+route+"` | `"+methods+"` |")) {
					t.Fatal("G2_NODE_CONF route differs from the agent-wallet README", route)
				}
			}
		}
	}
}

// Claim: deploy validate accepts the "g2" member only with an explicit chain
// pin and a launch-valid operator block; W2 bytes without it are unchanged.
func TestPX1S5WalletG2Member(t *testing.T) {
	w2 := walletFixture()
	if e := ValidateServiceInputs(newPolicy("wallet"), [][]byte{encoded(t, w2)}); e != nil {
		t.Fatal("W2 neighbour", e)
	}
	g2 := w2
	g2.Network, g2.Genesis = "main", mainGenesis
	op := px1OperatorParameters()
	g2.G2 = &op
	if e := ValidateServiceInputs(g2MainWalletPolicy(), [][]byte{encoded(t, g2)}); e != nil {
		t.Fatal("G2 member refused", e)
	}
	unpinned := w2
	unpinned.G2 = &op
	if e := ValidateServiceInputs(newPolicy("wallet"), [][]byte{encoded(t, unpinned)}); e != ErrNetwork {
		t.Fatal("G2_WALLET_PIN accepted an unpinned G2 block", e)
	}
	for name, mut := range map[string]func(*G2OperatorParameters){
		"single-use": func(o *G2OperatorParameters) { o.AllowSingleUse = true },
		"terms-v1":   func(o *G2OperatorParameters) { o.RequireTermsVersion = 1 },
		"any":        func(o *G2OperatorParameters) { o.AllowAnyRecipients = true },
	} {
		bad := px1OperatorParameters()
		mut(&bad)
		c := g2
		c.G2 = &bad
		if e := ValidateServiceInputs(g2MainWalletPolicy(), [][]byte{encoded(t, c)}); e != ErrPolicy {
			t.Fatal("G2_WALLET_OPERATOR accepted", name, e)
		}
	}
}

// g2Fixture builds a probe spec for the test UID: one 0000 file and one 0000
// directory (EACCES for a non-root UID), a closed loopback port (REFUSED) and
// a live unix socket (CONNECTED).
func g2Fixture(t *testing.T) (CustodySpecV1, string) {
	t.Helper()
	if os.Getuid() == 0 {
		t.Skip("root bypasses file modes; the probe refuses root anyway")
	}
	root, e := os.MkdirTemp("", "t18")
	if e != nil {
		t.Fatal(e)
	}
	file, dir := filepath.Join(root, "receipt.key"), filepath.Join(root, "state")
	if e := os.WriteFile(file, []byte("not-a-key"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	os.Chmod(file, 0)
	os.Chmod(dir, 0)
	t.Cleanup(func() { os.Chmod(dir, 0700); os.Chmod(file, 0600); os.RemoveAll(root) })
	sock := filepath.Join(root, "w.sock")
	l, e := net.Listen("unix", sock)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			c.Close()
		}
	}()
	uid := uint32(os.Getuid())
	return CustodySpecV1{Version: 1, AgentUID: uid, ServiceUID: uid + 1, DeniedReads: []string{file, dir}, DeniedRPC: []string{g2ClosedPort(t)}, AllowedSocket: sock}, root
}

func g2ClosedPort(t *testing.T) string {
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

// Claim (T18 unit, positive control): as the agent UID, genuine EACCES reads,
// a refused loopback RPC port and a connectable own socket produce a passing
// report that VerifyCustodyReport accepts, bound to the spec hash.
func TestPX1T18ProbePositive(t *testing.T) {
	spec, _ := g2Fixture(t)
	r, e := RunCustodyProbe(context.Background(), spec)
	if e != nil || !r.Pass {
		t.Fatalf("T18_POSITIVE %v %+v", e, r)
	}
	want := []string{"read:EACCES", "read:EACCES", "rpc:REFUSED", "socket:CONNECTED"}
	var got []string
	for _, p := range r.Probes {
		got = append(got, p.Kind+":"+p.Observed)
	}
	if !reflect.DeepEqual(got, want) || r.UID != spec.AgentUID || r.SpecSHA256 != CustodySpecSHA256(spec) {
		t.Fatalf("T18_POSITIVE probes %v", got)
	}
	if e := VerifyCustodyReport(spec, r); e != nil {
		t.Fatal("T18_VERIFY_POSITIVE", e)
	}
}

// Claim (T18): a denied path that does not exist (ENOENT) or that the agent
// can read (READ_OK) fails its probe and the report; the EACCES neighbour in
// the same run still passes.
func TestPX1T18DeniedReadMustBeEACCES(t *testing.T) {
	for _, mode := range []string{"missing", "readable", "readable-dir"} {
		t.Run(mode, func(t *testing.T) {
			spec, root := g2Fixture(t)
			target := filepath.Join(root, "missing")
			want := "ENOENT"
			switch mode {
			case "readable":
				target, want = filepath.Join(root, "wallet.json"), "READ_OK"
				os.WriteFile(target, []byte("{}"), 0600)
			case "readable-dir":
				target, want = filepath.Join(root, "objects"), "READ_OK"
				os.Mkdir(target, 0700)
			}
			spec.DeniedReads = append(spec.DeniedReads, target)
			r, e := RunCustodyProbe(context.Background(), spec)
			if e != nil {
				t.Fatal(e)
			}
			last := r.Probes[2]
			if last.Target != target || last.Observed != want || last.Pass || r.Pass {
				t.Fatalf("T18_DENIED_GUARD %s %+v", mode, last)
			}
			if !r.Probes[0].Pass || r.Probes[0].Observed != "EACCES" {
				t.Fatal("EACCES neighbour", r.Probes[0])
			}
			if e := VerifyCustodyReport(spec, r); e != ErrCustody {
				t.Fatal("T18_VERIFY accepted a failing report", e)
			}
		})
	}
}

// Claim (T18): a denied directory passes only if it is also unsearchable; a searchable-but-unlistable one (mode 0111) fails.
// Limit: same-UID modes model the agent's view of another UID's 0711/0700 directory; no cross-UID host run.
func TestPX1T18SearchableDirectory(t *testing.T) {
	for _, c := range []struct {
		name               string
		dirMode, childMode os.FileMode
		childReadable      bool
		targetChild        bool
		want               string
	}{
		{"private-0000", 0000, 0644, false, false, "EACCES"},             // valid neighbour: nothing below is reachable
		{"private-0200", 0200, 0644, false, false, "EACCES"},             // neither read nor search: still private
		{"child-under-0000", 0000, 0644, false, true, "EACCES"},          // a known file behind an unsearchable parent
		{"searchable-0111-readable", 0111, 0644, true, false, "READ_OK"}, // the reproduced bypass: the known journal is readable
		{"searchable-0111-private", 0111, 0000, false, false, "READ_OK"}, // unlistable: children cannot all be proven private
		{"child-0000-under-0111", 0111, 0000, false, true, "EACCES"},     // the concrete private file itself passes (ENOTDIR)
		{"child-0644-under-0111", 0111, 0644, true, true, "READ_OK"},     // the concrete readable file itself fails
	} {
		t.Run(c.name, func(t *testing.T) {
			spec, root := g2Fixture(t)
			dir := filepath.Join(root, "service")
			journal := filepath.Join(dir, "journal.jsonl")
			if os.Mkdir(dir, 0700) != nil || os.WriteFile(journal, []byte("fixture-journal"), 0600) != nil || os.Chmod(journal, c.childMode) != nil || os.Chmod(dir, c.dirMode) != nil {
				t.Fatal("[setup failed] fixture directory")
			}
			t.Cleanup(func() { os.Chmod(dir, 0700); os.Chmod(journal, 0600) })
			if _, e := os.ReadFile(journal); (e == nil) != c.childReadable {
				t.Fatalf("[setup failed] child readable=%v want %v", e == nil, c.childReadable)
			}
			target := dir
			if c.targetChild {
				target = journal
			}
			spec.DeniedReads = append(spec.DeniedReads, target)
			r, e := RunCustodyProbe(context.Background(), spec)
			if e != nil {
				t.Fatal(e)
			}
			last, pass := r.Probes[2], c.want == "EACCES"
			if last.Target != target || last.Observed != c.want || last.Pass != pass || r.Pass != pass || (VerifyCustodyReport(spec, r) == nil) != pass {
				t.Fatalf("T18_SEARCH_GUARD %s: %+v report_pass=%v", c.name, last, r.Pass)
			}
			if r.Probes[0].Observed != "EACCES" || r.Probes[1].Observed != "EACCES" || !r.Probes[0].Pass || !r.Probes[1].Pass {
				t.Fatal("private file and directory neighbours in the same run", r.Probes[:2])
			}
		})
	}
}

// Claim (T18): the probe refuses to run unless the real and effective UID is
// spec.AgentUID and differs from spec.ServiceUID; malformed specs refuse
// ErrPolicy. The matching-UID neighbour runs.
func TestPX1T18ProbeUIDGate(t *testing.T) {
	spec, _ := g2Fixture(t)
	uid := spec.AgentUID
	other := spec
	other.AgentUID, other.ServiceUID = uid+1, uid+2
	if _, e := RunCustodyProbe(context.Background(), other); e != ErrCustody {
		t.Fatal("T18_UID_GATE probe ran as another UID", e)
	}
	asService := spec
	asService.AgentUID, asService.ServiceUID = uid+1, uid
	if _, e := RunCustodyProbe(context.Background(), asService); e != ErrCustody {
		t.Fatal("T18_UID_GATE probe ran as the service UID", e)
	}
	for name, mut := range map[string]func(*CustodySpecV1){
		"same-uid":        func(s *CustodySpecV1) { s.ServiceUID = s.AgentUID },
		"service-root":    func(s *CustodySpecV1) { s.ServiceUID = 0 },
		"version":         func(s *CustodySpecV1) { s.Version = 2 },
		"relative":        func(s *CustodySpecV1) { s.DeniedReads = append(s.DeniedReads, "etc/swarma/wallet/wallet.json") },
		"unclean":         func(s *CustodySpecV1) { s.DeniedReads = append(s.DeniedReads, "/etc/swarma/../shadow") },
		"duplicate":       func(s *CustodySpecV1) { s.DeniedReads = append(s.DeniedReads, s.DeniedReads[0]) },
		"socket-denied":   func(s *CustodySpecV1) { s.DeniedReads = append(s.DeniedReads, s.AllowedSocket) },
		"no-reads":        func(s *CustodySpecV1) { s.DeniedReads = nil },
		"no-rpc":          func(s *CustodySpecV1) { s.DeniedRPC = nil },
		"rpc-remote":      func(s *CustodySpecV1) { s.DeniedRPC = []string{"10.0.0.1:8336"} },
		"rpc-name":        func(s *CustodySpecV1) { s.DeniedRPC = []string{"localhost:8336"} },
		"rpc-leading-0":   func(s *CustodySpecV1) { s.DeniedRPC = []string{"127.0.0.1:08336"} },
		"rpc-port-0":      func(s *CustodySpecV1) { s.DeniedRPC = []string{"127.0.0.1:0"} },
		"socket-relative": func(s *CustodySpecV1) { s.AllowedSocket = "wallet.sock" },
	} {
		bad := spec
		bad.DeniedReads = append([]string{}, spec.DeniedReads...)
		mut(&bad)
		if _, e := RunCustodyProbe(context.Background(), bad); e != ErrPolicy {
			t.Fatal("T18_SPEC_GUARD probe accepted", name, e)
		}
		if e := VerifyCustodyReport(bad, CustodyReportV1{}); e != ErrPolicy {
			t.Fatal("T18_SPEC_GUARD verify accepted", name, e)
		}
	}
	if r, e := RunCustodyProbe(context.Background(), spec); e != nil || !r.Pass {
		t.Fatal("matching-UID neighbour", e)
	}
}

// Claim (T18): a credential-less RPC call passes only when refused (401, 403,
// connection refused); any other status, including 200 and 500, is HTTP_OK and
// fails. Limit: httptest stands in for Core here; the Core test uses a node.
func TestPX1T18RPCClassification(t *testing.T) {
	for status, want := range map[int]string{401: "HTTP_401", 403: "HTTP_403", 200: "HTTP_OK", 500: "HTTP_OK", 404: "HTTP_OK"} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, _, ok := r.BasicAuth(); ok {
				t.Error("probe sent credentials")
			}
			w.WriteHeader(status)
		}))
		target := strings.TrimPrefix(srv.URL, "http://")
		got, e := probeRPC(context.Background(), target)
		srv.Close()
		if e != nil || got != want || custodyPass("rpc", got) != (status == 401 || status == 403) {
			t.Fatalf("T18_RPC_CLASS status %d: %q %v", status, got, e)
		}
	}
	if got, e := probeRPC(context.Background(), g2ClosedPort(t)); e != nil || got != "REFUSED" || !custodyPass("rpc", got) {
		t.Fatal("refused port", got, e)
	}
}

// Claim (T18): the positive control fails when the own socket is missing or
// refuses connections; a live socket is the neighbour.
func TestPX1T18SocketPositiveControl(t *testing.T) {
	spec, root := g2Fixture(t)
	missing := spec
	missing.AllowedSocket = filepath.Join(root, "none.sock")
	r, e := RunCustodyProbe(context.Background(), missing)
	if e != nil || r.Pass || r.Probes[3].Observed != "ENOENT" || r.Probes[3].Pass {
		t.Fatalf("T18_SOCKET_GUARD missing socket %+v %v", r, e)
	}
	stale := filepath.Join(root, "stale.sock")
	l, _ := net.Listen("unix", stale)
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	l.Close()
	refused := spec
	refused.AllowedSocket = stale
	r, e = RunCustodyProbe(context.Background(), refused)
	if e != nil || r.Pass || r.Probes[3].Observed != "REFUSED" {
		t.Fatalf("T18_SOCKET_GUARD stale socket %+v %v", r, e)
	}
	if r, e := RunCustodyProbe(context.Background(), spec); e != nil || !r.Pass {
		t.Fatal("live socket neighbour", e)
	}
}

// Claim (T18 evidence): VerifyCustodyReport refuses a report from another UID
// or the service UID, a stale spec hash, a Pass bit that contradicts its
// observation, an unknown observation, reordered, missing or extra probes, a
// changed expectation and a failed overall verdict; the genuine report passes.
func TestPX1T18VerifyRefusals(t *testing.T) {
	spec, _ := g2Fixture(t)
	good, e := RunCustodyProbe(context.Background(), spec)
	if e != nil || VerifyCustodyReport(spec, good) != nil {
		t.Fatal("genuine report", e)
	}
	clone := func() CustodyReportV1 {
		r := good
		r.Probes = append([]CustodyProbeV1{}, good.Probes...)
		return r
	}
	for name, mut := range map[string]func(*CustodyReportV1){
		"other-uid":       func(r *CustodyReportV1) { r.UID = spec.AgentUID + 7 },
		"service-uid":     func(r *CustodyReportV1) { r.UID = spec.ServiceUID },
		"version":         func(r *CustodyReportV1) { r.Version = 2 },
		"spec-hash":       func(r *CustodyReportV1) { r.SpecSHA256 = strings.Repeat("0", 64) },
		"enoent-pass":     func(r *CustodyReportV1) { r.Probes[0].Observed = "ENOENT" },
		"readok-pass":     func(r *CustodyReportV1) { r.Probes[1].Observed = "READ_OK" },
		"rpc-ok-pass":     func(r *CustodyReportV1) { r.Probes[2].Observed = "HTTP_OK" },
		"unknown-code":    func(r *CustodyReportV1) { r.Probes[2].Observed = "TIMEOUT" },
		"pass-bit-lie":    func(r *CustodyReportV1) { r.Probes[3].Pass = false },
		"reordered":       func(r *CustodyReportV1) { r.Probes[0], r.Probes[1] = r.Probes[1], r.Probes[0] },
		"missing-socket":  func(r *CustodyReportV1) { r.Probes = r.Probes[:3] },
		"extra":           func(r *CustodyReportV1) { r.Probes = append(r.Probes, r.Probes[0]) },
		"expect-flipped":  func(r *CustodyReportV1) { r.Probes[0].Expect = "allowed" },
		"kind-swapped":    func(r *CustodyReportV1) { r.Probes[3].Kind = "read" },
		"overall-fail":    func(r *CustodyReportV1) { r.Pass = false },
		"socket-observed": func(r *CustodyReportV1) { r.Probes[3].Observed = "ENOENT" },
	} {
		r := clone()
		mut(&r)
		if e := VerifyCustodyReport(spec, r); e != ErrCustody {
			t.Fatal("T18_VERIFY_GUARD accepted", name, e)
		}
		if VerifyCustodyReport(spec, clone()) != nil {
			t.Fatal("genuine neighbour refused")
		}
	}
}

// Claim: the launch-spec check accepts only the rendered layout; a spec
// trimmed of a private path, of the status directory, of the node files or
// redirected to another socket is refused (the render is the positive control).
func TestPX1S5LaunchSpec(t *testing.T) {
	files, _ := RenderG2PayTemplates(g2Params())
	spec, e := ParseCustodySpec(bytes.TrimSuffix(files[G2FileCustodySpec], []byte("\n")))
	if e != nil || ValidateG2CustodyLaunchSpec(spec) != nil {
		t.Fatal("rendered spec", e)
	}
	for name, mut := range map[string]func(*CustodySpecV1){
		"no-receipt-key":       func(s *CustodySpecV1) { s.DeniedReads = append(s.DeniedReads[:1:1], s.DeniedReads[2:]...) },
		"no-wallet-dat":        func(s *CustodySpecV1) { s.DeniedReads = s.DeniedReads[:8] },
		"no-status-dir":        func(s *CustodySpecV1) { s.DeniedReads = append(s.DeniedReads[:6:6], s.DeniedReads[7:]...) },
		"status-dir-replaced":  func(s *CustodySpecV1) { s.DeniedReads[6] = "/run/swarma-wallet" },
		"wallet-json-replaced": func(s *CustodySpecV1) { s.DeniedReads[0] = "/etc/swarma/wallet/service.json" },
		"cookie-swapped":       func(s *CustodySpecV1) { s.DeniedReads[7], s.DeniedReads[8] = s.DeniedReads[8], s.DeniedReads[7] },
		"node-in-state": func(s *CustodySpecV1) {
			s.DeniedReads[7], s.DeniedReads[8] = "/var/lib/swarma-wallet/.cookie", "/var/lib/swarma-wallet/wallets/hot/wallet.dat"
		},
		"split-datadir": func(s *CustodySpecV1) { s.DeniedReads[7] = "/srv/other/.cookie" },
		"other-socket":  func(s *CustodySpecV1) { s.AllowedSocket = "/run/swarma-wallet/status.sock" },
		"two-rpc":       func(s *CustodySpecV1) { s.DeniedRPC = append(s.DeniedRPC, "127.0.0.1:8337") },
	} {
		bad := spec
		bad.DeniedReads = append([]string{}, spec.DeniedReads...)
		bad.DeniedRPC = append([]string{}, spec.DeniedRPC...)
		mut(&bad)
		if e := ValidateG2CustodyLaunchSpec(bad); e != ErrPolicy {
			t.Fatal("G2_LAUNCH_SPEC accepted", name, e)
		}
	}
}

// --- Core layer: genuine Namecoin Core 28 regtest node -----------------------

type g2Node struct {
	cmd     *exec.Cmd
	datadir string
	target  string
	users   map[string]string
}

func g2RPCAuth(user, password string) string {
	salt := make([]byte, 16)
	rand.Read(salt)
	s := hex.EncodeToString(salt)
	m := hmac.New(sha256.New, []byte(s))
	m.Write([]byte(password))
	return "rpcauth=" + user + ":" + s + "$" + hex.EncodeToString(m.Sum(nil)) + "\n"
}

// g2Call posts one JSON-RPC call; user "" sends no credentials and user
// "__cookie__" reads the node cookie.
func (n *g2Node) call(t *testing.T, user, path, method string) (int, []byte) {
	t.Helper()
	body := `{"jsonrpc":"1.0","id":"g2","method":"` + method + `","params":[]}`
	req, _ := http.NewRequest(http.MethodPost, "http://"+n.target+path, strings.NewReader(body))
	switch user {
	case "":
	case "__cookie__":
		cookie, _ := G2NodeCustodyPaths("regtest", n.datadir, g2HotName)
		raw, e := os.ReadFile(cookie)
		if e != nil {
			return 0, nil
		}
		u, pw, _ := strings.Cut(strings.TrimSpace(string(raw)), ":")
		req.SetBasicAuth(u, pw)
	default:
		req.SetBasicAuth(user, n.users[user])
	}
	resp, e := (&http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil}}).Do(req)
	if e != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	b := new(bytes.Buffer)
	b.ReadFrom(resp.Body)
	return resp.StatusCode, b.Bytes()
}

// g2StartNode renders the regtest node policy, appends rpcauth lines for the
// three routes (random per run, never logged), pre-creates the legacy hot
// wallet under <datadir>/regtest/wallets, and starts namecoind in the
// foreground. Cleanup stops that PID only.
func g2StartNode(t *testing.T) *g2Node {
	t.Helper()
	if os.Getenv("W1_REGTEST") != "1" {
		t.Skip("W1_REGTEST=1 with W1_CORE_DAEMON and W1_RUN_ROOT runs the Core layer")
	}
	daemon, runRoot := os.Getenv("W1_CORE_DAEMON"), os.Getenv("W1_RUN_ROOT")
	if !filepath.IsAbs(daemon) || !filepath.IsAbs(runRoot) {
		t.Fatal("[setup failed] absolute W1_CORE_DAEMON and W1_RUN_ROOT required")
	}
	os.MkdirAll(runRoot, 0700)
	dir, e := os.MkdirTemp(runRoot, "g2node")
	if e != nil {
		t.Fatal("[setup failed]", e)
	}
	port, _ := strconv.Atoi(strings.TrimPrefix(g2ClosedPort(t), "127.0.0.1:"))
	p := g2Params()
	p.Network, p.Genesis, p.NodeRPCPort = "regtest", regtestGenesis, uint16(port)
	files, e := RenderG2PayTemplates(p)
	if e != nil {
		t.Fatal("[setup failed]", e)
	}
	n := &g2Node{datadir: filepath.Join(dir, "node"), target: g2RPCTarget(p.NodeRPCPort), users: map[string]string{}}
	conf := string(files[G2FileRPCWhitelist])
	for _, route := range []string{"w3-observer", "w1-wallet", "w1-broadcast"} {
		pw := make([]byte, 24)
		rand.Read(pw)
		n.users[route] = hex.EncodeToString(pw)
		conf += g2RPCAuth(route, n.users[route])
	}
	os.MkdirAll(filepath.Join(n.datadir, "regtest", "wallets"), 0700)
	if e := os.WriteFile(filepath.Join(n.datadir, "namecoin.conf"), []byte(conf), 0600); e != nil {
		t.Fatal("[setup failed]", e)
	}
	tool := exec.Command(filepath.Join(filepath.Dir(daemon), "namecoin-wallet"), "-datadir="+n.datadir, "-regtest", "-wallet="+g2HotName, "-legacy", "create")
	if out, e := tool.CombinedOutput(); e != nil {
		t.Fatal("[setup failed] wallet tool", e, string(out))
	}
	logf, _ := os.Create(filepath.Join(dir, "namecoind.out"))
	n.cmd = exec.Command(daemon, "-datadir="+n.datadir, "-printtoconsole=0")
	n.cmd.Stdout, n.cmd.Stderr = logf, logf
	if e := n.cmd.Start(); e != nil {
		t.Fatal("[setup failed]", e)
	}
	os.WriteFile(filepath.Join(dir, "namecoind.pid"), []byte(strconv.Itoa(n.cmd.Process.Pid)+"\n"), 0600)
	done := make(chan struct{})
	go func() { n.cmd.Wait(); close(done) }()
	t.Cleanup(func() {
		n.cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(60 * time.Second):
			n.cmd.Process.Kill()
			<-done
		}
		logf.Close()
	})
	for i := 0; ; i++ {
		if code, _ := n.call(t, "__cookie__", "/", "getblockchaininfo"); code == 200 {
			break
		}
		select {
		case <-done:
			t.Fatal("[setup failed] namecoind exited; see", filepath.Join(dir, "namecoind.out"))
		case <-time.After(250 * time.Millisecond):
		}
		if i > 240 {
			t.Fatal("[setup failed] namecoind not ready")
		}
	}
	return n
}

// Claim (T18 Core layer): on a genuine Namecoin Core 28 regtest node started
// from the rendered policy, a credential-less call is HTTP_401, each route can
// call only its README methods (403 otherwise, including key export and
// sendtoaddress), the hot wallet loads from the rendered wallet= line, and the
// cookie and wallet.dat sit at the paths the custody spec denies. The probe run
// as the node's own UID observes READ_OK on both and the report is refused:
// same-UID custody fails T18. Limit: one UID only; no cross-UID denial here.
func TestPX1T18CoreNodePolicy(t *testing.T) {
	n := g2StartNode(t)
	if got, e := probeRPC(context.Background(), n.target); e != nil || got != "HTTP_401" {
		t.Fatal("T18_CORE_NOAUTH", got, e)
	}
	wallet := "/wallet/" + g2HotName
	for _, c := range []struct {
		user, path, method string
		allowed            bool
	}{
		{"w3-observer", "/", "getblockchaininfo", true},
		{"w3-observer", "/", "getbalances", false},
		{"w3-observer", "/", "stop", false},
		{"w1-wallet", wallet, "getbalances", true},
		{"w1-wallet", wallet, "listtransactions", true},
		{"w1-wallet", wallet, "dumpprivkey", false},
		{"w1-wallet", wallet, "dumpwallet", false},
		{"w1-wallet", wallet, "sendtoaddress", false},
		{"w1-wallet", "/", "getblockchaininfo", false},
		{"w1-broadcast", "/", "getblockchaininfo", false},
		{"w1-broadcast", wallet, "getbalances", false},
	} {
		code, body := n.call(t, c.user, c.path, c.method)
		if c.allowed && code != 200 || !c.allowed && code != 403 {
			t.Fatalf("T18_CORE_WHITELIST %s %s: HTTP %d %s", c.user, c.method, code, body)
		}
	}
	cookie, walletDat := G2NodeCustodyPaths("regtest", n.datadir, g2HotName)
	for _, p := range []string{cookie, walletDat} {
		if _, e := os.Stat(p); e != nil {
			t.Fatal("T18_CORE_PATHS rendered custody path absent on Core 28", p)
		}
	}
	spec, _ := g2Fixture(t)
	spec.DeniedReads = []string{cookie, walletDat}
	spec.DeniedRPC = []string{n.target}
	r, e := RunCustodyProbe(context.Background(), spec)
	if e != nil || r.Pass || r.Probes[0].Observed != "READ_OK" || r.Probes[1].Observed != "READ_OK" || r.Probes[2].Observed != "HTTP_401" || !r.Probes[2].Pass {
		t.Fatalf("T18_CORE_SAME_UID %+v %v", r, e)
	}
	if e := VerifyCustodyReport(spec, r); e != ErrCustody {
		t.Fatal("T18_CORE_SAME_UID same-UID report accepted", e)
	}
}

// --- PX1 S5 narrowing mutants -----------------------------------------------

type g2Plant struct {
	Name, File, Old, New, Selector, Marker, Package string
	Core                                            bool
}

// Claim: each S5 plant in testdata/px1-mutations-s5.json applies exactly once
// to a fresh copy of this module and fails its named test with its marker.
// Build failures, setup failures, panics and timeouts are never kills. The
// agent-wallet runner cannot host these plants (it copies only agent-wallet).
// The copy also carries the unmodified agent-wallet module and its local
// replace targets, so the client-consumer test builds the real CLI there.
func TestPX1S5GuardPlants(t *testing.T) {
	if os.Getenv("W1_MUTATIONS") != "1" {
		t.Skip("W1_MUTATIONS=1 with an absolute new W1_MUTATION_ROOT runs the S5 plants")
	}
	root := os.Getenv("W1_MUTATION_ROOT")
	if !filepath.IsAbs(root) || os.Mkdir(root, 0700) != nil {
		t.Fatal("absolute new W1_MUTATION_ROOT required")
	}
	raw, e := os.ReadFile("testdata/px1-mutations-s5.json")
	var plants []g2Plant
	if e != nil || json.Unmarshal(raw, &plants) != nil || len(plants) < 1 {
		t.Fatal("S5 plant manifest")
	}
	cwd, _ := os.Getwd()
	copyTree := func(src, dst string) error {
		return filepath.WalkDir(src, func(path string, d fs.DirEntry, e error) error {
			if e != nil {
				return e
			}
			rel, _ := filepath.Rel(src, path)
			if d.IsDir() {
				if d.Name() == ".temp" || d.Name() == ".git" {
					return filepath.SkipDir
				}
				return os.MkdirAll(filepath.Join(dst, rel), 0700)
			}
			if d.Type()&os.ModeSymlink != 0 {
				return errors.New("source symlink")
			}
			b, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			return os.WriteFile(filepath.Join(dst, rel), b, 0600)
		})
	}
	frozen := filepath.Join(root, "baseline")
	for _, m := range []string{"deploy", "experiments/single-use", "experiments/sealwatch", "experiments/agent-wallet", "experiments/rental", "experiments/payment-chain", "experiments/rental-booking"} {
		src, dst := filepath.Join(cwd, "..", m), filepath.Join(frozen, m)
		if info, e := os.Stat(src); e == nil && !info.IsDir() {
			os.MkdirAll(filepath.Dir(dst), 0700)
			b, _ := os.ReadFile(src)
			e = os.WriteFile(dst, b, 0600)
		} else if e = copyTree(src, dst); e != nil {
			t.Fatal(e)
		}
	}
	var rows []map[string]any
	for _, p := range plants {
		t.Run(p.Name, func(t *testing.T) {
			dir := filepath.Join(root, p.Name)
			if e := copyTree(frozen, dir); e != nil {
				t.Fatal(e)
			}
			file := filepath.Join(dir, "deploy", p.File)
			original, e := os.ReadFile(file)
			if e != nil || strings.Count(string(original), p.Old) != 1 {
				t.Fatal("plant guard not uniquely applied")
			}
			mutated := strings.Replace(string(original), p.Old, p.New, 1)
			os.WriteFile(file, []byte(mutated), 0600)
			pkg := p.Package
			if pkg == "" {
				pkg = "."
			}
			ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
			defer cancel()
			selector := "^" + strings.ReplaceAll(p.Selector, "/", "$/^") + "$"
			cmd := exec.CommandContext(ctx, "go", "test", "-count=1", "-run", selector, pkg)
			cmd.Dir = filepath.Join(dir, "deploy")
			for _, v := range os.Environ() {
				if !strings.HasPrefix(v, "W1_") && !strings.HasPrefix(v, "GOWORK=") {
					cmd.Env = append(cmd.Env, v)
				}
			}
			cmd.Env = append(cmd.Env, "GOWORK=off")
			if p.Core {
				cmd.Env = append(cmd.Env, "W1_REGTEST=1", "W1_RUN_ROOT="+filepath.Join(dir, "core"), "W1_CORE_DAEMON="+os.Getenv("W1_CORE_DAEMON"))
			}
			output, err := cmd.CombinedOutput()
			os.WriteFile(filepath.Join(dir, "test.log"), output, 0600)
			exit := -1
			if cmd.ProcessState != nil {
				exit = cmd.ProcessState.ExitCode()
			}
			out := string(output)
			killed := err != nil && ctx.Err() == nil && strings.Contains(out, p.Marker) && strings.Contains(out, "--- FAIL:") && !strings.Contains(out, "[build failed]") && !strings.Contains(out, "[setup failed]") && !strings.Contains(out, "panic:")
			rows = append(rows, map[string]any{"name": p.Name, "file": p.File, "selector": selector, "marker": p.Marker, "exit": exit, "killed": killed, "core": p.Core, "mutant_sha256": digest([]byte(mutated))})
			if !killed {
				t.Fatalf("intended control not detected: %s", filepath.Join(dir, "test.log"))
			}
		})
	}
	b, _ := json.MarshalIndent(rows, "", " ")
	os.WriteFile(filepath.Join(root, "results.json"), b, 0600)
}

// g2ResolveTemplate fills templates/g2-pay/parameters.json the way the
// operator does: string placeholders become JSON numbers or pinned keys.
func g2ResolveTemplate(raw []byte) []byte {
	s := string(bytes.TrimSuffix(raw, []byte("\n")))
	for old, value := range map[string]string{
		`"PLACEHOLDER_AGENT_UID"`:              "1201",
		`"PLACEHOLDER_PER_AGENT_GROUP_GID"`:    "1301",
		`"PLACEHOLDER_OPERATOR_GROUP_GID"`:     "1401",
		`"PLACEHOLDER_SERVICE_UID"`:            "1101",
		`PLACEHOLDER_AGENT_USER`:               g2Agent,
		`PLACEHOLDER_AGENT_KEY_FILE`:           g2KeyFile,
		`PLACEHOLDER_NODE_DATADIR`:             g2Datadir,
		`"PLACEHOLDER_NODE_RPC_PORT"`:          "8336",
		`"PLACEHOLDER_CANARY_VOUT"`:            "0",
		`PLACEHOLDER_GRANTEE_XONLY_PUBLIC_KEY`: g2KeyG,
		`PLACEHOLDER_RECEIPT_XONLY_PUBLIC_KEY`: g2Key2G,
		`PLACEHOLDER_CANARY_TXID`:              strings.Repeat("c", 64),
	} {
		s = strings.ReplaceAll(s, old, value)
	}
	return []byte(s)
}

// Claim: the shipped parameters template refuses ErrPlaceholder as is; once
// resolved it is canonical, equals the launch fixture (fee rate 110, never
// 200; the four amendment-1 members service_uid, agent_user, agent_key_file
// and node_datadir in frozen order) and carries the frozen operator golden.
func TestPX1S5ParametersTemplate(t *testing.T) {
	raw, e := os.ReadFile("templates/g2-pay/parameters.json")
	if e != nil {
		t.Fatal(e)
	}
	if _, e := ParseG2PayParameters(bytes.TrimSuffix(raw, []byte("\n"))); e != ErrPlaceholder {
		t.Fatal("G2_TEMPLATE unresolved template accepted", e)
	}
	resolved := g2ResolveTemplate(raw)
	p, e := ParseG2PayParameters(resolved)
	if e != nil || !reflect.DeepEqual(p, g2Params()) {
		t.Fatalf("G2_TEMPLATE resolved template %v %+v", e, p)
	}
	if !bytes.HasSuffix(resolved, []byte(`"g2":`+px1OperatorGolden+`}`)) || p.FeeRateSatVB != 110 {
		t.Fatal("G2_TEMPLATE operator bytes or fee rate")
	}
}

// g2ScriptFakes writes stand-ins for deploy-kit, agent-wallet and id whose
// exits, receipt verdict and group readback the test controls; the fake
// wallet keeps a copy of the request it was given. The fake id answers -G
// with FAKE_ID_G, -g with its first GID and -u with 1201.
func g2ScriptFakes(t *testing.T) (string, string, string) {
	t.Helper()
	dir := t.TempDir()
	kit := filepath.Join(dir, "deploy-kit")
	wallet := filepath.Join(dir, "agent-wallet")
	os.WriteFile(kit, []byte("#!/bin/sh\ncase $1 in\ng2-custody-probe) echo '{\"pass\":true}'; exit \"${FAKE_PROBE_EXIT:-0}\" ;;\ng2-custody-verify) exit \"${FAKE_VERIFY_EXIT:-0}\" ;;\nesac\nexit 9\n"), 0700)
	os.WriteFile(wallet, []byte("#!/bin/sh\ncp \"$4\" \"$FAKE_CAPTURE\"\nprintf '{\"receipt\":{\"verdict\":\"%s\"}}\\n' \"${FAKE_VERDICT:-executed}\"\nexit \"${FAKE_WALLET_EXIT:-0}\"\n"), 0700)
	bin := filepath.Join(dir, "bin")
	os.Mkdir(bin, 0700)
	os.WriteFile(filepath.Join(bin, "id"), []byte("#!/bin/sh\ncase $1 in\n-G) echo \"$FAKE_ID_G\" ;;\n-g) echo \"${FAKE_ID_G%% *}\" ;;\n-u) echo 1201 ;;\n*) exit 9 ;;\nesac\n"), 0700)
	return kit, wallet, bin
}

// Claim: g2-custody-check.sh prints T18_PASS and exits 0 only when the
// readback `id -G` is exactly the socket GID (primary agent_socket_gid, no
// supplementary group, never the operator GID), the probe, the own-agent
// request (exit 0 and verdict "executed") and the verify step all succeed;
// any single failure, a non-executed verdict, an extra, other or operator
// group, an existing evidence directory, a malformed grantee or GID, or a
// socket GID equal to the operator GID fails. A refused readback runs neither
// the probe nor the request. The positive request is a canonical "balance"
// read with a fresh nonce. Limit: the binaries and id are fakes here; the real
// probe and verify are covered by the T18 Go tests.
func TestPX1T18CustodyScript(t *testing.T) {
	kit, wallet, bin := g2ScriptFakes(t)
	work := t.TempDir()
	spec, client := filepath.Join(work, "spec.json"), filepath.Join(work, "client.json")
	os.WriteFile(spec, []byte("{}"), 0600)
	os.WriteFile(client, []byte("{}"), 0600)
	run := func(name, grantee, socketGID, operatorGID string, env ...string) (int, string, string) {
		out := filepath.Join(work, name)
		capture := filepath.Join(work, name+".request")
		cmd := exec.Command("/bin/sh", "g2-custody-check.sh", spec, client, grantee, socketGID, operatorGID, out)
		cmd.Env = append(os.Environ(), append([]string{"PATH=" + bin + ":" + os.Getenv("PATH"), "DEPLOY_KIT=" + kit, "AGENT_WALLET=" + wallet, "FAKE_CAPTURE=" + capture, "FAKE_ID_G=1301"}, env...)...)
		stdout, _ := cmd.Output()
		return cmd.ProcessState.ExitCode(), strings.TrimSpace(string(stdout)), capture
	}
	code, got, capture := run("pass", g2KeyG, "1301", "1401")
	if code != 0 || got != "T18_PASS" {
		t.Fatal("T18_SCRIPT positive", code, got)
	}
	if creds, _ := os.ReadFile(filepath.Join(work, "pass", "credentials.txt")); string(creds) != "uid=1201 gid=1301 groups=1301\n" {
		t.Fatalf("T18_SCRIPT credentials evidence %q", creds)
	}
	raw, _ := os.ReadFile(capture)
	var req struct {
		V         int               `json:"v"`
		Service   string            `json:"service"`
		Action    string            `json:"action"`
		Params    map[string]string `json:"params"`
		Grant     map[string]string `json:"grant"`
		Nonce     string            `json:"nonce"`
		CreatedAt int64             `json:"created_at"`
		Grantee   string            `json:"grantee"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&req) != nil || req.Action != "balance" || req.Service != "wallet.nmc" || req.V != 1 || req.Grant["kind"] != "none" || len(req.Grant) != 1 || len(req.Params) != 0 || !exactHex(req.Nonce, 16) || req.Grantee != g2KeyG || time.Since(time.Unix(req.CreatedAt, 0)).Abs() > time.Minute {
		t.Fatal("T18_SCRIPT request", string(raw))
	}
	if again, _ := json.Marshal(req); !bytes.Equal(again, raw) {
		t.Fatal("T18_SCRIPT request not canonical", string(raw))
	}
	for _, c := range []struct {
		name, grantee, socket, operator string
		code                            int
		env                             []string
	}{
		{"probe-fails", g2KeyG, "1301", "1401", 1, []string{"FAKE_PROBE_EXIT=1"}},
		{"verify-fails", g2KeyG, "1301", "1401", 1, []string{"FAKE_VERIFY_EXIT=1"}},
		{"wallet-fails", g2KeyG, "1301", "1401", 1, []string{"FAKE_WALLET_EXIT=2", "FAKE_VERDICT=refused"}},
		{"refused-exit-zero", g2KeyG, "1301", "1401", 1, []string{"FAKE_VERDICT=refused"}},
		{"supplementary-group", g2KeyG, "1301", "1401", 1, []string{"FAKE_ID_G=1301 1201"}},
		{"primary-not-socket", g2KeyG, "1301", "1401", 1, []string{"FAKE_ID_G=1201 1301"}},
		{"operator-primary", g2KeyG, "1301", "1401", 1, []string{"FAKE_ID_G=1401"}},
		{"operator-supplementary", g2KeyG, "1301", "1401", 1, []string{"FAKE_ID_G=1301 1401"}},
		{"socket-is-operator", g2KeyG, "1401", "1401", 64, []string{"FAKE_ID_G=1401"}},
		{"gid-zero", g2KeyG, "0", "1401", 64, []string{"FAKE_ID_G=0"}},
		{"gid-leading-zero", g2KeyG, "01301", "1401", 64, []string{"FAKE_ID_G=01301"}},
		{"gid-empty", g2KeyG, "1301", "", 64, nil},
		{"grantee-upper", strings.ToUpper(g2KeyG), "1301", "1401", 64, nil},
		{"grantee-short", g2KeyG[:62], "1301", "1401", 64, nil},
		{"pass", g2KeyG, "1301", "1401", 64, nil}, // evidence directory exists: never overwritten
	} {
		code, got, capture := run(c.name, c.grantee, c.socket, c.operator, c.env...)
		if code != c.code || c.code == 1 && got != "T18_FAIL" {
			t.Fatal("T18_SCRIPT guard", c.name, code, got)
		}
		if strings.HasPrefix(c.name, "operator-") || c.name == "supplementary-group" || c.name == "primary-not-socket" {
			_, probeRan := os.Stat(filepath.Join(work, c.name, "custody-report.json"))
			_, requestRan := os.Stat(capture)
			if probeRan == nil || requestRan == nil {
				t.Fatal("T18_SCRIPT guard ran the probe or the request with refused credentials", c.name)
			}
		}
	}
}
