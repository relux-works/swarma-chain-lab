package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-chain-lab/deploy"
)

type g2PayPublicCase struct {
	Name         string
	Public       json.RawMessage
	Want         string
	ProductValid bool
}

// g2PayPublicCases keeps product-policy fixtures and command refusals identical.
func g2PayPublicCases(t *testing.T) []g2PayPublicCase {
	t.Helper()
	p := cliParams()
	var policy map[string]any
	if e := json.Unmarshal([]byte(g2TestPolicy(p.Network, p.Genesis)), &policy); e != nil {
		t.Fatal(e)
	}
	encode := func(policy map[string]any) []byte {
		b, e := json.Marshal(g2WalletPublic{Policy: mustG2JSON(t, policy), ChangeAddress: g2TestMainChange, WalletDir: "/var/lib/namecoind/wallets/g2-hot", MemoryZone: "/srv/agent/.curator/memory"})
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	cases := []g2PayPublicCase{{"valid-main", encode(policy), "", true}}
	add := func(name, member string, value any, missing bool, want string, productValid bool) {
		c := map[string]any{}
		for k, v := range policy {
			c[k] = v
		}
		if missing {
			delete(c, member)
		} else {
			c[member] = value
		}
		cases = append(cases, g2PayPublicCase{name, encode(c), want, productValid})
	}
	for _, member := range []string{"construction_profile", "network", "genesis", "state_dir", "agent_name", "landlord_name", "seal_script"} {
		add("missing-"+member, member, nil, true, "policy."+member, false)
		add("empty-"+member, member, "", false, "policy."+member, false)
		add("null-"+member, member, nil, false, "policy schema", false)
		add("wrong-type-"+member, member, 1, false, "policy schema", false)
	}
	for _, row := range []struct {
		name, member, value string
		productValid        bool
	}{
		{"wrong-construction-profile", "construction_profile", "legacy", false},
		{"wrong-network", "network", "regtest", false},
		{"wrong-genesis", "genesis", g2TestRegtestGenesis, false},
		{"wrong-state-dir", "state_dir", "/var/lib/swarma-wallet/other", true},
		{"unclean-state-dir", "state_dir", "/var/lib/swarma-wallet/../kernel", false},
		{"agent-no-prefix", "agent_name", "g2-agent", false},
		{"agent-empty-id", "agent_name", "id/", false},
		{"agent-upper", "agent_name", "id/G2", false},
		{"agent-unicode", "agent_name", "id/é", false},
		{"agent-slash", "agent_name", "id/a/b", false},
		{"agent-too-long", "agent_name", "id/" + strings.Repeat("a", 253), false},
		{"landlord-no-prefix", "landlord_name", "landlord", false},
		{"landlord-too-long", "landlord_name", "id/" + strings.Repeat("a", 253), false},
		{"same-names", "landlord_name", "id/g2-test-agent", false},
		{"seal-short", "seal_script", "76a91488ac", false},
		{"seal-witness", "seal_script", "0014" + strings.Repeat("11", 20), false},
		{"seal-wrong-opcode", "seal_script", "76a914" + strings.Repeat("11", 20) + "88ad", false},
		{"seal-uppercase", "seal_script", "76A914" + strings.Repeat("11", 20) + "88AC", false},
		{"seal-nonhex", "seal_script", "zz" + strings.Repeat("11", 24), false},
	} {
		add(row.name, row.member, row.value, false, "policy."+row.member, row.productValid)
	}
	for _, member := range []string{"issuer_pubkey", "agent_pubkey", "station_name", "station_script", "funding_script", "fee_rate"} {
		var value any = ""
		if member == "fee_rate" {
			value = 0
		}
		// Grant validation ignores these legacy fields; G2 deliberately refuses their presence.
		add("legacy-"+member, member, value, false, "policy schema", true)
	}
	add("unknown-policy-field", "unknown", "x", false, "policy schema", false)
	for _, row := range []struct{ name, from, to string }{
		{"duplicate-policy-member", `"construction_profile":"W"`, `"construction_profile":"W","construction_profile":"W"`},
		{"aliased-policy-member", `"agent_name":`, `"Agent_Name":`},
	} {
		b := bytes.Replace(cases[0].Public, []byte(row.from), []byte(row.to), 1)
		if bytes.Equal(b, cases[0].Public) {
			t.Fatal("schema fixture unchanged", row.name)
		}
		cases = append(cases, g2PayPublicCase{row.name, b, "schema", false})
	}
	point := map[string]any{"txid": strings.Repeat("12", 32), "vout": 1}
	add("valid-inventory", "known_pool_seals", []any{point}, false, "", true)
	add("duplicate-inventory", "known_pool_seals", []any{point, point}, false, "policy.known_pool_seals", false)
	add("bad-inventory-txid", "known_pool_seals", []any{map[string]any{"txid": "bad", "vout": 1}}, false, "policy.known_pool_seals", false)
	add("null-inventory", "known_pool_seals", nil, false, "policy schema", false)
	add("unknown-inventory-field", "known_pool_seals", []any{map[string]any{"txid": strings.Repeat("12", 32), "vout": 1, "other": 1}}, false, "policy schema", false)
	inventory := make([]any, 4097)
	for i := range inventory {
		inventory[i] = map[string]any{"txid": strings.Repeat("12", 32), "vout": i}
	}
	add("too-many-inventory", "known_pool_seals", inventory, false, "policy.known_pool_seals", false)
	for _, row := range []struct{ name, value string }{
		{"valid-id-punctuation", "id/a-0_."}, {"valid-max-id", "id/" + strings.Repeat("a", 252)},
	} {
		add(row.name, "agent_name", row.value, false, "", true)
	}
	return cases
}

func mustG2JSON(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

type g2NoEntropy struct{ reads int }

func (r *g2NoEntropy) Read(b []byte) (int, error) {
	r.reads++
	return 0, errors.New("unexpected entropy read")
}

// Claim: every missing or invalid W pay-policy member refuses by name before entropy/output, beside valid mainnet and inventory neighbours.
func TestG2RPCAuthPayPolicy(t *testing.T) {
	for _, c := range g2PayPublicCases(t) {
		t.Run(c.Name, func(t *testing.T) {
			// The oversized inventory cannot fit the public-file size bound; exercise
			// its exact validator separately instead of claiming command reachability.
			if c.Name == "too-many-inventory" {
				var w g2WalletPublic
				json.Unmarshal(c.Public, &w)
				if e := g2ValidatePayPolicy(w.Policy, cliParams()); e == nil || !strings.Contains(e.Error(), c.Want) {
					t.Fatal("inventory bound not enforced", e)
				}
				return
			}
			g2CheckPublicCommand(t, c.Public, c.Want)
		})
	}
}

func g2CheckPublicCommand(t *testing.T, raw []byte, want string) {
	t.Helper()
	dir := t.TempDir()
	params := g2TestWriteParams(t, dir, "params.json", cliParams())
	public, out := filepath.Join(dir, "public.json"), filepath.Join(dir, "wallet.json")
	if e := os.WriteFile(public, raw, 0600); e != nil {
		t.Fatal(e)
	}
	var stdout bytes.Buffer
	if want == "" {
		if e := g2RPCAuth([]string{"-params", params, "-wallet-public", public, "-wallet-config-out", out}, &stdout); e != nil {
			t.Fatal("valid neighbour refused", e)
		}
		if _, e := os.Stat(out); e != nil || stdout.Len() == 0 {
			t.Fatal("valid neighbour output missing", e)
		}
		return
	}
	entropy := new(g2NoEntropy)
	e := g2RPCAuthFrom([]string{"-params", params, "-wallet-public", public, "-wallet-config-out", out}, &stdout, entropy)
	if !errors.Is(e, deploy.ErrPolicy) || !strings.Contains(e.Error(), want) {
		t.Fatalf("want named refusal %s, got %v", want, e)
	}
	if _, e := os.Lstat(out); !os.IsNotExist(e) {
		t.Fatal("refusal wrote output", e)
	}
	entries, e := os.ReadDir(dir)
	if e != nil || len(entries) != 2 {
		t.Fatal("refusal left extra files", e)
	}
	if entropy.reads != 0 || stdout.Len() != 0 {
		t.Fatal("refusal consumed entropy or printed output")
	}
}

func g2AddressCases() []struct {
	Name, Address string
	Valid         bool
} {
	return []struct {
		Name, Address string
		Valid         bool
	}{
		{"main-p2pkh", g2TestMainChange, true},
		{"regtest-on-main", g2TestRegtestChange, false},
		{"main-p2sh", "6Fx5jVAN9MirDjMbikRJGe2M6Fy4SEUPeC", false},
		{"main-segwit-nc1", "nc1qzyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3stkwkp", false},
		{"checksum", g2TestMainChange[:len(g2TestMainChange)-1] + "Y", false},
		{"leading-zero", "1" + g2TestMainChange, false},
		{"whitespace", g2TestMainChange + " ", false},
		{"invalid-alphabet", "0" + g2TestMainChange[1:], false},
		{"empty", "", false},
	}
}

// Claim: main P2PKH passes while valid wrong-network/P2SH/segwit encodings and malformed addresses refuse before output.
func TestG2RPCAuthPayChangeAddress(t *testing.T) {
	for _, c := range g2AddressCases() {
		t.Run(c.Name, func(t *testing.T) {
			w := g2WalletPublic{Policy: []byte(g2TestPolicy(cliParams().Network, cliParams().Genesis)), ChangeAddress: c.Address, WalletDir: "/var/lib/namecoind/wallets/g2-hot", MemoryZone: "/srv/agent/.curator/memory"}
			want := "change_address"
			if c.Valid {
				want = ""
			}
			g2CheckPublicCommand(t, mustG2JSON(t, w), want)
		})
	}
}

// Claim: wallet_dir rejects equality, ancestry and descendants of wallet/service state, but accepts adjacent names; memory_zone is absolute, clean and distinct from wallet state, as startup requires.
func TestG2RPCAuthPayPaths(t *testing.T) {
	for _, c := range []struct{ Name, Wallet, Memory, Want string }{
		{"wallet-equal", g2WalletStateDir, "/memory", "wallet_dir"},
		{"wallet-child", g2WalletStateDir + "/node", "/memory", "wallet_dir"},
		{"service-equal", "/var/lib/swarma-wallet/service", "/memory", "wallet_dir"},
		{"service-child", "/var/lib/swarma-wallet/service/node", "/memory", "wallet_dir"},
		{"state-parent", "/var/lib/swarma-wallet", "/memory", "wallet_dir"},
		{"var-parent", "/var", "/memory", "wallet_dir"},
		{"wallet-adjacent", g2WalletStateDir + "-node", "/memory", ""},
		{"service-adjacent", "/var/lib/swarma-wallet/service-node", "/memory", ""},
		{"unclean-wallet", "/node/../node", "/memory", "wallet_dir"},
		{"memory-is-wallet-state", "/node", g2WalletStateDir, "memory_zone"},
		{"relative-memory", "/node", "memory", "memory_zone"},
		{"unclean-memory", "/node", "/memory/../memory", "memory_zone"},
	} {
		t.Run(c.Name, func(t *testing.T) {
			w := g2WalletPublic{Policy: []byte(g2TestPolicy(cliParams().Network, cliParams().Genesis)), ChangeAddress: g2TestMainChange, WalletDir: c.Wallet, MemoryZone: c.Memory}
			g2CheckPublicCommand(t, mustG2JSON(t, w), c.Want)
		})
	}
}

// g2ProductProbe injects tests via a Go overlay; source files stay untouched.
func g2ProductProbe(t *testing.T, module, source string, fixtures any) {
	t.Helper()
	dir := t.TempDir()
	cwd, e := os.Getwd()
	if e != nil {
		t.Fatal(e)
	}
	module = filepath.Clean(filepath.Join(cwd, "../../../experiments", module))
	probe, data, overlay := filepath.Join(dir, "probe_test.go"), filepath.Join(dir, "fixtures.json"), filepath.Join(dir, "overlay.json")
	for path, b := range map[string][]byte{probe: []byte(source), data: mustG2JSON(t, fixtures), overlay: mustG2JSON(t, map[string]any{"Replace": map[string]string{filepath.Join(module, "g2_deploy_probe_test.go"): probe}})} {
		if e := os.WriteFile(path, b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "test", "-mod=readonly", "-overlay", overlay, "-count=1", "-run", "^TestG2DeployProbe$", ".")
	cmd.Dir = module
	for _, v := range os.Environ() {
		if !strings.HasPrefix(v, "GOWORK=") && !strings.HasPrefix(v, "G2_DEPLOY_FIXTURES=") {
			cmd.Env = append(cmd.Env, v)
		}
	}
	cmd.Env = append(cmd.Env, "GOWORK=off", "G2_DEPLOY_FIXTURES="+data)
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("product probe %s: %v\n%s", filepath.Base(module), e, out)
	}
}

// Claim: the command's policy/address fixtures match real private product validators; main wallet.json also passes the real loader and startup network check.
func TestG2RPCAuthProductValidators(t *testing.T) {
	cases := g2PayPublicCases(t)
	t.Run("rental", func(t *testing.T) { g2ProductProbe(t, "rental", g2RentalProbe, cases) })
	t.Run("wallet", func(t *testing.T) {
		dir := t.TempDir()
		p := cliParams()
		params := g2TestWriteParams(t, dir, "params.json", p)
		public := g2TestWritePublic(t, dir, "public.json", p.Network, p.Genesis, g2TestMainChange)
		out := filepath.Join(dir, "wallet.json")
		if e := g2RPCAuth([]string{"-params", params, "-wallet-public", public, "-wallet-config-out", out}, &bytes.Buffer{}); e != nil {
			t.Fatal(e)
		}
		// LoadConfig's explicit owner-only contract; installed loading instead needs a signed root-owned set.
		if e := os.Chmod(out, 0600); e != nil {
			t.Fatal(e)
		}
		g2ProductProbe(t, "agent-wallet", g2WalletProbe, map[string]any{"Config": out, "Addresses": g2AddressCases()})
	})
}

const g2RentalProbe = `package rental

import (
	"encoding/json"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"os"
	"testing"
)

// Claim: deploy's shared fixtures pin its W policy checks to rental.Policy and validateGrant; legacy presence and the exact state directory are stricter G2 constraints.
func TestG2DeployProbe(t *testing.T) {
	var cases []struct {
		Name         string
		Public       json.RawMessage
		ProductValid bool
	}
	b, e := os.ReadFile(os.Getenv("G2_DEPLOY_FIXTURES"))
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(b, &cases); e != nil {
		t.Fatal(e)
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			var w struct{ Policy json.RawMessage }
			if e := json.Unmarshal(c.Public, &w); e != nil {
				t.Fatal(e)
			}
			var p Policy
			e := su.StrictInput(w.Policy, &p)
			if e == nil {
				e = p.validateGrant()
			}
			if (e == nil) != c.ProductValid {
				t.Fatalf("product policy valid=%v want=%v: %v", e == nil, c.ProductValid, e)
			}
		})
	}
}
`

const g2WalletProbe = `package wallet

import (
	"bytes"
	"encoding/json"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"os"
	"testing"
)

// Claim: the generated mainnet config passes LoadConfig and validateNetwork; shared addresses exercise the exact startup address function with positive network neighbours.
func TestG2DeployProbe(t *testing.T) {
	var fixture struct {
		Config    string
		Addresses []struct {
			Name, Address string
			Valid         bool
		}
	}
	b, e := os.ReadFile(os.Getenv("G2_DEPLOY_FIXTURES"))
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(b, &fixture); e != nil {
		t.Fatal(e)
	}
	c, e := LoadConfig(fixture.Config)
	if e != nil {
		t.Fatal("real loader", e)
	}
	if e = c.validateNetwork(); e != nil {
		t.Fatal("startup network validator", e)
	}
	for _, a := range fixture.Addresses {
		t.Run(a.Name, func(t *testing.T) {
			_, e := addressScriptForNetwork(a.Address, "main", su.MainGenesis)
			if (e == nil) != a.Valid {
				t.Fatalf("startup address valid=%v want=%v: %v", e == nil, a.Valid, e)
			}
			if a.Name == "main-p2sh" && (e == nil || e.Error() != "ADDRESS_P2PKH_ONLY") {
				t.Fatal("fixture is not a valid address of the intended forbidden type", e)
			}
		})
	}
	// The product decoder does not recognize nc1 before its P2PKH type guard.
	// Independently establish that the shared nc1 fixture is a valid encoding.
	params := chaincfg.MainNetParams
	params.Bech32HRPSegwit = "nc"
	witness, e := btcutil.NewAddressWitnessPubKeyHash(bytes.Repeat([]byte{0x11}, 20), &params)
	if e != nil {
		t.Fatal(e)
	}
	for _, a := range fixture.Addresses {
		if a.Name == "main-segwit-nc1" {
			if a.Address != witness.EncodeAddress() {
				t.Fatal("invalid nc1 fixture")
			}
			if _, e := addressScriptForNetwork(a.Address, "main", su.MainGenesis); e == nil || e.Error() != "ADDRESS_MAIN" {
				t.Fatal("nc1 decoding refusal changed", e)
			}
		}
	}
	// Startup refuses this metadata collision before opening any state or RPC.
	bad := c
	bad.MemoryZone = bad.StateDir
	if _, e := openWallet(bad); e == nil || e.Error() != "CONFIG_PATH_SEPARATION" {
		t.Fatal("startup memory/state separation changed", e)
	}
	if _, e := addressScriptForNetwork("mh5CE8Nbj38iND267s4XnvhSmhDW7yWc6Q", "regtest", su.RegtestGenesis); e != nil {
		t.Fatal("regtest positive neighbour", e)
	}
	if _, e := addressScriptForNetwork(c.ChangeAddress, "main", su.RegtestGenesis); e == nil {
		t.Fatal("wrong genesis accepted")
	}
}
`
