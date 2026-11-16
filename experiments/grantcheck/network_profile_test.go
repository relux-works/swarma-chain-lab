package grantcheck

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernel"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// Claim: MainGenesis is the Namecoin mainnet genesis hash that Namecoin Core
// asserts in CMainParams (chainparams.cpp), written here a second time as a
// literal, and it is the constant that the rental kernel pins for "main".
// Each network name admits its own genesis only.
func TestMainGenesisLiteral(t *testing.T) {
	const literal = "000000000062b72c5e2ceb45fbc8587e807c155b0da735e6483dfba2f0a9c770"
	if MainGenesis != literal || len(MainGenesis) != 64 {
		t.Fatal("MainGenesis is not the Namecoin mainnet genesis hash")
	}
	if MainGenesis != su.MainGenesis {
		t.Fatal("MainGenesis differs from the rental kernel pin")
	}
	if !pinnedNetwork("main", MainGenesis) || !pinnedNetwork("regtest", su.RegtestGenesis) || !su.NetworkPinned("main", MainGenesis) {
		t.Fatal("a network does not admit its own genesis")
	}
	if pinnedNetwork("main", su.RegtestGenesis) || pinnedNetwork("regtest", MainGenesis) || MainGenesis == su.RegtestGenesis {
		t.Fatal("a network admits the genesis of the other")
	}
}

// Claim: the network binding comes from configuration and has no default
// under the trust profile. A missing network, a missing genesis, an unknown
// network name, a pair of one network with the genesis of the other and an
// unknown profile all refuse at construction with ErrConfig, before any
// state opens. "regtest" and "main" each construct with their own genesis.
// The pay profile constructs without a network, as it did before, and with
// an explicit admitted pair; a half-set pair refuses. Both the constructor
// and the resolver are asserted, because the kernel binding refuses an
// unpinned pair as well.
func TestNetworkConfig(t *testing.T) {
	for _, tc := range []struct {
		name, profile, network, genesis string
		ok                              bool
	}{
		{"trust-regtest", ContractProfileTrust, "regtest", su.RegtestGenesis, true},
		{"trust-main", ContractProfileTrust, "main", MainGenesis, true},
		{"trust-missing-network-and-genesis", ContractProfileTrust, "", "", false},
		{"trust-missing-network", ContractProfileTrust, "", MainGenesis, false},
		{"trust-missing-genesis", ContractProfileTrust, "main", "", false},
		{"trust-unknown-network", ContractProfileTrust, "test", su.RegtestGenesis, false},
		{"trust-network-alias", ContractProfileTrust, "mainnet", MainGenesis, false},
		{"trust-network-case", ContractProfileTrust, "Main", MainGenesis, false},
		{"trust-main-with-regtest-genesis", ContractProfileTrust, "main", su.RegtestGenesis, false},
		{"trust-regtest-with-main-genesis", ContractProfileTrust, "regtest", MainGenesis, false},
		{"trust-unknown-genesis", ContractProfileTrust, "main", strings.Repeat("0", 64), false},
		{"pay-without-network", "", "", "", true},
		{"pay-named-without-network", ContractProfilePay, "", "", true},
		{"pay-regtest", ContractProfilePay, "regtest", su.RegtestGenesis, true},
		{"pay-main", ContractProfilePay, "main", MainGenesis, true},
		{"pay-missing-genesis", ContractProfilePay, "regtest", "", false},
		{"pay-missing-network", "", "", su.RegtestGenesis, false},
		{"pay-main-with-regtest-genesis", "", "main", su.RegtestGenesis, false},
		{"unknown-profile", "auto", "regtest", su.RegtestGenesis, false},
		{"profile-case", "Trust", "regtest", su.RegtestGenesis, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := unitConfig(t)
			config.ContractProfile, config.Network, config.Genesis = tc.profile, tc.network, tc.genesis
			if tc.profile == ContractProfileTrust {
				config.ExecutorKey = ""
			}
			profile, network, genesis, resolved := resolveBinding(config)
			if resolved != tc.ok {
				t.Fatalf("configuration resolved=%v, want %v", resolved, tc.ok)
			}
			c, err := New(config)
			if !tc.ok {
				if c != nil || !errors.Is(err, ErrConfig) || profile != "" || network != "" || genesis != "" {
					t.Fatalf("unpinned configuration did not refuse with ErrConfig: %v", err)
				}
				if entries, e := os.ReadDir(config.StateDir); e != nil || len(entries) != 0 {
					t.Fatal("refused configuration opened state")
				}
				return
			}
			if err != nil || c == nil {
				t.Fatalf("pinned configuration refused: %v", err)
			}
			wantNetwork, wantGenesis := tc.network, tc.genesis
			if wantNetwork == "" {
				wantNetwork, wantGenesis = "regtest", su.RegtestGenesis
			}
			wantProfile := tc.profile
			if wantProfile == "" {
				wantProfile = ContractProfilePay
			}
			if c.profile != wantProfile || c.network != wantNetwork || c.genesis != wantGenesis || c.node.chain != wantNetwork ||
				profile != wantProfile || network != wantNetwork || genesis != wantGenesis {
				t.Fatalf("checker binding %s/%s/%s", c.profile, c.network, c.genesis)
			}
		})
	}
}

// Claim (addendum 1): the configured network is on the admission path. A
// grant whose network and genesis are regtest refuses under a main
// configuration, and a grant whose network and genesis are main refuses
// under a regtest configuration, both as binding_mismatch before the
// backend; the grant of the configured network is admitted by the same
// checker. A grant that pairs one network with the genesis of the other is no
// valid v3 grant and refuses as invalid_presentation under either
// configuration, although its signature is valid over its bytes.
func TestTrustNetworkBinding(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		config, network, genesis string
		code                     Code
		unvalidated              bool
	}{
		{"regtest-grant-under-main-config", "main", "regtest", su.RegtestGenesis, CodeBindingMismatch, false},
		{"main-grant-under-regtest-config", "regtest", "main", MainGenesis, CodeBindingMismatch, false},
		{"main-network-with-regtest-genesis-under-main-config", "main", "main", su.RegtestGenesis, CodeInvalidPresentation, true},
		{"main-network-with-regtest-genesis-under-regtest-config", "regtest", "main", su.RegtestGenesis, CodeInvalidPresentation, true},
		{"regtest-network-with-main-genesis-under-main-config", "main", "regtest", MainGenesis, CodeInvalidPresentation, true},
		{"regtest-network-with-main-genesis-under-regtest-config", "regtest", "regtest", MainGenesis, CodeInvalidPresentation, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			own := trustV1(t, tc.config, nil)
			foreign := trustV1(t, tc.network, nil)
			c, b := trustChecker(t, trustConfig(t, tc.config, genesisOf(tc.config), own, foreign))
			ctx := context.Background()
			refused := trustGrant(t, trustGrantSpec{Network: tc.network, Genesis: tc.genesis, Contract: foreign, Unvalidated: tc.unvalidated})
			assertVerdict(t, c.Inbound(ctx, xonly(2), &refused), Refused, tc.code, false, false)
			if b.Calls != 0 {
				t.Fatal("a grant of another network reached the backend")
			}
			if _, err := c.cachedGrant(xonly(2)); err != kernel.ErrNoPresentation {
				t.Fatal("a grant of another network was cached")
			}
			control := trustGrant(t, trustGrantSpec{Network: tc.config, Genesis: genesisOf(tc.config), Contract: own})
			assertVerdict(t, c.Inbound(ctx, xonly(2), &control), Live, CodeLive, false, false)
		})
	}
}

// Claim: a stored proof is bound to the configured network as well. A cache
// entry whose grant is of the other network is not a valid cache for this
// checker, beside an entry of the configured network that is.
func TestCacheNetworkBinding(t *testing.T) {
	for _, network := range []string{"regtest", "main"} {
		t.Run(network, func(t *testing.T) {
			other := "main"
			if network == "main" {
				other = "regtest"
			}
			own, foreign := trustV1(t, network, nil), trustV1(t, other, nil)
			c, _ := trustChecker(t, trustConfig(t, network, genesisOf(network), own, foreign))
			entry := func(net string, contract []byte) []cachedProof {
				p := trustGrant(t, trustGrantSpec{Network: net, Genesis: genesisOf(net), Contract: contract})
				return []cachedProof{{Peer: xonly(2), GrantID: p.GrantID, Bytes: p.Bytes}}
			}
			if !c.validCache(entry(network, own)) {
				t.Fatal("cached proof of the configured network refused")
			}
			if c.validCache(entry(other, foreign)) {
				t.Fatal("cached proof of another network admitted")
			}
		})
	}
}

func chainNode(chain string) su.Node {
	best := strings.Repeat("a", 64)
	return nodeFunc(func(_ context.Context, method string, _ ...any) (json.RawMessage, error) {
		switch method {
		case "getblockchaininfo":
			return json.RawMessage(`{"chain":"` + chain + `","blocks":5,"headers":5,"bestblockhash":"` + best + `","initialblockdownload":false}`), nil
		case "getblockheader":
			return json.RawMessage(`{"hash":"` + best + `","height":5,"confirmations":1,"time":500}`), nil
		}
		return nil, errors.New("unexpected node method")
	})
}

// Claim: the node observation is bound to the configured network. A node
// that reports the other chain refuses as verifier_unavailable, beside a
// node that reports the configured chain and passes the same policy. Limit:
// this tests the checker's own wrapper; the kernel checks the chain name and
// the genesis block hash on its own.
func TestNodeChainFollowsConfig(t *testing.T) {
	for _, tc := range []struct{ name, config, chain string }{
		{"regtest-node-under-main-config", "main", "regtest"},
		{"main-node-under-regtest-config", "regtest", "main"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, chain := range []string{tc.config, tc.chain} {
				config := trustConfig(t, tc.config, genesisOf(tc.config))
				config.Node = chainNode(chain)
				c, err := New(config)
				if err != nil {
					t.Fatal(err)
				}
				c.node.reset(time.Unix(500, 0))
				_, err = c.node.Call(context.Background(), "getblockchaininfo")
				if chain == tc.config {
					if err != nil || c.node.code != "" || !c.node.seen {
						t.Fatalf("node of the configured chain refused: %v %s", err, c.node.code)
					}
					continue
				}
				if err == nil || c.node.code != CodeVerifierUnavailable {
					t.Fatalf("node of another chain passed the observation policy: %v %q", err, c.node.code)
				}
			}
		})
	}
}

func landlordAnswer(t *testing.T, value string) json.RawMessage {
	t.Helper()
	return jsonBytes(t, map[string]any{"name": "id/test-landlord", "value": value, "txid": strings.Repeat("c", 64), "vout": 0, "height": 3})
}

// Claim (LIP-0010 section 10, the G1.0 profile): under the trust profile a
// landlord value that carries holders, empty or populated, refuses as
// binding_mismatch and is not cached, beside the legacy value of the same
// landlord, which is admitted. The grant is in the G1.0 shape: profile /1,
// instruct and review, network main. The backend stands in for the kernel
// only in that it reads the landlord name through the checker's node, as the
// kernel does; it would answer live for any value. Limit: the kernel's own
// reader also refuses a non-legacy value (TestR1V3NameCompatibility); this
// test is about the checker's gate and its code, not about a node.
func TestTrustLegacyLandlord(t *testing.T) {
	legacy, err := rental.LandlordValue(rental.LandlordBinding{Grant: xonly(1)})
	if err != nil {
		t.Fatal(err)
	}
	withHolders := func(holders string) string {
		old := `"grant":"` + xonly(1) + `"`
		if strings.Count(legacy, old) != 1 {
			t.Fatal("legacy landlord value has an unexpected shape")
		}
		return strings.Replace(legacy, old, old+`,"holders":`+holders, 1)
	}
	for _, tc := range []struct {
		name, value string
		decision    Decision
		code        Code
	}{
		{"legacy", legacy, Live, CodeLive},
		{"holders-empty", withHolders(`[]`), Refused, CodeBindingMismatch},
		{"holders-populated", withHolders(`["02` + xonly(1) + `"]`), Refused, CodeBindingMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			contract := trustV1(t, "main", nil)
			config := trustConfig(t, "main", MainGenesis, contract)
			reads := 0
			config.Node = nodeFunc(func(_ context.Context, method string, args ...any) (json.RawMessage, error) {
				if method != "name_show" || len(args) == 0 || args[0] != "id/test-landlord" {
					return nil, errors.New("unexpected node method")
				}
				reads++
				return landlordAnswer(t, tc.value), nil
			})
			c, b := trustChecker(t, config)
			live := b.Handler
			b.Handler = func(ctx context.Context, raw []byte, agent, sender string, now int64) (kernel.Receipt, error) {
				r, e := live(ctx, raw, agent, sender, now)
				if _, readErr := c.node.Call(ctx, "name_show", r.LandlordName, map[string]any{"nameEncoding": "ascii", "valueEncoding": "ascii", "allowExpired": true}); readErr != nil {
					r.Verdict, r.Reason = "refused", "RPC_UNAVAILABLE"
				}
				return r, e
			}
			p := trustGrant(t, trustGrantSpec{Network: "main", Genesis: MainGenesis, Contract: contract})
			assertVerdict(t, c.Inbound(context.Background(), xonly(2), &p), tc.decision, tc.code, false, false)
			if reads != 1 {
				t.Fatalf("the landlord name was read %d times, want 1", reads)
			}
			_, cacheErr := c.cachedGrant(xonly(2))
			if (cacheErr == nil) != (tc.decision == Live) {
				t.Fatal("the proof cache does not follow the landlord value verdict")
			}
		})
	}
}

// Claim: landlordHolders reports the holders member of the landlord binding
// and nothing else: the legacy value, a holders member outside the landlord
// binding and an unreadable answer are not reported, so they stay with the
// kernel's strict reader.
func TestLandlordHoldersReader(t *testing.T) {
	key := xonly(1)
	for _, tc := range []struct {
		name, value string
		want        bool
	}{
		{"legacy", `{"swarma":{"landlord":{"grant":"` + key + `"}}}`, false},
		{"holders-empty", `{"swarma":{"landlord":{"grant":"` + key + `","holders":[]}}}`, true},
		{"holders-populated", `{"swarma":{"landlord":{"grant":"` + key + `","holders":["02` + key + `"]}}}`, true},
		{"holders-first", `{"swarma":{"landlord":{"holders":[],"grant":"` + key + `"}}}`, true},
		{"holders-beside-nostr", `{"nostr":"` + key + `","swarma":{"landlord":{"grant":"` + key + `","holders":[]}}}`, true},
		{"holders-outside-landlord", `{"holders":[],"swarma":{"landlord":{"grant":"` + key + `"}}}`, false},
		{"agent-value", `{"swarma":{"agent":{"landlord":"id/test-landlord"}}}`, false},
		{"not-json", `holders`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := landlordHolders(landlordAnswer(t, tc.value)); got != tc.want {
				t.Fatalf("landlordHolders=%v, want %v", got, tc.want)
			}
		})
	}
	if landlordHolders(json.RawMessage(`{"value":7}`)) || landlordHolders(nil) {
		t.Fatal("an unreadable answer was reported as holders")
	}
}

// Claim: the pay profile is unchanged. (1) Its durable binding is the hash
// of the same pins as before this profile existed, recomputed here from the
// earlier struct with the literal regtest pair, so an existing state root
// reopens. (2) Naming the profile and the regtest pair explicitly gives the
// same binding and reopens the same root. (3) A state root never serves both
// profiles: the trust profile cannot adopt a pay root, nor pay a trust root,
// nor one network the root of the other. (4) The pay profile's node wrapper
// passes a name_show answer through untouched, holders or not: its landlord
// values are judged by the kernel alone, as before.
func TestPayProfileUnchanged(t *testing.T) {
	config := unitConfig(t)
	holders := landlordAnswer(t, `{"swarma":{"landlord":{"grant":"`+xonly(1)+`","holders":[]}}}`)
	config.Node = nodeFunc(func(context.Context, string, ...any) (json.RawMessage, error) { return holders, nil })
	c, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	pins := jsonBytes(t, struct {
		Identity, Agent, Landlord, Issuer, Network, Genesis, Construction string
		Transport                                                         Transport
		Executor                                                          string
		Age, Skew                                                         int64
		Floor                                                             int64
	}{
		config.Identity, config.AgentName, config.LandlordName, config.IssuerPubkey, "regtest", "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206", "W", NostrNIP17Seal, config.ExecutorKey, int64(600 * time.Second), int64(120 * time.Second), 0,
	})
	var stored state
	raw, err := os.ReadFile(filepath.Join(config.StateDir, stateName))
	if err != nil || json.Unmarshal(raw, &stored) != nil {
		t.Fatal("pay state unreadable")
	}
	if c.binding != rental.Hash(pins) || stored.Binding != rental.Hash(pins) || c.profile != ContractProfilePay || c.network != "regtest" {
		t.Fatal("pay state binding changed")
	}
	explicit := config
	explicit.ContractProfile, explicit.Network, explicit.Genesis = ContractProfilePay, "regtest", su.RegtestGenesis
	if again, e := New(explicit); e != nil || again.binding != c.binding {
		t.Fatal("explicit pay configuration did not reopen the pay state root", e)
	}
	for name, edit := range map[string]func(*Config){
		"trust-on-pay-root":    func(x *Config) { x.ContractProfile = ContractProfileTrust; x.ExecutorKey = "" },
		"main-on-regtest-root": func(x *Config) { x.Network, x.Genesis = "main", MainGenesis },
	} {
		other := explicit
		edit(&other)
		if got, e := New(other); got != nil || e != ErrState {
			t.Fatalf("%s: state root served both profiles or networks: %v", name, e)
		}
	}
	after, err := os.ReadFile(filepath.Join(config.StateDir, stateName))
	if err != nil || !bytes.Equal(raw, after) {
		t.Fatal("a refused constructor changed the pay state")
	}
	answer, err := c.node.Call(context.Background(), "name_show", config.LandlordName)
	if err != nil || !bytes.Equal(answer, holders) || c.node.code != "" {
		t.Fatal("the pay profile's node wrapper changed a name_show answer")
	}
}

// Claim: the contract profile is part of the durable binding. A state root
// that a trust checker created reopens under the same trust configuration
// and refuses the pay profile and the other network with ErrState.
func TestProfileStateBinding(t *testing.T) {
	config := trustConfig(t, "regtest", su.RegtestGenesis)
	c, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	// Isolate the profile pin even though pay also requires a distinct executor.
	pins := struct {
		Identity, Agent, Landlord, Issuer, Network, Genesis, Construction string
		Transport                                                         Transport
		Executor                                                          string
		Age, Skew                                                         int64
		Floor                                                             int64
	}{config.Identity, config.AgentName, config.LandlordName, config.IssuerPubkey, "regtest", su.RegtestGenesis, config.ConstructionProfile, NostrNIP17Seal, "", int64(config.Freshness.MaxTipAge), int64(*config.Freshness.MaxFutureSkew), *config.Freshness.MinimumHeight}
	want := rental.Hash(jsonBytes(t, struct {
		Contract string
		Pins     any
	}{ContractProfileTrust, pins}))
	if c.binding != want {
		t.Fatal("state root served both profiles: contract profile missing from binding")
	}
	if _, err := New(config); err != nil {
		t.Fatal("the same trust configuration did not reopen its state root", err)
	}
	pay := config
	pay.ContractProfile = ContractProfilePay
	pay.ExecutorKey = unitConfig(t).ExecutorKey
	if got, err := New(pay); got != nil || err != ErrState {
		t.Fatalf("state root served both profiles: %v", err)
	}
	mainnet := config
	mainnet.Network, mainnet.Genesis = "main", MainGenesis
	if got, err := New(mainnet); got != nil || err != ErrState {
		t.Fatalf("state root served both networks: %v", err)
	}
}

// Claim: trust rejects every nonempty executor before state opens, including
// a valid pay key; the empty trust control constructs in the same untouched
// directory. Pay still requires its valid key and refuses an empty key.
func TestTrustExecutorConfig(t *testing.T) {
	for _, key := range []string{xonly(9), "invalid", " "} {
		t.Run(key, func(t *testing.T) {
			config := trustConfig(t, "main", MainGenesis)
			config.ExecutorKey = key
			if c, err := New(config); c != nil || !errors.Is(err, ErrConfig) {
				t.Fatalf("trust executor did not refuse with ErrConfig: %v", err)
			}
			if entries, err := os.ReadDir(config.StateDir); err != nil || len(entries) != 0 {
				t.Fatal("refused executor configuration opened state")
			}
			config.ExecutorKey = ""
			if _, err := New(config); err != nil {
				t.Fatalf("empty trust executor control refused: %v", err)
			}
		})
	}
	config := unitConfig(t)
	config.ExecutorKey = ""
	if c, err := New(config); c != nil || !errors.Is(err, ErrConfig) {
		t.Fatalf("pay accepted an empty executor: %v", err)
	}
	config.ExecutorKey = xonly(9)
	if _, err := New(config); err != nil {
		t.Fatalf("valid pay executor control refused: %v", err)
	}
}
