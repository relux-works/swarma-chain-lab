package grantcheck

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/grantcheck/internal/trustcontract"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// Claim: under the trust profile a valid trust grant is admitted on its own
// configured network: profile /1 in the G1.0 shape (instruct and review, no
// right of re-delegation) and a profile /2 root at depth 0, on regtest and on
// main. The admitted proof is then served from the cache by a fresh check.
// These are the valid controls that the refusal tests below stand beside.
func TestTrustValid(t *testing.T) {
	for _, network := range []string{"regtest", "main"} {
		for name, build := range map[string]func(*testing.T, string) []byte{
			"v1":        func(t *testing.T, n string) []byte { return trustV1(t, n, nil) },
			"v2-depth0": func(t *testing.T, n string) []byte { return trustV2(t, n, nil) },
		} {
			t.Run(name+"-"+network, func(t *testing.T) {
				contract := build(t, network)
				c, b := trustChecker(t, trustConfig(t, network, genesisOf(network), contract))
				p := trustGrant(t, trustGrantSpec{Network: network, Genesis: genesisOf(network), Contract: contract})
				v := c.Inbound(context.Background(), xonly(2), &p)
				assertVerdict(t, v, Live, CodeLive, false, false)
				if v.GrantID != p.GrantID || len(v.Scope) != 0 || v.NotBefore != 300 || v.NotAfter != 1000 {
					t.Fatalf("live trust verdict metadata: %+v", v)
				}
				assertVerdict(t, c.Outbound(context.Background(), xonly(2)), Live, CodeLive, false, false)
				if b.Calls != 2 {
					t.Fatal("cached trust proof bypassed the fresh check")
				}
			})
		}
	}
}

// Claim: every valid contract of the LIP-0013 vectors is admitted with its
// exact published bytes when a grant binds to it as its binding vector says:
// instruct and review; land with two repositories; spend with a budget; all
// four actions with a 280-byte note. The grant fields come from the vector
// file, the grantee is the published BIP-340 test key of the vectors, and
// the network is main.
func TestTrustVectorsAccepted(t *testing.T) {
	raw, err := os.ReadFile("internal/trustcontract/testdata/lip-0013-contract-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		ValidContracts []struct {
			ID       string `json:"id"`
			Contract string `json:"contract"`
			SHA256   string `json:"sha256"`
		} `json:"valid_contracts"`
		Bindings []struct {
			ID          string              `json:"id"`
			ContractRef string              `json:"contract_ref"`
			Grant       trustcontract.Grant `json:"grant"`
			Expect      string              `json:"expect"`
		} `json:"bindings"`
	}
	if err = json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	contracts := map[string][]byte{}
	for _, v := range file.ValidContracts {
		if rental.Hash([]byte(v.Contract)) != v.SHA256 {
			t.Fatalf("%s: the contract bytes do not have the published hash", v.ID)
		}
		contracts[v.ID] = []byte(v.Contract)
	}
	admitted := 0
	for _, v := range file.Bindings {
		if v.Expect != "OK" {
			continue
		}
		t.Run(v.ID, func(t *testing.T) {
			contract, ok := contracts[v.ContractRef]
			if !ok {
				t.Fatal("binding names no valid contract")
			}
			config := trustConfig(t, "main", MainGenesis, contract)
			config.AgentName, config.LandlordName = v.Grant.AgentName, v.Grant.LandlordName
			config.Now = func() time.Time { return time.Unix(v.Grant.NotBefore+1, 0) }
			c, _ := trustChecker(t, config)
			p := trustGrant(t, trustGrantSpec{Network: "main", Genesis: MainGenesis, Contract: contract, Grantee: 3})
			g := proofGrant(t, p.Bytes).Grant
			if g.ContractSHA256 != v.Grant.ContractSHA256 || g.GranteeKey != v.Grant.GranteeKey || g.BudgetSat() != v.Grant.Budget ||
				strings.Join(g.Scope, ",") != strings.Join(v.Grant.Scope, ",") || g.NotBefore != v.Grant.NotBefore || g.NotAfter != v.Grant.NotAfter {
				t.Fatalf("fixture grant does not have the fields of the binding vector: %+v", g)
			}
			got := c.Inbound(context.Background(), v.Grant.GranteeKey, &p)
			assertVerdict(t, got, Live, CodeLive, false, false)
			if strings.Join(got.Scope, ",") != strings.Join(v.Grant.Scope, ",") {
				t.Fatalf("live scope %v, the vector derives %v", got.Scope, v.Grant.Scope)
			}
			admitted++
		})
	}
	if admitted != 4 {
		t.Fatalf("admitted %d valid vectors, want 4", admitted)
	}
}

// Claim: the profile is selected by configuration and never detected from the
// contract. A pay grant under the trust profile and a trust grant under the
// pay profile both refuse as terms_invalid before the backend, although the
// checker can resolve the contract bytes of both; the grant of the configured
// profile is admitted by the same checker.
func TestTrustCrossProfile(t *testing.T) {
	trust := trustV1(t, "regtest", nil)
	trustProof := trustGrant(t, trustGrantSpec{Network: "regtest", Genesis: su.RegtestGenesis, Contract: trust})
	payRaw := unitGrant(t)
	payProof := Presentation{GrantID: proofGrant(t, payRaw).ID(), Bytes: payRaw}
	for _, tc := range []struct {
		name, profile string
		refused, live Presentation
	}{
		{"pay-grant-under-trust", ContractProfileTrust, payProof, trustProof},
		{"trust-grant-under-pay", ContractProfilePay, trustProof, payProof},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := unitConfig(t)
			config.ContractProfile = tc.profile
			config.Network, config.Genesis = "regtest", su.RegtestGenesis
			config.Terms = termsOf(trust, unitTerms(t))
			c, b := trustChecker(t, config)
			assertVerdict(t, c.Inbound(context.Background(), xonly(2), &tc.refused), Refused, CodeTermsInvalid, false, false)
			if b.Calls != 0 {
				t.Fatal("a grant of the other profile reached the backend")
			}
			assertVerdict(t, c.Inbound(context.Background(), xonly(2), &tc.live), Live, CodeLive, false, false)
		})
	}
}

// Claim: under the trust profile each defect of the contract, or of its
// binding to the grant, refuses with its closed code before the backend and
// leaves the admitted proof and the durable state unchanged. Every case is
// one edit away from the valid grant of the same profile, which the same
// checker admits first and serves again afterwards. terms_invalid: bytes that
// do not have the committed hash, bytes that cannot be resolved, non-canonical
// bytes, a repeated, unknown or case-folded member, trailing data, the size
// bound, a wrong profile string, actions that are unsorted or outside the
// set, a right of re-delegation (depth above 0) and a child contract.
// binding_mismatch: a contract whose network, landlord, agent, grantee or
// window is not the grant's, a grant scope or budget that is not the derived
// one, and consent tags that are not those of the contract.
func TestTrustContractRefusals(t *testing.T) {
	v1, v2 := trustV1(t, "regtest", nil), trustV2(t, "regtest", nil)
	other := trustV1(t, "regtest", func(c *trustcontract.V1) { c.Note = "another valid contract" })
	// control is the valid contract of the control grant. contract holds the
	// bytes the refused grant commits to, and like its valid neighbour. serve
	// replaces what the lookup returns for those bytes; unavailable makes the
	// lookup fail for them.
	type refusal struct {
		name        string
		control     []byte
		contract    []byte
		like        []byte
		edit        func(*rental.Grant)
		tags        func([][]string)
		serve       []byte
		unavailable bool
		code        Code
	}
	cases := []refusal{
		{name: "contract-hash-mismatch", control: v1, contract: other, serve: v1, code: CodeTermsInvalid},
		{name: "contract-unavailable", control: v1, contract: other, unavailable: true, code: CodeTermsInvalid},
		{name: "v1-whitespace", control: v1, contract: replaceOnce(t, v1, `"spend_budget":0`, `"spend_budget": 0`), like: v1, code: CodeTermsInvalid},
		{name: "v1-trailing-newline", control: v1, contract: append(bytes.Clone(v1), '\n'), like: v1, code: CodeTermsInvalid},
		{name: "v1-trailing-data", control: v1, contract: append(bytes.Clone(v1), "{}"...), like: v1, code: CodeTermsInvalid},
		{name: "v1-duplicate-member", control: v1, contract: replaceOnce(t, v1, `"note":""}`, `"note":"","note":""}`), like: v1, code: CodeTermsInvalid},
		{name: "v1-unknown-member", control: v1, contract: replaceOnce(t, v1, `"note":""}`, `"note":"","extra":0}`), like: v1, code: CodeTermsInvalid},
		{name: "v1-case-folded-member", control: v1, contract: replaceOnce(t, v1, `"note":""}`, `"Note":""}`), like: v1, code: CodeTermsInvalid},
		{name: "v1-over-8192-bytes", control: v1, contract: append(bytes.Clone(v1), bytes.Repeat([]byte(" "), trustcontract.MaxContractBytes+1-len(v1))...), like: v1, code: CodeTermsInvalid},
		{name: "v1-wrong-profile-string", control: v1, contract: replaceOnce(t, v1, `"profile":"swarma-trust-contract/1"`, `"profile":"swarma-trust-contract/3"`), like: v1, code: CodeTermsInvalid},
		{name: "v1-profile-2-string", control: v1, contract: replaceOnce(t, v1, `"profile":"swarma-trust-contract/1"`, `"profile":"swarma-trust-contract/2"`), like: v1, code: CodeTermsInvalid},
		{name: "v1-actions-unsorted", control: v1, contract: replaceOnce(t, v1, `["instruct","review"]`, `["review","instruct"]`), like: v1, code: CodeTermsInvalid},
		{name: "v1-action-outside-set", control: v1, contract: replaceOnce(t, v1, `["instruct","review"]`, `["instruct","publish"]`), like: v1, code: CodeTermsInvalid},
		{name: "contract-network-mismatch", control: v1, contract: trustV1(t, "main", nil), like: v1, code: CodeBindingMismatch},
		{name: "contract-landlord-mismatch", control: v1, contract: trustV1(t, "regtest", func(c *trustcontract.V1) { c.LandlordName = "id/other-landlord" }), like: v1, code: CodeBindingMismatch},
		{name: "contract-agent-mismatch", control: v1, contract: trustV1(t, "regtest", func(c *trustcontract.V1) { c.AgentName = "id/other-agent" }), like: v1, code: CodeBindingMismatch},
		{name: "contract-grantee-mismatch", control: v1, contract: trustV1(t, "regtest", func(c *trustcontract.V1) { c.GranteeKey = xonly(3) }), like: v1, code: CodeBindingMismatch},
		{name: "contract-window-mismatch", control: v1, contract: trustV1(t, "regtest", func(c *trustcontract.V1) { c.NotAfter = 1001 }), like: v1, code: CodeBindingMismatch},
		{name: "scope-mismatch", control: v1, contract: v1, edit: func(g *rental.Grant) { g.Scope = []string{"pay"} }, code: CodeBindingMismatch},
		{name: "budget-mismatch", control: v1, contract: v1, edit: func(g *rental.Grant) { budget := int64(1000); g.Budget = &budget }, code: CodeBindingMismatch},
		{name: "consent-booking-mismatch", control: v1, contract: v1, tags: func(tags [][]string) { tags[2][1] = strings.Repeat("b", 64) }, code: CodeBindingMismatch},
		{name: "consent-privacy-mismatch", control: v1, contract: v1, tags: func(tags [][]string) { tags[3][1] = strings.Repeat("c", 64) }, code: CodeBindingMismatch},
		{name: "v2-whitespace", control: v2, contract: replaceOnce(t, v2, `"ordinal":0`, `"ordinal": 0`), like: v2, code: CodeTermsInvalid},
		{name: "v2-duplicate-member", control: v2, contract: replaceOnce(t, v2, `"ordinal":0,`, `"ordinal":0,"ordinal":0,`), like: v2, code: CodeTermsInvalid},
		{name: "v2-unknown-member", control: v2, contract: replaceOnce(t, v2, `"ordinal":0,`, `"ordinal":0,"extra":0,`), like: v2, code: CodeTermsInvalid},
		{name: "v2-wrong-profile-string", control: v2, contract: replaceOnce(t, v2, `"profile":"swarma-trust-contract/2"`, `"profile":"swarma-trust-contract/1"`), like: v2, code: CodeTermsInvalid},
		{name: "v2-actions-unsorted", control: v2, contract: replaceOnce(t, v2, `"actions":["instruct","review"]`, `"actions":["review","instruct"]`), like: v2, code: CodeTermsInvalid},
		{name: "v2-depth-1", control: v2, contract: trustV2(t, "regtest", func(c *trustcontract.V2) { c.Delegate = json.RawMessage(trustDepthOne()) }), code: CodeTermsInvalid},
		{name: "v2-depth-2", control: v2, contract: replaceOnce(t, v2, `"depth":0`, `"depth":2`), like: v2, code: CodeTermsInvalid},
		{name: "v2-child", control: v2, contract: trustV2(t, "regtest", func(c *trustcontract.V2) { c.ParentGrantID, c.Ordinal = strings.Repeat("a", 64), 1 }), code: CodeTermsInvalid},
		{name: "v2-contract-agent-mismatch", control: v2, contract: trustV2(t, "regtest", func(c *trustcontract.V2) { c.AgentName = "id/other-agent" }), like: v2, code: CodeBindingMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := trustConfig(t, "regtest", su.RegtestGenesis)
			config.Terms = func(hash string) ([]byte, error) {
				switch {
				case hash == rental.Hash(tc.control):
					return tc.control, nil
				case hash == rental.Hash(tc.contract) && tc.serve != nil:
					return tc.serve, nil
				case hash == rental.Hash(tc.contract) && !tc.unavailable:
					return tc.contract, nil
				}
				return nil, os.ErrNotExist
			}
			c, b := trustChecker(t, config)
			ctx := context.Background()
			control := trustGrant(t, trustGrantSpec{Network: "regtest", Genesis: su.RegtestGenesis, Contract: tc.control})
			assertVerdict(t, c.Inbound(ctx, xonly(2), &control), Live, CodeLive, false, false)
			calls := b.Calls
			state := filepath.Join(c.config.StateDir, stateName)
			before, err := os.ReadFile(state)
			if err != nil {
				t.Fatal(err)
			}
			refused := trustGrant(t, trustGrantSpec{Network: "regtest", Genesis: su.RegtestGenesis, Contract: tc.contract, Like: tc.like, Edit: tc.edit, Tags: tc.tags})
			if bytes.Equal(refused.Bytes, control.Bytes) {
				t.Fatal("the refused fixture equals its valid control")
			}
			assertVerdict(t, c.Inbound(ctx, xonly(2), &refused), Refused, tc.code, false, false)
			after, err := os.ReadFile(state)
			if err != nil || !bytes.Equal(before, after) || b.Calls != calls || !bytes.Equal(cachedBytes(t, c, xonly(2)), control.Bytes) {
				t.Fatal("a refused trust contract changed state, replaced the admitted proof or reached the backend")
			}
			assertVerdict(t, c.Outbound(ctx, xonly(2)), Live, CodeLive, false, false)
		})
	}
}
