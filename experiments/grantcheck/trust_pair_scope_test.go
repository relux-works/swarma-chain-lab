package grantcheck

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/relux-works/swarma-chain-lab/experiments/grantcheck/internal/trustcontract"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
)

// Claim: all 39 pair parents retain their own §3.1 contract verdict; valid
// roots without delegation or unchecked scope text pass trustTerms; D2 refuses children and
// depth above zero. Every child-slot document refuses with terms_invalid.
// §8 pair verdicts are not judged by CG1; it refuses all children (D2); the notary judges pairs.
// Pair-21's child slot is itself a depth-1 root. Six spend-profile parents
// retain D12's CONTRACT_DELEGATE. This is an offline terms gate test, not
// signature, chain or notary certification. The trust_pair_child_refusal
// plant removes D2's parent-id/ordinal check and must fail this test.
func TestTrustLIP0014PairScope(t *testing.T) {
	raw, err := os.ReadFile("internal/trustcontract/testdata/contract-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if rental.Hash(raw) != "563d49574f3c2bd913316cd0b0a295987648f5c281d28a68b065bf96ef180f14" {
		t.Fatal("LIP-0014 corpus differs from pinned upstream bytes")
	}
	var file struct {
		Contracts []struct{ ID, Contract, Expected string }
		Pairs     []struct {
			ID, Parent, Child string
			ParentVector      string `json:"parent_vector"`
		}
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Contracts) != 151 || len(file.Pairs) != 39 {
		t.Fatal("LIP-0014 corpus shortened")
	}
	seen := map[string]bool{}
	for _, pair := range file.Pairs {
		if seen[pair.ID] {
			t.Fatalf("duplicate pair %s", pair.ID)
		}
		seen[pair.ID] = true
		t.Run(pair.ID, func(t *testing.T) {
			// The published contract vector, not the §8 verdict, supplies the
			// parent's independent expected result. Only pair-07/23 have no
			// contract reference: their parents are valid child documents.
			want := "ok"
			if pair.ParentVector != "" {
				found := false
				for _, v := range file.Contracts {
					if v.ID == pair.ParentVector {
						if v.Contract != pair.Parent {
							t.Fatal("parent differs from its referenced contract vector")
						}
						want, found = v.Expected, true
						break
					}
				}
				if !found {
					t.Fatal("missing parent contract vector")
				}
			} else if pair.ID != "pair-07" && pair.ID != "pair-23" {
				t.Fatal("parent has no independent §3.1 expectation")
			}
			_, got := trustcontract.Parse([]byte(pair.Parent))
			if got == "" {
				got = "ok"
			}
			if got != want {
				t.Fatalf("parent §3.1: got %s, want %s", got, want)
			}
			for _, doc := range []struct{ name, text string }{{"parent", pair.Parent}, {"child", pair.Child}} {
				t.Run(doc.name, func(t *testing.T) {
					// Read the document fields directly, so invalid D12 parents
					// still reach the production parser with a matching grant.
					var c trustcontract.V2
					if err := json.Unmarshal([]byte(doc.text), &c); err != nil {
						t.Fatal(err)
					}
					var d trustcontract.Delegate
					if len(c.Delegate) != 0 {
						if err := json.Unmarshal(c.Delegate, &d); err != nil {
							t.Fatal(err)
						}
					}
					g := rental.Grant{Network: c.Network, AgentName: c.AgentName, LandlordName: c.LandlordName,
						GranteeKey: c.GranteeKey, ContractSHA256: rental.Hash([]byte(doc.text)),
						Scope: trustcontract.V3Scope(c.Actions), NotBefore: c.NotBefore, NotAfter: c.NotAfter}
					if c.SpendBudget != 0 {
						g.Budget = &c.SpendBudget
					}
					g.Consent.ConsentEvent.Tags = trustcontract.ConsentTags([]byte(doc.text))
					wantCode := CodeTermsInvalid
					if doc.name == "parent" && want == "ok" && c.ParentGrantID == "" && c.Ordinal == 0 && d.Depth == 0 && c.ScopeTextSHA256 == "" {
						wantCode = CodeLive
					}
					if got := trustTerms(g, []byte(doc.text), nil); got != wantCode {
						t.Fatalf("D2 %s refusal: got %s, want %s", doc.name, got, wantCode)
					}
				})
			}
		})
	}
}
