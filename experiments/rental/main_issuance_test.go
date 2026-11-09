package rental

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"

	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

type issuanceBoundaryNode struct{ calls []string }

func (n *issuanceBoundaryNode) Call(_ context.Context, method string, _ ...any) (json.RawMessage, error) {
	n.calls = append(n.calls, method)
	return nil, errors.New("explicit offline observation boundary")
}

// Both public wrappers must reach framed funding admission on main. The fake
// node then refuses its first observation: this proves routing/fee guards and
// absence of burns/signatures, not successful issuance or mainnet node behavior.
// V1 payment authentication remains regtest-only; main issuance uses V2 terms.
func TestMainPublicGrantFundingAdmission(t *testing.T) {
	for _, v2 := range []bool{false, true} {
		name := "IssueGrant"
		if v2 {
			name = "IssueGrantWithNodes"
		}
		t.Run(name, func(t *testing.T) {
			p, s, raw := locatorFixture(t)
			if e := os.Chmod(p.StateDir, 0700); e != nil {
				t.Fatal(e)
			}
			g, e := ParseSignedGrant(raw)
			if e != nil {
				t.Fatal(e)
			}
			p.Network, p.Genesis, p.FeeRate = "main", su.MainGenesis, 201
			ip := IssuerPolicy{Policy: p}
			pool := g.Grant.Seal
			request, _ := json.Marshal(IssuanceRequest{Version: 1, BookingID: Hash([]byte("public main funding")), ContractSHA256: g.Grant.ContractSHA256, Scope: []string{"deliver"}})
			if v2 {
				request, _ = json.Marshal(IssuanceRequestV2{Version: 2, BookingID: Hash([]byte("public main funding")), ContractSHA256: g.Grant.ContractSHA256, Scope: []string{"deliver"}})
			}
			call := func(spec PlanSpec, n *issuanceBoundaryNode) GrantIssueResult {
				if v2 {
					return IssueGrantWithNodes(context.Background(), n, nil, IssuerPolicyV2{IssuerPolicy: ip}, request, nil, pool, spec, "", 500)
				}
				return IssueGrant(context.Background(), n, ip, request, nil, pool, spec, "", 500)
			}
			// Independent size boundary: historical one-input/two-output bare projection
			// plus exactly the dust reserve cannot fund the additional framed bytes.
			bare := su.Transaction{Version: 2, Inputs: []su.Input{{Point: s.Inputs[0].Point, Script: make([]byte, 140), Sequence: 0xfffffffe}}, Outputs: []su.Output{{Value: 0, Script: make([]byte, 34)}, {Value: 0, Script: mustDecodeKey(p.FundingScript)}}}
			_, fee, _, e := su.ReserveFee(bare, 1000000, p.FeeRate)
			if e != nil {
				t.Fatal(e)
			}
			for _, tc := range []struct {
				name, reason string
				edit         func(*PlanSpec)
				calls        int
			}{
				{"framed-budget", "FUNDING_OR_DUST_RESERVE", func(s *PlanSpec) { s.Inputs[0].ValueSat = fee + 1000 }, 0},
				{"seal-as-funding", "FUNDING_SEAL_SCRIPT", func(s *PlanSpec) { s.Inputs[0].Script = p.SealScript }, 0},
				{"pool-input", "ISSUANCE_SPENDS_SEAL", func(s *PlanSpec) { s.Inputs[0].Point = su.Point{TxID: pool.TxID, Vout: pool.Vout} }, 0},
				{"wrong-change", "ISSUANCE_TEMPLATE", func(s *PlanSpec) { s.ChangeScript = p.SealScript }, 0},
				{"funded-observation", "NODE_UNAVAILABLE", func(*PlanSpec) {}, 1},
			} {
				t.Run(tc.name, func(t *testing.T) {
					spec := s
					spec.Inputs = append([]su.PlanInput(nil), s.Inputs...)
					tc.edit(&spec)
					n := &issuanceBoundaryNode{}
					got := call(spec, n)
					if got.Verdict != "refused" || got.Reason != tc.reason || got.Plan != nil || len(got.SignedGrant) != 0 || got.GrantID != "" || got.Replay {
						t.Fatalf("public main funding boundary: want %s, got %s/%s", tc.reason, got.Verdict, got.Reason)
					}
					if len(n.calls) != tc.calls || (tc.calls == 1 && n.calls[0] != "getblockchaininfo") {
						t.Fatal("funding guard crossed wrong observation boundary", n.calls)
					}
					assertNoIssuerBurn(t, p.StateDir)
				})
			}
		})
	}
}
