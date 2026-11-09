package rental

import (
	"context"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// Explicit NMC-main v3 planning conserves inputs at the configured fee rate.
// Missing rate/genesis and legacy execution refuse before node or key access.
// This is offline planning with synthetic funds, not mainnet qualification.
func TestMainGrantPolicyAndFees(t *testing.T) {
	g := testGrant(t)
	g.Network, g.Genesis = "main", su.MainGenesis
	script, _ := GrantSealScript(g.IssuerKey)
	p := Policy{Network: g.Network, Genesis: g.Genesis, AgentName: g.AgentName, LandlordName: g.LandlordName, SealScript: script, FundingScript: testFundingScript(), StateDir: t.TempDir(), FeeRate: 201}
	in := su.PlanInput{Point: su.Point{TxID: Hash([]byte("main-fixture-funds"))}, ValueSat: 1000000, Script: p.FundingScript, Role: "funding"}
	s := PlanSpec{Kind: "grant-issue", Inputs: []su.PlanInput{in}, ChangeScript: p.FundingScript}
	raw := signGrantTest(t, g, 1)
	plan, err := MakeGrantIssuancePlan(p, s, raw)
	if err != nil || plan.Network != "main" || plan.FeeRate != 201 || plan.FeeSat != 201*int64(plan.MaxSignedVBytes) || plan.Outputs[1].ValueSat+plan.FeeSat != in.ValueSat {
		t.Fatal("explicit main issuance projection", plan, err)
	}
	for _, rate := range []int64{0, -1, 1001} {
		q := p
		q.FeeRate = rate
		got, err := MakeGrantIssuancePlan(q, s, raw)
		if err == nil || err.Error() != "FEE_RATE" || len(got.Outputs) != 0 {
			t.Fatal("invalid main fee produced a plan", rate, err)
		}
	}
	q := p
	q.Genesis = su.RegtestGenesis
	if err = q.validateGrant(); err == nil || err.Error() != "NETWORK_PIN" {
		t.Fatal("mismatched main genesis", err)
	}
	if r := CheckLegacy(context.Background(), nil, p, nil, "", "", 500); r.Reason != "REGTEST_ONLY" || r.Calls != 0 {
		t.Fatal("legacy v1 main admission", r)
	}
	if r := CheckV2(context.Background(), nil, p, nil, "", "", 500); r.Reason != "REGTEST_ONLY" || r.Calls != 0 {
		t.Fatal("legacy detached main admission", r)
	}
	if _, err = makeGrantIssuancePlan(p, s, raw, true); err == nil || err.Error() != "LEGACY_REGTEST_ONLY" {
		t.Fatal("legacy issuance framing on main", err)
	}
	for _, spec := range []PlanSpec{
		{Kind: "refill", Inputs: []su.PlanInput{in}, ChangeScript: p.FundingScript, Count: 4, ValueSat: 100000},
		{Kind: "revoke", Inputs: []su.PlanInput{{Point: su.Point{TxID: g.Seal.TxID, Vout: g.Seal.Vout}, ValueSat: 200000, Script: script, Role: "seal"}}, ChangeScript: p.FundingScript, Pool: PoolOutput{Point: g.Seal, ValueSat: 200000, Script: script}},
	} {
		plan, err := MakePlan(IssuerPolicy{Policy: p}, spec, nil, nil, nil, 500)
		if err != nil || plan.FeeSat != 201*int64(plan.MaxSignedVBytes) {
			t.Fatal(spec.Kind, err)
		}
		total := plan.FeeSat
		for _, out := range plan.Outputs {
			total += out.ValueSat
		}
		if total != spec.Inputs[0].ValueSat {
			t.Fatal("main pool conservation", spec.Kind)
		}
	}
}

// A freshly re-signed main v2 payment package authenticates only against a
// trusted main identity policy; a signed request cannot switch its network.
func TestMainPaymentPackageBinding(t *testing.T) {
	p, r, pack, pub := paymentV2Fixture(t, "nmc")
	p.Policy.Network, p.Policy.Genesis = "main", su.MainGenesis
	params := chaincfg.MainNetParams
	params.PubKeyHashAddrID = 52
	address, _ := btcutil.NewAddressPubKeyHash(make([]byte, 20), &params)
	pack.Contract.Payment.Network, pack.Contract.Payment.Genesis = "main", su.MainGenesis
	pack.Contract.Payment.Address = address.EncodeAddress()
	r.PaymentNetwork, r.PaymentGenesis = "main", su.MainGenesis
	resignPaymentV2(t, &r, &pack, &pub, true)
	now := pack.HoldCreatedAt + 10
	if _, _, err := VerifyIssuancePackageV2(p, eventBytes(r), eventBytes(pub), now); err != nil {
		t.Fatal("valid main package", err)
	}
	p.Policy.Network, p.Policy.Genesis = "regtest", su.RegtestGenesis
	if _, _, err := VerifyIssuancePackageV2(p, eventBytes(r), eventBytes(pub), now); err == nil || err.Error() != "PAYMENT_PROFILE" {
		t.Fatal("main package switched regtest policy", err)
	}
	p.Policy.Network, p.Policy.Genesis = "main", su.MainGenesis
	for _, coin := range []string{"btc", "ltc"} {
		r.PaymentCoin = coin
		pack.Contract.Payment.Coin = coin
		resignPaymentV2(t, &r, &pack, &pub, true)
		if _, _, err := VerifyIssuancePackageV2(p, eventBytes(r), eventBytes(pub), now); err == nil || err.Error() != "PAYMENT_PROFILE" {
			t.Fatal("unsupported main coin", coin, err)
		}
	}
}
