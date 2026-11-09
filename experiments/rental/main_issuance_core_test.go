package rental

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	pc "github.com/relux-works/swarma-chain-lab/experiments/payment-chain"
	booking "github.com/relux-works/swarma-chain-lab/experiments/rental-booking"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// This explicit test seam changes only chain/genesis replies from disposable
// regtest nodes. All other name/payment/funding/ancestry observations are real.
// It is NOT a mainnet node, consensus proof, or permission to use real custody.
type mainIssuanceProjection struct {
	base           su.Node
	chain, genesis int
}

func (n *mainIssuanceProjection) Call(ctx context.Context, m string, args ...any) (json.RawMessage, error) {
	raw, e := n.base.Call(ctx, m, args...)
	if e != nil {
		return nil, e
	}
	if m == "getblockchaininfo" {
		var fields map[string]json.RawMessage
		if e = json.Unmarshal(raw, &fields); e != nil {
			return nil, e
		}
		fields["chain"] = eventBytes("main")
		n.chain++
		return json.Marshal(fields)
	}
	if m == "getblockhash" && len(args) == 1 && string(eventBytes(args[0])) == "0" {
		n.genesis++
		return eventBytes(su.MainGenesis), nil
	}
	return raw, nil
}

// The legacy payment API refuses main at package policy admission without burns
// or returned authority. The same authentic v1 fixture prepares on regtest.
// Only the main observation's public chain/genesis replies are projected.
func TestCoreMainLegacyPaymentRefusal(t *testing.T) {
	l := newCore(t)
	l.grantIdentity()
	seal := l.detachedPool(1, true)
	p, _, _ := l.grantFixture("main-legacy-refusal", seal, 2)
	ip, request, event, key, spec := l.grantIssueInputs(p, "main-legacy-refusal", true)
	mainPolicy := ip
	mainPolicy.Policy.Network, mainPolicy.Policy.Genesis, mainPolicy.Policy.FeeRate = "main", su.MainGenesis, 201
	node := &mainIssuanceProjection{base: l.observer}
	r := IssueGrant(context.Background(), node, mainPolicy, request, event, seal, spec, key, 500)
	if r.Verdict != "refused" || r.Reason != "ISSUER_POLICY" || r.Plan != nil || len(r.SignedGrant) != 0 || r.GrantID != "" || r.Replay {
		t.Fatalf("legacy main payment boundary: want ISSUER_POLICY got %s/%s", r.Verdict, r.Reason)
	}
	if node.chain == 0 || node.genesis == 0 {
		t.Fatal("main policy boundary not reached")
	}
	assertNoIssuerBurn(t, p.StateDir)
	requirePrepared(t, IssueGrant(context.Background(), l.observer, ip, request, event, seal, spec, key, 500))
	l.save("main-legacy-refusal", map[string]any{"status": "PASS", "main_v1_reason": r.Reason, "no_burn": true, "regtest_v1_prepared": true, "mainnet_contacted": false})
}

// Public V2 fresh main issuance must prepare a signed framed grant, then replay
// its exact bytes without node/key access. Wrong identity/payment chain refuses
// with no burn; real regtest nodes and explicit public reply mutation are used.
// Nothing from this main-labelled unsigned plan is broadcast.
func TestCoreMainPublicGrantV2(t *testing.T) {
	if os.Getenv("P1_REGTEST") != "1" {
		t.Skip("explicit disposable M1/P1 Core fixtures required")
	}
	l := newCore(t)
	l.grantIdentity()
	pay := newPaymentCoreLab(t, "nmc")
	seal := l.detachedPool(1, true)
	fund := l.detachedPool(7, true)
	p, _, _ := l.grantFixture("main-public-v2", seal, 2)
	p.Network, p.Genesis, p.FeeRate = "main", su.MainGenesis, 201
	spec := PlanSpec{Kind: "grant-issue", Inputs: []su.PlanInput{{Point: su.Point{TxID: fund.TxID, Vout: fund.Vout}, ValueSat: 1000000, Script: p.FundingScript, Role: "funding"}}, ChangeScript: p.FundingScript}
	key, _ := testKey(1)
	keyPath := filepath.Join(l.private, "main-projection-fixture-key")
	if e := os.WriteFile(keyPath, key.Serialize(), 0600); e != nil {
		t.Fatal(e)
	}
	f := newPaymentBooking(t, l, map[string]*paymentCoreLab{"nmc": pay}, "main-public-v2")
	renter, renterPub := testKey(2)
	ctx := context.Background()
	b, e := f.s.Book(ctx, booking.BookInputV2{SlotID: "slot", Coin: pc.Coin("nmc"), RenterPubkey: renterPub, PrivacyAcknowledged: true})
	if e != nil {
		t.Fatal(e)
	}
	pay.pay(b.Contract.Payment.Address, b.Contract.Payment.AmountAtoms+1000)
	pay.mine(2)
	f.refresh(t)
	consent := booking.ConsentV2(b.Contract, f.now)
	if e = consent.Sign(renter); e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.AcceptConsent(ctx, b.Contract.BookingID, consent); e != nil {
		t.Fatal(e)
	}
	f.refresh(t)
	ready := f.get(t, b.Contract.BookingID)
	if ready.Issuance == nil || !ready.Published {
		t.Fatal("real regtest producer fixture absent")
	}
	var request IssuanceRequestV2
	var pack PackageV2
	var publication Event
	for _, v := range []struct {
		raw []byte
		out any
	}{{eventBytes(ready.Issuance), &request}, {eventBytes(ready.Package), &pack}, {eventBytes(ready.PackageEvent), &publication}} {
		if e = json.Unmarshal(v.raw, v.out); e != nil {
			t.Fatal(e)
		}
	}
	address, e := btcutil.DecodeAddress(pack.Contract.Payment.Address, &chaincfg.RegressionNetParams)
	if e != nil {
		t.Fatal(e)
	}
	params := chaincfg.MainNetParams
	params.PubKeyHashAddrID = 52
	mainAddress, e := btcutil.NewAddressPubKeyHash(address.ScriptAddress(), &params)
	if e != nil {
		t.Fatal(e)
	}
	pack.Contract.Payment.Network, pack.Contract.Payment.Genesis, pack.Contract.Payment.Address = "main", su.MainGenesis, mainAddress.EncodeAddress()
	request.PaymentNetwork, request.PaymentGenesis = "main", su.MainGenesis
	contractHash := Hash(eventBytes(pack.Contract))
	request.ContractSHA256 = contractHash
	pack.Consent.Tags = [][]string{{"t", "swarma-rental-consent-v1"}, {"contract", contractHash}, {"booking", request.BookingID}, {"privacy", pack.Contract.PrivacySHA256}}
	pack.Consent = signedEvent(t, pack.Consent, 2)
	pack.ProviderSignature = signature(t, contractHash, 4)
	publication.Tags = [][]string{{"t", "swarma-rental-package-v1"}, {"contract", contractHash}, {"booking", request.BookingID}, {"e", pack.Consent.ID}}
	publication.Content = string(eventBytes(pack))
	publication = signedEvent(t, publication, 4)
	request.PackageEventID = publication.ID
	_, provider := testKey(4)
	ip := IssuerPolicyV2{IssuerPolicy: IssuerPolicy{Policy: p, ProviderPubkey: provider}, PaymentPolicies: map[string]PaymentAdmissionPolicy{"nmc": {MaxRateAgeSeconds: 60, MinConfirmations: 2, Limits: pc.Limits{MaxBlocks: 2016, MaxMempool: 100000, MaxCalls: 200000, MaxBytes: 512 << 20}}}}
	rq, pub := eventBytes(request), eventBytes(publication)
	if _, _, e = VerifyIssuancePackageV2(ip, rq, pub, 500); e != nil {
		t.Fatal("re-signed main package", e)
	}
	identity, payment := &mainIssuanceProjection{base: l.observer}, &mainIssuanceProjection{base: pay.issuer}
	for _, tc := range []struct {
		name, want        string
		identity, payment su.Node
	}{{"wrong-identity-chain", "CHAIN_STATE", l.observer, payment}, {"wrong-payment-chain", "NODE_CHAIN", identity, pay.issuer}} {
		t.Run(tc.name, func(t *testing.T) {
			r := IssueGrantWithNodes(ctx, tc.identity, map[string]su.Node{"nmc": tc.payment}, ip, rq, pub, seal, spec, keyPath, 500)
			if r.Verdict != "refused" || r.Reason != tc.want || r.Plan != nil || len(r.SignedGrant) != 0 {
				t.Fatalf("main public negative: want %s got %s/%s", tc.want, r.Verdict, r.Reason)
			}
			assertNoIssuerBurn(t, p.StateDir)
		})
	}
	issued := IssueGrantWithNodes(ctx, identity, map[string]su.Node{"nmc": payment}, ip, rq, pub, seal, spec, keyPath, 500)
	requirePrepared(t, issued)
	signed, e := ParseSignedGrant(issued.SignedGrant)
	if e != nil {
		t.Fatal(e)
	}
	if signed.Grant.Network != "main" || signed.Grant.Genesis != su.MainGenesis || issued.Plan.Network != "main" || issued.Plan.Outputs[0].Script != hex.EncodeToString(framedGrantScript(t, issued.SignedGrant)) || issued.Plan.FeeRate != 201 || issued.Plan.FeeSat != 201*int64(issued.Plan.MaxSignedVBytes) || issued.Plan.FeeSat+issued.Plan.Outputs[1].ValueSat != 1000000 {
		t.Fatal("main public signed framing/fee/binding")
	}
	if issued.PaymentAdmission == nil || issued.PaymentAdmission.Network != "main" || issued.PaymentAdmission.Observation == nil || issued.PaymentAdmission.Observation.SurplusAtoms != 1000 {
		t.Fatal("main public payment evidence")
	}
	before := issuerFiles(t, p.StateDir)
	replay := IssueGrantWithNodes(ctx, nil, nil, ip, rq, pub, seal, spec, "", ready.HoldExpiresAt+1)
	requirePrepared(t, replay)
	if !replay.Replay || !bytes.Equal(replay.SignedGrant, issued.SignedGrant) || !sameJSON(replay.Plan, issued.Plan) || !sameJSON(replay.PaymentAdmission, issued.PaymentAdmission) || !reflect.DeepEqual(before, issuerFiles(t, p.StateDir)) {
		t.Fatal("main public replay changed bytes/state")
	}
	if identity.chain == 0 || identity.genesis == 0 || payment.chain == 0 || payment.genesis == 0 {
		t.Fatal("declared main projection did not apply")
	}
	l.save("main-public-v2", map[string]any{"status": "PASS", "source": "real isolated regtest fixtures with explicit main chain/genesis reply projection and re-signed public V2 terms", "mainnet_contacted": false, "broadcast": false, "identity_chain_projections": identity.chain, "identity_genesis_projections": identity.genesis, "payment_chain_projections": payment.chain, "payment_genesis_projections": payment.genesis, "framed_plan": true, "exact_replay": true, "negative_wrong_chains_no_burn": true, "result": issued})
}
