package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"github.com/btcsuite/btcd/btcec/v2"
	gs "github.com/relux-works/swarma-chain-lab/experiments/grant-store"
	pc "github.com/relux-works/swarma-chain-lab/experiments/payment-chain"
	rental "github.com/relux-works/swarma-chain-lab/experiments/rental"
	booking "github.com/relux-works/swarma-chain-lab/experiments/rental-booking"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
	sg "github.com/relux-works/swarma-chain-lab/experiments/signer-service"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"time"
)

// Genuine Core fixture: original exporter bytes feed the real SG1 service,
// broadcaster and S1 store. Only SG1 publishes the confirmed presentation;
// the test does not write a replacement request, index or presentation.
func (l *coreLab) issueBookingV2(b booking.BookingV2, provider, sourceDir, presentationDir string) []byte {
	t := l.t
	t.Helper()
	ctx := context.Background()
	dir := func(name string) string {
		p := filepath.Join(l.private, name)
		if e := os.Mkdir(p, 0700); e != nil {
			t.Fatal(e)
		}
		return p
	}
	keys := dir("g6-keys")
	grantKey := filepath.Join(keys, "grant")
	fundKey := filepath.Join(keys, "funding")
	raw := make([]byte, 32)
	raw[31] = 7
	funding, _ := btcec.PrivKeyFromBytes(raw)
	pub := hex.EncodeToString(funding.PubKey().SerializeCompressed())
	nativeScript, e := su.WitnessKeyScript(funding.PubKey().SerializeCompressed())
	fundScript := hex.EncodeToString(nativeScript)
	if e != nil {
		t.Fatal(e)
	}
	for path, value := range map[string][]byte{grantKey: l.issuer.Serialize(), fundKey: funding.Serialize()} {
		if e = os.WriteFile(path, value, 0600); e != nil {
			t.Fatal(e)
		}
	}
	sealScript, _ := rental.GrantSealScript(l.issuerPub)
	cfg := sg.Config{Profile: "v2", PresentationDir: presentationDir, StateDir: dir("g6-signer"), GrantKeyPath: grantKey, FundingKeyPath: fundKey, Caps: sg.RegtestCaps(), Policy: rental.IssuerPolicy{Policy: rental.Policy{ConstructionProfile: "W", Network: "regtest", Genesis: su.RegtestGenesis, StationName: e2eAgentName, StationScript: sealScript, AgentName: e2eAgentName, LandlordName: e2eLandlordName, AgentPubkey: l.agentNostrPub, IssuerPubkey: l.issuerPub, SealScript: sealScript, FundingScript: fundScript, StateDir: dir("g6-issuer")}, ProviderPubkey: provider}, PaymentPolicies: map[string]rental.PaymentAdmissionPolicy{"nmc": {MaxRateAgeSeconds: 7200, MinConfirmations: 2, Limits: pc.Limits{MaxBlocks: 512, MaxMempool: 2000, MaxCalls: 10000, MaxBytes: 64 << 20}}}}
	// The funding key is never imported into Core; SG1 owns both signing roles.
	descriptor := labObject(t, l.rpc("", "getdescriptorinfo", "wpkh("+pub+")"))
	var addresses []string
	if e = json.Unmarshal(l.rpc("", "deriveaddresses", labText(t, descriptor["descriptor"])), &addresses); e != nil || len(addresses) != 1 {
		t.Fatal("fund descriptor")
	}
	fund := l.output(addresses[0], fundScript)
	seal := l.seal()
	inputs := []su.PlanInput{{Point: su.Point{TxID: seal.TxID, Vout: seal.Vout}, Role: "seal", ValueSat: 1000000, Script: sealScript}, {Point: su.Point{TxID: fund.TxID, Vout: fund.Vout}, Role: "funding", ValueSat: 1000000, Script: fundScript}}
	signer, e := nostr.PrivKeyFromBytes(l.issuer.Serialize())
	if e != nil {
		t.Fatal(e)
	}
	var store *gs.Server
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { store.ServeHTTP(w, r) }))
	origin := "http://" + srv.Listener.Addr().String()
	store, e = gs.Open(gs.Config{Root: dir("g6-store"), PublicURL: origin, Writers: []string{signer.PubKeyHex()}})
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	srv.Start()
	defer srv.Close()
	sink, e := sg.NewS1Store(origin, signer, l.issuerPub, l.agentNostrPub)
	if e != nil {
		t.Fatal(e)
	}
	route := l.route
	route.Username = "sg1-broadcaster"
	broadcast, e := sg.NewRPCBroadcast(route, l.route)
	if e != nil {
		t.Fatal(e)
	}
	paymentNode, e := pc.NewIssuerRPC(pc.Route{Host: l.route.Host, Port: l.route.Port, Username: "payment-issuer", Password: l.route.Password})
	if e != nil {
		t.Fatal(e)
	}
	adapter := sg.V2Issuer{Policy: rental.IssuerPolicyV2{IssuerPolicy: cfg.Policy, PaymentPolicies: cfg.PaymentPolicies}, Identity: l.observer, Payments: map[string]su.Node{"nmc": paymentNode}, KeyPath: grantKey}
	engine, e := sg.Open(cfg, adapter, l.observer, broadcast, sink)
	if e != nil {
		t.Fatal(e)
	}
	defer engine.Close()
	if e = engine.Enroll(ctx, inputs, time.Now().Unix()); e != nil {
		t.Fatal(e)
	}
	source, e := sg.OpenFileSource(sourceDir)
	if e != nil {
		t.Fatal(e)
	}
	batch, e := source.Pull(ctx, "", sg.MaxRecords)
	if e != nil || len(batch) != 1 {
		t.Fatal("V2 exporter intake", e)
	}
	var item sg.Item
	if json.Unmarshal(batch[0].Raw, &item) != nil || item.Request != string(jsonCanonical(b.Issuance)) || item.Publication != string(jsonCanonical(b.PackageEvent)) {
		t.Fatal("exporter changed V2 wire")
	}
	if e = engine.Pull(ctx, source, sg.BookingSource, time.Now().Unix()); e != nil {
		t.Fatal(e)
	}
	results := engine.Step(ctx, time.Now().Unix())
	if len(results) != 1 || results[0].Reason != "PRESENTATION_UNCONFIRMED" || results[0].Phase != "stored" {
		t.Fatal("SG1 issuance", results)
	}
	target := filepath.Join(presentationDir, b.Contract.BookingID+".json")
	if _, e = os.Stat(target); !os.IsNotExist(e) {
		t.Fatal("unconfirmed presentation published", e)
	}
	l.mine(1)
	_ = engine.Step(ctx, time.Now().Unix())
	proof, e := os.ReadFile(target)
	if e != nil {
		t.Fatal("confirmed SG1 presentation", e)
	}
	return proof
}
