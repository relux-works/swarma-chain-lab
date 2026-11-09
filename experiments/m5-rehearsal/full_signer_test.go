package rehearsal

import (
	"encoding/json"
	"os"
	"path/filepath"
	pc "github.com/relux-works/swarma-chain-lab/experiments/payment-chain"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	booking "github.com/relux-works/swarma-chain-lab/experiments/rental-booking"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
	signer "github.com/relux-works/swarma-chain-lab/experiments/signer-service"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"strings"
	"time"
)

// Only disposable regtest outputs are provisioned. Core never receives either
// signing key; the actual SG1 CLI performs native enrollment and all signing.
func (l *lab) signerInput(key *nostr.PrivKey, role string) su.PlanInput {
	t := l.t
	t.Helper()
	script, e := rental.GrantSealScript(key.PubKeyHex())
	checked(t, e, "signer inventory script")
	var descriptor struct {
		Descriptor string `json:"descriptor"`
	}
	checked(t, json.Unmarshal(l.rpc("", "getdescriptorinfo", "pkh(02"+key.PubKeyHex()+")"), &descriptor), "inventory descriptor")
	var addresses []string
	checked(t, json.Unmarshal(l.rpc("", "deriveaddresses", descriptor.Descriptor), &addresses), "inventory address")
	if len(addresses) != 1 {
		t.Fatal("inventory address count")
	}
	txid := str(t, l.rpc("rehearsal", "sendtoaddress", addresses[0], su.Coins(1000000)))
	l.mine(1)
	var tx su.TransactionView
	checked(t, json.Unmarshal(l.rpc("", "getrawtransaction", txid, true), &tx), "inventory transaction")
	for _, o := range tx.Vout {
		if o.Script.Hex == script && int64(o.Value) == 1000000 {
			return su.PlanInput{Point: su.Point{TxID: txid, Vout: o.N}, Role: role, ValueSat: 1000000, Script: script}
		}
	}
	t.Fatal("inventory output absent")
	return su.PlanInput{}
}
func (l *lab) signerConfig(cfg booking.ConfigV2, storeURL, presentations string, grant, funding, provider *nostr.PrivKey) string {
	seal, e := rental.GrantSealScript(grant.PubKeyHex())
	checked(l.t, e, "signer seal")
	fund, e := rental.GrantSealScript(funding.PubKeyHex())
	checked(l.t, e, "signer funding")
	fc := signer.FileConfig{Config: signer.Config{Profile: "v2", PresentationDir: presentations, StateDir: l.dir("signer"), GrantKeyPath: filepath.Join(l.private, "grant.key"), FundingKeyPath: filepath.Join(l.private, "funding.key"), Caps: signer.RegtestCaps(), Policy: rental.IssuerPolicy{Policy: rental.Policy{Network: "regtest", Genesis: su.RegtestGenesis, IssuerPubkey: grant.PubKeyHex(), AgentPubkey: cfg.AgentPubkey, AgentName: agentName, StationName: agentName, LandlordName: landlordName, SealScript: seal, StationScript: seal, FundingScript: fund, StateDir: l.dir("issuer")}, ProviderPubkey: provider.PubKeyHex()}, PaymentPolicies: map[string]rental.PaymentAdmissionPolicy{"nmc": {MaxRateAgeSeconds: 7200, MinConfirmations: 2, Limits: pc.Limits{MaxBlocks: 512, MaxMempool: 2000, MaxCalls: 10000, MaxBytes: 64 << 20}}}}, ReadRouteFile: l.json("signer-reader.json", l.read, 0600), BroadcastRouteFile: l.json("signer-broadcaster.json", l.broadcast, 0600), PaymentRouteFiles: map[string]string{"nmc": l.json("signer-payment.json", l.paymentIssuer, 0600)}, BookingOutbox: cfg.StateDir, StoreURL: storeURL, StoreLandlordReader: grant.PubKeyHex(), StoreAgentReader: cfg.AgentPubkey, IntervalSeconds: 1, Inventory: []su.PlanInput{l.signerInput(grant, "seal"), l.signerInput(funding, "funding")}}
	return l.json("signer.json", fc, 0600)
}
func (l *lab) signerCycle(config string) {
	out, code := l.command("SG1 native cycle", l.bins["signer"], "-config", config, "-once")
	l.write(filepath.Join(l.private, "signer-last-cycle.log"), out, 0600)
	if code != 0 || leaked(out, l.secrets) || strings.Contains(string(out), "DATA RACE") {
		l.t.Fatal("native signer cycle failed; output withheld")
	}
}
func (l *lab) confirmedPresentation(config, id, dir string) []byte {
	target := filepath.Join(dir, id+".json")
	l.signerCycle(config)
	if _, e := os.Stat(target); !os.IsNotExist(e) {
		l.t.Fatal("unconfirmed signer presentation published")
	}
	l.mine(1)
	l.signerCycle(config)
	raw, e := os.ReadFile(target)
	checked(l.t, e, "confirmed native SG1 presentation")
	l.evidence["native_signer"] = map[string]any{"original_booking_outbox": true, "native_inventory_enrollment": true, "unconfirmed_presentation_absent": true, "confirmed_presentation_published": true, "observed_at": time.Now().Unix()}
	return raw
}
