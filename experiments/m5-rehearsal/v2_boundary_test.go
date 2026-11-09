package rehearsal

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	pc "relux.works/swarma-chain-lab/experiments/payment-chain"
	booking "relux.works/swarma-chain-lab/experiments/rental-booking"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/nostr"
	signer "relux.works/swarma-chain-lab/experiments/signer-service"
	su "relux.works/swarma-chain-lab/experiments/single-use"
)

// The actual booking CLI selects V2 without adapting any existing v1 contract.
// Real gateway/relay Book stops at G6. A separate direct-HTTP V2 positive control
// pays on genuine NMC and feeds the real signer FileSource; it is not a bridge
// around the gateway failure and does not issue a grant or allocate a slot.
func (l *lab) v2Diagnostic(v1 booking.Config, profile string, operator su.OperatorRoute, address, relay string, agent *nostr.PrivKey) {
	t := l.t
	cfg := booking.ConfigV2{StateDir: l.dir("booking-v2"), AgentPubkey: v1.AgentPubkey, ProviderPubkey: v1.ProviderPubkey, HoldSeconds: v1.HoldSeconds, PriceUSDCents: v1.PriceUSDCents, Template: v1.Template, TemplateSHA256: v1.TemplateSHA256, Slots: v1.Slots, Limits: v1.Limits, Coins: map[string]booking.CoinConfig{"nmc": {PublicBranch: v1.PublicBranch, PublicBranchSHA256: v1.PublicBranchSHA256, USDMicrosPerCoin: v1.USDMicrosPerNMC, RateAsOf: time.Now().Unix(), MaxRateAgeSeconds: 7200, MinConfirmations: 1}}}
	selected := struct {
		Version int               `json:"service_version"`
		Config  booking.ConfigV2  `json:"config"`
		Routes  map[string]string `json:"payment_route_files"`
	}{2, cfg, map[string]string{"nmc": l.json("payment-observer.json", l.payment, 0600)}}
	l.bins["booking-v2"] = l.bins["booking"]
	l.spawn("booking-v2", "-config", l.json("booking-v2.json", selected, 0600), "-profile", profile, "-provider-key", filepath.Join(l.private, "provider.key"), "-route", l.json("operator-v2.json", operator, 0600), "-listen", address, "-relay", relay, "-poll", "1s")
	origin := "http://" + address
	l.await("booking V2 readiness", func() bool { return l.http("GET", origin+"/", nil, nil) == 200 })
	renter := l.key("v2-renter.key", false)
	l.converse(relay, origin, agent, renter, true)
	var cat booking.CatalogueV2
	path := fmt.Sprintf("/catalogue?until=%d&limit=16", time.Now().Unix()+86400)
	if l.http("GET", origin+path, nil, &cat) != 200 || len(cat.Slots) != 1 {
		t.Fatal("G6 failed booking reserved the slot")
	}
	// Reproduce the exact v1 HTTP shape used by the command's bookingClient.
	legacy := booking.BookInput{SlotID: "one", RenterPubkey: renter.PubKeyHex(), PrivacyAcknowledged: true}
	r, e := http.NewRequest("POST", origin+"/book", strings.NewReader(string(encoded(legacy))))
	checked(t, e, "legacy HTTP request")
	r.Header.Set("Origin", origin)
	r.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil}}
	defer client.CloseIdleConnections()
	res, e := client.Do(r)
	checked(t, e, "legacy HTTP response")
	raw, e := io.ReadAll(io.LimitReader(res.Body, 1025))
	res.Body.Close()
	checked(t, e, "legacy body")
	var refusal struct {
		Error string `json:"error"`
	}
	if res.StatusCode != 409 || booking.Strict(raw, &refusal) != nil || refusal.Error != "COIN_UNAVAILABLE" {
		t.Fatal("G6 exact HTTP coin refusal not observed")
	}
	var held struct {
		Booking booking.BookingV2 `json:"booking"`
		Hash    string            `json:"contract_sha256"`
	}
	if l.http("POST", origin+"/book", booking.BookInputV2{SlotID: "one", Coin: pc.CoinNMC, RenterPubkey: renter.PubKeyHex(), PrivacyAcknowledged: true}, &held) != 201 || held.Booking.Contract.Version != 2 || held.Hash != held.Booking.Contract.Hash() {
		t.Fatal("direct V2 positive book refused")
	}
	rk, _ := btcec.PrivKeyFromBytes(renter.Bytes())
	consent := booking.ConsentV2(held.Booking.Contract, time.Now().Unix())
	checked(t, consent.Sign(rk), "V2 consent")
	var accepted booking.BookingV2
	if l.http("POST", origin+"/consent", map[string]any{"booking_id": held.Booking.Contract.BookingID, "event": consent}, &accepted) != 200 || accepted.PackageEvent == nil || accepted.PackageEvent.Verify() != nil {
		t.Fatal("direct V2 consent refused")
	}
	l.rpc("rehearsal", "sendtoaddress", held.Booking.Contract.Payment.Address, su.Coins(held.Booking.Contract.Payment.AmountAtoms))
	l.mine(1)
	var paid booking.BookingV2
	l.await("V2 genuine payment", func() bool {
		return l.http("GET", origin+"/booking?id="+held.Booking.Contract.BookingID, nil, &paid) == 200 && paid.Issuance != nil
	})
	source, e := signer.OpenFileSource(cfg.StateDir)
	checked(t, e, "V2 source open")
	items, e := source.Pull(context.Background(), "", 4)
	checked(t, e, "V2 source pull")
	if len(items) != 1 {
		t.Fatal("V2 positive source lacks issue")
	}
	var content map[string]json.RawMessage
	if json.Unmarshal(encoded(items[0]), &content) != nil {
		t.Fatal("V2 item evidence shape")
	}
	l.evidence["G6"] = map[string]any{"native_gateway_uses_v1_request": true, "v2_http_status": 409, "v2_http_code": refusal.Error, "rejection_preserved_slot": true, "gateway_response": "BookPending", "direct_v2_book_consent_payment": true, "direct_v2_original_export_consumed": true, "direct_v2_source_items": len(items), "positive_control_is_not_gateway_adaptation": true}
}
