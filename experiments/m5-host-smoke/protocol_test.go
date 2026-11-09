package smoke

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	pc "github.com/relux-works/swarma-chain-lab/experiments/payment-chain"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	booking "github.com/relux-works/swarma-chain-lab/experiments/rental-booking"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/exchange"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

func publicFixture(t *testing.T) (Config, booking.ContractV2, exchange.Terms) {
	t.Helper()
	key, e := nostr.GeneratePrivKey()
	if e != nil {
		t.Fatal(e)
	}
	issuer, e := nostr.GeneratePrivKey()
	if e != nil {
		t.Fatal(e)
	}
	renter, e := nostr.GeneratePrivKey()
	if e != nil {
		t.Fatal(e)
	}
	h := strings.Repeat("1", 64)
	now := time.Now().Unix()
	c := Config{Scenario: "expiry", Relay: "ws://127.0.0.1:9991", Booking: "http://127.0.0.1:9992", AgentPubkey: key.PubKeyHex(), IssuerPubkey: issuer.PubKeyHex(), AgentName: "id/agent", LandlordName: "id/landlord", TemplateSHA256: h, ProfileSHA256: h, ProfileID: "demo", ProfileVersion: "1", EvidenceSHA256: h, EnvironmentSHA256: h, Allowed: []string{"deliver"}, Forbidden: []string{"pay", "publish", "repository.push", "secret.release"}, BudgetSat: 1000000, NotBefore: now + 300, NotAfter: now + 3900}
	master, e := hdkeychain.NewMaster([]byte(strings.Repeat("a", 32)), &chaincfg.RegressionNetParams)
	if e != nil {
		t.Fatal(e)
	}
	pub, e := master.Neuter()
	if e != nil {
		t.Fatal(e)
	}
	p, e := pc.ForNetwork("nmc", "regtest", su.RegtestGenesis)
	if e != nil {
		t.Fatal(e)
	}
	d, e := pc.NewAddressDeriver(p, pub.String(), rental.Hash([]byte(pub.String())))
	if e != nil {
		t.Fatal(e)
	}
	addr, _, e := d.Address(0)
	if e != nil {
		t.Fatal(e)
	}
	v := booking.ContractV2{Version: 2, BookingID: h, RenterPubkey: renter.PubKeyHex(), AgentPubkey: c.AgentPubkey, StationName: c.AgentName, NotBefore: c.NotBefore, NotAfter: c.NotAfter, Allowed: c.Allowed, Forbidden: c.Forbidden, BudgetSat: c.BudgetSat, TemplateID: "demo-60", TemplateSHA256: c.TemplateSHA256, ProfileID: c.ProfileID, ProfileVersion: c.ProfileVersion, ProfileSHA256: c.ProfileSHA256, Payment: pc.Terms{Coin: "nmc", Network: "regtest", Genesis: su.RegtestGenesis, PriceUSDCents: 1000, USDMicrosPerCoin: 100000000, RateAsOf: now, MaxRateAgeSeconds: 3600, AmountAtoms: 10000000, Address: addr, MinConfirmations: 1}, PaymentPolicy: "advance", PrivacySHA256: privacy()}
	terms := exchange.Terms{AgentName: c.AgentName, LandlordName: c.LandlordName, PrivacyNotice: booking.PrivacyNotice, PrivacySHA256: privacy(), PowBits: 16, Templates: []exchange.Template{{ID: "demo-60", SHA256: c.TemplateSHA256, ProfileID: c.ProfileID, ProfileVersion: c.ProfileVersion, ProfileSHA256: c.ProfileSHA256, PriceUSDCents: 1000, SlotLengths: []int64{3600}, Coins: []exchange.Coin{exchange.NMC}}}, Slots: []exchange.Slot{{ID: "demo-60", TemplateID: "demo-60", NotBefore: c.NotBefore, NotAfter: c.NotAfter, Coins: []exchange.Coin{exchange.NMC}}}}
	return c, v, terms
}

// Host profile is fixed: shortened windows cannot become host evidence. Only
// loopback plain transport is accepted; remote TLS cannot embed credentials.
func TestConfigurationProfileAndEndpointPlants(t *testing.T) {
	c, _, _ := publicFixture(t)
	if e := c.validate(host()); e != nil {
		t.Fatal(e)
	}
	for _, s := range []string{"https://example.invalid", "wss://example.invalid", "http://127.0.0.1:123", "ws://[::1]:123"} {
		if !endpoint(s, strings.HasPrefix(s, "ws")) {
			t.Fatal("valid endpoint")
		}
	}
	for _, s := range []string{"http://example.invalid", "ws://example.invalid", "https://u:secret@example.invalid", "https://example.invalid?token=secret", "https://example.invalid/private", "https://example.invalid#secret"} {
		if endpoint(s, strings.HasPrefix(s, "ws")) {
			t.Fatal("unsafe endpoint accepted")
		}
	}
	short := c
	short.NotAfter = short.NotBefore + 210
	wantCode(t, short.validate(host()), "CONFIG_WINDOW")
	if e := short.validate(rehearsal(short)); e != nil {
		t.Fatal("self-test positive", e)
	}
	report, e := Run(context.Background(), short, OperatorFunc(func(context.Context, Request) (Receipt, error) {
		t.Fatal("invalid host config reached operator")
		return Receipt{}, nil
	}))
	wantCode(t, e, "CONFIG_WINDOW")
	if report.Outcome != "FAIL" || report.Mode != "host" {
		t.Fatal("invalid host report")
	}
}

// Every bound ContractV2 top-level field except the randomly allocated booking
// ID is independently perturbed. Native validation and expected pins reject it.
// Native quote checks separately reject amount, coin, genesis and depth changes.
func TestContractBindingPlants(t *testing.T) {
	c, v, _ := publicFixture(t)
	if e := checkContract(c, host(), v, v.RenterPubkey); e != nil {
		t.Fatal("positive", e)
	}
	fields := reflect.TypeOf(v)
	for i := 0; i < fields.NumField(); i++ {
		name := fields.Field(i).Name
		if name == "BookingID" || name == "Payment" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			bad := v
			f := reflect.ValueOf(&bad).Elem().FieldByName(name)
			switch f.Kind() {
			case reflect.String:
				f.SetString("invalid")
			case reflect.Int, reflect.Int64:
				f.SetInt(f.Int() + 1)
			case reflect.Slice:
				f.Set(reflect.MakeSlice(f.Type(), 0, 0))
			}
			if checkContract(c, host(), bad, v.RenterPubkey) == nil {
				t.Fatal("contract plant accepted")
			}
		})
	}
	for name, mutate := range map[string]func(*pc.Terms){"coin": func(p *pc.Terms) { p.Coin = "btc" }, "network": func(p *pc.Terms) { p.Network = "main" }, "genesis": func(p *pc.Terms) { p.Genesis = strings.Repeat("2", 64) }, "amount": func(p *pc.Terms) { p.AmountAtoms++ }, "depth": func(p *pc.Terms) { p.MinConfirmations++ }, "stale": func(p *pc.Terms) { p.RateAsOf -= 7200 }} {
		t.Run(name, func(t *testing.T) {
			bad := v
			mutate(&bad.Payment)
			if checkContract(c, host(), bad, v.RenterPubkey) == nil {
				t.Fatal("payment plant accepted")
			}
		})
	}
}

// Terms pinning rejects changed identity, price, profile, PoW, window or coin
// beside the native positive fixture; an arbitrary similar prefix is insufficient.
func TestTermsPlantsAndExactReplies(t *testing.T) {
	c, _, good := publicFixture(t)
	if e := checkTerms(c, host(), good); e != nil {
		t.Fatal(e)
	}
	for name, mutate := range map[string]func(*exchange.Terms){"agent": func(v *exchange.Terms) { v.AgentName = "id/other" }, "privacy": func(v *exchange.Terms) { v.PrivacySHA256 = "" }, "pow": func(v *exchange.Terms) { v.PowBits = 4 }, "template": func(v *exchange.Terms) { v.Templates[0].SHA256 = "" }, "price": func(v *exchange.Terms) { v.Templates[0].PriceUSDCents++ }, "profile": func(v *exchange.Terms) { v.Templates[0].ProfileSHA256 = "" }, "length": func(v *exchange.Terms) { v.Templates[0].SlotLengths = []int64{2} }, "coin": func(v *exchange.Terms) { v.Slots[0].Coins = []exchange.Coin{"btc"} }, "window": func(v *exchange.Terms) { v.Slots[0].NotAfter-- }} {
		t.Run(name, func(t *testing.T) {
			var bad exchange.Terms
			_ = json.Unmarshal(encode(good), &bad)
			mutate(&bad)
			if checkTerms(c, host(), bad) == nil {
				t.Fatal("terms plant accepted")
			}
		})
	}
	for _, reply := range []string{"ready", "ready injected-canary"} {
		peer := conversation{inbox: make(chan received, 1), fault: make(chan error, 1)}
		peer.inbox <- received{reply, time.Now().Unix()}
		e := peer.expect(context.Background(), "ready", time.Second)
		if reply == "ready" {
			if e != nil {
				t.Fatal(e)
			}
		} else {
			wantCode(t, e, "REPLY_EXACT")
		}
	}
}

// Read-only HTTP does not follow redirects or leak a malformed response body.
func TestHTTPBoundary(t *testing.T) {
	hits := 0
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++; w.Write([]byte(`{}`)) }))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Error("non-GET")
		}
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, destination.URL, 302)
			return
		}
		w.Write([]byte(`{"password":"secret-canary"}`))
	}))
	defer source.Close()
	var v Receipt
	wantCode(t, get(context.Background(), source.URL, "/redirect", &v), "HTTP_TRANSPORT")
	if hits != 0 {
		t.Fatal("followed redirect")
	}
	e := get(context.Background(), source.URL, "/bad", &v)
	if e == nil || strings.Contains(e.Error(), "secret-canary") {
		t.Fatal("body accepted/leaked")
	}
}
