package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/exchange"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/kernelbind/bookingbind"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	pc "relux.works/swarma-chain-lab/experiments/payment-chain"
	booking "relux.works/swarma-chain-lab/experiments/rental-booking"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/nostr"
)

type bookingV2Node struct{ coin string }

func (n bookingV2Node) Call(ctx context.Context, method string, args ...any) (json.RawMessage, error) {
	if method == "getnetworkinfo" {
		sub, protocol := "/Satoshi:32.1.0/", 70017
		if n.coin == "ltc" {
			sub = "/LitecoinCore:0.21.5.8/"
		}
		if n.coin == "nmc" {
			protocol = 110016
		}
		return jsonCanonical(map[string]any{"subversion": sub, "protocolversion": protocol}), nil
	}
	if method == "getblockhash" {
		p, _ := pc.ForCoin(n.coin)
		return jsonCanonical(p.Genesis), nil
	}
	return (bookingTestNode{}).Call(ctx, method, args...)
}
func bookingV2Fixture(t *testing.T, coin string, nodes ...booking.Node) (*bookingV2Client, *booking.ServiceV2, *btcec.PrivateKey, string, string) {
	t.Helper()
	provider, _ := nostr.GeneratePrivKey()
	agent, _ := nostr.GeneratePrivKey()
	renter, _ := nostr.GeneratePrivKey()
	pk, _ := btcec.PrivKeyFromBytes(provider.Bytes())
	rk, _ := btcec.PrivKeyFromBytes(renter.Bytes())
	master, e := hdkeychain.NewMaster([]byte("public-g6-v2-booking-fixture-seed"), &chaincfg.RegressionNetParams)
	if e != nil {
		t.Fatal(e)
	}
	branch, e := master.Neuter()
	if e != nil {
		t.Fatal(e)
	}
	profile := []byte("public V2 booking fixture\n")
	tmpl := booking.Template{Version: 1, ID: "demo", ProfileID: "fixture", ProfileVersion: "1", ProfileSHA256: booking.Hash(profile), Allowed: []string{"deliver", "pay"}, Forbidden: []string{"publish", "repository.push", "secret.release"}, BudgetSat: 10000}
	now := time.Now().Unix()
	cfg := booking.ConfigV2{StateDir: testRoot(t), AgentPubkey: agent.PubKeyHex(), ProviderPubkey: provider.PubKeyHex(), HoldSeconds: 1200, PriceUSDCents: 100, Template: tmpl, TemplateSHA256: booking.Hash(jsonCanonical(tmpl)), Slots: []booking.Slot{{ID: "one", StationName: "id/test-agent", NotBefore: now + 3600, NotAfter: now + 7200, PaymentPolicy: "advance"}}, Coins: map[string]booking.CoinConfig{coin: {PublicBranch: branch.String(), PublicBranchSHA256: booking.Hash([]byte(branch.String())), USDMicrosPerCoin: 1000000, RateAsOf: now, MaxRateAgeSeconds: 7200, MinConfirmations: 2}}, Limits: booking.Limits{MaxBlocks: 512, MaxMempool: 2000, MaxCalls: 10000, MaxBytes: 64 << 20}}
	var node booking.Node = bookingV2Node{coin}
	if len(nodes) > 0 {
		node = nodes[0]
	}
	svc, e := booking.NewServiceV2(cfg, profile, pk, map[string]booking.Node{coin: node}, bookingV2Node{"nmc"}, packagePublisher{}, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(svc.Close)
	srv := httptest.NewUnstartedServer(nil)
	handler, e := booking.NewHTTPHandlerV2(svc, "http://"+srv.Listener.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	srv.Config.Handler = handler
	srv.Start()
	t.Cleanup(srv.Close)
	c := newBookingV2Client(srv.URL, booking.Hash([]byte(booking.PrivacyNotice)), cfg.TemplateSHA256, tmpl.ProfileSHA256, 2*time.Second)
	t.Cleanup(c.close)
	return c, svc, rk, renter.PubKeyHex(), agent.PubKeyHex()
}

// Actual V2 HTTP responses retain exact frozen terms for all three coins. An
// omitted/unsupported coin creates no hold; foreign consent creates no package.
// Deterministic observer here is not evidence of real Core payment admission.
func TestBookingV2ClientRealHTTP(t *testing.T) {
	for _, coin := range []string{"nmc", "btc", "ltc"} {
		t.Run(coin, func(t *testing.T) {
			c, s, key, pub, _ := bookingV2Fixture(t, coin)
			ctx := context.Background()
			cat, e := c.Catalogue(time.Now().Unix()+86400, 16)
			if e != nil || len(cat.Slots) != 1 {
				t.Fatal("catalogue", e)
			}
			for _, bad := range []pc.Coin{"", "eth"} {
				if _, e = c.Book(ctx, booking.BookInputV2{SlotID: "one", Coin: bad, RenterPubkey: pub, PrivacyAcknowledged: true}); e == nil {
					t.Fatal("invalid coin accepted")
				}
			}
			b, e := c.Book(ctx, booking.BookInputV2{SlotID: "one", Coin: pc.Coin(coin), RenterPubkey: pub, PrivacyAcknowledged: true})
			if e != nil {
				t.Fatal(e)
			}
			if b.AddressIndex != 0 || b.Contract.Version != 2 || b.Contract.Payment.Coin != coin || b.Contract.Payment.MinConfirmations != 2 {
				t.Fatal("terms/allocation")
			}
			ev := booking.ConsentV2(b.Contract, time.Now().Unix())
			ev.Tags[1][1] = strings.Repeat("f", 64)
			if e = ev.Sign(key); e != nil {
				t.Fatal(e)
			}
			if _, e = c.AcceptConsent(ctx, b.Contract.BookingID, ev); e == nil {
				t.Fatal("foreign consent accepted")
			}
			unchanged, e := s.Get(b.Contract.BookingID)
			if e != nil || unchanged.Package != nil {
				t.Fatal("foreign consent had effect", e)
			}
			ev = booking.ConsentV2(b.Contract, time.Now().Unix())
			if e = ev.Sign(key); e != nil {
				t.Fatal(e)
			}
			accepted, e := c.AcceptConsent(ctx, b.Contract.BookingID, ev)
			if e != nil || accepted.Package == nil || !accepted.Published {
				t.Fatal("consent", e)
			}
			got, e := c.Get(b.Contract.BookingID)
			if e != nil || got.Contract.Hash() != b.Contract.Hash() || got.Package == nil {
				t.Fatal("frozen status", e)
			}
			direct, e := s.Get(b.Contract.BookingID)
			if e != nil || string(jsonCanonical(direct)) != string(jsonCanonical(got)) {
				t.Fatal("wire changed", e)
			}
		})
	}
}

// A successfully decoded V1 catalogue cannot authorize downgrade. The first V1
// booking response is rejected by the typed V2 client, with no fallback retry.
func TestBookingV2RefusesV1Response(t *testing.T) {
	old, _, _ := bookingFixture(t)
	renter, _ := nostr.GeneratePrivKey()
	realV1, e := old.Book(context.Background(), booking.BookInput{SlotID: "one", RenterPubkey: renter.PubKeyHex(), PrivacyAcknowledged: true})
	if e != nil {
		t.Fatal(e)
	}
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(jsonCanonical(map[string]any{"booking": realV1, "contract_sha256": realV1.Contract.Hash()}))
	}))
	defer srv.Close()
	c := newBookingV2Client(srv.URL, old.privacy, old.template, old.profile, time.Second)
	defer c.close()
	if _, e := c.Book(context.Background(), booking.BookInputV2{}); e != errBooking || calls != 1 {
		t.Fatal("V1 downgrade or retry", e, calls)
	}
}

type v2CallSpy struct {
	*bookingV2Client
	books, consents int
}

func (s *v2CallSpy) Book(ctx context.Context, in booking.BookInputV2) (booking.BookingV2, error) {
	s.books++
	return s.bookingV2Client.Book(ctx, in)
}
func (s *v2CallSpy) AcceptConsent(ctx context.Context, id string, event booking.Event) (booking.BookingV2, error) {
	s.consents++
	return s.bookingV2Client.AcceptConsent(ctx, id, event)
}

// The production adapter reaches real ServiceV2 HTTP on every coin. Its local
// guards stop unoffered selection and foreign consent before backend mutation
// calls; valid controls retain exact contract bytes and confirmation policy.
func TestAdapterV2HTTP(t *testing.T) {
	for _, coin := range []string{"nmc", "btc", "ltc"} {
		t.Run(coin, func(t *testing.T) {
			c, s, key, pub, agent := bookingV2Fixture(t, coin)
			spy := &v2CallSpy{bookingV2Client: c}
			ctx := context.Background()
			a := &bookingbind.AdapterV2{ServiceV2: spy, AgentName: "id/test-agent", LandlordName: "id/test-landlord", AgentPubkey: agent, Now: time.Now, PaymentCoins: []exchange.Coin{exchange.Coin(coin)}}
			cat, e := a.Catalogue(ctx)
			if e != nil || len(cat.Slots) != 1 || len(cat.Templates[0].Coins) != 1 || cat.Slots[0].Coins[0] != exchange.Coin(coin) {
				t.Fatal("V2 catalogue", e)
			}
			if _, e = a.Book(ctx, pub, exchange.Selection{Template: "demo", Slot: "one", Coin: "eth"}); !errors.Is(e, exchange.ErrCoinNotOffered) || spy.books != 0 {
				t.Fatal("adapter coin guard missing", e, spy.books)
			}
			h, e := a.Book(ctx, pub, exchange.Selection{Template: "demo", Slot: "one", Coin: exchange.Coin(coin)})
			if e != nil {
				t.Fatal("V2 adapter book", e)
			}
			b, e := s.Get(h.BookingID)
			if e != nil {
				t.Fatal(e)
			}
			if b.AddressIndex != 0 || spy.books != 1 || string(h.Contract) != string(b.Contract.Bytes()) || h.MinConfirmations != 2 || h.AmountAtomic != b.Contract.Payment.AmountAtoms {
				t.Fatal("V2 opaque hold")
			}
			ev := booking.ConsentV2(b.Contract, time.Now().Unix())
			ev.Tags[1][1] = strings.Repeat("f", 64)
			_ = ev.Sign(key)
			if _, e = a.Consent(ctx, h.BookingID, jsonCanonical(ev)); !errors.Is(e, exchange.ErrRejected) || spy.consents != 0 {
				t.Fatal("adapter consent guard missing", e, spy.consents)
			}
			unchanged, e := s.Get(h.BookingID)
			if e != nil || unchanged.Package != nil {
				t.Fatal("adapter foreign consent changed state")
			}
			ev = booking.ConsentV2(b.Contract, time.Now().Unix())
			_ = ev.Sign(key)
			accepted, e := a.Consent(ctx, h.BookingID, jsonCanonical(ev))
			if e != nil || accepted.ConsentID != ev.ID || spy.consents != 1 || accepted.ContractSHA256 != h.ContractSHA256 {
				t.Fatal("V2 adapter consent", e)
			}
		})
	}
}

// Provisioning drift is refused by the authoritative service before allocation;
// the adapter preserves its closed no-effect classification, then valid NMC works.
func TestAdapterV2ServiceCoinRefusal(t *testing.T) {
	c, s, _, pub, agent := bookingV2Fixture(t, "nmc")
	a := &bookingbind.AdapterV2{ServiceV2: c, AgentName: "id/test-agent", LandlordName: "id/test-landlord", AgentPubkey: agent, Now: time.Now, PaymentCoins: []exchange.Coin{exchange.BTC, exchange.NMC}}
	ctx := context.Background()
	if _, e := a.Book(ctx, pub, exchange.Selection{Template: "demo", Slot: "one", Coin: exchange.BTC}); !errors.Is(e, exchange.ErrRejected) || !errors.Is(e, exchange.ErrCoinNotOffered) {
		t.Fatal("service coin refusal reclassified", e)
	}
	h, e := a.Book(ctx, pub, exchange.Selection{Template: "demo", Slot: "one", Coin: exchange.NMC})
	if e != nil {
		t.Fatal(e)
	}
	b, e := s.Get(h.BookingID)
	if e != nil || b.AddressIndex != 0 {
		t.Fatal("coin refusal allocated", e)
	}
}

// The V2 client rejects changed hash, selected coin, renter and public pins in a
// syntactically valid response. Each case has a valid typed response neighbor.
func TestBookingV2ResponseBindings(t *testing.T) {
	c, _, _, pub, _ := bookingV2Fixture(t, "nmc")
	ctx := context.Background()
	in := booking.BookInputV2{SlotID: "one", Coin: "nmc", RenterPubkey: pub, PrivacyAcknowledged: true}
	b, e := c.Book(ctx, in)
	if e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"valid", "hash", "coin", "renter", "profile", "confirmations"} {
		t.Run(kind, func(t *testing.T) {
			value := b
			request := in
			switch kind {
			case "coin":
				request.Coin = "btc"
			case "renter":
				key, _ := nostr.GeneratePrivKey()
				request.RenterPubkey = key.PubKeyHex()
			case "profile":
				value.Contract.ProfileSHA256 = strings.Repeat("a", 64)
			case "confirmations":
				value.Contract.Payment.MinConfirmations = 0
			}
			hash := value.Contract.Hash()
			if kind == "hash" {
				hash = strings.Repeat("f", 64)
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(201)
				_ = json.NewEncoder(w).Encode(map[string]any{"booking": value, "contract_sha256": hash})
			}))
			defer srv.Close()
			client := newBookingV2Client(srv.URL, c.privacy, c.template, c.profile, time.Second)
			defer client.close()
			_, e := client.Book(ctx, request)
			if kind == "valid" {
				if e != nil {
					t.Fatal("valid V2 response", e)
				}
			} else if e != errBooking {
				t.Fatal("V2 response binding accepted", kind, e)
			}
		})
	}
}
