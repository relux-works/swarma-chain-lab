package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	booking "relux.works/swarma-chain-lab/experiments/rental-booking"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/nostr"
	su "relux.works/swarma-chain-lab/experiments/single-use"
)

type bookingTestNode struct{}

func (bookingTestNode) Call(_ context.Context, method string, args ...any) (json.RawMessage, error) {
	switch method {
	case "getblockchaininfo":
		return jsonCanonical(map[string]any{"chain": "regtest", "blocks": 100, "headers": 100, "bestblockhash": strings.Repeat("a", 64), "initialblockdownload": false}), nil
	case "getblockhash":
		return jsonCanonical(su.RegtestGenesis), nil
	case "getrawmempool":
		return []byte("[]"), nil
	}
	return nil, errors.New("unexpected test node method")
}

type packagePublisher struct{}

func (packagePublisher) Publish(_ context.Context, e booking.Event) error { return e.Verify() }

func bookingFixture(t *testing.T) (*bookingClient, *booking.Service, *btcec.PrivateKey) {
	t.Helper()
	provider, _ := nostr.GeneratePrivKey()
	agent, _ := nostr.GeneratePrivKey()
	renter, _ := nostr.GeneratePrivKey()
	pk, _ := btcec.PrivKeyFromBytes(provider.Bytes())
	rk, _ := btcec.PrivKeyFromBytes(renter.Bytes())
	master, e := hdkeychain.NewMaster([]byte("public-gw1-booking-fixture-seed!!"), &chaincfg.RegressionNetParams)
	if e != nil {
		t.Fatal(e)
	}
	public, e := master.Neuter()
	if e != nil {
		t.Fatal(e)
	}
	profile := []byte("public booking client fixture\n")
	tmpl := booking.Template{Version: 1, ID: "demo", ProfileID: "fixture", ProfileVersion: "1", ProfileSHA256: booking.Hash(profile), Allowed: []string{"deliver", "pay"}, Forbidden: []string{"publish", "repository.push", "secret.release"}, BudgetSat: 10000}
	now := time.Now().Unix()
	cfg := booking.Config{StateDir: testRoot(t), PublicBranch: public.String(), PublicBranchSHA256: booking.Hash([]byte(public.String())), AgentPubkey: agent.PubKeyHex(), ProviderPubkey: provider.PubKeyHex(), HoldSeconds: 1200, PriceUSDCents: 100, USDMicrosPerNMC: 1000000, RateAsOf: now, MaxRateAge: 7200, Template: tmpl, TemplateSHA256: booking.Hash(jsonCanonical(tmpl)), Slots: []booking.Slot{{ID: "one", StationName: "id/test-agent", NotBefore: now + 3600, NotAfter: now + 7200, PaymentPolicy: "advance"}}, Limits: booking.Limits{MaxBlocks: 512, MaxMempool: 2000, MaxCalls: 10000, MaxBytes: 64 << 20}}
	service, e := booking.NewService(cfg, profile, pk, bookingTestNode{}, packagePublisher{}, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(service.Close)
	server := httptest.NewUnstartedServer(nil)
	origin := "http://" + server.Listener.Addr().String()
	handler, e := booking.NewHTTPHandler(service, origin)
	if e != nil {
		t.Fatal(e)
	}
	server.Config.Handler = handler
	server.Start()
	t.Cleanup(server.Close)
	client := newBookingClient(server.URL, booking.Hash([]byte(booking.PrivacyNotice)), cfg.TemplateSHA256, tmpl.ProfileSHA256, 2*time.Second)
	t.Cleanup(client.close)
	return client, service, rk
}

// Real booking HTTP handlers accept catalogue/book/consent/status through this
// client. A rejected selection neither holds a slot nor consumes an address.
// The node here is a deterministic observer fixture, not payment/Core evidence.
func TestBookingClientRealHTTP(t *testing.T) {
	c, s, renter := bookingFixture(t)
	ctx := context.Background()
	cat, e := c.Catalogue(time.Now().Unix()+86400, 16)
	if e != nil || len(cat.Slots) != 1 {
		t.Fatalf("catalogue: %v", e)
	}
	_, e = c.Book(ctx, booking.BookInput{SlotID: "missing", RenterPubkey: hex.EncodeToString(schnorr.SerializePubKey(renter.PubKey())), PrivacyAcknowledged: true})
	if e == nil || e.Error() != "SLOT_UNAVAILABLE" {
		t.Fatalf("definitive rejection: %v", e)
	}
	b, e := c.Book(ctx, booking.BookInput{SlotID: "one", RenterPubkey: hex.EncodeToString(schnorr.SerializePubKey(renter.PubKey())), PrivacyAcknowledged: true})
	if e != nil {
		t.Fatal("book", e)
	}
	if b.AddressIndex != 0 {
		t.Fatal("rejection reserved an address")
	}
	event := booking.Consent(b.Contract, time.Now().Unix())
	if e = event.Sign(renter); e != nil {
		t.Fatal(e)
	}
	accepted, e := c.AcceptConsent(ctx, b.Contract.BookingID, event)
	if e != nil || accepted.Package == nil || !accepted.Published {
		t.Fatalf("consent: %v", e)
	}
	got, e := c.Get(b.Contract.BookingID)
	if e != nil || got.Contract.Hash() != b.Contract.Hash() || got.Package == nil {
		t.Fatalf("status: %v", e)
	}
	direct, e := s.Get(b.Contract.BookingID)
	if e != nil || string(jsonCanonical(direct)) != string(jsonCanonical(got)) {
		t.Fatal("HTTP changed service snapshot")
	}
	cat, e = c.Catalogue(time.Now().Unix()+86400, 16)
	if e != nil || len(cat.Slots) != 0 {
		t.Fatal("held slot advertised")
	}
}

// Public pin mismatches, unknown/duplicate/oversize responses and redirects
// fail with a fixed error. Ambiguous Book failures are not retried or echoed.
func TestBookingClientRefusals(t *testing.T) {
	c, _, _ := bookingFixture(t)
	cat, e := c.Catalogue(time.Now().Unix()+86400, 16)
	if e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"privacy", "template", "profile", "unknown", "duplicate", "oversize", "status"} {
		t.Run(name, func(t *testing.T) {
			modified := cat
			status := 200
			switch name {
			case "privacy":
				modified.PrivacyNotice = "private-upstream-marker"
			case "template":
				modified.TemplateSHA256 = strings.Repeat("0", 64)
			case "profile":
				modified.Template.ProfileSHA256 = strings.Repeat("0", 64)
			case "status":
				status = 500
			}
			body := jsonCanonical(modified)
			switch name {
			case "unknown":
				body = append([]byte(`{"unexpected":"private-upstream-marker",`), body[1:]...)
			case "duplicate":
				body = append([]byte(`{"privacy_sha256":"x",`), body[1:]...)
			case "oversize":
				body = []byte(strings.Repeat("x", (1<<20)+1))
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status); _, _ = w.Write(body) }))
			defer srv.Close()
			bad := newBookingClient(srv.URL, c.privacy, c.template, c.profile, 2*time.Second)
			defer bad.close()
			if _, e := bad.Catalogue(time.Now().Unix()+86400, 16); !errors.Is(e, errBooking) {
				t.Fatalf("bad catalogue accepted: %v", e)
			}
		})
	}
	var redirected atomic.Int64
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1) }))
	defer dest.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, dest.URL, 307) }))
	defer source.Close()
	redir := newBookingClient(source.URL, c.privacy, c.template, c.profile, 2*time.Second)
	defer redir.close()
	if _, e := redir.Catalogue(time.Now().Unix()+86400, 16); !errors.Is(e, errBooking) || redirected.Load() != 0 {
		t.Fatal("redirect followed")
	}
	for _, body := range []string{`{"error":"private-upstream-marker"}`, `{"error":"CAPACITY_FULL","extra":true}`, `{"error":"BOOKING_CLOCK_CHANGED"}`} {
		var count atomic.Int64
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			count.Add(1)
			w.WriteHeader(409)
			_, _ = w.Write([]byte(body))
		}))
		bad := newBookingClient(srv.URL, c.privacy, c.template, c.profile, 2*time.Second)
		_, e := bad.Book(context.Background(), booking.BookInput{})
		want := errBooking.Error()
		if strings.Contains(body, "BOOKING_CLOCK_CHANGED") {
			want = "BOOKING_CLOCK_CHANGED"
		}
		if e == nil || e.Error() != want || count.Load() != 1 {
			t.Fatal("ambiguous book retried, leaked or reclassified")
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, e = bad.Book(ctx, booking.BookInput{}); !errors.Is(e, errBooking) || count.Load() != 1 {
			t.Fatal("cancelled request caused effect")
		}
		bad.close()
		srv.Close()
	}
	if _, e = c.Catalogue(time.Now().Unix()+86400, 16); e != nil {
		t.Fatal("valid catalogue neighbour", e)
	}
}

// Catalogue has no context parameter in the existing Service interface, so its
// HTTP client deadline must enforce the configured call budget itself.
func TestBookingClientDeadline(t *testing.T) {
	entered := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { entered <- struct{}{}; <-r.Context().Done() }))
	defer server.Close()
	client := newBookingClient(server.URL, "privacy", "template", "profile", 50*time.Millisecond)
	defer client.close()
	start := time.Now()
	if _, e := client.Catalogue(time.Now().Unix()+86400, 16); !errors.Is(e, errBooking) {
		t.Fatal("unresponsive booking did not refuse")
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatal("booking call budget ignored")
	}
	select {
	case <-entered:
	default:
		t.Fatal("deadline control did not exercise server")
	}
}
