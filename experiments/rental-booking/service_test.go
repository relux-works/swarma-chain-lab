package booking

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	singleuse "relux.works/swarma-chain-lab/experiments/single-use"
)

type staticNode struct{ fail bool }

func (n *staticNode) Call(_ context.Context, method string, args ...any) (json.RawMessage, error) {
	if n.fail {
		return nil, refuse("offline")
	}
	switch method {
	case "getblockchaininfo":
		return canonical(map[string]any{"chain": "regtest", "blocks": 100, "headers": 100, "bestblockhash": strings.Repeat("a", 64), "initialblockdownload": false}), nil
	case "getblockhash":
		return canonical(singleuse.RegtestGenesis), nil
	case "getrawmempool":
		return []byte("[]"), nil
	}
	return nil, refuse("unexpected method")
}

type memoryRelay struct {
	events []Event
	fail   bool
}

func (r *memoryRelay) Publish(_ context.Context, e Event) error {
	if r.fail {
		return refuse("offline")
	}
	if err := e.Verify(); err != nil {
		return err
	}
	r.events = append(r.events, e)
	return nil
}

type fixture struct {
	s                *Service
	cfg              Config
	profile          []byte
	provider, renter *btcec.PrivateKey
	node             *staticNode
	relay            *memoryRelay
	now              int64
}

func testKey(v byte) *btcec.PrivateKey {
	b := make([]byte, 32)
	b[31] = v
	k, _ := btcec.PrivKeyFromBytes(b)
	return k
}
func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{profile: []byte("public test profile\n"), provider: testKey(2), renter: testKey(3), node: &staticNode{}, relay: &memoryRelay{}, now: 2000000000}
	template := Template{1, "demo", "curator-test", "1.0.0", Hash(f.profile), []string{"deliver", "pay"}, []string{"publish", "repository.push", "secret.release"}, 10000}
	branch := fixtureBranch(t)
	f.cfg = Config{StateDir: privateDir(t), PublicBranch: branch, PublicBranchSHA256: Hash([]byte(branch)), AgentPubkey: keyHex(testKey(4)), ProviderPubkey: keyHex(f.provider), HoldSeconds: 1200, PriceUSDCents: 100, USDMicrosPerNMC: 1000000, RateAsOf: f.now, MaxRateAge: 7200, Template: template, TemplateSHA256: Hash(canonical(template)), Slots: []Slot{{"one", "id/station-one", f.now + 3600, f.now + 7200, "advance"}, {"two", "id/station-two", f.now + 3600, f.now + 7200, "advance"}}, Limits: Limits{512, 2000, 10000, 64 << 20}}
	var e error
	f.s, e = NewService(f.cfg, f.profile, f.provider, f.node, f.relay, func() time.Time { return time.Unix(f.now, 0) })
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { f.s.Close() })
	return f
}
func (f *fixture) book(t *testing.T, slot string) Booking {
	t.Helper()
	b, e := f.s.Book(context.Background(), BookInput{slot, keyHex(f.renter), "", true})
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func (f *fixture) consent(t *testing.T, b Booking) Event {
	t.Helper()
	e := Consent(b.Contract, f.now)
	if err := e.Sign(f.renter); err != nil {
		t.Fatal(err)
	}
	return e
}

// Rejected requests leave the persistent address index and bookings unchanged;
// each refusal is followed by a valid booking in the same service.
func TestBookingInputRefusals(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		edit       func(*BookInput)
	}{
		{"privacy", "PRIVACY_REQUIRED", func(i *BookInput) { i.PrivacyAcknowledged = false }},
		{"key", "RENTER_KEY", func(i *BookInput) { i.RenterPubkey = strings.Repeat("0", 64) }},
		{"slot", "SLOT_UNAVAILABLE", func(i *BookInput) { i.SlotID = "missing" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			before := string(canonical(f.s.state))
			in := BookInput{"one", keyHex(f.renter), "", true}
			tc.edit(&in)
			_, e := f.s.Book(context.Background(), in)
			if e == nil || e.Error() != tc.code || string(canonical(f.s.state)) != before {
				t.Fatalf("refusal/state: %v", e)
			}
			f.book(t, "one")
		})
	}
}

// Two overlapping holds cannot reserve one station interval, including when
// requests race; another station remains available and expiry frees the slot.
func TestCapacityAndExpiry(t *testing.T) {
	f := newFixture(t)
	first := f.book(t, "one")
	before := string(canonical(f.s.state))
	if _, e := f.s.Book(context.Background(), BookInput{"one", keyHex(f.renter), "", true}); e == nil || e.Error() != "CAPACITY_FULL" || string(canonical(f.s.state)) != before {
		t.Fatalf("capacity: %v", e)
	}
	f.book(t, "two")
	f.now = first.HoldExpiresAt
	replacement := f.book(t, "one")
	if replacement.AddressIndex == first.AddressIndex || replacement.Contract.PaymentAddress == first.Contract.PaymentAddress {
		t.Fatal("address reused")
	}
}
func TestConcurrentBooking(t *testing.T) {
	f := newFixture(t)
	var wg sync.WaitGroup
	ch := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, e := f.s.Book(context.Background(), BookInput{"one", keyHex(f.renter), "", true})
			ch <- e
		}()
	}
	wg.Wait()
	close(ch)
	ok, refused := 0, 0
	for e := range ch {
		if e == nil {
			ok++
		} else if e.Error() == "CAPACITY_FULL" {
			refused++
		} else {
			t.Fatal(e)
		}
	}
	if ok != 1 || refused != 1 || len(f.s.state.Bookings) != 1 {
		t.Fatal("double booking")
	}
}

// A node outage produces neither a booking nor a partial refresh write; the
// same request succeeds after node availability returns.
func TestNodeUnavailableNoStateChange(t *testing.T) {
	f := newFixture(t)
	before := string(canonical(f.s.state))
	f.node.fail = true
	if _, e := f.s.Book(context.Background(), BookInput{"one", keyHex(f.renter), "", true}); e == nil || e.Error() != "NODE_UNAVAILABLE" {
		t.Fatalf("node: %v", e)
	}
	if e := f.s.Refresh(context.Background()); e == nil || e.Error() != "NODE_UNAVAILABLE" {
		t.Fatalf("refresh: %v", e)
	}
	if string(canonical(f.s.state)) != before {
		t.Fatal("partial state")
	}
	f.node.fail = false
	f.book(t, "one")
}

// Signature, hash, booking and time violations never store a package. The
// original consent succeeds immediately after each failed attempt.
func TestConsentRefusals(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		edit       func(*fixture, Booking, *Event)
	}{
		{"other_key", "CONSENT_KEY", func(f *fixture, b Booking, e *Event) { _ = e.Sign(testKey(5)) }},
		{"other_hash", "CONSENT_BINDING", func(f *fixture, b Booking, e *Event) { e.Tags[1][1] = strings.Repeat("0", 64); _ = e.Sign(f.renter) }},
		{"other_booking", "CONSENT_BINDING", func(f *fixture, b Booking, e *Event) { e.Tags[2][1] = strings.Repeat("1", 64); _ = e.Sign(f.renter) }},
		{"other_privacy", "CONSENT_BINDING", func(f *fixture, b Booking, e *Event) { e.Tags[3][1] = strings.Repeat("2", 64); _ = e.Sign(f.renter) }},
		{"event_id", "EVENT_ID", func(f *fixture, b Booking, e *Event) { e.ID = strings.Repeat("0", 64) }},
		{"signature", "EVENT_SIGNATURE", func(f *fixture, b Booking, e *Event) { e.Sig = strings.Repeat("0", 128) }},
		{"before_hold", "CONSENT_TIME", func(f *fixture, b Booking, e *Event) { e.CreatedAt = b.HoldCreatedAt - 1; _ = e.Sign(f.renter) }},
		{"after_hold", "CONSENT_TIME", func(f *fixture, b Booking, e *Event) { e.CreatedAt = b.HoldExpiresAt; _ = e.Sign(f.renter) }},
		{"future", "CONSENT_TIME", func(f *fixture, b Booking, e *Event) { e.CreatedAt = f.now + 1; _ = e.Sign(f.renter) }},
		{"extra_tag", "CONSENT_BINDING", func(f *fixture, b Booking, e *Event) {
			e.Tags = append(e.Tags, []string{"contract", b.Contract.Hash()})
			_ = e.Sign(f.renter)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			b := f.book(t, "one")
			bad := f.consent(t, b)
			tc.edit(f, b, &bad)
			before := string(canonical(f.s.state))
			_, e := f.s.AcceptConsent(context.Background(), b.Contract.BookingID, bad)
			if e == nil || e.Error() != tc.code || string(canonical(f.s.state)) != before || len(f.relay.events) != 0 {
				t.Fatalf("refusal/state: want %s got %v", tc.code, e)
			}
			good := f.consent(t, b)
			got, e := f.s.AcceptConsent(context.Background(), b.Contract.BookingID, good)
			if e != nil || got.Package == nil || !got.Published || len(f.relay.events) != 1 {
				t.Fatalf("valid consent: %v", e)
			}
		})
	}
}

// Cross-booking replay and contract-byte tampering fail with valid neighbouring
// packages, while a restart preserves the original public package and index.
func TestPackageReplayTamperingAndRestart(t *testing.T) {
	f := newFixture(t)
	a := f.book(t, "one")
	b := f.book(t, "two")
	event := f.consent(t, a)
	if _, e := f.s.AcceptConsent(context.Background(), b.Contract.BookingID, event); e == nil || e.Error() != "CONSENT_BINDING" {
		t.Fatalf("replay: %v", e)
	}
	signed, e := f.s.AcceptConsent(context.Background(), a.Contract.BookingID, event)
	if e != nil {
		t.Fatal(e)
	}
	raw := canonical(signed.Package)
	if _, e = DecodePackage(raw, f.cfg.ProviderPubkey, a.HoldCreatedAt, a.HoldExpiresAt); e != nil {
		t.Fatal(e)
	}
	var tampered Package
	_ = json.Unmarshal(raw, &tampered)
	tampered.Contract.BudgetSat++
	if _, e = DecodePackage(canonical(tampered), f.cfg.ProviderPubkey, a.HoldCreatedAt, a.HoldExpiresAt); e == nil || e.Error() != "CONSENT_BINDING" {
		t.Fatalf("tamper: %v", e)
	}
	f.s.Close()
	f.s, e = NewService(f.cfg, f.profile, f.provider, f.node, f.relay, func() time.Time { return time.Unix(f.now, 0) })
	if e != nil {
		t.Fatal(e)
	}
	loaded, e := f.s.Get(a.Contract.BookingID)
	if e != nil || string(canonical(loaded.Package)) != string(raw) || f.s.state.NextIndex != 2 {
		t.Fatalf("restart: %v", e)
	}
}

// Pin mismatches and malformed scope partitions fail before a state directory
// is opened; an explicit empty allowed list is accepted for chat-only slots.
func TestTemplatePinsAndScope(t *testing.T) {
	f := newFixture(t)
	for _, tc := range []struct {
		name, code string
		edit       func(*Template)
	}{
		{"profile", "TEMPLATE_PROFILE_PIN", func(t *Template) { t.ProfileSHA256 = strings.Repeat("0", 64) }},
		{"unknown", "TEMPLATE_SCOPE", func(t *Template) { t.Allowed = []string{"deliver", "pay.nmc"} }},
		{"overlap", "TEMPLATE_SCOPE", func(t *Template) { t.Forbidden = append(t.Forbidden, "pay") }},
		{"negative_budget", "TEMPLATE_SCOPE", func(t *Template) { t.BudgetSat = -1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := f.cfg.Template
			tc.edit(&v)
			e := v.Validate(f.profile, Hash(canonical(v)))
			if e == nil || e.Error() != tc.code {
				t.Fatalf("want %s got %v", tc.code, e)
			}
			if e = f.cfg.Template.Validate(f.profile, f.cfg.TemplateSHA256); e != nil {
				t.Fatal(e)
			}
		})
	}
	chat := f.cfg.Template
	chat.Allowed = []string{}
	chat.Forbidden = append([]string{}, actions...)
	if e := chat.Validate(f.profile, Hash(canonical(chat))); e != nil {
		t.Fatal(e)
	}
	if e := f.cfg.Template.Validate(f.profile, strings.Repeat("0", 64)); e == nil || e.Error() != "TEMPLATE_PROFILE_PIN" {
		t.Fatal("template pin accepted")
	}
}

// A lost relay ACK retains the same signed event for retry; no issuance is
// produced merely because consent exists, and restart does not sign anew.
func TestRelayRetryStableEvent(t *testing.T) {
	f := newFixture(t)
	b := f.book(t, "one")
	f.relay.fail = true
	if _, e := f.s.AcceptConsent(context.Background(), b.Contract.BookingID, f.consent(t, b)); e == nil || e.Error() != "RELAY_UNAVAILABLE" {
		t.Fatalf("relay: %v", e)
	}
	pending, _ := f.s.Get(b.Contract.BookingID)
	if pending.Published || pending.Issuance != nil || pending.PackageEvent == nil {
		t.Fatal("premature publication/issuance")
	}
	id := pending.PackageEvent.ID
	f.relay.fail = false
	if e := f.s.PublishPending(context.Background()); e != nil {
		t.Fatal(e)
	}
	after, _ := f.s.Get(b.Contract.BookingID)
	if !after.Published || after.PackageEvent.ID != id || after.Issuance != nil {
		t.Fatal("retry changed event")
	}
	files, _ := filepath.Glob(filepath.Join(f.cfg.StateDir, "issue-*"))
	if len(files) != 0 {
		t.Fatal("unpaid issuance")
	}
	if _, e := os.Stat(filepath.Join(f.cfg.StateDir, "package-"+b.Contract.BookingID+".json")); e != nil {
		t.Fatal(e)
	}
}

// The shared station grammar is lowercase id/<identifier>; uppercase, empty,
// nested and oversized station names are refused beside the frozen valid name.
func TestStationNameGrammar(t *testing.T) {
	if !stationName("id/station-one") {
		t.Fatal("valid station refused")
	}
	for _, name := range []string{"id/Station", "id/", "id/a/b", "d/station", "id/" + strings.Repeat("a", 158)} {
		if stationName(name) {
			t.Fatalf("invalid station accepted: %s", name)
		}
	}
}

// Package hold bounds are signed metadata and must equal the stored hold. A
// well-formed package remains valid, but changed bounds cannot pass validation.
func TestPackageHoldBinding(t *testing.T) {
	f := newFixture(t)
	b := f.book(t, "one")
	p, _, e := NewPackage(b.Contract, f.consent(t, b), b.HoldCreatedAt, b.HoldExpiresAt, f.now, f.provider)
	if e != nil {
		t.Fatal(e)
	}
	p.HoldExpiresAt++
	if e = p.Validate(f.cfg.ProviderPubkey, b.HoldCreatedAt, b.HoldExpiresAt); e == nil || e.Error() != "PACKAGE_BINDING" {
		t.Fatalf("hold tamper: %v", e)
	}
	p.HoldExpiresAt--
	if e = p.Validate(f.cfg.ProviderPubkey, b.HoldCreatedAt, b.HoldExpiresAt); e != nil {
		t.Fatal(e)
	}
}

// A forged provider countersignature is refused while the original signature
// validates; this does not rely only on the outer Nostr package event signature.
func TestProviderCountersignature(t *testing.T) {
	f := newFixture(t)
	b := f.book(t, "one")
	p, _, e := NewPackage(b.Contract, f.consent(t, b), b.HoldCreatedAt, b.HoldExpiresAt, f.now, f.provider)
	if e != nil {
		t.Fatal(e)
	}
	good := p.ProviderSignature
	p.ProviderSignature = strings.Repeat("0", 128)
	if e = p.Validate(f.cfg.ProviderPubkey, b.HoldCreatedAt, b.HoldExpiresAt); e == nil || e.Error() != "COUNTERSIGNATURE" {
		t.Fatalf("provider signature: %v", e)
	}
	p.ProviderSignature = good
	if e = p.Validate(f.cfg.ProviderPubkey, b.HoldCreatedAt, b.HoldExpiresAt); e != nil {
		t.Fatal(e)
	}
}
