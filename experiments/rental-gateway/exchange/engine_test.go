package exchange

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
)

type backend struct {
	terms           Terms
	hold            Hold
	books, consents int
	failBook        error
}

func (b *backend) Catalogue(context.Context) (Terms, error) { return b.terms, nil }
func (b *backend) Book(_ context.Context, sender string, s Selection) (Hold, error) {
	b.books++
	if b.failBook != nil {
		return Hold{}, b.failBook
	}
	b.hold.Sender = sender
	b.hold.Coin = s.Coin
	return b.hold, nil
}
func (b *backend) Consent(_ context.Context, id string, raw []byte) (Hold, error) {
	b.consents++
	ev, e := nostr.ParseEvent(raw)
	if e != nil || id != b.hold.BookingID || ev.PubKey != b.hold.Sender || !ev.CheckID() || nostr.VerifySignature(ev) != nil {
		return Hold{}, ErrRejected
	}
	if len(ev.Tags) != 1 || len(ev.Tags[0]) != 2 || ev.Tags[0][0] != "contract" || ev.Tags[0][1] != b.hold.ContractSHA256 {
		return Hold{}, ErrRejected
	}
	b.hold.ConsentID = ev.ID
	return b.hold, nil
}
func (b *backend) Status(context.Context, string) (Hold, error) { return b.hold, nil }

type source struct {
	issued *Issued
	err    error
}

func (s *source) Lookup(context.Context, Hold) (*Issued, error) { return s.issued, s.err }

type publisher struct {
	events []*nostr.Event
	fail   bool
}

func (p *publisher) Publish(_ context.Context, v *nostr.Event) error {
	if p.fail {
		return errors.New("offline")
	}
	p.events = append(p.events, v)
	return nil
}

type fixture struct {
	e                   *Engine
	c                   Config
	b                   *backend
	source              *source
	p                   *publisher
	agent, renter       *nostr.PrivKey
	now                 int64
	seq                 int
	registeredContract  []byte
	registered, checked int
	live                bool
	dir                 string
}

func fixtureNew(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{now: 500, live: true, dir: t.TempDir()}
	if err := os.Chmod(f.dir, 0700); err != nil {
		t.Fatal(err)
	}
	f.agent, _ = nostr.GeneratePrivKey()
	f.renter, _ = nostr.GeneratePrivKey()
	f.b = &backend{terms: Terms{AgentName: "id/agent", LandlordName: "id/landlord", PrivacyNotice: "notice", PrivacySHA256: hash([]byte("notice")), Templates: []Template{{ID: "demo", SHA256: hash([]byte("template")), ProfileID: "profile", ProfileVersion: "1", ProfileSHA256: hash([]byte("profile")), PriceUSDCents: 100, SlotLengths: []int64{300}}}, Slots: []Slot{{ID: "one", TemplateID: "demo", NotBefore: 600, NotAfter: 900, Coins: []Coin{NMC}}}}}
	raw := []byte(`{"opaque":"contract"}`)
	f.b.hold = Hold{BookingID: hash([]byte("booking")), ContractSHA256: hash(raw), Sender: f.renter.PubKeyHex(), AgentName: "id/agent", LandlordName: "id/landlord", StationName: "id/agent", NotBefore: 600, NotAfter: 900, Expires: 700, Coin: NMC, Address: "test-address", AmountAtomic: 10000, Contract: raw}
	f.source = &source{}
	f.p = &publisher{}
	f.c = DefaultConfig()
	f.c.StateDir = f.dir
	f.c.AgentName = "id/agent"
	f.c.LandlordName = "id/landlord"
	f.c.Backend = f.b
	f.c.Grants = f.source
	f.c.Now = func() time.Time { return time.Unix(f.now, 0) }
	f.c.PowBits = 4
	f.c.Burst = 16
	f.c.MaxReplay = 32
	f.c.PollInterval = time.Minute
	f.open(t)
	t.Cleanup(func() { f.e.Close() })
	return f
}
func (f *fixture) open(t *testing.T) {
	t.Helper()
	e, err := New(f.c)
	if err != nil {
		t.Fatal(err)
	}
	f.e = e
	err = e.Bind(f.agent, f.p, Hooks{Register: func(_ context.Context, i Issued) error { f.registered++; f.registeredContract = i.Contract; return nil }, Check: func(_ context.Context, _ Hold, now int64) (bool, error) {
		f.checked++
		if now != f.now {
			t.Error("fabricated clock")
		}
		return f.live, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	// Stop only the scheduler; the real bound engine, disk and methods are tested
	// synchronously below. Gateway/relay and Core suites exercise its live worker.
	e.cancel()
	<-e.done
}
func (f *fixture) rumor(content string, pow bool) *nostr.Event {
	f.seq++
	r := &nostr.Event{PubKey: f.renter.PubKeyHex(), CreatedAt: f.now, Kind: 14, Tags: [][]string{{"p", f.agent.PubKeyHex()}, {"x", strconv.Itoa(f.seq)}}, Content: content}
	r.ID = r.ComputeID()
	if pow {
		r.Tags = append(r.Tags, []string{"nonce", "0", strconv.Itoa(f.c.PowBits)})
		for n := 0; ; n++ {
			r.Tags[2][1] = strconv.Itoa(n)
			r.ID = r.ComputeID()
			if CheckWork(r, f.c.PowBits) {
				break
			}
		}
	}
	return r
}
func (f *fixture) send(content string) { f.e.process(context.Background(), f.rumor(content, true)) }
func (f *fixture) last(t *testing.T) string {
	t.Helper()
	if len(f.p.events) == 0 {
		t.Fatal("missing response")
	}
	u, e := nostr.UnwrapDM(f.p.events[len(f.p.events)-1], f.renter)
	if e != nil || u.SenderHex != f.agent.PubKeyHex() {
		t.Fatal("response signing", e)
	}
	return u.Rumor.Content
}
func (f *fixture) consent(t *testing.T, edit func(*nostr.Event)) string {
	t.Helper()
	ev := &nostr.Event{CreatedAt: f.now, Kind: 8181, Tags: [][]string{{"contract", f.b.hold.ContractSHA256}}, Content: ""}
	if edit != nil {
		edit(ev)
	}
	if e := f.renter.SignEvent(ev); e != nil {
		t.Fatal(e)
	}
	return "consent " + string(canonical(ev))
}
func (f *fixture) held(t *testing.T) {
	f.send("terms")
	if !strings.HasPrefix(f.last(t), "terms\n") {
		t.Fatal("terms")
	}
	f.send("book demo one nmc")
	if !strings.HasPrefix(f.last(t), "contract\n") {
		t.Fatal("book", f.last(t))
	}
}
func (f *fixture) paid(t *testing.T) {
	f.held(t)
	f.send(f.consent(t, nil))
	if !strings.HasPrefix(f.last(t), "pay\n") {
		t.Fatal("consent", f.last(t))
	}
	f.b.hold.Issuable = true
	h := f.b.hold
	f.source.issued = &Issued{BookingID: h.BookingID, ContractSHA256: h.ContractSHA256, Sender: h.Sender, AgentName: h.AgentName, LandlordName: h.LandlordName, StationName: h.StationName, GrantID: hash([]byte("grant")), NotBefore: h.NotBefore, NotAfter: h.NotAfter, Presentation: []byte(`{"fixture":true}`)}
}

// Synthetic backend controls prove deterministic engine transitions only; the
// genuine booking/issuer/kernel and station effects are covered by Core e2e.
func TestExchangeTransitions(t *testing.T) {
	f := fixtureNew(t)
	f.paid(t)
	f.e.poll(context.Background())
	if !strings.HasPrefix(f.last(t), "issued\n") || f.registered != 1 || f.checked != 0 {
		t.Fatal("issued before window")
	}
	f.send("hello")
	if f.last(t) != NotYet {
		t.Fatal("pre-window notice")
	}
	f.now = 600
	f.e.poll(context.Background())
	if f.last(t) != "ready" || f.checked != 1 {
		t.Fatal("ready not checked")
	}
	n := len(f.p.events)
	f.e.poll(context.Background())
	if len(f.p.events) != n || f.checked != 1 {
		t.Fatal("duplicate ready")
	}
}

// Malformed/out-of-order input gets the single help text and no booking/consent
// effect. Every row then completes a valid terms/book/consent neighbor.
func TestExchangeCommandRefusals(t *testing.T) {
	for _, input := range []string{"", "hello", "TERMS", " terms", "terms ", "book demo one", "book demo one nmc", "book demo", "book demo one NMC", "book demo one eth", "book  demo one", "book demo one nmc extra", "consent {}"} {
		t.Run(strconv.Quote(input), func(t *testing.T) {
			f := fixtureNew(t)
			f.send(input)
			if f.last(t) != Help || f.b.books != 0 || f.b.consents != 0 {
				t.Fatal("command escaped deterministic refusal")
			}
			f.held(t)
			f.send(f.consent(t, nil))
			if f.b.books != 1 || f.b.consents != 1 || !strings.HasPrefix(f.last(t), "pay\n") {
				t.Fatal("valid neighbor refused")
			}
		})
	}
}

// Known senders still cannot consent for another key/contract, use invalid
// signatures, reserve an unsupported coin or advance an expired hold.
func TestExchangeBindingRefusals(t *testing.T) {
	for _, mode := range []string{"foreign_key", "foreign_contract", "bad_signature", "duplicate_booking", "unsupported_coin", "expired_hold"} {
		t.Run(mode, func(t *testing.T) {
			f := fixtureNew(t)
			f.held(t)
			command := f.consent(t, nil)
			switch mode {
			case "foreign_key":
				other, _ := nostr.GeneratePrivKey()
				ev := &nostr.Event{CreatedAt: f.now, Kind: 8181, Tags: [][]string{{"contract", f.b.hold.ContractSHA256}}}
				_ = other.SignEvent(ev)
				command = "consent " + string(canonical(ev))
			case "foreign_contract":
				command = f.consent(t, func(e *nostr.Event) { e.Tags[0][1] = hash([]byte("wrong")) })
			case "bad_signature":
				raw := []byte(strings.TrimPrefix(command, "consent "))
				ev, _ := nostr.ParseEvent(raw)
				ev.Sig = strings.Repeat("0", 128)
				command = "consent " + string(canonical(ev))
			case "duplicate_booking":
				command = "book demo one nmc"
			case "unsupported_coin":
				command = "book demo one btc"
			case "expired_hold":
				f.send(command)
				if !strings.HasPrefix(f.last(t), "pay\n") {
					t.Fatal("valid consent before expiry")
				}
				f.now = 700
			}
			before := f.b.books
			f.send(command)
			if f.last(t) != Help || f.b.books != before || f.e.disk.clients[f.renter.PubKeyHex()].Phase == "issued" {
				t.Fatal("invalid transition accepted")
			}
			if mode != "expired_hold" {
				f.send(f.consent(t, nil))
				if !strings.HasPrefix(f.last(t), "pay\n") {
					t.Fatal("binding neighbor refused")
				}
			}
		})
	}
}

// NIP-13 checks both actual work and the committed target, on the rumor rather
// than the ephemeral wrapper. Rejected first contact creates no client state.
func TestExchangePoW(t *testing.T) {
	for _, mode := range []string{"missing", "low_actual", "low_target", "duplicate", "bad_nonce", "bad_id"} {
		t.Run(mode, func(t *testing.T) {
			f := fixtureNew(t)
			r := f.rumor("terms", true)
			switch mode {
			case "missing":
				r.Tags = r.Tags[:2]
			case "low_actual":
				for n := 0; ; n++ {
					r.Tags[2][1] = strconv.Itoa(n)
					r.ID = r.ComputeID()
					if r.ID[0] != '0' {
						break
					}
				}
			case "low_target":
				r.Tags[2][2] = "1"
			case "duplicate":
				r.Tags = append(r.Tags, r.Tags[2])
			case "bad_nonce":
				r.Tags[2][1] = "00"
			case "bad_id":
				r.ID = strings.Repeat("0", 64)
			}
			if mode != "bad_id" {
				// Independent four-bit hash witness: every other PoW guard is
				// satisfied, so removing one guard cannot hide behind another.
				r.ID = r.ComputeID()
				if mode != "low_actual" {
					for r.ID[0] != '0' {
						r.CreatedAt++
						r.ID = r.ComputeID()
					}
					// Keep the timestamp inside the allowed future window.
					f.now = r.CreatedAt
				}
			}
			f.e.process(context.Background(), r)
			if len(f.e.disk.clients) != 0 || len(f.p.events) != 0 {
				t.Fatal("invalid PoW allocated state or replied")
			}
			f.send("terms")
			if len(f.e.disk.clients) != 1 || !strings.HasPrefix(f.last(t), "terms\n") {
				t.Fatal("valid PoW refused")
			}
		})
	}
}

// Per-key exhaustion and replay survive a real disk reopen; another valid key
// retains capacity. Clock rollback and stale messages cause no new response.
func TestExchangeLimitsRestart(t *testing.T) {
	f := fixtureNew(t)
	f.c.Burst = 2
	f.e.Close()
	for _, n := range []string{"meta.json", "agent.json"} {
		_ = os.Remove(filepath.Join(f.dir, n))
	}
	f.open(t)
	r := f.rumor("terms", true)
	f.e.process(context.Background(), r)
	f.send("hello")
	n := len(f.p.events)
	f.send("hello again")
	if len(f.p.events) != n {
		t.Fatal("per-key bucket exceeded")
	}
	f.e.Close()
	f.open(t)
	f.send("hello after restart")
	f.e.process(context.Background(), r)
	if len(f.p.events) != n {
		t.Fatal("restart reset bucket or replay")
	}
	other, _ := nostr.GeneratePrivKey()
	old := f.renter
	f.renter = other
	f.send("terms")
	if len(f.p.events) != n+1 {
		t.Fatal("other key starved")
	}
	f.renter = old
	f.now += 10
	f.send("hello refill")
	if len(f.p.events) != n+2 {
		t.Fatal("refill refused")
	}
	n = len(f.p.events)
	f.now--
	f.send("terms")
	if len(f.p.events) != n {
		t.Fatal("clock rollback admitted")
	}
	f.now += 2
	r = f.rumor("terms", true)
	r.CreatedAt = f.now - f.c.MessageAgeSeconds - 1
	r.ID = r.ComputeID()
	f.e.process(context.Background(), r)
	if len(f.p.events) != n {
		t.Fatal("stale rumor admitted")
	}
}

// Fresh valid-work keys cannot pin all idle slots: the next honest sender gets
// terms and can book. Both memory and private client files stay bounded across
// restart. Evicted keys lose cached terms and cannot replay an old book directly.
func TestExchangeManyKeys(t *testing.T) {
	f := fixtureNew(t)
	f.e.Close()
	f.c.MaxClients = 2
	f.open(t)
	f.send("terms")
	first := f.renter
	for i := 0; i < 8; i++ {
		f.now++
		f.renter, _ = nostr.GeneratePrivKey()
		before := len(f.p.events)
		f.send("terms")
		if len(f.p.events) != before+1 || !strings.HasPrefix(f.last(t), "terms\n") {
			t.Fatal("fresh honest sender starved by idle table")
		}
		files, err := filepath.Glob(filepath.Join(f.dir, "client-*.json"))
		if err != nil || len(f.e.disk.clients) != 2 || len(files) != 2 {
			t.Fatal("client cap exceeded", err)
		}
	}
	if f.e.disk.clients[first.PubKeyHex()] != nil {
		t.Fatal("oldest idle client retained")
	}
	f.e.Close()
	f.open(t)
	if len(f.e.disk.clients) != 2 {
		t.Fatal("restart changed client bound")
	}
	f.send("book demo one nmc")
	if f.b.books != 1 || !strings.HasPrefix(f.last(t), "contract\n") {
		t.Fatal("honest booking refused")
	}
	honest := f.renter.PubKeyHex()
	f.renter = first
	f.send("book demo one nmc")
	if f.b.books != 1 || f.last(t) != Help || f.e.disk.clients[honest].Phase != "held" {
		t.Fatal("evicted key reused old terms or displaced booking")
	}
}

// No-work senders cannot cause eviction. When every record protects a booking
// or pending reply, admission refuses without writes or bucket resets. Only the
// idle neighbor is reclaimable; equal-age ties choose the lower sender key.
func TestExchangeEvictionBoundaries(t *testing.T) {
	for _, state := range []string{"book_pending", "held", "consent_pending", "consented", "issued", "ready_done", "pending"} {
		t.Run(state, func(t *testing.T) {
			f := fixtureNew(t)
			f.e.Close()
			f.c.MaxClients = 2
			f.open(t)
			f.send("terms")
			protected := f.renter.PubKeyHex()
			v := clone(f.e.disk.clients[protected])
			if state == "pending" {
				f.p.fail = true
				f.send("terms")
				f.p.fail = false
			} else {
				v.Phase = state
				if state != "book_pending" {
					h := f.b.hold
					v.Hold = &h
				}
				if err := f.e.disk.save(v); err != nil {
					t.Fatal(err)
				}
			}
			protectedBytes := canonical(f.e.disk.clients[protected])
			f.renter, _ = nostr.GeneratePrivKey()
			f.send("terms")
			idle := f.renter.PubKeyHex()
			before := canonical(f.e.disk.clients)
			f.renter, _ = nostr.GeneratePrivKey()
			f.e.process(context.Background(), f.rumor("terms", false))
			if !bytes.Equal(before, canonical(f.e.disk.clients)) {
				t.Fatal("no-work sender evicted state")
			}
			f.send("terms")
			if f.e.disk.clients[idle] != nil || !bytes.Equal(protectedBytes, canonical(f.e.disk.clients[protected])) {
				t.Fatal("protected state evicted or changed")
			}
			v = clone(f.e.disk.clients[f.renter.PubKeyHex()])
			v.Phase = "book_pending"
			if err := f.e.disk.save(v); err != nil {
				t.Fatal(err)
			}
			before = canonical(f.e.disk.clients)
			n := len(f.p.events)
			f.renter, _ = nostr.GeneratePrivKey()
			f.send("terms")
			if !bytes.Equal(before, canonical(f.e.disk.clients)) || len(f.p.events) != n || len(f.e.disk.clients) != 2 {
				t.Fatal("protected table modified")
			}
			f.e.Close()
			f.open(t)
			if !bytes.Equal(before, canonical(f.e.disk.clients)) {
				t.Fatal("protected records changed on restart")
			}
		})
	}
	t.Run("tie", func(t *testing.T) {
		f := fixtureNew(t)
		f.e.Close()
		f.c.MaxClients = 2
		f.open(t)
		f.send("terms")
		a := f.renter.PubKeyHex()
		f.renter, _ = nostr.GeneratePrivKey()
		f.send("terms")
		b := f.renter.PubKeyHex()
		if a > b {
			a, b = b, a
		}
		f.renter, _ = nostr.GeneratePrivKey()
		f.send("terms")
		if f.e.disk.clients[a] != nil || f.e.disk.clients[b] == nil {
			t.Fatal("eviction tie not deterministic")
		}
	})
}

// A failed victim deletion poisons/refuses admission without allocating the
// replacement or publishing a reply. Fault injection touches only this fixture.
func TestExchangeEvictionDiskFailure(t *testing.T) {
	f := fixtureNew(t)
	f.e.Close()
	f.c.MaxClients = 1
	f.open(t)
	f.send("terms")
	victim := f.renter.PubKeyHex()
	path := filepath.Join(f.dir, "client-"+victim+".json")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "block"), []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	before := canonical(f.e.disk.clients)
	n := len(f.p.events)
	f.renter, _ = nostr.GeneratePrivKey()
	f.send("terms")
	if !f.e.disk.poisoned || !bytes.Equal(before, canonical(f.e.disk.clients)) || len(f.p.events) != n {
		t.Fatal("failed eviction admitted or changed state")
	}
}

// Pending fixed replies are persisted before publication and retry the same
// signed event; a failed publisher cannot provoke a second booking on restart.
func TestExchangeOutboxRestart(t *testing.T) {
	f := fixtureNew(t)
	f.p.fail = true
	f.send("terms")
	v := f.e.disk.clients[f.renter.PubKeyHex()]
	if v.Pending == nil {
		t.Fatal("reply not durable")
	}
	id := v.Pending.ID
	f.e.Close()
	f.open(t)
	f.p.fail = false
	f.e.poll(context.Background())
	if len(f.p.events) != 1 || f.p.events[0].ID != id {
		t.Fatal("outbox event changed on restart")
	}
	f.send("book demo one nmc")
	if f.b.books != 1 {
		t.Fatal("book neighbor")
	}
}

// Ambiguous booking errors retain a durable intent and never call Book twice;
// an explicit no-effect rejection permits a later valid retry.
func TestExchangeBookingRecovery(t *testing.T) {
	for _, ambiguous := range []bool{true, false} {
		t.Run(strconv.FormatBool(ambiguous), func(t *testing.T) {
			f := fixtureNew(t)
			f.send("terms")
			f.b.failBook = ErrRejected
			if ambiguous {
				f.b.failBook = errors.New("uncertain")
			}
			f.send("book demo one nmc")
			// The dedicated pending-text test checks the ambiguous first reply;
			// this recovery witness must reach the second Book attempt.
			if !ambiguous && f.last(t) != Unavailable {
				t.Fatal("booking failure text")
			}
			f.e.Close()
			f.open(t)
			f.b.failBook = nil
			f.send("book demo one nmc")
			if ambiguous {
				if f.b.books != 1 || f.last(t) != BookPending {
					t.Fatal("uncertain booking repeated")
				}
			} else if f.b.books != 2 || !strings.HasPrefix(f.last(t), "contract\n") {
				t.Fatal("safe retry refused")
			}
		})
	}
}

// Foreign issuance metadata never registers a dormant slot; a valid neighbor
// registers without checking early. A non-live start yields one fixed notice.
func TestExchangeIssuedBinding(t *testing.T) {
	for _, field := range []string{"sender", "contract", "agent", "landlord", "window", "id", "bytes"} {
		t.Run(field, func(t *testing.T) {
			f := fixtureNew(t)
			f.paid(t)
			good := *f.source.issued
			switch field {
			case "sender":
				f.source.issued.Sender = strings.Repeat("1", 64)
			case "contract":
				f.source.issued.ContractSHA256 = hash([]byte("wrong"))
			case "agent":
				f.source.issued.AgentName = "id/wrong"
			case "landlord":
				f.source.issued.LandlordName = "id/wrong"
			case "window":
				f.source.issued.NotAfter++
			case "id":
				f.source.issued.GrantID = "bad"
			case "bytes":
				f.source.issued.Presentation = make([]byte, 16385)
			}
			f.e.poll(context.Background())
			if f.registered != 0 {
				t.Fatal("foreign issuance registered")
			}
			f.source.issued = &good
			f.e.poll(context.Background())
			if f.registered != 1 || f.checked != 0 {
				t.Fatal("valid issued neighbor refused")
			}
			f.now = 600
			f.live = false
			f.e.poll(context.Background())
			if f.last(t) != NotLive || f.checked != 1 {
				t.Fatal("non-live grant ready")
			}
			n := len(f.p.events)
			f.e.poll(context.Background())
			if len(f.p.events) != n {
				t.Fatal("failure notice repeated")
			}
		})
	}
}

// State corruption/permissions/config changes fail closed instead of clearing
// counters or holds. A correctly reopened original state remains usable.
func TestExchangeStateRefusals(t *testing.T) {
	for _, mode := range []string{"corrupt", "permissions", "config"} {
		t.Run(mode, func(t *testing.T) {
			f := fixtureNew(t)
			f.send("terms")
			f.e.Close()
			path := filepath.Join(f.dir, "client-"+f.renter.PubKeyHex()+".json")
			raw, _ := os.ReadFile(path)
			c := f.c
			switch mode {
			case "corrupt":
				_ = os.WriteFile(path, []byte(`{}`), 0600)
			case "permissions":
				_ = os.Chmod(path, 0644)
			case "config":
				c.PowBits++
			}
			bad, e := New(c)
			if e == nil {
				bad.Close()
				t.Fatal("invalid state accepted")
			}
			_ = os.Chmod(path, 0600)
			_ = os.WriteFile(path, raw, 0600)
			f.open(t)
			f.send("hello")
			if f.last(t) != Help {
				t.Fatal("restored state refused")
			}
		})
	}
}

// Wire responses are fixed schemas and preserve opaque canonical contract bytes.
func TestExchangeResponseBytes(t *testing.T) {
	f := fixtureNew(t)
	f.held(t)
	body := strings.TrimPrefix(f.last(t), "contract\n")
	var p struct {
		BookingID, ContractSHA256 string
		Contract                  []byte `json:"contract_base64"`
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal([]byte(body), &raw) != nil || len(raw) != 4 {
		t.Fatal("contract response schema")
	}
	if json.Unmarshal([]byte(body), &p) != nil || !bytes.Equal(p.Contract, f.b.hold.Contract) {
		t.Fatal("opaque bytes changed")
	}
}

// An accepted rumor cannot spend a second token or create another fixed reply,
// before or after restart, even with spare capacity; a new rumor still works.
func TestExchangeReplayWithCapacity(t *testing.T) {
	f := fixtureNew(t)
	r := f.rumor("terms", true)
	f.e.process(context.Background(), r)
	f.send("intervening accepted rumor")
	tokens := f.e.disk.clients[f.renter.PubKeyHex()].Tokens
	n := len(f.p.events)
	for i := 0; i < 2; i++ {
		f.e.process(context.Background(), r)
		if len(f.p.events) != n || f.e.disk.clients[f.renter.PubKeyHex()].Tokens != tokens {
			t.Fatal("replay repeated response or debit")
		}
		f.e.Close()
		f.open(t)
	}
	f.send("new command")
	if f.last(t) != Help || len(f.p.events) != n+1 {
		t.Fatal("new rumor neighbour refused")
	}
}

// Expired first-contact knowledge requires new inner-rumor work even while
// the old entry is still persisted. A fresh valid-work message is accepted.
func TestExchangeKnownExpiry(t *testing.T) {
	f := fixtureNew(t)
	f.held(t)
	f.now = 1101
	n := len(f.p.events)
	r := f.rumor("terms", false)
	f.e.process(context.Background(), r)
	if len(f.p.events) != n {
		t.Fatal("expired known key bypassed work")
	}
	f.send("terms")
	if len(f.p.events) != n+1 {
		t.Fatal("renewed work refused")
	}
}

// Persisted replies are recipient-bound, and another agent key cannot reopen
// the outbox. Restoring the original reply/key permits the exact pending event.
func TestExchangeOutboxIdentity(t *testing.T) {
	f := fixtureNew(t)
	f.p.fail = true
	f.send("terms")
	v := clone(f.e.disk.clients[f.renter.PubKeyHex()])
	original := v.Pending
	other, _ := nostr.GeneratePrivKey()
	wrong, _, err := nostr.WrapDM(f.agent, other.PubKeyHex(), Help, nil, f.now)
	if err != nil {
		t.Fatal(err)
	}
	v.Pending = wrong
	if f.e.disk.valid(v) {
		t.Fatal("foreign outbox recipient accepted")
	}
	v.Pending = original
	if !f.e.disk.valid(v) {
		t.Fatal("valid outbox recipient refused")
	}
	f.e.Close()
	e, err := New(f.c)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Bind(other, f.p, Hooks{Register: func(context.Context, Issued) error { return nil }, Check: func(context.Context, Hold, int64) (bool, error) { return false, nil }}); err == nil {
		e.Close()
		t.Fatal("foreign messaging key accepted")
	}
	e.Close()
	f.open(t)
}

// Ordinary expiry still reclaims idle records once replay and bucket horizons
// pass, independently of the new capacity-pressure eviction policy.
func TestExchangeIdlePrune(t *testing.T) {
	f := fixtureNew(t)
	f.send("terms")
	f.now = 1200
	if err := f.e.disk.prune(f.now); err != nil || len(f.e.disk.clients) != 0 {
		t.Fatal("idle expiry not reclaimed", err)
	}
}

// An evicted sender has no global replay tombstone. An exact old rumor without
// first-contact work refuses; an old valid-work rumor may re-enter while still
// fresh, but an old book cannot reuse erased terms or cause a booking effect.
func TestExchangeEvictedReplay(t *testing.T) {
	f := fixtureNew(t)
	f.e.Close()
	f.c.MaxClients = 1
	f.open(t)
	original := f.renter
	oldBook := f.rumor("book demo one nmc", true)
	f.e.process(context.Background(), oldBook)
	if f.last(t) != Help || f.b.books != 0 {
		t.Fatal("book without terms")
	}
	oldTerms := f.rumor("terms", true)
	f.e.process(context.Background(), oldTerms)
	oldNoWork := f.rumor("book missing slot", false)
	f.e.process(context.Background(), oldNoWork)
	if f.last(t) != Help || f.b.books != 0 {
		t.Fatal("invalid known-key neighbor")
	}
	f.now++
	f.renter, _ = nostr.GeneratePrivKey()
	f.send("terms")
	before := canonical(f.e.disk.clients)
	n := len(f.p.events)
	f.renter = original
	f.e.process(context.Background(), oldNoWork)
	if !bytes.Equal(before, canonical(f.e.disk.clients)) || len(f.p.events) != n {
		t.Fatal("evicted replay bypassed first-contact work")
	}
	f.e.process(context.Background(), oldBook)
	if f.last(t) != Help || f.b.books != 0 || f.e.disk.clients[original.PubKeyHex()].TermsPin != "" {
		t.Fatal("evicted replay recreated booking authority")
	}
	n = len(f.p.events)
	f.e.process(context.Background(), oldBook)
	if len(f.p.events) != n || f.b.books != 0 {
		t.Fatal("readmitted replay escaped retained journal")
	}
	f.e.process(context.Background(), oldTerms)
	if !strings.HasPrefix(f.last(t), "terms\n") || f.b.books != 0 {
		t.Fatal("valid-work replay was not a harmless terms response")
	}
	f.send("book demo one nmc")
	if f.b.books != 1 || !strings.HasPrefix(f.last(t), "contract\n") {
		t.Fatal("fresh terms booking neighbor refused")
	}
}

// Ambiguous bookings return one fixed reconciliation message, including after
// restart and for attacker-chosen commands. Terms stays available, and no input
// echoes or repeated Book calls occur. A failed publish retries the exact wrap.
func TestExchangePendingText(t *testing.T) {
	const expected = "Booking pending reconciliation. Wait or retry terms; do not repeat the booking."
	for _, input := range []string{"book demo one nmc", "book attacker-private-marker slot", "consent attacker-private-marker", "attacker-private-marker"} {
		t.Run(input, func(t *testing.T) {
			f := fixtureNew(t)
			f.send("terms")
			f.b.failBook = errors.New("backend-private-marker")
			f.send("book demo one nmc")
			if f.last(t) != expected {
				t.Fatal("pending text mismatch", f.last(t))
			}
			f.e.Close()
			f.open(t)
			f.b.failBook = nil
			f.send(input)
			if f.last(t) != expected || f.b.books != 1 || f.e.disk.clients[f.renter.PubKeyHex()].Phase != "book_pending" {
				t.Fatal("pending text mismatch or booking repeated", f.last(t))
			}
			f.send("terms")
			if !strings.HasPrefix(f.last(t), "terms\n") || f.b.books != 1 {
				t.Fatal("pending terms unavailable")
			}
			f.p.fail = true
			f.send(input)
			saved := f.e.disk.clients[f.renter.PubKeyHex()].Pending
			if saved == nil {
				t.Fatal("missing durable pending reply")
			}
			f.e.Close()
			f.open(t)
			f.p.fail = false
			f.e.poll(context.Background())
			if f.last(t) != expected || f.p.events[len(f.p.events)-1].ID != saved.ID || f.b.books != 1 {
				t.Fatal("pending reply changed on restart")
			}
		})
	}
}

// Even after valid terms, omitted coin is not guessed. An unoffered coin gets
// fixed text without calling Book; the explicit offered coin remains usable.
func TestExplicitCoinSelection(t *testing.T) {
	f := fixtureNew(t)
	f.send("terms")
	f.send("book demo one")
	if f.last(t) != Help || f.b.books != 0 {
		t.Fatal("implicit coin accepted")
	}
	f.send("book demo one btc")
	if f.last(t) != CoinNotOffered || f.b.books != 0 {
		t.Fatalf("unoffered coin effect/text: %q books=%d", f.last(t), f.b.books)
	}
	f.send("book demo one nmc")
	if !strings.HasPrefix(f.last(t), "contract\n") || f.b.books != 1 {
		t.Fatal("explicit coin neighbor")
	}
}

// A configured coin later refused by the service gets the same fixed text;
// definitive no-effect rejection clears pending state and permits a valid retry.
func TestServiceCoinRefusalText(t *testing.T) {
	f := fixtureNew(t)
	f.send("terms")
	f.b.failBook = errors.Join(ErrRejected, ErrCoinNotOffered)
	f.send("book demo one nmc")
	if f.last(t) != CoinNotOffered || f.e.disk.clients[f.renter.PubKeyHex()].Phase != "" {
		t.Fatal("service coin refusal text/state")
	}
	f.b.failBook = nil
	f.send("book demo one nmc")
	if !strings.HasPrefix(f.last(t), "contract\n") {
		t.Fatal("coin retry neighbor")
	}
}

// Actual encrypted pay replies preserve the backend minimum (legacy one and
// V2 two), without converting that display into payment/issuance authority.
// This fixture checks serialization; adapter tests establish the source value.
func TestPayConfirmationDisplay(t *testing.T) {
	for _, minimum := range []int64{1, 2} {
		t.Run(strconv.FormatInt(minimum, 10), func(t *testing.T) {
			f := fixtureNew(t)
			f.b.hold.MinConfirmations = minimum
			f.held(t)
			f.send(f.consent(t, nil))
			text := f.last(t)
			var payment struct {
				MinConfirmations int64 `json:"min_confirmations"`
			}
			if !strings.HasPrefix(text, "pay\n") || json.Unmarshal([]byte(strings.TrimPrefix(text, "pay\n")), &payment) != nil || payment.MinConfirmations != minimum {
				t.Fatal("pay confirmation display")
			}
			if f.b.hold.Issuable || f.registered != 0 {
				t.Fatal("pay display authorized issuance")
			}
		})
	}
}

// Fresh status contract bytes must match the consent-bound hash before
// registration. The grant source cannot substitute its own bytes; the hook
// receives an owned copy of the validated booking contract.
func TestIssuedContractHandoff(t *testing.T) {
	for _, bad := range [][]byte{nil, []byte("changed"), make([]byte, 8193)} {
		t.Run(fmt.Sprintf("size-%d", len(bad)), func(t *testing.T) {
			f := fixtureNew(t)
			f.paid(t)
			good := append([]byte(nil), f.b.hold.Contract...)
			f.b.hold.Contract = bad
			f.e.poll(context.Background())
			if f.registered != 0 {
				t.Fatal("invalid status contract registered")
			}
			f.b.hold.Contract = append([]byte(nil), good...)
			f.source.issued.Contract = []byte("untrusted source copy")
			f.e.poll(context.Background())
			if f.registered != 1 || !bytes.Equal(f.registeredContract, good) {
				t.Fatal("validated contract not handed off")
			}
			f.b.hold.Contract[0] ^= 1
			if !bytes.Equal(f.registeredContract, good) {
				t.Fatal("registration shares mutable contract bytes")
			}
		})
	}
}
