package bookingbind_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"encoding/hex"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	booking "relux.works/swarma-chain-lab/experiments/rental-booking"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/exchange"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/kernelbind/bookingbind"
	su "relux.works/swarma-chain-lab/experiments/single-use"
)

func raw(v any) []byte {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if e.Encode(v) != nil {
		panic("json fixture")
	}
	return bytes.TrimSuffix(b.Bytes(), []byte{'\n'})
}
func key(n byte) *btcec.PrivateKey {
	b := make([]byte, 32)
	b[31] = n
	k, _ := btcec.PrivKeyFromBytes(b)
	return k
}
func pub(k *btcec.PrivateKey) string { return hex.EncodeToString(schnorr.SerializePubKey(k.PubKey())) }

type node struct{}

func (node) Call(_ context.Context, method string, args ...any) (json.RawMessage, error) {
	switch method {
	case "getblockchaininfo":
		return raw(map[string]any{"chain": "regtest", "blocks": 100, "headers": 100, "bestblockhash": strings.Repeat("a", 64), "initialblockdownload": false}), nil
	case "getblockhash":
		return raw(su.RegtestGenesis), nil
	}
	return nil, errors.New("unexpected RPC")
}

type relay struct{ calls int }

func (r *relay) Publish(_ context.Context, e booking.Event) error {
	if err := e.Verify(); err != nil {
		return err
	}
	r.calls++
	return nil
}

type fixture struct {
	a      *bookingbind.Adapter
	s      *booking.Service
	r      *relay
	now    int64
	renter *btcec.PrivateKey
}

func setup(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{now: 500, renter: key(3), r: &relay{}}
	profile := []byte("public fixture profile\n")
	master, err := hdkeychain.NewMaster(bytes.Repeat([]byte{7}, 32), &chaincfg.RegressionNetParams)
	if err != nil {
		t.Fatal(err)
	}
	branch, err := master.Neuter()
	if err != nil {
		t.Fatal(err)
	}
	template := booking.Template{Version: 1, ID: "demo", ProfileID: "lab", ProfileVersion: "1", ProfileSHA256: booking.Hash(profile), Allowed: []string{"deliver", "pay"}, Forbidden: []string{"publish", "repository.push", "secret.release"}, BudgetSat: 1000}
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	cfg := booking.Config{StateDir: dir, PublicBranch: branch.String(), PublicBranchSHA256: booking.Hash([]byte(branch.String())), AgentPubkey: pub(key(4)), ProviderPubkey: pub(key(2)), HoldSeconds: 1200, PriceUSDCents: 100, USDMicrosPerNMC: 100000000, RateAsOf: 500, MaxRateAge: 7200, Template: template, TemplateSHA256: booking.Hash(raw(template)), Slots: []booking.Slot{{ID: "one", StationName: "id/agent", NotBefore: 600, NotAfter: 1000, PaymentPolicy: "advance"}}, Limits: booking.Limits{MaxBlocks: 512, MaxMempool: 2000, MaxCalls: 10000, MaxBytes: 64 << 20}}
	clock := func() time.Time { return time.Unix(f.now, 0) }
	f.s, err = booking.NewService(cfg, profile, key(2), node{}, f.r, clock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.s.Close)
	f.a = &bookingbind.Adapter{Service: f.s, AgentName: "id/agent", LandlordName: "id/landlord", AgentPubkey: cfg.AgentPubkey, Now: clock}
	return f
}
func (f *fixture) book(t *testing.T) exchange.Hold {
	t.Helper()
	h, e := f.a.Book(context.Background(), pub(f.renter), exchange.Selection{Template: "demo", Slot: "one", Coin: exchange.NMC})
	if e != nil {
		t.Fatal(e)
	}
	return h
}
func (f *fixture) consent(t *testing.T, h exchange.Hold) booking.Event {
	t.Helper()
	var c booking.Contract
	if booking.Strict(h.Contract, &c) != nil {
		t.Fatal("contract")
	}
	v := booking.Consent(c, f.now)
	if e := v.Sign(f.renter); e != nil {
		t.Fatal(e)
	}
	return v
}

// Real booking state proves v1 adapter refusals perform no address allocation;
// the nearby NMC booking returns the service's exact opaque canonical contract.
func TestAdapterSelectionAndOpaqueContract(t *testing.T) {
	for _, s := range []exchange.Selection{{Template: "demo", Slot: "one", Coin: exchange.BTC}, {Template: "demo", Slot: "one", Coin: exchange.LTC}, {Template: "demo", Slot: "one", Coin: "NMC"}, {Template: "wrong", Slot: "one", Coin: exchange.NMC}, {Template: "demo", Slot: "missing", Coin: exchange.NMC}} {
		t.Run(string(s.Coin)+s.Template+s.Slot, func(t *testing.T) {
			f := setup(t)
			_, e := f.a.Book(context.Background(), pub(f.renter), s)
			if !errors.Is(e, exchange.ErrRejected) {
				t.Fatalf("route accepted: %v", e)
			}
			h := f.book(t)
			b, e := f.s.Get(h.BookingID)
			if e != nil || b.AddressIndex != 0 || !bytes.Equal(h.Contract, b.Contract.Bytes()) || h.ContractSHA256 != b.Contract.Hash() {
				t.Fatal("refused route allocated or changed exact contract")
			}
			terms, e := f.a.Catalogue(context.Background())
			if e != nil || len(terms.Slots) != 0 {
				t.Fatal("held capacity advertised")
			}
		})
	}
}

// The adapter repeats the booking consent checks and preserves exact wire.
// Each rejected signature/key/contract/window/canonical form leaves Package nil
// and emits no provider publication, followed by an accepted valid consent.
func TestAdapterConsentRefusals(t *testing.T) {
	for _, name := range []string{"foreign_key", "wrong_contract", "wrong_kind", "bad_signature", "whitespace", "unknown_field", "expired"} {
		t.Run(name, func(t *testing.T) {
			f := setup(t)
			h := f.book(t)
			ev := f.consent(t, h)
			switch name {
			case "foreign_key":
				_ = ev.Sign(key(5))
			case "wrong_contract":
				ev.Tags[1][1] = strings.Repeat("f", 64)
				_ = ev.Sign(f.renter)
			case "wrong_kind":
				ev.Kind = 8182
				_ = ev.Sign(f.renter)
			case "bad_signature":
				ev.Sig = strings.Repeat("0", 128)
			case "expired":
				f.now = h.Expires
			}
			bad := raw(ev)
			if name == "whitespace" {
				bad = append([]byte(" "), bad...)
			}
			if name == "unknown_field" {
				bad = append(bad[:len(bad)-1], []byte(`,"extra":true}`)...)
			}
			_, e := f.a.Consent(context.Background(), h.BookingID, bad)
			if !errors.Is(e, exchange.ErrRejected) {
				t.Fatalf("invalid consent not rejected: %v", e)
			}
			b, e := f.s.Get(h.BookingID)
			if e != nil || b.Package != nil || f.r.calls != 0 {
				t.Fatal("rejected consent created provider package")
			}
			// Reset only the fixture clock for the valid neighbour; service owns time.
			f.now = 500
			valid := f.consent(t, h)
			got, e := f.a.Consent(context.Background(), h.BookingID, raw(valid))
			if e != nil || got.ConsentID != valid.ID || f.r.calls != 1 || got.Issuable {
				t.Fatalf("valid consent/payment boundary: %+v %v", got, e)
			}
			b, e = f.s.Get(h.BookingID)
			if e != nil || !bytes.Equal(raw(b.Package.Consent), raw(valid)) {
				t.Fatal("adapter rewrote consent")
			}
		})
	}
}

// Wrong provider-facing agent configuration cannot relabel a real contract;
// changing it back admits the same service metadata without any new booking.
func TestAdapterContractIdentity(t *testing.T) {
	f := setup(t)
	h := f.book(t)
	f.a.AgentPubkey = pub(key(7))
	if _, e := f.a.Status(context.Background(), h.BookingID); e == nil {
		t.Fatal("wrong agent key relabelled contract")
	}
	f.a.AgentPubkey = pub(key(4))
	if got, e := f.a.Status(context.Background(), h.BookingID); e != nil || got.ContractSHA256 != h.ContractSHA256 {
		t.Fatal("valid identity neighbour")
	}
}
