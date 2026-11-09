package booking

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	paymentchain "relux.works/swarma-chain-lab/experiments/payment-chain"
)

func contractV2Fixture(t *testing.T, coin string) (*fixture, ContractV2) {
	t.Helper()
	f := newFixture(t)
	old := f.book(t, "one").Contract
	p, e := paymentchain.ForCoin(coin)
	if e != nil {
		t.Fatal(e)
	}
	d, e := paymentchain.NewAddressDeriver(p, f.cfg.PublicBranch, f.cfg.PublicBranchSHA256)
	if e != nil {
		t.Fatal(e)
	}
	address, _, e := d.Address(0)
	if e != nil {
		t.Fatal(e)
	}
	c := ContractV2{Version: 2, BookingID: strings.Repeat(map[string]string{"btc": "1", "ltc": "2", "nmc": "3"}[coin], 64), RenterPubkey: old.RenterPubkey, RenterName: old.RenterName, AgentPubkey: old.AgentPubkey, StationName: old.StationName, NotBefore: old.NotBefore, NotAfter: old.NotAfter, Allowed: old.Allowed, Forbidden: old.Forbidden, BudgetSat: old.BudgetSat, TemplateID: old.TemplateID, TemplateSHA256: old.TemplateSHA256, ProfileID: old.ProfileID, ProfileVersion: old.ProfileVersion, ProfileSHA256: old.ProfileSHA256, Payment: paymentchain.Terms{Coin: coin, Network: p.Network, Genesis: p.Genesis, PriceUSDCents: 100, USDMicrosPerCoin: 1000000, RateAsOf: f.now, MaxRateAgeSeconds: 60, AmountAtoms: 100000000, Address: address, MinConfirmations: 2}, PaymentPolicy: old.PaymentPolicy, PrivacySHA256: old.PrivacySHA256}
	if e = c.Validate(); e != nil {
		t.Fatal(e)
	}
	return f, c
}
func signedV2Fixture(t *testing.T, f *fixture, c ContractV2) (PackageV2, Event, IssuanceRequestV2) {
	t.Helper()
	consent := ConsentV2(c, f.now)
	deterministicEvent(t, f.renter, &consent)
	pack, event, e := NewPackageV2(c, consent, f.now, f.now+1200, f.now, f.provider)
	if e != nil {
		t.Fatal(e)
	}
	pack.ProviderSignature = deterministicSign(t, f.provider, c.Hash())
	event.Content = string(canonical(pack))
	deterministicEvent(t, f.provider, &event)
	payment := paymentchain.Payment{TxID: strings.Repeat("4", 64), Vout: 0, ValueAtoms: c.Payment.AmountAtoms, Height: 101, BlockHash: strings.Repeat("5", 64)}
	request, e := NewIssuanceRequestV2(c, payment, paymentchain.Tip{Hash: strings.Repeat("6", 64), Height: 102}, event.ID)
	if e != nil {
		t.Fatal(e)
	}
	return pack, event, request
}

// Valid per-coin v2 signatures bind every payment term and the original NMC
// execution budget. Mutations cannot reuse consent, widen policy or relabel the
// request's coin; refusal produces no package. This is offline wire evidence.
func TestWireV2Binding(t *testing.T) {
	for _, coin := range []string{"btc", "ltc", "nmc"} {
		t.Run(coin, func(t *testing.T) {
			f, c := contractV2Fixture(t, coin)
			pack, event, request := signedV2Fixture(t, f, c)
			if event.Verify() != nil || pack.Validate(keyHex(f.provider), f.now, f.now+1200) != nil || request.Validate(c, event.ID) != nil {
				t.Fatal("valid v2")
			}
			if request.BudgetSat != 10000 || c.BudgetSat != 10000 {
				t.Fatal("NMC execution budget was converted")
			}
			for _, tc := range []struct {
				name   string
				edit   func(*ContractV2)
				reason string
			}{
				{"version", func(v *ContractV2) { v.Version = 1 }, "CONTRACT_IDENTITY"},
				{"network", func(v *ContractV2) { v.Payment.Network = "main" }, "PAYMENT_PROFILE"},
				{"genesis", func(v *ContractV2) { v.Payment.Genesis = strings.Repeat("a", 64) }, "PAYMENT_PROFILE"},
				{"amount", func(v *ContractV2) { v.Payment.AmountAtoms++ }, "PAYMENT_QUOTE"},
				{"stale", func(v *ContractV2) { v.Payment.RateAsOf = f.now - 61 }, "QUOTE_RATE"},
				{"future", func(v *ContractV2) { v.Payment.RateAsOf = f.now + 1 }, "QUOTE_RATE"},
				{"zero_confirmations", func(v *ContractV2) { v.Payment.MinConfirmations = 0 }, "PAYMENT_POLICY"},
				{"rebound_price", func(v *ContractV2) { v.Payment.PriceUSDCents++; v.Payment.AmountAtoms += 1000000 }, "CONSENT_BINDING"},
				{"rebound_budget", func(v *ContractV2) { v.BudgetSat++ }, "CONSENT_BINDING"},
				{"rebound_coin", func(v *ContractV2) {
					other := "btc"
					if coin == "btc" {
						other = "nmc"
					}
					p, _ := paymentchain.ForCoin(other)
					d, e := paymentchain.NewAddressDeriver(p, f.cfg.PublicBranch, f.cfg.PublicBranchSHA256)
					if e != nil {
						t.Fatal(e)
					}
					address, _, e := d.Address(0)
					if e != nil {
						t.Fatal(e)
					}
					v.Payment.Coin = other
					v.Payment.Network = p.Network
					v.Payment.Genesis = p.Genesis
					v.Payment.Address = address
				}, "CONSENT_BINDING"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					bad := c
					tc.edit(&bad)
					p, e, err := NewPackageV2(bad, pack.Consent, f.now, f.now+1200, f.now, f.provider)
					if err == nil || err.Error() != tc.reason || !reflect.DeepEqual(p, PackageV2{}) || !reflect.DeepEqual(e, Event{}) {
						t.Fatalf("want %s and zero outputs, got %v", tc.reason, err)
					}
					if _, _, err = NewPackageV2(c, pack.Consent, f.now, f.now+1200, f.now, f.provider); err != nil {
						t.Fatal("valid neighbor", err)
					}
				})
			}
			for _, field := range []string{"coin", "network", "genesis", "hash", "budget", "scope"} {
				t.Run("request_"+field, func(t *testing.T) {
					bad := request
					switch field {
					case "coin":
						bad.PaymentCoin = "unknown"
					case "network":
						bad.PaymentNetwork = "main"
					case "genesis":
						bad.PaymentGenesis = strings.Repeat("a", 64)
					case "hash":
						bad.ContractSHA256 = strings.Repeat("a", 64)
					case "budget":
						bad.BudgetSat++
					case "scope":
						bad.Scope = []string{"deliver"}
					}
					if err := bad.Validate(c, event.ID); err == nil || err.Error() != "PACKAGE_REQUEST_BINDING" {
						t.Fatal("request mutation accepted", err)
					}
					if err := request.Validate(c, event.ID); err != nil {
						t.Fatal(err)
					}
				})
			}
			bad := pack
			bad.ProviderSignature = strings.Repeat("0", 128)
			if p, e := DecodePackageV2(canonical(bad), keyHex(f.provider), f.now, f.now+1200); e == nil || e.Error() != "COUNTERSIGNATURE" || !reflect.DeepEqual(p, PackageV2{}) {
				t.Fatal("counterfeit package returned", e)
			}
			bad = pack
			bad.Consent.Sig = strings.Repeat("0", 128)
			if p, e := DecodePackageV2(canonical(bad), keyHex(f.provider), f.now, f.now+1200); e == nil || e.Error() != "EVENT_SIGNATURE" || !reflect.DeepEqual(p, PackageV2{}) {
				t.Fatal("forged consent returned", e)
			}
			// Disjoint decoders prevent interpreting a v1 fee as another coin.
			var legacy Package
			if e := Strict(canonical(pack), &legacy); e == nil {
				t.Fatal("v2 accepted as v1")
			}
			v1 := wireFixture(t)["package.json"]
			if p, e := DecodePackageV2(v1, keyHex(f.provider), f.now, f.now+1200); e == nil || e.Error() != "PACKAGE_ENCODING" || !reflect.DeepEqual(p, PackageV2{}) {
				t.Fatal("v1 accepted as v2", e)
			}
			raw := append(canonical(pack), byte('\n'))
			if _, e := DecodePackageV2(raw, keyHex(f.provider), f.now, f.now+1200); e == nil || e.Error() != "PACKAGE_ENCODING" {
				t.Fatal("noncanonical package accepted", e)
			}
			if _, e := DecodePackageV2(canonical(pack), keyHex(f.provider), f.now, f.now+1200); e != nil {
				t.Fatal("valid canonical neighbor", e)
			}
		})
	}
}

// Deterministic public wire vectors fix field order/signatures independently of
// runtime serialization changes. The fake txids are not chain payment evidence.
func TestFrozenWireV2(t *testing.T) {
	for _, coin := range []string{"btc", "ltc", "nmc"} {
		t.Run(coin, func(t *testing.T) {
			f, c := contractV2Fixture(t, coin)
			pack, event, request := signedV2Fixture(t, f, c)
			files := map[string][]byte{"contract.json": c.Bytes(), "consent.json": canonical(pack.Consent), "package.json": canonical(pack), "package-event.json": canonical(event), "issuance-request.json": canonical(request)}
			dir := filepath.Join("testdata", "wire-v2", coin)
			if root := os.Getenv("P1_FIXTURE_OUT"); root != "" {
				if !filepath.IsAbs(root) {
					t.Fatal("absolute P1_FIXTURE_OUT required")
				}
				dir = filepath.Join(root, coin)
				if e := os.MkdirAll(dir, 0755); e != nil {
					t.Fatal(e)
				}
				for name, b := range files {
					if e := os.WriteFile(filepath.Join(dir, name), b, 0644); e != nil {
						t.Fatal(e)
					}
				}
				return
			}
			for name, want := range files {
				got, e := os.ReadFile(filepath.Join(dir, name))
				if e != nil || !bytes.Equal(got, want) {
					t.Fatalf("frozen %s/%s mismatch: %v", coin, name, e)
				}
			}
			var decoded ContractV2
			if e := json.Unmarshal(files["contract.json"], &decoded); e != nil || decoded.Payment.Coin != coin {
				t.Fatal("coin wire")
			}
		})
	}
}

// The producer cannot form an issuance request from a partial/mempool payment
// or before the full confirmation threshold; exact and surplus neighbours pass.
func TestWireV2Eligibility(t *testing.T) {
	f, c := contractV2Fixture(t, "btc")
	_, event, r := signedV2Fixture(t, f, c)
	payment := paymentchain.Payment{TxID: r.PaymentTxID, Vout: r.PaymentVout, ValueAtoms: c.Payment.AmountAtoms, Height: r.PaymentHeight, BlockHash: r.PaymentBlockHash}
	tip := paymentchain.Tip{Hash: r.ObservedTipHash, Height: r.PaymentHeight + 1}
	for _, mode := range []string{"underpayment", "mempool", "threshold", "future-height"} {
		t.Run(mode, func(t *testing.T) {
			bad, head := payment, tip
			want := "PAYMENT_INELIGIBLE"
			switch mode {
			case "underpayment":
				bad.ValueAtoms--
			case "mempool":
				bad.Height = 0
				bad.BlockHash = ""
				want = "ISSUANCE_REQUEST"
			case "threshold":
				head.Height--
			case "future-height":
				bad.Height = head.Height + 1
			}
			got, e := NewIssuanceRequestV2(c, bad, head, event.ID)
			if e == nil || e.Error() != want || !reflect.DeepEqual(got, IssuanceRequestV2{}) {
				t.Fatalf("want %s zero request got %v", want, e)
			}
			for _, surplus := range []int64{0, 1} {
				valid := payment
				valid.ValueAtoms += surplus
				if _, e = NewIssuanceRequestV2(c, valid, tip, event.ID); e != nil {
					t.Fatal("valid neighbor", e)
				}
			}
		})
	}
	bad := r
	bad.Scope = nil
	if e := bad.Validate(c, event.ID); e == nil || e.Error() != "ISSUANCE_REQUEST" {
		t.Fatal("null scope accepted", e)
	}
}
