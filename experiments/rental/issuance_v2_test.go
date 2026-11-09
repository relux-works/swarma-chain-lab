package rental

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	paymentchain "github.com/relux-works/swarma-chain-lab/experiments/payment-chain"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

func paymentV2Fixture(t *testing.T, coin string) (IssuerPolicyV2, IssuanceRequestV2, PackageV2, Event) {
	t.Helper()
	var r IssuanceRequestV2
	var pack PackageV2
	var pub Event
	for name, out := range map[string]any{"issuance-request.json": &r, "package.json": &pack, "package-event.json": &pub} {
		raw, e := os.ReadFile(filepath.Join("testdata", "payment-v2", coin, name))
		if e != nil {
			t.Fatal(e)
		}
		if e = su.StrictInput(raw, out); e != nil {
			t.Fatal(e)
		}
	}
	p := IssuerPolicyV2{IssuerPolicy: unitPolicy(t), PaymentPolicies: map[string]PaymentAdmissionPolicy{coin: {MaxRateAgeSeconds: 60, MinConfirmations: 1, Limits: paymentchain.Limits{MaxBlocks: 2016, MaxMempool: 10000, MaxCalls: 10000, MaxBytes: 64 << 20}}}}
	p.ProviderPubkey = pack.ProviderPubkey
	p.Policy.AgentPubkey = pack.Contract.AgentPubkey
	p.Policy.StationName = pack.Contract.StationName
	return p, r, pack, pub
}
func resignPaymentV2(t *testing.T, r *IssuanceRequestV2, pack *PackageV2, pub *Event, consent bool) {
	t.Helper()
	hash := Hash(eventBytes(pack.Contract))
	r.ContractSHA256 = hash
	if consent {
		pack.Consent.Tags = [][]string{{"t", "swarma-rental-consent-v1"}, {"contract", hash}, {"booking", pack.Contract.BookingID}, {"privacy", pack.Contract.PrivacySHA256}}
		pack.Consent = signedEvent(t, pack.Consent, 3)
	}
	pack.ProviderSignature = signature(t, hash, 2)
	pub.Tags = [][]string{{"t", "swarma-rental-package-v1"}, {"contract", hash}, {"booking", pack.Contract.BookingID}, {"e", pack.Consent.ID}}
	pub.Content = string(eventBytes(pack))
	*pub = signedEvent(t, *pub, 2)
	r.PackageEventID = pub.ID
}

// The issuer independently accepts all three frozen producer vectors, refuses
// even fully re-signed invalid payment terms, and checks its own stricter policy.
// This proves offline authentication/binding, not a real payment or live grant.
func TestPaymentV2Authentication(t *testing.T) {
	for _, coin := range []string{"btc", "ltc", "nmc"} {
		t.Run(coin, func(t *testing.T) {
			p, r, pack, pub := paymentV2Fixture(t, coin)
			now := pack.HoldCreatedAt + 10
			verify := func(r IssuanceRequestV2, pack PackageV2, pub Event, want string) {
				t.Helper()
				got, decoded, e := VerifyIssuancePackageV2(p, eventBytes(r), eventBytes(pub), now)
				if want != "" {
					if e == nil || e.Error() != want {
						t.Fatalf("want %s got %v", want, e)
					}
				} else if e != nil || got.ContractSHA256 != r.ContractSHA256 || decoded.Contract.Payment.Coin != coin {
					t.Fatalf("valid vector: %v", e)
				}
			}
			verify(r, pack, pub, "")
			for _, tc := range []struct {
				name   string
				edit   func(*PackageV2)
				reason string
			}{
				{"wrong_profile", func(v *PackageV2) { v.Contract.Payment.Genesis = strings.Repeat("a", 64) }, "PAYMENT_PROFILE"},
				{"bad_quote", func(v *PackageV2) { v.Contract.Payment.AmountAtoms++ }, "PAYMENT_QUOTE"},
				{"stale_rate", func(v *PackageV2) { v.Contract.Payment.RateAsOf -= 61 }, "QUOTE_RATE"},
				{"future_rate", func(v *PackageV2) { v.Contract.Payment.RateAsOf++ }, "QUOTE_RATE"},
				{"weaker_confirmations", func(v *PackageV2) { v.Contract.Payment.MinConfirmations = 0 }, "PAYMENT_POLICY"},
				{"bad_address", func(v *PackageV2) { v.Contract.Payment.Address = "bc1invalid" }, "PAYMENT_ADDRESS"},
				{"long_hold", func(v *PackageV2) { v.HoldExpiresAt = v.HoldCreatedAt + 1801 }, "HOLD_BINDING"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					badR, badPack, badPub := r, pack, pub
					tc.edit(&badPack)
					badR.PaymentCoin = badPack.Contract.Payment.Coin
					badR.PaymentNetwork = badPack.Contract.Payment.Network
					badR.PaymentGenesis = badPack.Contract.Payment.Genesis
					resignPaymentV2(t, &badR, &badPack, &badPub, true)
					verify(badR, badPack, badPub, tc.reason)
					verify(r, pack, pub, "")
				})
			}
			for _, field := range []string{"coin", "network", "genesis", "budget"} {
				t.Run("request_"+field, func(t *testing.T) {
					bad := r
					switch field {
					case "coin":
						bad.PaymentCoin = "other"
					case "network":
						bad.PaymentNetwork = "main"
					case "genesis":
						bad.PaymentGenesis = strings.Repeat("a", 64)
					case "budget":
						bad.BudgetSat++
					}
					verify(bad, pack, pub, "PACKAGE_REQUEST_BINDING")
					verify(r, pack, pub, "")
				})
			}
			t.Run("old_consent_new_price", func(t *testing.T) {
				rr, pp, ee := r, pack, pub
				pp.Contract.Payment.PriceUSDCents++
				pp.Contract.Payment.AmountAtoms += 1000000
				resignPaymentV2(t, &rr, &pp, &ee, false)
				verify(rr, pp, ee, "RENTER_CONSENT")
				verify(r, pack, pub, "")
			})
			t.Run("trusted_policy", func(t *testing.T) {
				old := p.PaymentPolicies[coin]
				stricter := old
				stricter.MinConfirmations = 3
				p.PaymentPolicies[coin] = stricter
				verify(r, pack, pub, "PAYMENT_POLICY")
				p.PaymentPolicies[coin] = old
				verify(r, pack, pub, "")
				delete(p.PaymentPolicies, coin)
				verify(r, pack, pub, "PAYMENT_POLICY")
				p.PaymentPolicies[coin] = old
				verify(r, pack, pub, "")
			})
			t.Run("missing_route", func(t *testing.T) {
				a := AdmitIssuanceV2(context.Background(), nil, p, eventBytes(r), eventBytes(pub), now)
				if a.Verdict != "refused" || a.Reason != "PAYMENT_NODE_UNAVAILABLE" || a.Observation != nil {
					t.Fatal(a)
				}
			})
			t.Run("legacy_refuses_v2", func(t *testing.T) {
				if _, _, e := VerifyIssuancePackage(p.IssuerPolicy, eventBytes(r), eventBytes(pub), now); e == nil || e.Error() != "ISSUANCE_REQUEST" {
					t.Fatal("v2 fell through legacy path", e)
				}
			})
			// These gates are read-only: not even a reservation/lock may be written.
			entries, e := os.ReadDir(p.Policy.StateDir)
			if e != nil || len(entries) != 0 {
				t.Fatal("offline admission changed issuer state", e)
			}
		})
	}
}

// Byte-for-byte parity fixes the agreed wire order without importing the
// booking implementation. Malformed JSON cannot silently drop duplicate fields.
func TestPaymentV2Wire(t *testing.T) {
	for _, coin := range []string{"btc", "ltc", "nmc"} {
		p, r, pack, pub := paymentV2Fixture(t, coin)
		for name, value := range map[string]any{"issuance-request.json": r, "package.json": pack, "package-event.json": pub, "contract.json": pack.Contract} {
			raw, e := os.ReadFile(filepath.Join("testdata", "payment-v2", coin, name))
			if e != nil || string(raw) != string(eventBytes(value)) {
				t.Fatalf("wire %s/%s differs", coin, name)
			}
		}
		raw := eventBytes(r)
		duplicate := append([]byte(`{"version":2,`), raw[1:]...)
		if !json.Valid(duplicate) {
			t.Fatal("invalid duplicate test")
		}
		if _, _, e := VerifyIssuancePackageV2(p, duplicate, eventBytes(pub), pack.HoldCreatedAt); e == nil || e.Error() != "ISSUANCE_REQUEST" {
			t.Fatal("duplicate request accepted", e)
		}
	}
}

// Each v2 signature layer is mandatory even when the outer provider event has
// been validly re-signed around a corrupted inner signature.
func TestPaymentV2SignatureLayers(t *testing.T) {
	for _, mode := range []string{"publication", "provider", "renter"} {
		t.Run(mode, func(t *testing.T) {
			p, r, pack, pub := paymentV2Fixture(t, "btc")
			originalR, originalPub := r, pub
			want := ""
			switch mode {
			case "publication":
				pub.Sig = strings.Repeat("0", 128)
				want = "PACKAGE_EVENT"
			case "provider":
				pack.ProviderSignature = strings.Repeat("0", 128)
				want = "PROVIDER_SIGNATURE"
			case "renter":
				pack.Consent.Sig = strings.Repeat("0", 128)
				want = "RENTER_CONSENT"
			}
			if mode != "publication" {
				pub.Content = string(eventBytes(pack))
				pub = signedEvent(t, pub, 2)
				r.PackageEventID = pub.ID
			}
			if _, _, e := VerifyIssuancePackageV2(p, eventBytes(r), eventBytes(pub), pack.HoldCreatedAt+10); e == nil || e.Error() != want {
				t.Fatalf("want %s got %v", want, e)
			}
			if _, _, e := VerifyIssuancePackageV2(p, eventBytes(originalR), eventBytes(originalPub), pack.HoldCreatedAt+10); e != nil {
				t.Fatal("valid neighbor", e)
			}
		})
	}
}
