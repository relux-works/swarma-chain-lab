package booking

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// Deterministic signing is confined to public vector keys. The application
// signer uses fresh auxiliary randomness; no real signing key is in a fixture.
func deterministicSign(t *testing.T, key *btcec.PrivateKey, digest string) string {
	t.Helper()
	h, _ := hex.DecodeString(digest)
	sig, e := schnorr.Sign(key, h)
	if e != nil {
		t.Fatal(e)
	}
	return hex.EncodeToString(sig.Serialize())
}
func deterministicEvent(t *testing.T, key *btcec.PrivateKey, event *Event) {
	t.Helper()
	event.Pubkey = keyHex(key)
	id, e := event.digest()
	if e != nil {
		t.Fatal(e)
	}
	event.ID = id
	event.Sig = deterministicSign(t, key, id)
}
func wireFixture(t *testing.T) map[string][]byte {
	t.Helper()
	f := newFixture(t)
	b := f.book(t, "one")
	b.Contract.BookingID = strings.Repeat("1", 64)
	consent := Consent(b.Contract, f.now)
	deterministicEvent(t, f.renter, &consent)
	p, event, e := NewPackage(b.Contract, consent, b.HoldCreatedAt, b.HoldExpiresAt, f.now, f.provider)
	if e != nil {
		t.Fatal(e)
	}
	p.ProviderSignature = deterministicSign(t, f.provider, b.Contract.Hash())
	event.Content = string(canonical(p))
	deterministicEvent(t, f.provider, &event)
	b.Package = &p
	b.PackageEvent = &event
	payment := Payment{TxID: strings.Repeat("4", 64), Vout: 0, ValueSat: b.Contract.PriceNMCSat, Height: 101, BlockHash: strings.Repeat("5", 64)}
	request := newIssuance(b, payment, strings.Repeat("6", 64))
	return map[string][]byte{"contract.json": b.Contract.Bytes(), "consent.json": canonical(consent), "package.json": canonical(p), "package-event.json": canonical(event), "issuance-request.json": canonical(request)}
}

// Frozen wire bytes match independent deterministic generation and signatures.
// Payment ids are synthetic: this fixture proves encoding, never chain admission.
func TestFrozenPublicFixture(t *testing.T) {
	want := wireFixture(t)
	if out := os.Getenv("M3_FIXTURE_OUT"); out != "" {
		if !filepath.IsAbs(out) {
			t.Fatal("absolute M3_FIXTURE_OUT required")
		}
		if e := os.Mkdir(out, 0755); e != nil {
			t.Fatal(e)
		}
		for name, b := range want {
			if e := os.WriteFile(filepath.Join(out, name), b, 0644); e != nil {
				t.Fatal(e)
			}
		}
		return
	}
	for name, w := range want {
		got, e := os.ReadFile(filepath.Join("testdata", "wire-v1", name))
		if e != nil || string(got) != string(w) {
			t.Fatalf("wire fixture %s differs: %v", name, e)
		}
	}
	var p Package
	if e := Strict(want["package.json"], &p); e != nil {
		t.Fatal(e)
	}
	if _, e := DecodePackage(want["package.json"], p.ProviderPubkey, p.HoldCreatedAt, p.HoldExpiresAt); e != nil {
		t.Fatal(e)
	}
}
