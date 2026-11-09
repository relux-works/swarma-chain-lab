package booking

import (
	"bytes"
	"encoding/json"
	"github.com/btcsuite/btcd/btcec/v2"
)

func ConsentV2(c ContractV2, at int64) Event {
	return Event{Pubkey: c.RenterPubkey, CreatedAt: at, Kind: ConsentKind, Tags: [][]string{{"t", "swarma-rental-consent-v1"}, {"contract", c.Hash()}, {"booking", c.BookingID}, {"privacy", c.PrivacySHA256}}, Content: ""}
}
func CheckConsentV2(c ContractV2, e Event, created, expires, now int64) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if e.Pubkey != c.RenterPubkey {
		return refuse("CONSENT_KEY")
	}
	if created <= 0 || expires <= created || expires-created > 1800 || e.CreatedAt < created || e.CreatedAt >= expires || e.CreatedAt > now || now >= expires || now >= c.NotAfter {
		return refuse("CONSENT_TIME")
	}
	if err := c.Payment.ValidateAt(created, c.Payment.MaxRateAgeSeconds, 1); err != nil {
		return err
	}
	want := ConsentV2(c, e.CreatedAt)
	if e.Kind != want.Kind || e.Content != "" || !bytes.Equal(canonical(e.Tags), canonical(want.Tags)) {
		return refuse("CONSENT_BINDING")
	}
	return e.Verify()
}

type PackageV2 struct {
	Version           int        `json:"version"`
	Contract          ContractV2 `json:"contract"`
	Consent           Event      `json:"consent"`
	ProviderPubkey    string     `json:"provider_pubkey"`
	ProviderSignature string     `json:"provider_signature"`
	PrivacyAckAt      int64      `json:"privacy_ack_at"`
	PrivacySHA256     string     `json:"privacy_sha256"`
	HoldCreatedAt     int64      `json:"hold_created_at"`
	HoldExpiresAt     int64      `json:"hold_expires_at"`
}

func (p PackageV2) Validate(provider string, created, expires int64) error {
	if p.Version != 1 || p.ProviderPubkey != provider || p.PrivacyAckAt != created || p.PrivacySHA256 != p.Contract.PrivacySHA256 || p.HoldCreatedAt != created || p.HoldExpiresAt != expires || expires <= created || expires-created > 1800 {
		return refuse("PACKAGE_BINDING")
	}
	if e := CheckConsentV2(p.Contract, p.Consent, created, expires, p.Consent.CreatedAt); e != nil {
		return e
	}
	if !verifySignature(provider, p.Contract.Hash(), p.ProviderSignature) {
		return refuse("COUNTERSIGNATURE")
	}
	return nil
}
func NewPackageV2(c ContractV2, e Event, created, expires, now int64, key *btcec.PrivateKey) (PackageV2, Event, error) {
	if err := CheckConsentV2(c, e, created, expires, now); err != nil {
		return PackageV2{}, Event{}, err
	}
	sig, err := signHash(key, c.Hash())
	if err != nil {
		return PackageV2{}, Event{}, err
	}
	p := PackageV2{1, c, e, keyHex(key), sig, created, c.PrivacySHA256, created, expires}
	if err = p.Validate(p.ProviderPubkey, created, expires); err != nil {
		return PackageV2{}, Event{}, err
	}
	event := Event{CreatedAt: now, Kind: PackageKind, Tags: [][]string{{"t", "swarma-rental-package-v1"}, {"contract", c.Hash()}, {"booking", c.BookingID}, {"e", e.ID}}, Content: string(canonical(p))}
	if err = event.Sign(key); err != nil {
		return PackageV2{}, Event{}, err
	}
	return p, event, nil
}

// DecodePackageV2 requires the canonical bytes used for the contract commitment.
func DecodePackageV2(b []byte, provider string, created, expires int64) (PackageV2, error) {
	var p PackageV2
	if Strict(b, &p) != nil || !json.Valid(b) || !bytes.Equal(b, canonical(p)) {
		return PackageV2{}, refuse("PACKAGE_ENCODING")
	}
	if err := p.Validate(provider, created, expires); err != nil {
		return PackageV2{}, err
	}
	return p, nil
}
