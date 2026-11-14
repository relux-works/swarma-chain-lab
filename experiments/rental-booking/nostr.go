package booking

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/bip340"
)

const ConsentKind = 8181
const PackageKind = 8182

type Event struct {
	ID        string     `json:"id"`
	Pubkey    string     `json:"pubkey"`
	CreatedAt int64      `json:"created_at"`
	Kind      int        `json:"kind"`
	Tags      [][]string `json:"tags"`
	Content   string     `json:"content"`
	Sig       string     `json:"sig"`
}

func (e Event) digest() (string, error) {
	if !pubkey(e.Pubkey) || e.CreatedAt <= 0 || e.Kind < 0 || e.Kind > 65535 || e.Tags == nil || len(e.Tags) > 16 || len(e.Content) > 65536 {
		return "", refuse("EVENT_SCHEMA")
	}
	// This experiment's event subset is printable ASCII. Go's UTF-8 escaping
	// for U+2028/U+2029 cannot diverge from a browser's NIP-01 serialization.
	ascii := func(s string) bool {
		for _, c := range s {
			if c < 32 || c > 126 {
				return false
			}
		}
		return true
	}
	if !ascii(e.Content) {
		return "", refuse("EVENT_SCHEMA")
	}
	for _, tag := range e.Tags {
		if len(tag) < 1 || len(tag) > 3 {
			return "", refuse("EVENT_SCHEMA")
		}
		for _, s := range tag {
			if len(s) > 512 || !ascii(s) {
				return "", refuse("EVENT_SCHEMA")
			}
		}
	}
	return Hash(canonical([]any{0, e.Pubkey, e.CreatedAt, e.Kind, e.Tags, e.Content})), nil
}
func verifySignature(key, digest, signature string) bool {
	if !pubkey(key) || !hexSize(digest, 32) || !hexSize(signature, 64) {
		return false
	}
	k, _ := hex.DecodeString(key)
	p, _ := schnorr.ParsePubKey(k)
	h, _ := hex.DecodeString(digest)
	s, _ := hex.DecodeString(signature)
	sig, e := bip340.ParseBIP340Strict(s)
	return e == nil && sig.Verify(h, p)
}
func signHash(key *btcec.PrivateKey, digest string) (string, error) {
	if key == nil || !hexSize(digest, 32) {
		return "", refuse("SIGN_INPUT")
	}
	h, _ := hex.DecodeString(digest)
	var aux [32]byte
	if _, e := rand.Read(aux[:]); e != nil {
		return "", refuse("SIGN_RANDOM")
	}
	s, e := schnorr.Sign(key, h, schnorr.CustomNonce(aux))
	if e != nil {
		return "", refuse("SIGN_FAILURE")
	}
	return hex.EncodeToString(s.Serialize()), nil
}
func keyHex(k *btcec.PrivateKey) string {
	return hex.EncodeToString(schnorr.SerializePubKey(k.PubKey()))
}
func (e *Event) Sign(k *btcec.PrivateKey) error {
	if k == nil {
		return refuse("SIGN_INPUT")
	}
	e.Pubkey = keyHex(k)
	id, err := e.digest()
	if err != nil {
		return err
	}
	sig, err := signHash(k, id)
	if err != nil {
		return err
	}
	e.ID = id
	e.Sig = sig
	return nil
}
func (e Event) Verify() error {
	id, err := e.digest()
	if err != nil {
		return err
	}
	if e.ID != id {
		return refuse("EVENT_ID")
	}
	if !verifySignature(e.Pubkey, id, e.Sig) {
		return refuse("EVENT_SIGNATURE")
	}
	return nil
}
func Consent(c Contract, at int64) Event {
	return Event{Pubkey: c.RenterPubkey, CreatedAt: at, Kind: ConsentKind, Tags: [][]string{{"t", "swarma-rental-consent-v1"}, {"contract", c.Hash()}, {"booking", c.BookingID}, {"privacy", c.PrivacySHA256}}, Content: ""}
}
func CheckConsent(c Contract, e Event, created, expires, now int64) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if e.Pubkey != c.RenterPubkey {
		return refuse("CONSENT_KEY")
	}
	if e.CreatedAt < created || e.CreatedAt >= expires || e.CreatedAt > now || now >= expires {
		return refuse("CONSENT_TIME")
	}
	want := Consent(c, e.CreatedAt)
	if e.Kind != want.Kind || e.Content != "" || !bytes.Equal(canonical(e.Tags), canonical(want.Tags)) {
		return refuse("CONSENT_BINDING")
	}
	return e.Verify()
}

type Package struct {
	Version           int      `json:"version"`
	Contract          Contract `json:"contract"`
	Consent           Event    `json:"consent"`
	ProviderPubkey    string   `json:"provider_pubkey"`
	ProviderSignature string   `json:"provider_signature"`
	PrivacyAckAt      int64    `json:"privacy_ack_at"`
	PrivacySHA256     string   `json:"privacy_sha256"`
	HoldCreatedAt     int64    `json:"hold_created_at"`
	HoldExpiresAt     int64    `json:"hold_expires_at"`
}

func (p Package) Validate(provider string, created, expires int64) error {
	if p.Version != 1 || p.ProviderPubkey != provider || p.PrivacyAckAt != created || p.PrivacySHA256 != p.Contract.PrivacySHA256 || p.HoldCreatedAt != created || p.HoldExpiresAt != expires || expires <= created || expires-created > 1800 {
		return refuse("PACKAGE_BINDING")
	}
	if e := CheckConsent(p.Contract, p.Consent, created, expires, p.Consent.CreatedAt); e != nil {
		return e
	}
	if !verifySignature(provider, p.Contract.Hash(), p.ProviderSignature) {
		return refuse("COUNTERSIGNATURE")
	}
	return nil
}
func NewPackage(c Contract, e Event, created, expires, now int64, key *btcec.PrivateKey) (Package, Event, error) {
	if err := CheckConsent(c, e, created, expires, now); err != nil {
		return Package{}, Event{}, err
	}
	sig, err := signHash(key, c.Hash())
	if err != nil {
		return Package{}, Event{}, err
	}
	p := Package{1, c, e, keyHex(key), sig, created, c.PrivacySHA256, created, expires}
	event := Event{CreatedAt: now, Kind: PackageKind, Tags: [][]string{{"t", "swarma-rental-package-v1"}, {"contract", c.Hash()}, {"booking", c.BookingID}, {"e", e.ID}}, Content: string(canonical(p))}
	if err = event.Sign(key); err != nil {
		return Package{}, Event{}, err
	}
	return p, event, nil
}

// DecodePackage requires the canonical bytes used for the contract commitment.
func DecodePackage(b []byte, provider string, created, expires int64) (Package, error) {
	var p Package
	if Strict(b, &p) != nil || !json.Valid(b) || !bytes.Equal(b, canonical(p)) {
		return p, refuse("PACKAGE_ENCODING")
	}
	return p, p.Validate(provider, created, expires)
}
