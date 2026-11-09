// Package exchange implements the deterministic, non-model rental conversation.
// Contract and consent wire interpretation belongs to the booking adapter.
package exchange

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
)

type Coin string

// ErrRejected means the backend definitively performed no booking effect.
// Unknown errors are ambiguous and must never trigger a second Book call.
var ErrCoinNotOffered = errors.New("coin not offered")

const CoinNotOffered = "Payment coin not offered for this template."

var ErrRejected = errors.New("booking rejected without effect")

const (
	NMC Coin = "nmc"
	BTC Coin = "btc"
	LTC Coin = "ltc"
)

func ParseCoin(s string) (Coin, error) {
	switch Coin(s) {
	case NMC, BTC, LTC:
		return Coin(s), nil
	}
	return "", errors.New("unsupported coin")
}

const Help = "Rental exchange: send terms, then book <template> <slot> <coin>, then consent <signed kind-8181 event JSON>. Booking acknowledges the privacy notice shown in terms. Wait for ready before sending a message with your grant."
const BookPending = "Booking pending reconciliation. Wait or retry terms; do not repeat the booking."
const Unavailable = "Rental exchange unavailable; retry later."
const NotYet = "Rental slot has not started yet."
const NotLive = "Rental grant is not live; try again later."

type Template struct {
	Coins          []Coin  `json:"coins,omitempty"`
	ID             string  `json:"id"`
	SHA256         string  `json:"template_sha256"`
	ProfileID      string  `json:"profile_id"`
	ProfileVersion string  `json:"profile_version"`
	ProfileSHA256  string  `json:"profile_sha256"`
	PriceUSDCents  int64   `json:"price_usd_cents"`
	SlotLengths    []int64 `json:"slot_lengths"`
	ModelTerms     string  `json:"model_terms,omitempty"`
}
type Slot struct {
	ID         string `json:"id"`
	TemplateID string `json:"template_id"`
	NotBefore  int64  `json:"not_before"`
	NotAfter   int64  `json:"not_after"`
	Coins      []Coin `json:"coins"`
}
type Terms struct {
	AgentName     string     `json:"agent_name"`
	LandlordName  string     `json:"landlord_name"`
	PrivacyNotice string     `json:"privacy_notice"`
	PrivacySHA256 string     `json:"privacy_sha256"`
	Templates     []Template `json:"templates"`
	Slots         []Slot     `json:"slots"`
	PowBits       int        `json:"pow_bits"`
}

// Hold carries verified metadata and exact opaque contract bytes. Only the
// adapter may interpret or produce the signed contract/consent wire.
type Hold struct {
	BookingID        string `json:"booking_id"`
	ContractSHA256   string `json:"contract_sha256"`
	Sender           string `json:"sender"`
	AgentName        string `json:"agent_name"`
	LandlordName     string `json:"landlord_name"`
	StationName      string `json:"station_name"`
	NotBefore        int64  `json:"not_before"`
	NotAfter         int64  `json:"not_after"`
	Expires          int64  `json:"expires"`
	Coin             Coin   `json:"coin"`
	Address          string `json:"address"`
	AmountAtomic     int64  `json:"amount_atomic"`
	MinConfirmations int64  `json:"min_confirmations"`
	Contract         []byte `json:"-"`
	ConsentID        string `json:"consent_id,omitempty"`
	Issuable         bool   `json:"issuable"`
	Revoked          bool   `json:"revoked"`
}
type Selection struct {
	Template, Slot string
	Coin           Coin
}
type Backend interface {
	Catalogue(context.Context) (Terms, error)
	Book(context.Context, string, Selection) (Hold, error)
	Consent(context.Context, string, []byte) (Hold, error)
	Status(context.Context, string) (Hold, error)
}

// Issued is a parsed and signature-checked presentation supplied by a separate
// issuer. It is not a live verdict; only the current-time kernel can give that.
type Issued struct {
	BookingID, ContractSHA256, Sender, AgentName, LandlordName, StationName, GrantID string
	NotBefore, NotAfter                                                              int64
	Presentation                                                                     []byte
	Contract                                                                         []byte
}
type GrantSource interface {
	Lookup(context.Context, Hold) (*Issued, error)
}
type Publisher interface {
	Publish(context.Context, *nostr.Event) error
}
type Hooks struct {
	Register func(context.Context, Issued) error
	Check    func(context.Context, Hold, int64) (bool, error)
}
type Config struct {
	StateDir                                       string
	AgentName, LandlordName                        string
	Backend                                        Backend
	Grants                                         GrantSource
	PowBits                                        int
	MaxClients, QueueSize, Burst, MaxReplay        int
	RefillSeconds, KnownSeconds, MessageAgeSeconds int64
	PollInterval, CallTimeout                      time.Duration
	Now                                            func() time.Time
}

func DefaultConfig() Config {
	return Config{PowBits: 16, MaxClients: 32, QueueSize: 32, Burst: 8, MaxReplay: 32, RefillSeconds: 10, KnownSeconds: 600, MessageAgeSeconds: 300, PollInterval: time.Second, CallTimeout: 2 * time.Second, Now: time.Now}
}
func hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func canonical(v any) []byte {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if e.Encode(v) != nil {
		panic("non-JSON exchange type")
	}
	return bytes.TrimSuffix(b.Bytes(), []byte{'\n'})
}
func digest(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == s
}
func identifier(s string) bool {
	if len(s) < 1 || len(s) > 160 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-._/", r)) {
			return false
		}
	}
	return true
}
func (c Config) validate() error {
	if c.Backend == nil || c.Grants == nil || c.Now == nil || !strings.HasPrefix(c.AgentName, "id/") || !identifier(c.AgentName) || !strings.HasPrefix(c.LandlordName, "id/") || !identifier(c.LandlordName) || c.PowBits < 1 || c.PowBits > 32 || c.MaxClients < 1 || c.MaxClients > 64 || c.QueueSize < 1 || c.QueueSize > 128 || c.Burst < 1 || c.Burst > 64 || c.MaxReplay < c.Burst || c.MaxReplay > 64 || c.RefillSeconds < 1 || c.RefillSeconds > 3600 || c.KnownSeconds < 1 || c.KnownSeconds > 86400 || c.MessageAgeSeconds < 1 || c.MessageAgeSeconds > 600 || c.PollInterval < 10*time.Millisecond || c.PollInterval > time.Minute || c.CallTimeout <= 0 || c.CallTimeout > 5*time.Second {
		return errors.New("exchange config")
	}
	return nil
}
func (h Hold) valid(c Config, sender string) bool {
	_, e := ParseCoin(string(h.Coin))
	return e == nil && digest(h.BookingID) && digest(h.ContractSHA256) && h.Sender == sender && h.AgentName == c.AgentName && h.LandlordName == c.LandlordName && identifier(h.StationName) && h.NotBefore > 0 && h.NotAfter > h.NotBefore && h.NotAfter-h.NotBefore <= 3600 && h.Expires > 0 && h.Expires <= h.NotAfter && len(h.Address) >= 1 && len(h.Address) <= 128 && h.AmountAtomic > 0
}
func sameHold(a, b Hold) bool {
	return a.BookingID == b.BookingID && a.ContractSHA256 == b.ContractSHA256 && a.Sender == b.Sender && a.AgentName == b.AgentName && a.LandlordName == b.LandlordName && a.StationName == b.StationName && a.NotBefore == b.NotBefore && a.NotAfter == b.NotAfter && a.Expires == b.Expires && a.Coin == b.Coin && a.Address == b.Address && a.AmountAtomic == b.AmountAtomic && a.MinConfirmations == b.MinConfirmations
}
