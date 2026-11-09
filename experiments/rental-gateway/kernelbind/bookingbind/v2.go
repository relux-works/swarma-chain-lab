package bookingbind

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	pc "github.com/relux-works/swarma-chain-lab/experiments/payment-chain"
	booking "github.com/relux-works/swarma-chain-lab/experiments/rental-booking"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/exchange"
	"slices"
	"time"
)

// AdapterV2 uses explicit deployment coin metadata: CatalogueV2 deliberately
// does not expose ConfigV2.Coins. The booking service remains authoritative.
type ServiceV2 interface {
	Catalogue(int64, int) (booking.CatalogueV2, error)
	Book(context.Context, booking.BookInputV2) (booking.BookingV2, error)
	AcceptConsent(context.Context, string, booking.Event) (booking.BookingV2, error)
	Get(string) (booking.BookingV2, error)
}
type AdapterV2 struct {
	ServiceV2                            ServiceV2
	AgentName, LandlordName, AgentPubkey string
	Now                                  func() time.Time
	PaymentCoins                         []exchange.Coin
}

func (a *AdapterV2) Catalogue(ctx context.Context) (exchange.Terms, error) {
	if ctx.Err() != nil {
		return exchange.Terms{}, ctx.Err()
	}
	if a.ServiceV2 == nil || a.Now == nil || !validCoins(a.PaymentCoins) {
		return exchange.Terms{}, errors.New("booking adapter config")
	}
	c, e := a.ServiceV2.Catalogue(a.Now().Unix()+86400, 16)
	if e != nil {
		return exchange.Terms{}, e
	}
	t := exchange.Terms{AgentName: a.AgentName, LandlordName: a.LandlordName, PrivacyNotice: c.PrivacyNotice, PrivacySHA256: c.PrivacySHA256, Templates: []exchange.Template{{ID: c.Template.ID, SHA256: c.TemplateSHA256, ProfileID: c.Template.ProfileID, ProfileVersion: c.Template.ProfileVersion, ProfileSHA256: c.Template.ProfileSHA256, PriceUSDCents: c.PriceUSDCents, SlotLengths: c.SlotLengths, Coins: append([]exchange.Coin{}, a.PaymentCoins...)}}, Slots: []exchange.Slot{}}
	for _, s := range c.Slots {
		if s.StationName != a.AgentName {
			continue
		}
		t.Slots = append(t.Slots, exchange.Slot{ID: s.ID, TemplateID: c.Template.ID, NotBefore: s.NotBefore, NotAfter: s.NotAfter, Coins: append([]exchange.Coin{}, a.PaymentCoins...)})
	}
	return t, nil
}
func (a *AdapterV2) Book(ctx context.Context, sender string, s exchange.Selection) (exchange.Hold, error) {
	if !slices.Contains(a.PaymentCoins, s.Coin) {
		return exchange.Hold{}, errors.Join(exchange.ErrRejected, exchange.ErrCoinNotOffered)
	}
	t, e := a.Catalogue(ctx)
	if e != nil {
		return exchange.Hold{}, e
	}
	valid := false
	for _, v := range t.Slots {
		valid = valid || (v.ID == s.Slot && v.TemplateID == s.Template)
	}
	if !valid {
		return exchange.Hold{}, exchange.ErrRejected
	}
	b, e := a.ServiceV2.Book(ctx, booking.BookInputV2{SlotID: s.Slot, Coin: pc.Coin(s.Coin), RenterPubkey: sender, PrivacyAcknowledged: true})
	if e != nil {
		switch e.Error() {
		case "COIN_UNAVAILABLE":
			return exchange.Hold{}, errors.Join(exchange.ErrRejected, exchange.ErrCoinNotOffered)
		case "CAPACITY_FULL", "SLOT_UNAVAILABLE", "SLOT_REMAINING_WINDOW", "BOOKING_CLOCK_CHANGED", "PRIVACY_REQUIRED", "RENTER_KEY":
			return exchange.Hold{}, errors.Join(exchange.ErrRejected, e)
		}
		return exchange.Hold{}, e
	}
	h, e := a.hold(b)
	if e != nil {
		return exchange.Hold{}, e
	}
	if h.Sender != sender || h.Coin != s.Coin || b.Contract.TemplateID != s.Template {
		return exchange.Hold{}, errors.New("booking sender")
	}
	return h, nil
}
func (a *AdapterV2) Consent(ctx context.Context, id string, raw []byte) (exchange.Hold, error) {
	var ev booking.Event
	if len(raw) > 8192 || booking.Strict(raw, &ev) != nil {
		return exchange.Hold{}, exchange.ErrRejected
	}
	// Preserve and verify the exact canonical event wire; do not synthesize consent.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if enc.Encode(ev) != nil || !bytes.Equal(bytes.TrimSuffix(buf.Bytes(), []byte{'\n'}), raw) {
		return exchange.Hold{}, exchange.ErrRejected
	}
	b, e := a.ServiceV2.Get(id)
	if e != nil {
		return exchange.Hold{}, e
	}
	if booking.CheckConsentV2(b.Contract, ev, b.HoldCreatedAt, b.HoldExpiresAt, a.Now().Unix()) != nil {
		return exchange.Hold{}, exchange.ErrRejected
	}
	b, e = a.ServiceV2.AcceptConsent(ctx, id, ev)
	if e != nil {
		return exchange.Hold{}, e
	}
	return a.hold(b)
}
func (a *AdapterV2) Status(ctx context.Context, id string) (exchange.Hold, error) {
	if ctx.Err() != nil {
		return exchange.Hold{}, ctx.Err()
	}
	b, e := a.ServiceV2.Get(id)
	if e != nil {
		return exchange.Hold{}, e
	}
	return a.hold(b)
}
func (a *AdapterV2) hold(b booking.BookingV2) (exchange.Hold, error) {
	c := b.Contract
	if c.Validate() != nil || c.AgentPubkey != a.AgentPubkey || c.StationName != a.AgentName || b.HoldExpiresAt <= b.HoldCreatedAt {
		return exchange.Hold{}, errors.New("booking response binding")
	}
	h := exchange.Hold{BookingID: c.BookingID, ContractSHA256: c.Hash(), Sender: c.RenterPubkey, AgentName: a.AgentName, LandlordName: a.LandlordName, StationName: c.StationName, NotBefore: c.NotBefore, NotAfter: c.NotAfter, Expires: b.HoldExpiresAt, Coin: exchange.Coin(c.Payment.Coin), Address: c.Payment.Address, AmountAtomic: c.Payment.AmountAtoms, MinConfirmations: c.Payment.MinConfirmations, Contract: append([]byte{}, c.Bytes()...), Issuable: b.Issuance != nil, Revoked: b.Revoke != nil}
	if b.Package != nil {
		h.ConsentID = b.Package.Consent.ID
	}
	return h, nil
}

func validCoins(coins []exchange.Coin) bool {
	if len(coins) < 1 || len(coins) > 3 {
		return false
	}
	seen := map[exchange.Coin]bool{}
	for _, coin := range coins {
		if _, e := exchange.ParseCoin(string(coin)); e != nil || seen[coin] {
			return false
		}
		seen[coin] = true
	}
	return true
}
