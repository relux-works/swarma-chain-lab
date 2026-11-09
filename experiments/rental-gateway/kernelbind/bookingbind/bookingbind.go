// Package bookingbind binds typed booking services to the opaque exchange.
// Adapter is the legacy V1 test binding; AdapterV2 is the deployment binding.
package bookingbind

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	booking "github.com/relux-works/swarma-chain-lab/experiments/rental-booking"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/exchange"
)

type Service interface {
	Catalogue(int64, int) (booking.Catalogue, error)
	Book(context.Context, booking.BookInput) (booking.Booking, error)
	AcceptConsent(context.Context, string, booking.Event) (booking.Booking, error)
	Get(string) (booking.Booking, error)
}
type Adapter struct {
	Service                              Service
	AgentName, LandlordName, AgentPubkey string
	Now                                  func() time.Time
}

func (a *Adapter) Catalogue(ctx context.Context) (exchange.Terms, error) {
	if ctx.Err() != nil {
		return exchange.Terms{}, ctx.Err()
	}
	if a.Service == nil || a.Now == nil {
		return exchange.Terms{}, errors.New("booking adapter config")
	}
	c, e := a.Service.Catalogue(a.Now().Unix()+86400, 16)
	if e != nil {
		return exchange.Terms{}, e
	}
	t := exchange.Terms{AgentName: a.AgentName, LandlordName: a.LandlordName, PrivacyNotice: c.PrivacyNotice, PrivacySHA256: c.PrivacySHA256, Templates: []exchange.Template{{ID: c.Template.ID, SHA256: c.TemplateSHA256, ProfileID: c.Template.ProfileID, ProfileVersion: c.Template.ProfileVersion, ProfileSHA256: c.Template.ProfileSHA256, PriceUSDCents: c.PriceUSDCents, SlotLengths: c.SlotLengths}}, Slots: []exchange.Slot{}}
	for _, s := range c.Slots {
		if s.StationName != a.AgentName {
			continue
		}
		t.Slots = append(t.Slots, exchange.Slot{ID: s.ID, TemplateID: c.Template.ID, NotBefore: s.NotBefore, NotAfter: s.NotAfter, Coins: []exchange.Coin{exchange.NMC}})
	}
	return t, nil
}
func (a *Adapter) Book(ctx context.Context, sender string, s exchange.Selection) (exchange.Hold, error) {
	if s.Coin != exchange.NMC {
		return exchange.Hold{}, errors.Join(exchange.ErrRejected, errors.New("v1 supports nmc only"))
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
	b, e := a.Service.Book(ctx, booking.BookInput{SlotID: s.Slot, RenterPubkey: sender, PrivacyAcknowledged: true})
	if e != nil {
		switch e.Error() {
		case "CAPACITY_FULL", "SLOT_UNAVAILABLE", "SLOT_REMAINING_WINDOW", "BOOKING_CLOCK_CHANGED", "PRIVACY_REQUIRED", "RENTER_KEY":
			return exchange.Hold{}, errors.Join(exchange.ErrRejected, e)
		}
		return exchange.Hold{}, e
	}
	h, e := a.hold(b)
	if e != nil {
		return exchange.Hold{}, e
	}
	if h.Sender != sender {
		return exchange.Hold{}, errors.New("booking sender")
	}
	return h, nil
}
func (a *Adapter) Consent(ctx context.Context, id string, raw []byte) (exchange.Hold, error) {
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
	b, e := a.Service.Get(id)
	if e != nil {
		return exchange.Hold{}, e
	}
	if booking.CheckConsent(b.Contract, ev, b.HoldCreatedAt, b.HoldExpiresAt, a.Now().Unix()) != nil {
		return exchange.Hold{}, exchange.ErrRejected
	}
	b, e = a.Service.AcceptConsent(ctx, id, ev)
	if e != nil {
		return exchange.Hold{}, e
	}
	return a.hold(b)
}
func (a *Adapter) Status(ctx context.Context, id string) (exchange.Hold, error) {
	if ctx.Err() != nil {
		return exchange.Hold{}, ctx.Err()
	}
	b, e := a.Service.Get(id)
	if e != nil {
		return exchange.Hold{}, e
	}
	return a.hold(b)
}
func (a *Adapter) hold(b booking.Booking) (exchange.Hold, error) {
	c := b.Contract
	if c.Validate() != nil || c.AgentPubkey != a.AgentPubkey || c.StationName != a.AgentName || b.HoldExpiresAt <= b.HoldCreatedAt {
		return exchange.Hold{}, errors.New("booking response binding")
	}
	// Legacy Service.Refresh admits payment only after one active confirmation.
	h := exchange.Hold{BookingID: c.BookingID, ContractSHA256: c.Hash(), Sender: c.RenterPubkey, AgentName: a.AgentName, LandlordName: a.LandlordName, StationName: c.StationName, NotBefore: c.NotBefore, NotAfter: c.NotAfter, Expires: b.HoldExpiresAt, Coin: exchange.NMC, Address: c.PaymentAddress, AmountAtomic: c.PriceNMCSat, MinConfirmations: 1, Contract: append([]byte{}, c.Bytes()...), Issuable: b.Issuance != nil, Revoked: b.Revoke != nil}
	if b.Package != nil {
		h.ConsentID = b.Package.Consent.ID
	}
	return h, nil
}

// PresentationSource reads an already-issued presentation from the external
// issuer. It does not prepare, sign, fund, broadcast, or assert current liveness.
type PresentationSource interface {
	Presentation(context.Context, string) ([]byte, error)
}
type Grants struct{ Source PresentationSource }

func (g Grants) Lookup(ctx context.Context, h exchange.Hold) (*exchange.Issued, error) {
	if g.Source == nil {
		return nil, errors.New("issuance source missing")
	}
	raw, e := g.Source.Presentation(ctx, h.BookingID)
	if e != nil || raw == nil {
		return nil, e
	}
	if len(raw) > 16384 {
		return nil, errors.New("presentation size")
	}
	p, e := rental.ParseGrantPresentation(raw)
	if e != nil {
		return nil, e
	}
	grant := p.SignedGrant.Grant
	if grant.ContractSHA256 != h.ContractSHA256 || grant.GranteeKey != h.Sender || grant.AgentName != h.AgentName || grant.LandlordName != h.LandlordName || grant.NotBefore != h.NotBefore || grant.NotAfter != h.NotAfter {
		return nil, errors.New("issued grant binding")
	}
	return &exchange.Issued{BookingID: h.BookingID, ContractSHA256: h.ContractSHA256, Sender: h.Sender, AgentName: h.AgentName, LandlordName: h.LandlordName, StationName: h.StationName, GrantID: p.SignedGrant.ID(), NotBefore: h.NotBefore, NotAfter: h.NotAfter, Presentation: append([]byte{}, raw...)}, nil
}
