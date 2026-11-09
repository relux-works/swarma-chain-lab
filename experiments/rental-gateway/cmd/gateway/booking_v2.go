package main

import (
	"context"
	"net/url"
	booking "github.com/relux-works/swarma-chain-lab/experiments/rental-booking"
	"strconv"
	"time"
)

// V2 preserves the exact ServiceV2 wire while sharing the bounded, no-retry
// transport. An incompatible booking response never falls back to V1.
type bookingV2Client struct{ *bookingClient }

func newBookingV2Client(origin, privacy, template, profile string, timeout time.Duration) *bookingV2Client {
	return &bookingV2Client{newBookingClient(origin, privacy, template, profile, timeout)}
}
func (c *bookingV2Client) Catalogue(until int64, limit int) (booking.CatalogueV2, error) {
	var out booking.CatalogueV2
	if limit < 1 || limit > 64 || until <= 0 {
		return out, errBooking
	}
	q := url.Values{"until": {strconv.FormatInt(until, 10)}, "limit": {strconv.Itoa(limit)}}
	e := c.call(context.Background(), "GET", "/catalogue?"+q.Encode(), nil, &out, 200)
	if e != nil {
		return booking.CatalogueV2{}, e
	}
	if out.PrivacyNotice != booking.PrivacyNotice || out.PrivacySHA256 != c.privacy || out.TemplateSHA256 != c.template || out.Template.ProfileSHA256 != c.profile || booking.Hash(jsonCanonical(out.Template)) != c.template || len(out.Slots) > limit {
		return booking.CatalogueV2{}, errBooking
	}
	return out, nil
}
func (c *bookingV2Client) Book(ctx context.Context, in booking.BookInputV2) (booking.BookingV2, error) {
	var out struct {
		Booking booking.BookingV2 `json:"booking"`
		Hash    string            `json:"contract_sha256"`
	}
	e := c.call(ctx, "POST", "/book", in, &out, 201)
	if e != nil {
		return booking.BookingV2{}, e
	}
	if out.Hash != out.Booking.Contract.Hash() || c.check(out.Booking) != nil || out.Booking.Contract.RenterPubkey != in.RenterPubkey || out.Booking.Contract.Payment.Coin != string(in.Coin) {
		return booking.BookingV2{}, errBooking
	}
	return out.Booking, nil
}
func (c *bookingV2Client) AcceptConsent(ctx context.Context, id string, event booking.Event) (booking.BookingV2, error) {
	var out booking.BookingV2
	if !digest(id) {
		return out, errBooking
	}
	e := c.call(ctx, "POST", "/consent", struct {
		ID    string        `json:"booking_id"`
		Event booking.Event `json:"event"`
	}{id, event}, &out, 200)
	if e != nil {
		return booking.BookingV2{}, e
	}
	if out.Contract.BookingID != id || c.check(out) != nil {
		return booking.BookingV2{}, errBooking
	}
	return out, nil
}
func (c *bookingV2Client) Get(id string) (booking.BookingV2, error) {
	var out booking.BookingV2
	if !digest(id) {
		return out, errBooking
	}
	e := c.call(context.Background(), "GET", "/booking?id="+id, nil, &out, 200)
	if e != nil {
		return booking.BookingV2{}, e
	}
	if out.Contract.BookingID != id || c.check(out) != nil {
		return booking.BookingV2{}, errBooking
	}
	return out, nil
}
func (c *bookingV2Client) check(b booking.BookingV2) error {
	if b.Contract.Validate() != nil || b.Contract.PrivacySHA256 != c.privacy || b.Contract.TemplateSHA256 != c.template || b.Contract.ProfileSHA256 != c.profile {
		return errBooking
	}
	return nil
}
