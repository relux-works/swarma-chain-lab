package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	booking "github.com/relux-works/swarma-chain-lab/experiments/rental-booking"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernelbind/bookingbind"
)

var errBooking = errors.New("BOOKING_UNAVAILABLE")

// bookingClient carries only public booking data. It neither retries ambiguous
// writes nor follows redirects/proxies to another endpoint.
type bookingClient struct {
	origin                     string
	privacy, template, profile string
	client                     *http.Client
	modelCaps                  *booking.ModelCaps
}

var _ bookingbind.Service = (*bookingClient)(nil)

func newBookingClient(origin, privacy, template, profile string, timeout time.Duration) *bookingClient {
	return &bookingClient{origin: origin, privacy: privacy, template: template, profile: profile, client: &http.Client{
		Timeout:       timeout,
		Transport:     &http.Transport{Proxy: nil, MaxIdleConns: 2, MaxConnsPerHost: 2},
		CheckRedirect: func(*http.Request, []*http.Request) error { return errBooking },
	}}
}
func (c *bookingClient) close() { c.client.CloseIdleConnections() }
func (c *bookingClient) call(ctx context.Context, method, path string, in, out any, status int) error {
	var body io.Reader
	if in != nil {
		b, e := json.Marshal(in)
		if e != nil || len(b) > 64<<10 {
			return errBooking
		}
		body = bytes.NewReader(b)
	}
	req, e := http.NewRequestWithContext(ctx, method, c.origin+path, body)
	if e != nil {
		return errBooking
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", c.origin)
	}
	resp, e := c.client.Do(req)
	if e != nil {
		return errBooking
	}
	defer resp.Body.Close()
	b, e := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if e != nil || len(b) > 1<<20 {
		return errBooking
	}
	if resp.StatusCode != status {
		// Only definitive no-effect Book errors may become ErrRejected upstream.
		// Unknown errors stay ambiguous; never echo an upstream response body.
		var failure struct {
			Error string `json:"error"`
		}
		if method == "POST" && path == "/book" && resp.StatusCode == 409 && booking.Strict(b, &failure) == nil {
			switch failure.Error {
			case "COIN_UNAVAILABLE", "CAPACITY_FULL", "SLOT_UNAVAILABLE", "SLOT_REMAINING_WINDOW", "BOOKING_CLOCK_CHANGED", "PRIVACY_REQUIRED", "RENTER_KEY":
				return errors.New(failure.Error)
			}
		}
		return errBooking
	}
	if booking.Strict(b, out) != nil {
		return errBooking
	}
	return nil
}
func (c *bookingClient) Catalogue(until int64, limit int) (booking.Catalogue, error) {
	var out booking.Catalogue
	if limit < 1 || limit > 64 || until <= 0 {
		return out, errBooking
	}
	q := url.Values{"until": {strconv.FormatInt(until, 10)}, "limit": {strconv.Itoa(limit)}}
	e := c.call(context.Background(), "GET", "/catalogue?"+q.Encode(), nil, &out, 200)
	if e != nil {
		return booking.Catalogue{}, e
	}
	if out.PrivacyNotice != booking.PrivacyNotice || out.PrivacySHA256 != c.privacy || out.TemplateSHA256 != c.template || out.Template.ProfileSHA256 != c.profile || booking.Hash(jsonCanonical(out.Template)) != c.template || len(out.Slots) > limit {
		return booking.Catalogue{}, errBooking
	}
	return out, nil
}
func (c *bookingClient) Book(ctx context.Context, in booking.BookInput) (booking.Booking, error) {
	var out struct {
		Booking booking.Booking `json:"booking"`
		Hash    string          `json:"contract_sha256"`
	}
	e := c.call(ctx, "POST", "/book", in, &out, 201)
	if e != nil {
		return booking.Booking{}, e
	}
	if out.Hash != out.Booking.Contract.Hash() || c.check(out.Booking) != nil {
		return booking.Booking{}, errBooking
	}
	return out.Booking, nil
}
func (c *bookingClient) AcceptConsent(ctx context.Context, id string, event booking.Event) (booking.Booking, error) {
	var out booking.Booking
	if !digest(id) {
		return out, errBooking
	}
	e := c.call(ctx, "POST", "/consent", struct {
		ID    string        `json:"booking_id"`
		Event booking.Event `json:"event"`
	}{id, event}, &out, 200)
	if e != nil {
		return booking.Booking{}, e
	}
	if out.Contract.BookingID != id || c.check(out) != nil {
		return booking.Booking{}, errBooking
	}
	return out, nil
}
func (c *bookingClient) Get(id string) (booking.Booking, error) {
	var out booking.Booking
	if !digest(id) {
		return out, errBooking
	}
	e := c.call(context.Background(), "GET", "/booking?id="+id, nil, &out, 200)
	if e != nil {
		return booking.Booking{}, e
	}
	if out.Contract.BookingID != id || c.check(out) != nil {
		return booking.Booking{}, errBooking
	}
	return out, nil
}
func (c *bookingClient) check(b booking.Booking) error {
	if b.Contract.Validate() != nil || b.Contract.PrivacySHA256 != c.privacy || b.Contract.TemplateSHA256 != c.template || b.Contract.ProfileSHA256 != c.profile {
		return errBooking
	}
	return nil
}
func jsonCanonical(v any) []byte {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	_ = e.Encode(v)
	return bytes.TrimSuffix(b.Bytes(), []byte{'\n'})
}
