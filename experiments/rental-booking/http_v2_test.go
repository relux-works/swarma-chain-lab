package booking

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	pc "github.com/relux-works/swarma-chain-lab/experiments/payment-chain"
	"strings"
	"testing"
)

// The real ServiceV2 is reached through the HTTP producer surface for every
// supported coin. Guard failures leave its state unchanged; signed consent,
// Get and restart preserve exact v2 contracts. Nodes are bounded test doubles.
func TestHTTPV2(t *testing.T) {
	for _, coin := range []string{"btc", "ltc", "nmc"} {
		t.Run(coin, func(t *testing.T) {
			f := newLedger(t)
			srv := httptest.NewUnstartedServer(nil)
			origin := "http://" + srv.Listener.Addr().String()
			h, e := NewHTTPHandlerV2(f.s, origin)
			if e != nil {
				t.Fatal(e)
			}
			srv.Config.Handler = h
			srv.Start()
			defer srv.Close()
			call := func(method, path, body, from, host string) (int, []byte, http.Header) {
				t.Helper()
				req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
				req.Header.Set("Origin", from)
				req.Header.Set("Content-Type", "application/json")
				if host != "" {
					req.Host = host
				}
				res, e := srv.Client().Do(req)
				if e != nil {
					t.Fatal(e)
				}
				defer res.Body.Close()
				raw, e := io.ReadAll(res.Body)
				if e != nil {
					t.Fatal(e)
				}
				return res.StatusCode, raw, res.Header
			}
			body := string(canonical(BookInputV2{SlotID: "slot0", Coin: pc.Coin(coin), RenterPubkey: keyHex(f.renter), PrivacyAcknowledged: true}))
			before := string(canonical(f.s.state))
			for _, tc := range []struct{ name, body, origin, host, code string }{
				{"origin", body, "http://evil.example", "", "ORIGIN_REFUSED"},
				{"host", body, origin, "evil.example", "HOST_REFUSED"},
				{"privacy", strings.Replace(body, "true", "false", 1), origin, "", "PRIVACY_REQUIRED"},
				{"duplicate", strings.Replace(body, `"coin":`, `"coin":"btc","coin":`, 1), origin, "", "INPUT_SCHEMA"},
				{"unknown", strings.Replace(body, `"coin":`, `"extra":true,"coin":`, 1), origin, "", "INPUT_SCHEMA"},
				{"oversize", strings.Repeat("x", 65537), origin, "", "BODY_BOUND"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					code, raw, _ := call("POST", "/book", tc.body, tc.origin, tc.host)
					if code < 400 || !strings.Contains(string(raw), tc.code) || string(canonical(f.s.state)) != before {
						t.Fatal("v2 HTTP guard changed state or accepted")
					}
				})
			}
			for _, query := range []string{"", "?until=0&limit=1", fmt.Sprintf("?until=%d&limit=1&limit=2", f.now+86400), fmt.Sprintf("?until=%d&limit=65", f.now+86400)} {
				code, raw, _ := call("GET", "/catalogue"+query, "", origin, "")
				if code != 400 || !strings.Contains(string(raw), "CATALOGUE_BOUNDS") || string(canonical(f.s.state)) != before {
					t.Fatal("v2 catalogue guard")
				}
			}
			query := fmt.Sprintf("?until=%d&limit=16", f.now+86400)
			code, raw, _ := call("GET", "/catalogue"+query, "", origin, "")
			var cat CatalogueV2
			if code != 200 || Strict(raw, &cat) != nil || len(cat.Slots) != 3 || string(canonical(f.s.state)) != before {
				t.Fatal("v2 catalogue not read-only")
			}
			code, raw, headers := call("GET", "/", "", origin, "")
			sum := sha256.Sum256([]byte(h.script))
			if code != 200 || !strings.Contains(string(raw), `id="coin"`) || !strings.Contains(string(raw), "coin:document.getElementById") || !strings.Contains(headers.Get("Content-Security-Policy"), base64.StdEncoding.EncodeToString(sum[:])) {
				t.Fatal("v2 page/script coin selector or CSP")
			}
			code, raw, _ = call("POST", "/book", body, origin, "")
			var got struct {
				Booking BookingV2 `json:"booking"`
				Hash    string    `json:"contract_sha256"`
			}
			if code != 201 || Strict(raw, &got) != nil || got.Booking.Contract.Version != 2 || got.Booking.Contract.Payment.Coin != coin || got.Hash != got.Booking.Contract.Hash() {
				t.Fatalf("v2 book response %d", code)
			}
			consent := ConsentV2(got.Booking.Contract, f.now)
			if e = consent.Sign(f.renter); e != nil {
				t.Fatal(e)
			}
			code, raw, _ = call("POST", "/consent", string(canonical(map[string]any{"booking_id": got.Booking.Contract.BookingID, "event": consent})), origin, "")
			var accepted BookingV2
			if code != 200 || Strict(raw, &accepted) != nil || accepted.PackageEvent == nil || accepted.PackageEvent.Verify() != nil {
				t.Fatal("v2 signed consent not accepted")
			}
			f.s.Close()
			f.open(t)
			h.v2 = f.s
			code, raw, _ = call("GET", "/booking?id="+got.Booking.Contract.BookingID, "", origin, "")
			var restored BookingV2
			if code != 200 || Strict(raw, &restored) != nil || string(canonical(restored)) != string(canonical(accepted)) {
				t.Fatal("v2 HTTP restart changed booking")
			}
			for _, path := range []string{"/missing", "/booking?id=bad"} {
				code, _, _ := call("GET", path, "", origin, "")
				if code < 400 {
					t.Fatal("v2 unknown route or invalid ID accepted")
				}
			}
			direct, e := f.s.Get(got.Booking.Contract.BookingID)
			if e != nil || direct.Contract.Hash() != got.Hash {
				t.Fatal("HTTP did not use real service")
			}
			if e = f.s.PublishPending(context.Background()); e != nil {
				t.Fatal(e)
			}
		})
	}
}

// No implicit coin is selected for legacy v1-shaped requests sent to v2.
func TestHTTPV2RequiresCoin(t *testing.T) {
	f := newLedger(t)
	origin := "http://127.0.0.1:12345"
	h, e := NewHTTPHandlerV2(f.s, origin)
	if e != nil {
		t.Fatal(e)
	}
	raw := canonical(BookInput{SlotID: "slot0", RenterPubkey: keyHex(f.renter), PrivacyAcknowledged: true})
	before, _ := json.Marshal(f.s.state)
	r := httptest.NewRequest("POST", origin+"/book", strings.NewReader(string(raw)))
	r.Header.Set("Origin", origin)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	after, _ := json.Marshal(f.s.state)
	if w.Code != 409 || !strings.Contains(w.Body.String(), "COIN") || string(before) != string(after) {
		t.Fatal("v1 request silently converted")
	}
}
