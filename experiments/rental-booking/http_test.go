package booking

import (
	"context"
	"encoding/json"
	"github.com/gorilla/websocket"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The real HTTP handler refuses cross-origin/host requests, missing privacy,
// malformed/duplicate JSON and oversize bodies before allocating an address;
// the same server accepts a normal booking and consent afterwards.
func TestHTTPGuardsAndConsent(t *testing.T) {
	f := newFixture(t)
	srv := httptest.NewUnstartedServer(nil)
	origin := "http://" + srv.Listener.Addr().String()
	handler, e := NewHTTPHandler(f.s, origin)
	if e != nil {
		t.Fatal(e)
	}
	srv.Config.Handler = handler
	srv.Start()
	defer srv.Close()
	body := string(canonical(BookInput{"one", keyHex(f.renter), "", true}))
	for _, tc := range []struct{ name, body, origin, host, code string }{
		{"origin", body, "http://evil.example", "", "ORIGIN_REFUSED"},
		{"host", body, origin, "evil.example", "HOST_REFUSED"},
		{"privacy", strings.Replace(body, "true", "false", 1), origin, "", "PRIVACY_REQUIRED"},
		{"duplicate", strings.Replace(body, `"slot_id":"one"`, `"slot_id":"one","slot_id":"two"`, 1), origin, "", "INPUT_SCHEMA"},
		{"alias", strings.Replace(body, "slot_id", "Slot_id", 1), origin, "", "INPUT_SCHEMA"},
		{"unknown", strings.Replace(body, `"slot_id":`, `"extra":true,"slot_id":`, 1), origin, "", "INPUT_SCHEMA"},
		{"oversize", strings.Repeat("x", 65537), origin, "", "BODY_BOUND"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest("POST", srv.URL+"/book", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Origin", tc.origin)
			if tc.host != "" {
				req.Host = tc.host
			}
			r, e := srv.Client().Do(req)
			if e != nil {
				t.Fatal(e)
			}
			defer r.Body.Close()
			raw, _ := io.ReadAll(r.Body)
			if r.StatusCode < 400 || !strings.Contains(string(raw), tc.code) || f.s.state.NextIndex != 0 {
				t.Fatalf("guard %d %s", r.StatusCode, raw)
			}
		})
	}
	r, e := srv.Client().Get(srv.URL)
	if e != nil {
		t.Fatal(e)
	}
	html, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if !strings.Contains(string(html), PrivacyNotice) || !strings.Contains(string(html), "window.nostr.getPublicKey") || strings.Contains(string(html), "<script src=") || !strings.Contains(r.Header.Get("Content-Security-Policy"), "sha256-") {
		t.Fatal("page privacy/script policy")
	}
	post := func(path string, v any) []byte {
		t.Helper()
		req, _ := http.NewRequest("POST", srv.URL+path, strings.NewReader(string(canonical(v))))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", origin)
		r, e := srv.Client().Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		if r.StatusCode >= 400 {
			t.Fatalf("valid http: %d %s", r.StatusCode, b)
		}
		return b
	}
	raw := post("/book", BookInput{"one", keyHex(f.renter), "", true})
	var got struct {
		Booking Booking `json:"booking"`
		Hash    string  `json:"contract_sha256"`
	}
	if e = json.Unmarshal(raw, &got); e != nil || got.Hash != got.Booking.Contract.Hash() {
		t.Fatal("contract response")
	}
	post("/consent", map[string]any{"booking_id": got.Booking.Contract.BookingID, "event": f.consent(t, got.Booking)})
}

// Real WebSocket EVENT/OK and REQ/EOSE paths preserve one signed event; a fake
// ACK for another id and a non-loopback URL cannot count as publication.
func TestLocalRelayProtocol(t *testing.T) {
	f := newFixture(t)
	b := f.book(t, "one")
	_, event, e := NewPackage(b.Contract, f.consent(t, b), b.HoldCreatedAt, b.HoldExpiresAt, f.now, f.provider)
	if e != nil {
		t.Fatal(e)
	}
	relay, e := NewLocalRelay(privateDir(t))
	if e != nil {
		t.Fatal(e)
	}
	defer relay.Close()
	srv := httptest.NewServer(relay)
	defer srv.Close()
	url := "ws" + strings.TrimPrefix(srv.URL, "http")
	pub, e := NewRelayPublisher(url)
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 2; i++ {
		if e = pub.Publish(context.Background(), event); e != nil {
			t.Fatal(e)
		}
	}
	conn, _, e := websocket.DefaultDialer.Dial(url, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	if e = conn.WriteJSON([]any{"REQ", "test", map[string]any{"ids": []string{event.ID}}}); e != nil {
		t.Fatal(e)
	}
	_, raw, e := conn.ReadMessage()
	if e != nil || !strings.Contains(string(raw), event.ID) {
		t.Fatalf("fetch: %s %v", raw, e)
	}
	_, raw, e = conn.ReadMessage()
	if e != nil || string(raw) != `["EOSE","test"]`+"\n" && string(raw) != `["EOSE","test"]` {
		t.Fatalf("eose: %s %v", raw, e)
	}
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, e := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if e != nil {
			return
		}
		defer c.Close()
		_, _, _ = c.ReadMessage()
		_ = c.WriteJSON([]any{"OK", strings.Repeat("0", 64), true, ""})
	}))
	defer fake.Close()
	wrong, _ := NewRelayPublisher("ws" + strings.TrimPrefix(fake.URL, "http"))
	if e = wrong.Publish(context.Background(), event); e == nil || e.Error() != "RELAY_ACK" {
		t.Fatalf("wrong ack: %v", e)
	}
	if _, e = NewRelayPublisher("ws://example.com:80/"); e == nil || e.Error() != "RELAY_ROUTE" {
		t.Fatal("remote relay accepted")
	}
}
