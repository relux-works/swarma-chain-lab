package booking

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
)

// The actual HTTP catalogue exposes the service-owned available snapshot without
// reserving an address. Invalid/duplicate/oversize query bounds refuse without
// changing booking state; a valid request still succeeds after those refusals.
func TestHTTPCatalogue(t *testing.T) {
	f := newFixture(t)
	origin := "http://127.0.0.1:12345"
	h, e := NewHTTPHandler(f.s, origin)
	if e != nil {
		t.Fatal(e)
	}
	query := fmt.Sprintf("?until=%d&limit=16", f.now+86400)
	before := string(canonical(f.s.state))
	for _, suffix := range []string{"", "?until=0&limit=16", "?until=999999999999&limit=1", "?until=bad&limit=1", query + "&limit=1", query + "&extra=1", fmt.Sprintf("?until=%d&limit=65", f.now+1), "?until=" + strings.Repeat("0", 130) + fmt.Sprint(f.now+86400) + "&limit=16"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", origin+"/catalogue"+suffix, nil))
		if w.Code != 400 || string(canonical(f.s.state)) != before {
			t.Fatalf("catalogue invalid query admitted or mutated: %d", w.Code)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", origin+"/catalogue"+query, nil))
	var got Catalogue
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &got) != nil || len(got.Slots) == 0 || got.PrivacySHA256 != Hash([]byte(PrivacyNotice)) || string(canonical(f.s.state)) != before {
		t.Fatal("catalogue valid snapshot")
	}
	b := f.book(t, "one")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", origin+"/catalogue"+query, nil))
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &got) != nil {
		t.Fatal("catalogue after booking")
	}
	for _, s := range got.Slots {
		if s.ID == "one" {
			t.Fatal("catalogue advertised held slot")
		}
	}
	if f.s.state.NextIndex != 1 || b.Contract.BookingID == "" {
		t.Fatal("catalogue created extra reservation")
	}
}
