package modelproxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// spellings lists the contract's encodings independently of the tripwire's own
// table, using only the standard encoders: raw, base64 and base64url with and
// without padding, lower and upper hex, percent-encoding and JSON escaping.
func spellings(value string) map[string]string {
	b := []byte(value)
	var percent strings.Builder
	for _, c := range b {
		fmt.Fprintf(&percent, "%%%02X", c)
	}
	escaped, _ := json.Marshal(value)
	var plain bytes.Buffer
	enc := json.NewEncoder(&plain)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(value)
	plainEscaped := bytes.TrimSuffix(plain.Bytes(), []byte("\n"))
	return map[string]string{
		"raw":             value,
		"base64":          base64.StdEncoding.EncodeToString(b),
		"base64-nopad":    base64.RawStdEncoding.EncodeToString(b),
		"base64url":       base64.URLEncoding.EncodeToString(b),
		"base64url-nopad": base64.RawURLEncoding.EncodeToString(b),
		"hex-lower":       hex.EncodeToString(b),
		"hex-upper":       strings.ToUpper(hex.EncodeToString(b)),
		"percent-query":   url.QueryEscape(value),
		"percent-path":    url.PathEscape(value),
		"percent-all":     percent.String(),
		"json-html":       string(escaped[1 : len(escaped)-1]),
		"json-plain":      string(plainEscaped[1 : len(plainEscaped)-1]),
	}
}

func persistedBlocks(t *testing.T, g *gatewayHarness) map[string]string {
	t.Helper()
	raw, e := g.s.disk.Read("registry.json", MaxBody)
	var v ledger
	if e != nil || json.Unmarshal(raw, &v) != nil {
		t.Fatal("ledger unreadable")
	}
	return v.Blocked
}

// Every listed spelling of an issued credential is caught in a header and in a
// body where the spelling straddles the scanner's 4096-byte chunk boundary
// (the handler reassembles transfer chunks before the scan, so that boundary is
// the only split the proxy path can prove), refusing LEAK_CREDENTIAL before any
// upstream call, durably blocking the run account and recording an audit
// without the value. The same request without the value is forwarded first.
func TestTripwireForms(t *testing.T) {
	forms := spellings(sourceMarker)
	if len(forms) != 12 || forms["json-html"] == forms["json-plain"] || forms["percent-query"] == forms["raw"] {
		t.Fatal("spelling table calibration failed")
	}
	names := make([]string, 0, len(forms))
	for name := range forms {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		form := forms[name]
		for _, where := range []string{"header", "body"} {
			t.Run(name+"/"+where, func(t *testing.T) {
				g := gatewayFixture(t, ModeManaged, newFakeSource(sourceMarker))
				if g.send(request(false)).Code != 200 {
					t.Fatal("tripwire positive neighbor refused")
				}
				var w *httptest.ResponseRecorder
				if where == "header" {
					w = g.sendAs(request(false), g.b.SlotID, g.cred.Bearer.Reveal(), map[string]string{"X-Client-Debug": form})
				} else {
					head := strings.Index(request(false), "private-prompt-marker")
					pad := strings.Repeat("x", tripwireChunk-len(form)/2-head)
					body := strings.Replace(request(false), "private-prompt-marker", pad+form, 1)
					if at := strings.Index(body, form); at >= tripwireChunk || at+len(form) <= tripwireChunk {
						t.Fatal("spelling does not straddle the chunk boundary", at)
					}
					w = g.send(body)
				}
				if w.Code != 403 || w.Body.String() != `{"error":"LEAK_CREDENTIAL"}` || g.calls.Load() != 1 {
					t.Fatal("leaked credential forwarded", w.Code, w.Body.String())
				}
				if v := g.status(t); v.Exposure != (Counts{7, 3, 1, 23}) || v.InFlight {
					t.Fatal("leak verdict changed accounting", v)
				}
				if persistedBlocks(t, g)[g.b.Run.Account] != "LEAK_CREDENTIAL" {
					t.Fatal("account block not persisted")
				}
				if a := g.lastAudit(); a.Code != "LEAK_CREDENTIAL" || a.HTTPStatus != 403 || a.Usage != (Usage{}) || a.SlotID != g.b.SlotID {
					t.Fatal("leak verdict not audited", a)
				}
				log := g.auditLog()
				for _, f := range forms {
					if strings.Contains(log, f) {
						t.Fatal("audit carried a credential spelling")
					}
				}
				if w = g.send(request(false)); w.Code != 403 || w.Body.String() != `{"error":"ACCOUNT_BLOCKED"}` || g.calls.Load() != 1 {
					t.Fatal("blocked account still served", w.Code, w.Body.String())
				}
			})
		}
	}
}

// The leak scan is the first verdict on every request, before the route, the
// bearer count and authorize. An issued credential presented as the bearer
// itself, beside a second Authorization header, with an invalid bearer, on an
// unknown slot or on a malformed route is refused 401 with the plain AUTH body,
// audited LEAK_CREDENTIAL on the route's slot with no account block (no binding
// owns the presented bearer) and no upstream call; the valid binding
// keeps serving afterwards. The same shapes without the credential are today's
// AUTH and ROUTE refusals, the negative control. The bound case, a valid bearer
// with the leak, is TestTripwireForms.
func TestTripwireBeforeAuthorize(t *testing.T) {
	g := gatewayFixture(t, ModeManaged, newFakeSource(sourceMarker))
	if g.send(request(false)).Code != 200 {
		t.Fatal("tripwire positive neighbor refused")
	}
	valid := "Bearer " + string(g.cred.Bearer.Reveal())
	route := "/slots/" + g.b.SlotID + "/v1/messages"
	unknown := strings.Repeat("9", 64)
	debug := func(h http.Header, leak bool) http.Header {
		if leak {
			h.Set("X-Client-Debug", sourceMarker)
		}
		return h
	}
	for _, tc := range []struct {
		name, path, slot, plain string
		status                  int
		headers                 func(leak bool) http.Header
	}{
		{"own-bearer", route, g.b.SlotID, "AUTH", 401, func(leak bool) http.Header {
			h := http.Header{}
			h.Set("Authorization", "Bearer not-the-bearer")
			if leak {
				h.Set("Authorization", "Bearer "+sourceMarker)
			}
			return h
		}},
		{"two-authorization", route, g.b.SlotID, "AUTH", 401, func(leak bool) http.Header {
			h := http.Header{}
			h.Add("Authorization", valid)
			second := valid
			if leak {
				second = "Bearer " + sourceMarker
			}
			h.Add("Authorization", second)
			return h
		}},
		{"invalid-bearer", route, g.b.SlotID, "AUTH", 401, func(leak bool) http.Header {
			h := http.Header{}
			h.Set("Authorization", "Bearer not-the-bearer")
			return debug(h, leak)
		}},
		// A bearer owned by another slot is TestTripwireScreenForeign, so the
		// unknown-slot and malformed-route shapes carry an unowned one.
		{"unknown-slot", "/slots/" + unknown + "/v1/messages", unknown, "AUTH", 401, func(leak bool) http.Header {
			h := http.Header{}
			h.Set("Authorization", "Bearer not-the-bearer")
			return debug(h, leak)
		}},
		{"bad-route", "/slots/" + g.b.SlotID + "/v1/other", g.b.SlotID, "ROUTE", 404, func(leak bool) http.Header {
			h := http.Header{}
			h.Set("Authorization", "Bearer not-the-bearer")
			return debug(h, leak)
		}},
	} {
		for _, leak := range []bool{false, true} {
			r := httptest.NewRequest("POST", "https://proxy.example"+tc.path, strings.NewReader(request(false)))
			r.Header = tc.headers(leak)
			w := httptest.NewRecorder()
			g.s.ServeHTTP(w, r)
			a := g.lastAudit()
			if !leak {
				if w.Code != tc.status || w.Body.String() != `{"error":"`+tc.plain+`"}` || a.Code != tc.plain {
					t.Fatal("control refusal changed", tc.name, w.Code, w.Body.String(), a)
				}
				continue
			}
			if w.Code != 401 || w.Body.String() != `{"error":"AUTH"}` || a.Code != "LEAK_CREDENTIAL" || a.HTTPStatus != 401 || a.SlotID != tc.slot || a.Usage != (Usage{}) {
				t.Fatal("unbound leak not refused as 401 LEAK_CREDENTIAL", tc.name, w.Code, w.Body.String(), a)
			}
			if len(persistedBlocks(t, g)) != 0 {
				t.Fatal("unbound leak blocked an account", tc.name)
			}
			if strings.Contains(g.auditLog(), sourceMarker) {
				t.Fatal("audit carried the credential", tc.name)
			}
		}
	}
	if w := g.send(request(false)); w.Code != 200 || g.calls.Load() != 2 {
		t.Fatal("valid binding affected by unbound leaks", w.Code, w.Body.String(), g.calls.Load())
	}
}

// A leaked credential beside a bearer that belongs to ANOTHER binding holds
// that binding to account exactly as the foreign bearer alone would: a foreign
// run bearer blocks its account under LEAK_BEARER in the ledger, a foreign
// rental bearer freezes its own record and blocks no account, and a bearer no
// binding owns blocks and freezes nothing (the control). Every shape is refused
// 401 with the plain AUTH body, audited LEAK_CREDENTIAL on the route's slot
// without the value, makes no upstream call, and leaves the route's own binding
// serving. The held binding is then refused on its own route.
func TestTripwireScreenForeign(t *testing.T) {
	g := gatewayFixture(t, ModeManaged, newFakeSource(sourceMarker))
	other := runBinding("5", "b")
	otherCred, e := g.s.Prepare(other)
	if e != nil {
		t.Fatal(e)
	}
	if e = g.s.Activate(other); e != nil {
		t.Fatal(e)
	}
	rental := rentalBinding("6")
	rentalCred, e := g.s.Prepare(rental)
	if e != nil {
		t.Fatal(e)
	}
	if e = g.s.Activate(rental); e != nil {
		t.Fatal(e)
	}
	if g.send(request(false)).Code != 200 || g.sendAs(request(false), other.SlotID, otherCred.Bearer.Reveal(), nil).Code != 200 || g.sendAs(request(false), rental.SlotID, rentalCred.Bearer.Reveal(), nil).Code != 200 {
		t.Fatal("screen-foreign positive neighbors refused")
	}
	calls := g.calls.Load()
	leak := map[string]string{"X-Client-Debug": sourceMarker}
	screened := func(name string, bearer Secret) {
		t.Helper()
		w := g.sendAs(request(false), g.b.SlotID, bearer, leak)
		a := g.lastAudit()
		if w.Code != 401 || w.Body.String() != `{"error":"AUTH"}` || a.Code != "LEAK_CREDENTIAL" || a.HTTPStatus != 401 || a.SlotID != g.b.SlotID || g.calls.Load() != calls {
			t.Fatal(name, "not refused as 401 LEAK_CREDENTIAL", w.Code, w.Body.String(), a, g.calls.Load())
		}
		if strings.Contains(g.auditLog(), sourceMarker) {
			t.Fatal(name, "audit carried the credential")
		}
	}
	phase := func(id string) string {
		t.Helper()
		v, e := g.s.Status(id)
		if e != nil {
			t.Fatal(e)
		}
		return v.Phase
	}
	// Control: a bearer no binding owns blocks and freezes nothing.
	screened("unowned", Secret("not-a-bearer"))
	if len(persistedBlocks(t, g)) != 0 || phase(other.SlotID) != "active" || phase(rental.SlotID) != "active" {
		t.Fatal("unowned bearer with a leak blocked or froze a binding")
	}
	// Foreign run bearer: its account is blocked under LEAK_BEARER, the route's
	// own account is not, and the bearer is refused on its own route.
	screened("foreign-run", otherCred.Bearer.Reveal())
	if blocks := persistedBlocks(t, g); len(blocks) != 1 || blocks[other.Run.Account] != "LEAK_BEARER" {
		t.Fatal("foreign run bearer with a leak did not block its account", blocks)
	}
	if w := g.sendAs(request(false), other.SlotID, otherCred.Bearer.Reveal(), nil); w.Code != 403 || w.Body.String() != `{"error":"ACCOUNT_BLOCKED"}` {
		t.Fatal("blocked account still served", w.Code, w.Body.String())
	}
	// Foreign rental bearer: no account to block, so its own record is frozen
	// and the bearer is refused on its own route as any inactive record.
	screened("foreign-rental", rentalCred.Bearer.Reveal())
	if blocks := persistedBlocks(t, g); len(blocks) != 1 || phase(rental.SlotID) != "frozen" {
		t.Fatal("foreign rental bearer with a leak blocked an account or left the record live", blocks, phase(rental.SlotID))
	}
	if w := g.sendAs(request(false), rental.SlotID, rentalCred.Bearer.Reveal(), nil); w.Code != 401 || w.Body.String() != `{"error":"AUTH"}` {
		t.Fatal("frozen rental still served", w.Code, w.Body.String())
	}
	g.reopen(t)
	if phase(rental.SlotID) != "frozen" || persistedBlocks(t, g)[other.Run.Account] != "LEAK_BEARER" {
		t.Fatal("foreign-leak verdicts not durable")
	}
	if w := g.send(request(false)); w.Code != 200 || g.calls.Load() != calls+1 {
		t.Fatal("route's own binding affected by foreign leaks", w.Code, w.Body.String(), g.calls.Load())
	}
}

// While the source is down an echoed issued version is still caught with the
// needles already known: the request is refused LEAK_CREDENTIAL and the account
// is blocked, not refused CREDENTIAL_UNAVAILABLE. The same request without the
// value is the plain CREDENTIAL_UNAVAILABLE with no block, and the request that
// issued the version was served first.
func TestTripwireSourceDown(t *testing.T) {
	src := newFakeSource(sourceMarker)
	g := gatewayFixture(t, ModeManaged, src)
	if g.send(request(false)).Code != 200 {
		t.Fatal("source positive neighbor refused")
	}
	src.mu.Lock()
	src.fail = "CREDENTIAL_EXPIRED"
	src.mu.Unlock()
	if w := g.send(request(false)); w.Code != 503 || w.Body.String() != `{"error":"CREDENTIAL_UNAVAILABLE"}` || len(persistedBlocks(t, g)) != 0 {
		t.Fatal("unavailable source control changed", w.Code, w.Body.String())
	}
	w := g.sendAs(request(false), g.b.SlotID, g.cred.Bearer.Reveal(), map[string]string{"X-Client-Debug": sourceMarker})
	if w.Code != 403 || w.Body.String() != `{"error":"LEAK_CREDENTIAL"}` || g.calls.Load() != 1 || persistedBlocks(t, g)[g.b.Run.Account] != "LEAK_CREDENTIAL" {
		t.Fatal("echoed version not caught while the source is down", w.Code, w.Body.String())
	}
	if a := g.lastAudit(); a.Code != "LEAK_CREDENTIAL" || a.HTTPStatus != 403 {
		t.Fatal("leak verdict not audited", a)
	}
}

// A loaded Blocked entry whose account is not a canonical digest, or whose
// verdict is not a tripwire code, refuses New with STATE and leaves the file
// bytes unchanged, so a plant that drops that validation fails here. The
// unmodified ledger with the same block reopens and still refuses the account,
// the positive control.
func TestTripwireBlockedLoad(t *testing.T) {
	g := gatewayFixture(t, ModeManaged, newFakeSource(sourceMarker))
	if w := g.sendAs(request(false), g.b.SlotID, g.cred.Bearer.Reveal(), map[string]string{"X-Client-Debug": sourceMarker}); w.Code != 403 {
		t.Fatal("leak not refused")
	}
	g.s.Close()
	path := filepath.Join(g.c.StateDir, "registry.json")
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	entry := `"blocked":{"` + g.b.Run.Account + `":"LEAK_CREDENTIAL"}`
	if !strings.Contains(string(raw), entry) {
		t.Fatal("block entry not persisted as expected")
	}
	for _, bad := range []string{
		`"blocked":{"` + strings.ToUpper(g.b.Run.Account) + `":"LEAK_CREDENTIAL"}`,
		`"blocked":{"` + g.b.Run.Account[:63] + `":"LEAK_CREDENTIAL"}`,
		`"blocked":{"` + g.b.Run.Account + `":"LEAK_OTHER"}`,
		`"blocked":{"` + g.b.Run.Account + `":""}`,
	} {
		corrupt := []byte(strings.Replace(string(raw), entry, bad, 1))
		if bytes.Equal(corrupt, raw) {
			t.Fatal("plant missing")
		}
		if e := os.WriteFile(path, corrupt, 0600); e != nil {
			t.Fatal(e)
		}
		if s, e := New(g.c); e == nil || e.Error() != "STATE" || s != nil {
			t.Fatal("corrupt block admitted", bad, e)
		}
		after, e := os.ReadFile(path)
		if e != nil || !bytes.Equal(after, corrupt) {
			t.Fatal("refusal rewrote the ledger", e)
		}
	}
	if e := os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	s, e := New(g.c)
	if e != nil {
		t.Fatal("valid blocked ledger refused", e)
	}
	g.s = s
	if w := g.send(request(false)); w.Code != 403 || w.Body.String() != `{"error":"ACCOUNT_BLOCKED"}` || g.calls.Load() != 0 {
		t.Fatal("reloaded block not enforced", w.Code, w.Body.String())
	}
}

// The scanner matches a spelling split into single-byte chunks and across
// header lines; a credential of 15 bytes is never added, so its spellings
// pass, while 16 bytes are matched. Calibration: an unrelated body is clean.
func TestTripwireScannerChunks(t *testing.T) {
	tw := newTripwire()
	if !tw.add(Secret(sourceMarker)) {
		t.Fatal("value not registered")
	}
	for name, form := range spellings(sourceMarker) {
		sc := tw.scanner()
		hit := false
		for i := 0; i < len(form); i++ {
			hit = sc.feed([]byte(form[i:i+1])) || hit
		}
		if !hit {
			t.Fatal("split spelling missed", name)
		}
	}
	if tw.scanner().feed([]byte(request(false))) {
		t.Fatal("clean body matched")
	}
	short := newTripwire()
	short.add(Secret("short-marker-15"))
	if len(short.needles) != 0 || short.scanner().feed([]byte("short-marker-15 short-marker-15")) {
		t.Fatal("15-byte value matched")
	}
	long := newTripwire()
	long.add(Secret("short-marker-16!"))
	if !long.scanner().feed([]byte(`{"k":"short-marker-16!"}`)) {
		t.Fatal("16-byte value missed")
	}
}

// Through the proxy a 15-byte credential in header and body is forwarded as
// ordinary content, so short values cannot cause false positives; the same
// request with a 16-byte credential is refused.
func TestTripwireShortValue(t *testing.T) {
	for _, value := range []string{"short-marker-15", "short-marker-16!"} {
		g := gatewayFixture(t, ModeManaged, newFakeSource(Secret(value)))
		g.accept(value)
		body := strings.Replace(request(false), "private-prompt-marker", value, 1)
		w := g.sendAs(body, g.b.SlotID, g.cred.Bearer.Reveal(), map[string]string{"X-Client-Debug": value})
		if len(value) < MinTripwireBytes {
			if w.Code != 200 || g.calls.Load() != 1 {
				t.Fatal("short value tripped", w.Code, w.Body.String())
			}
		} else if w.Code != 403 || w.Body.String() != `{"error":"LEAK_CREDENTIAL"}` || g.calls.Load() != 0 {
			t.Fatal("16-byte value not matched", w.Code, w.Body.String())
		}
	}
}

// An account block survives restart from state and refuses Prepare, Activate
// and use for that account only; another account's run binding keeps serving;
// only the peer-checked clear_block operation lifts it and restores service.
func TestTripwireRestartAndClear(t *testing.T) {
	g := gatewayFixture(t, ModeManaged, newFakeSource(sourceMarker))
	other := runBinding("5", "b")
	otherCred, e := g.s.Prepare(other)
	if e != nil {
		t.Fatal(e)
	}
	if e = g.s.Activate(other); e != nil {
		t.Fatal(e)
	}
	if w := g.sendAs(request(false), g.b.SlotID, g.cred.Bearer.Reveal(), map[string]string{"X-Client-Debug": sourceMarker}); w.Code != 403 {
		t.Fatal("leak not refused")
	}
	g.reopen(t)
	if g.s.state.Blocked[g.b.Run.Account] != "LEAK_CREDENTIAL" {
		t.Fatal("block lost across restart")
	}
	same := runBinding("6", "a")
	if _, e = g.s.Prepare(same); e == nil || e.Error() != "ACCOUNT_BLOCKED" {
		t.Fatal("blocked account prepared", e)
	}
	if e = g.s.Activate(g.b); e == nil || e.Error() != "ACCOUNT_BLOCKED" {
		t.Fatal("blocked account activated", e)
	}
	if w := g.send(request(false)); w.Code != 403 || w.Body.String() != `{"error":"ACCOUNT_BLOCKED"}` || g.calls.Load() != 0 {
		t.Fatal("blocked account served after restart", w.Code)
	}
	if w := g.sendAs(request(false), other.SlotID, otherCred.Bearer.Reveal(), nil); w.Code != 200 || g.calls.Load() != 1 {
		t.Fatal("unrelated account affected", w.Code, w.Body.String())
	}
	admin := func(raw []byte, peer bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "http://local/v1/registry", bytes.NewReader(raw))
		if peer {
			r = r.WithContext(context.WithValue(r.Context(), peerKey{}, true))
		}
		w := httptest.NewRecorder()
		g.s.adminHandler(w, r)
		return w
	}
	lift := privateCanonical(adminRequest{V: 1, Op: "clear_block", Account: g.b.Run.Account})
	if w := admin(lift, false); w.Code != 403 {
		t.Fatal("unverified peer cleared block")
	}
	if w := admin(privateCanonical(adminRequest{V: 1, Op: "clear_block", Account: "not-a-digest"}), true); w.Code != 400 {
		t.Fatal("malformed clear accepted")
	}
	if w := admin(privateCanonical(adminRequest{V: 1, Op: "clear_block", Account: strings.Repeat("c", 64)}), true); !strings.Contains(w.Body.String(), "ADMIN_REFUSED") {
		t.Fatal("clearing an unblocked account succeeded")
	}
	if g.send(request(false)).Code != 403 {
		t.Fatal("refused clears lifted the block")
	}
	w := admin(lift, true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"ok":true`) || !strings.Contains(w.Body.String(), `"account":"`+g.b.Run.Account+`"`) {
		t.Fatal("owner clear refused", w.Code, w.Body.String())
	}
	if len(persistedBlocks(t, g)) != 0 {
		t.Fatal("clear not persisted")
	}
	if w := g.send(request(false)); w.Code != 200 || g.calls.Load() != 2 {
		t.Fatal("cleared account not restored", w.Code, w.Body.String())
	}
	g.reopen(t)
	if g.send(request(false)).Code != 200 {
		t.Fatal("clear lost across restart")
	}
	if !supportsPeers() {
		if e := (Client{SocketPath: "/unavailable/sock"}).ClearBlock(context.Background(), g.b.Run.Account); e == nil || e.Error() != "LINUX_ONLY" {
			t.Fatal("non-Linux clear fallback")
		}
	}
}

// A run binding's bearer presented on another binding's route is refused as
// any bad bearer and durably blocks that run account under LEAK_BEARER; the
// route's own binding keeps serving; a rental binding's foreign bearer keeps
// today's refusal without any block.
func TestTripwireForeignBearer(t *testing.T) {
	g := gatewayFixture(t, ModeManaged, newFakeSource(sourceMarker))
	other := runBinding("5", "b")
	otherCred, e := g.s.Prepare(other)
	if e != nil {
		t.Fatal(e)
	}
	if e = g.s.Activate(other); e != nil {
		t.Fatal(e)
	}
	rental := Binding{SlotID: strings.Repeat("6", 64), GrantID: strings.Repeat("2", 64), NotBefore: 90, NotAfter: 1000, Caps: g.b.Caps}
	rentalCred, e := g.s.Prepare(rental)
	if e != nil {
		t.Fatal(e)
	}
	if e = g.s.Activate(rental); e != nil {
		t.Fatal(e)
	}
	w := g.sendAs(request(false), other.SlotID, rentalCred.Bearer.Reveal(), nil)
	if w.Code != 401 || w.Body.String() != `{"error":"AUTH"}` || len(persistedBlocks(t, g)) != 0 || g.lastAudit().Code != "AUTH" {
		t.Fatal("rental foreign bearer changed behavior", w.Code, w.Body.String())
	}
	if g.sendAs(request(false), rental.SlotID, rentalCred.Bearer.Reveal(), nil).Code != 200 {
		t.Fatal("rental binding blocked")
	}
	w = g.sendAs(request(false), other.SlotID, g.cred.Bearer.Reveal(), nil)
	if w.Code != 401 || w.Body.String() != `{"error":"AUTH"}` || g.calls.Load() != 1 {
		t.Fatal("foreign run bearer not refused as before", w.Code, w.Body.String())
	}
	if a := g.lastAudit(); a.Code != "LEAK_BEARER" || a.HTTPStatus != 401 || a.SlotID != other.SlotID {
		t.Fatal("foreign bearer verdict not audited", a)
	}
	if persistedBlocks(t, g)[g.b.Run.Account] != "LEAK_BEARER" {
		t.Fatal("leaked run account not blocked durably")
	}
	if w = g.send(request(false)); w.Code != 403 || w.Body.String() != `{"error":"ACCOUNT_BLOCKED"}` || g.calls.Load() != 1 {
		t.Fatal("leaked run account still served", w.Code)
	}
	if w = g.sendAs(request(false), other.SlotID, otherCred.Bearer.Reveal(), nil); w.Code != 200 || g.calls.Load() != 2 {
		t.Fatal("route owner affected by foreign bearer", w.Code, w.Body.String())
	}
}

// When the block cannot be persisted the request is still refused with no
// upstream call, the ledger bytes stay unchanged and the process poisons closed,
// so later requests for any binding fail instead of serving an unrecorded leak.
func TestTripwirePersistenceFailure(t *testing.T) {
	g := gatewayFixture(t, ModeManaged, newFakeSource(sourceMarker))
	if g.send(request(false)).Code != 200 {
		t.Fatal("persistence positive neighbor refused")
	}
	path := filepath.Join(g.c.StateDir, "registry.json")
	before, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(g.c.StateDir, 0500); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = os.Chmod(g.c.StateDir, 0700) })
	w := g.sendAs(request(false), g.b.SlotID, g.cred.Bearer.Reveal(), map[string]string{"X-Client-Debug": sourceMarker})
	if w.Code != 503 || w.Body.String() != `{"error":"STATE_WRITE"}` || g.calls.Load() != 1 {
		t.Fatal("unpersisted block served or misreported", w.Code, w.Body.String())
	}
	after, e := os.ReadFile(path)
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("failed block partially wrote")
	}
	if !g.s.poisoned {
		t.Fatal("failed block did not poison the process")
	}
	if w = g.send(request(false)); w.Code == 200 || g.calls.Load() != 1 {
		t.Fatal("poisoned process kept serving", w.Code)
	}
}

// On the Responses route the static operator key found in a client body is
// refused before upstream I/O; a rental binding has no account, so its own
// record is frozen instead, while the clean request before it was served.
func TestTripwireResponsesRoute(t *testing.T) {
	h := responsesFixture(t)
	if w := h.send(responsesRequest(true, false)); !strings.Contains(w.Body.String(), "response.completed") || h.calls.Load() != 1 {
		t.Fatal("Responses tripwire positive neighbor refused", w.Code, w.Body.String())
	}
	body := strings.Replace(responsesRequest(true, false), "private-request-marker", keyMarker, 1)
	w := h.send(body)
	if w.Code != 403 || w.Body.String() != `{"error":"LEAK_CREDENTIAL"}` || h.calls.Load() != 1 {
		t.Fatal("Responses leaked key forwarded", w.Code, w.Body.String())
	}
	if v := h.status(t); v.Phase != "frozen" || v.Exposure != (Counts{7, 3, 1, 23}) {
		t.Fatal("rental leak did not freeze the record", v)
	}
	if h.send(responsesRequest(true, false)).Code != 401 || h.calls.Load() != 1 {
		t.Fatal("frozen rental record served")
	}
}

// Every explicit credential reveal in this package is inventoried by file,
// function and expression. A new reveal site must be reviewed here; the
// synthetic control proves the detector sees a planted reveal.
func TestGatewayRevealInventory(t *testing.T) {
	want := map[string]int{
		"admin.go:Credential.Valid:c.Bearer.Reveal()":             1,
		"credential.go:FileSource.read:f.current.Reveal()":        1,
		"credential.go:Service.issued:c.Value.Reveal()":           1,
		"credential.go:UpstreamCredential.valid:c.Value.Reveal()": 1,
		"credential.go:authenticate:c.Value.Reveal()":             1,
		"messages.go:Messages.Headers:key.Reveal()":               1,
		"private.go:credentialPrivateValue:s.Bearer.Reveal()":     1,
		"private.go:recordPrivateValue:s.Bearer.Reveal()":         1,
		"registry.go:Service.authorize:r.Bearer.Reveal()":         1,
		"registry.go:newService:c.APIKey.Reveal()":                3,
		"registry.go:newService:r.Bearer.Reveal()":                4,
		"responses.go:Responses.Headers:key.Reveal()":             1,
		"tripwire.go:Service.foreignBearer:r.Bearer.Reveal()":     1,
		"tripwire.go:Service.foreignLeak:r.Bearer.Reveal()":       1,
		"types.go:Credential.Equal:c.Bearer.Reveal()":             1,
		"types.go:Credential.Equal:other.Bearer.Reveal()":         1,
	}
	control := map[string]int{}
	revealInventory(t, "control.go", []byte("package control\nfunc expose(c Carrier) { _ = c.Value.Reveal() }\n"), control)
	if len(control) != 1 || control["control.go:expose:c.Value.Reveal()"] != 1 {
		t.Fatal("reveal detector control failed")
	}
	got := map[string]int{}
	entries, e := os.ReadDir(".")
	if e != nil {
		t.Fatal(e)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		raw, e := os.ReadFile(name)
		if e != nil {
			t.Fatal(e)
		}
		revealInventory(t, name, raw, got)
	}
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("credential reveal inventory changed; re-audit required: %v", got)
	}
}

func revealInventory(t *testing.T, path string, raw []byte, out map[string]int) {
	t.Helper()
	f, e := parser.ParseFile(token.NewFileSet(), path, raw, 0)
	if e != nil {
		t.Fatal("source parse refused", path)
	}
	render := func(n ast.Node) string {
		var b bytes.Buffer
		_ = format.Node(&b, token.NewFileSet(), n)
		return b.String()
	}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		owner := fn.Name.Name
		if fn.Recv != nil {
			typ := fn.Recv.List[0].Type
			if p, ok := typ.(*ast.StarExpr); ok {
				typ = p.X
			}
			owner = render(typ) + "." + fn.Name.Name
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Reveal" {
				out[path+":"+owner+":"+render(call)]++
			}
			return true
		})
	}
}
