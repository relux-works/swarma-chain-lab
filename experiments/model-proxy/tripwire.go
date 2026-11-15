package modelproxy

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// MinTripwireBytes is the shortest credential value the tripwire matches.
// Shorter values are never matched, so they cannot cause false positives.
const MinTripwireBytes = 16

// tripwireChunk is the feed size used for an assembled body; the scanner's
// tail window makes a needle split across feeds still match.
const tripwireChunk = 4096

// tripwire holds every recognized spelling of every upstream credential value
// issued in this process. It lives only in memory behind a pointer: it is
// never formatted, persisted, audited or exposed through Status.
type tripwire struct {
	mu      sync.RWMutex
	seen    map[string]bool
	needles [][]byte
	window  int
}

func newTripwire() *tripwire { return &tripwire{seen: map[string]bool{}} }

// forms lists the plaintext spellings matched for one value: raw, base64 and
// base64url with and without padding, lower and upper hex, percent-encoding
// (query, path and every-byte in both hex cases) and JSON string escaping
// (with and without HTML escaping). Identical spellings are kept once.
func forms(value []byte) [][]byte {
	if len(value) < MinTripwireBytes {
		return nil
	}
	var out [][]byte
	add := func(s string) {
		for _, have := range out {
			if string(have) == s {
				return
			}
		}
		out = append(out, []byte(s))
	}
	add(string(value))
	add(base64.StdEncoding.EncodeToString(value))
	add(base64.RawStdEncoding.EncodeToString(value))
	add(base64.URLEncoding.EncodeToString(value))
	add(base64.RawURLEncoding.EncodeToString(value))
	lower := hex.EncodeToString(value)
	add(lower)
	add(strings.ToUpper(lower))
	add(url.QueryEscape(string(value)))
	add(url.PathEscape(string(value)))
	var upper, lowerPercent strings.Builder
	for _, b := range value {
		fmt.Fprintf(&upper, "%%%02X", b)
		fmt.Fprintf(&lowerPercent, "%%%02x", b)
	}
	add(upper.String())
	add(lowerPercent.String())
	if escaped, e := json.Marshal(string(value)); e == nil && len(escaped) >= 2 {
		add(string(escaped[1 : len(escaped)-1]))
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if enc.Encode(string(value)) == nil {
		escaped := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
		if len(escaped) >= 2 {
			add(string(escaped[1 : len(escaped)-1]))
		}
	}
	return out
}

// add registers one issued value. It reports false only when the bound on
// remembered values is reached; the caller then refuses the credential.
func (t *tripwire) add(value Secret) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	key := sum([]byte(value))
	if t.seen[key] {
		return true
	}
	if len(t.seen) >= MaxCredentialVersions {
		return false
	}
	t.seen[key] = true
	for _, f := range forms([]byte(value)) {
		t.needles = append(t.needles, f)
		if len(f) > t.window {
			t.window = len(f)
		}
	}
	return true
}

// scanner matches across chunk boundaries by retaining a tail one byte
// shorter than the longest needle, so a value split over any number of
// chunks is still found. The tail is bounded by the longest needle form.
type scanner struct {
	t    *tripwire
	tail []byte
}

func (t *tripwire) scanner() *scanner { return &scanner{t: t} }

func (s *scanner) feed(chunk []byte) bool {
	s.t.mu.RLock()
	defer s.t.mu.RUnlock()
	if len(s.t.needles) == 0 {
		return false
	}
	buf := append(append([]byte(nil), s.tail...), chunk...)
	hit := false
	for _, n := range s.t.needles {
		if bytes.Contains(buf, n) {
			hit = true
			break
		}
	}
	keep := s.t.window - 1
	if keep < 0 {
		keep = 0
	}
	if len(buf) > keep {
		buf = buf[len(buf)-keep:]
	}
	s.tail = append([]byte(nil), buf...)
	return hit
}

// request scans the request line and every header line.
func (t *tripwire) request(r *http.Request) bool {
	sc := t.scanner()
	if sc.feed([]byte(r.Method + " " + r.URL.RequestURI() + " " + r.Host)) {
		return true
	}
	for k, vs := range r.Header {
		for _, v := range vs {
			if sc.feed([]byte(k + ": " + v)) {
				return true
			}
		}
	}
	return false
}

// body scans an assembled body in bounded chunks through one scanner.
func (t *tripwire) body(raw []byte) bool {
	sc := t.scanner()
	for off := 0; off < len(raw); off += tripwireChunk {
		end := off + tripwireChunk
		if end > len(raw) {
			end = len(raw)
		}
		if sc.feed(raw[off:end]) {
			return true
		}
	}
	return false
}

// inspect turns a scan hit into a durable verdict before any upstream I/O. The
// refusal names only the fixed code; neither the body nor the value is kept.
func (s *Service) inspect(id string, hit bool) (int, string) {
	if !hit {
		return 0, ""
	}
	if e := s.block(id, "LEAK_CREDENTIAL"); e != nil {
		return 503, e.Error()
	}
	return 403, "LEAK_CREDENTIAL"
}

// block persists the verdict with the same atomic save as every other state
// change; a failed save poisons the process closed. A run binding's account
// is blocked. A rental binding has no account, so its own record is frozen.
func (s *Service) block(id, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.poisoned {
		return fail("UNAVAILABLE")
	}
	r, ok := s.state.Records[id]
	if !ok {
		return nil
	}
	if r.Binding.Kind() == KindRun {
		s.blockAccount(r.Binding.Run.Account, code)
	} else {
		r.Phase = "frozen"
		s.state.Records[id] = r
	}
	if cancel := s.cancel[id]; cancel != nil {
		cancel()
	}
	return s.save()
}

// blockAccount and isBlocked run under mu.
func (s *Service) blockAccount(account, code string) {
	if s.state.Blocked == nil {
		s.state.Blocked = map[string]string{}
	}
	s.state.Blocked[account] = code
}
func (s *Service) isBlocked(b Binding) bool {
	return b.Kind() == KindRun && s.state.Blocked[b.Run.Account] != ""
}
func blockCode(code string) bool { return code == "LEAK_BEARER" || code == "LEAK_CREDENTIAL" }

// foreignBearer handles a bearer presented on another binding's route. It
// returns LEAK_BEARER after durably blocking the owning run binding's account,
// a persistence code when that save failed, or "" when the bearer belongs to
// no other binding or to a rental binding, which keeps today's refusal only.
func (s *Service) foreignBearer(id string, bearer Secret) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.poisoned {
		return ""
	}
	for other, r := range s.state.Records {
		if other == id || subtle.ConstantTimeCompare([]byte(bearer), []byte(r.Bearer.Reveal())) != 1 {
			continue
		}
		if r.Binding.Kind() != KindRun {
			return ""
		}
		s.blockAccount(r.Binding.Run.Account, "LEAK_BEARER")
		if cancel := s.cancel[other]; cancel != nil {
			cancel()
		}
		if e := s.save(); e != nil {
			return e.Error()
		}
		return "LEAK_BEARER"
	}
	return ""
}

// ClearBlock is the explicit owner operation that lifts an account block. It
// is reached only through the peer-checked admin socket, like Prepare.
func (s *Service) ClearBlock(account string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.poisoned {
		return fail("UNAVAILABLE")
	}
	if !digest(account) || s.state.Blocked[account] == "" {
		return fail("NOT_FOUND")
	}
	delete(s.state.Blocked, account)
	if len(s.state.Blocked) == 0 {
		s.state.Blocked = nil
	}
	return s.save()
}
