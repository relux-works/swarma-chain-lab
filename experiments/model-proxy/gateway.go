package modelproxy

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
)

// routeSlot names the slot of a well-formed route for the audit record only;
// every other request keeps the empty id of the early refusals.
func routeSlot(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) == 5 && parts[1] == "slots" && parts[3] == "v1" && digest(parts[2]) {
		return parts[2]
	}
	return ""
}

// singleBearer returns the one Authorization bearer a request carries; any
// other shape is not a valid binding presentation.
func singleBearer(r *http.Request) (Secret, bool) {
	h := r.Header.Values("Authorization")
	if len(h) != 1 || !strings.HasPrefix(h[0], "Bearer ") {
		return "", false
	}
	return Secret(strings.TrimPrefix(h[0], "Bearer ")), true
}

// screen is the first verdict on every request, before the route, the bearer
// count and authorize: the request line and every header are scanned against
// every credential version issued so far, so an issued value is caught even as
// the bearer itself, beside several Authorization headers, with an invalid
// bearer, on an unknown slot, or while the source is down. With a valid binding
// on the route the account is blocked as for any leak; without one no block is
// possible, the client sees a plain 401 AUTH and the audit records
// LEAK_CREDENTIAL. The version the source issues for this very request is not
// known yet here; admit scans again once it is.
func (s *Service) screen(w http.ResponseWriter, r *http.Request) bool {
	if !s.tripwire.request(r) {
		return false
	}
	id := routeSlot(r.URL.Path)
	status, code := 401, "LEAK_CREDENTIAL"
	if bearer, ok := singleBearer(r); ok && id != "" {
		s.mu.Lock()
		_, e := s.authorize(id, bearer)
		s.mu.Unlock()
		if e == nil {
			status, code = s.inspect(id, true)
		}
	}
	s.refuse(w, id, status, code)
	return true
}

// admit runs the gateway checks both routes share before the body is read:
// bearer authorization including the account block and the run re-check, the
// foreign-bearer tripwire, the per-use credential and the request-line/header
// leak scan against the version just issued (screen already scanned with the
// versions known before it). A returned code is a refusal that made no
// reservation and no upstream call.
func (s *Service) admit(r *http.Request, id string, bearer Secret) (UpstreamCredential, int, string) {
	s.mu.Lock()
	_, e := s.authorize(id, bearer)
	s.mu.Unlock()
	if e != nil {
		code := e.Error()
		if accountingCode(code) {
			return UpstreamCredential{}, 503, code
		}
		if code == "ACCOUNT_BLOCKED" || code == "RUN_REQUIRES_MANAGED" || code == "RUN_WINDOW" {
			return UpstreamCredential{}, 403, code
		}
		switch verdict := s.foreignBearer(id, bearer); verdict {
		case "":
			return UpstreamCredential{}, 401, "AUTH"
		case "LEAK_BEARER":
			return UpstreamCredential{}, 401, verdict
		default:
			return UpstreamCredential{}, 503, verdict
		}
	}
	cred, e := s.upstreamCredential(r.Context())
	if e != nil {
		return UpstreamCredential{}, 503, "CREDENTIAL_UNAVAILABLE"
	}
	if status, code := s.inspect(id, s.tripwire.request(r)); code != "" {
		return UpstreamCredential{}, status, code
	}
	return cred, 0, ""
}

// inspectBody scans the assembled body. Transfer chunking is already
// reassembled here; the scanner's tail window covers a split inside a needle.
func (s *Service) inspectBody(id string, raw []byte) (int, string) {
	return s.inspect(id, s.tripwire.body(raw))
}

// refuse writes a gateway refusal. A foreign bearer, and a leak with no valid
// binding behind it, are refused exactly as any other bad bearer; only the
// audit names the verdict.
func (s *Service) refuse(w http.ResponseWriter, id string, status int, code string) {
	body := code
	if code == "LEAK_BEARER" || (code == "LEAK_CREDENTIAL" && status == 401) {
		body = "AUTH"
	}
	refusal(w, status, body)
	s.audit(id, status, code, Usage{})
}

// exchange performs the upstream call. After an explicit 401, and only then,
// it asks the source for a renewal naming the rejected version and retries
// once with the renewed credential. A transport error has an unknown outcome
// and any other status has begun its response: neither is ever retried.
func (s *Service) exchange(call context.Context, req *http.Request, body []byte, d Dialect, cred UpstreamCredential, transport http.RoundTripper) (*http.Response, error) {
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return fail("REDIRECT") }}
	authenticate(req.Header, d, cred)
	resp, e := client.Do(req)
	if e != nil {
		return nil, fail("UPSTREAM")
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, MaxBody))
	resp.Body.Close()
	renewed, e := s.renewCredential(call, cred.Version)
	if e != nil || renewed.Version == cred.Version || call.Err() != nil {
		return nil, fail("CREDENTIAL_REJECTED")
	}
	again := req.Clone(call)
	again.Body = io.NopCloser(bytes.NewReader(body))
	again.ContentLength = int64(len(body))
	authenticate(again.Header, d, renewed)
	resp, e = client.Do(again)
	if e != nil {
		return nil, fail("UPSTREAM")
	}
	return resp, nil
}
