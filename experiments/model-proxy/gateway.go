package modelproxy

import (
	"bytes"
	"context"
	"io"
	"net/http"
)

// admit runs the gateway checks both routes share before the body is read:
// bearer authorization including the account block, the foreign-bearer
// tripwire, the per-use credential and the request-line/header leak scan.
// A returned code is a refusal that made no reservation and no upstream call.
func (s *Service) admit(r *http.Request, id string, bearer Secret) (UpstreamCredential, int, string) {
	s.mu.Lock()
	_, e := s.authorize(id, bearer)
	s.mu.Unlock()
	if e != nil {
		code := e.Error()
		if accountingCode(code) {
			return UpstreamCredential{}, 503, code
		}
		if code == "ACCOUNT_BLOCKED" {
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

// refuse writes a gateway refusal. A foreign bearer is refused exactly as any
// other bad bearer; only the audit names the verdict.
func (s *Service) refuse(w http.ResponseWriter, id string, status int, code string) {
	body := code
	if code == "LEAK_BEARER" {
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
