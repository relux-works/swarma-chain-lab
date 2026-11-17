//go:build linux

package service

import (
	"bytes"
	"context"
	"crypto/subtle"
	"io"
	"net/http"

	"github.com/relux-works/swarma-chain-lab/experiments/model-proxy/service/internal/wire"
)

// Lifecycle is the credential-lifecycle half. Enrollment, refresh and vendor
// invalidation stay broker-owned; this gateway interface only leases and holds.
// Neither interface below enumerates account kinds or selects an account.
type Lifecycle interface {
	Request(context.Context, string, Caller) (*Lease, error)
	Renew(context.Context, string, *Lease) error
	Check(context.Context, *Lease) error
	Hold(context.Context, string, *Lease) error
	Release(context.Context, *Lease) error
}
type Operation struct{ Class, Action, Resource string }
type RequestAdapter interface {
	Kind() string
	Classify(*http.Request) (Operation, []byte, error)
	Build(context.Context, []byte) (*http.Request, error)
	Attach(*http.Request, *Lease) error
}

// Mapping is supplied by a protected qualified listener/launch registry. The
// placeholder is not caller authority, and no mapping crosses generations.
type Mapping struct {
	Caller            Caller
	ServiceGeneration string
	Listener          string
	Policy            string
	Placeholder       string
}

// UseGuard owns current service AND caller authority, listener/launch/policy,
// issued-version inventory, pre-injection scanning and registered revocable use.
// A nil/missing guard refuses. It must not rely on cached lease admission.
// Implementations must hold no state lock across another service's I/O.
type UseGuard interface {
	Validate(context.Context, Mapping, Operation, string) error
	Scan(context.Context, Mapping, *http.Request, []byte) error
}

// Prepare builds an in-memory request for a trusted gateway holder. It performs
// no network I/O and makes no submission/response/stream-closure claim. The next
// owner must revalidate after dialing/waits before submitting this request.
func Prepare(ctx context.Context, life Lifecycle, adapter RequestAdapter, guard UseGuard, m Mapping, in *http.Request) (*http.Request, *Lease, error) {
	if ctx == nil || life == nil || adapter == nil || guard == nil || in == nil || !valid(m.Placeholder) || !valid(m.ServiceGeneration) || !valid(m.Listener) || !valid(m.Policy) {
		return nil, nil, ErrInput
	}
	if len(in.Header.Values("Authorization")) != 1 || subtle.ConstantTimeCompare([]byte(in.Header.Get("Authorization")), []byte("Bearer "+m.Placeholder)) != 1 {
		return nil, nil, ErrRole
	}
	op, body, e := adapter.Classify(in)
	if e != nil {
		return nil, nil, sanitized(e)
	}
	if e = guard.Validate(ctx, m, op, "intake"); e != nil {
		return nil, nil, ErrRole
	}
	// Agent bytes must be scanned before any real material is requested/attached.
	if e = guard.Scan(ctx, m, in, body); e != nil {
		return nil, nil, ErrRole
	}
	if e = guard.Validate(ctx, m, op, "dequeue"); e != nil {
		return nil, nil, ErrRole
	}
	id, e := OperationID()
	if e != nil {
		return nil, nil, e
	}
	lease, e := life.Request(ctx, id, m.Caller)
	if e != nil {
		return nil, nil, sanitized(e)
	}
	if lease == nil || lease.leaseState == nil {
		return nil, nil, ErrUnavailable
	}
	fail := func(err error) (*http.Request, *Lease, error) { lease.close(); return nil, nil, err }
	if lease.owner == nil || lease.owner.cfg.Generation != m.ServiceGeneration || lease.caller != m.Caller {
		return fail(ErrRole)
	}
	if e = life.Check(ctx, lease); e != nil {
		return fail(sanitized(e))
	}
	if e = guard.Validate(ctx, m, op, "attachment"); e != nil {
		return fail(ErrRole)
	}
	out, e := adapter.Build(ctx, body)
	if e != nil {
		return fail(ErrInput)
	}
	if e = adapter.Attach(out, lease); e != nil {
		return fail(sanitized(e))
	}
	return out, lease, nil
}

// Claude is the only request adapter. It accepts a bounded non-streaming text
// Messages subset. Model and API version come from protected qualified policy.
// This fixture-tested seam alone does not qualify OAuth billing or a harness.
type Claude struct {
	Model      string
	APIVersion string
}

func (Claude) Kind() string { return "claude-oauth-token" }
func (a Claude) Classify(r *http.Request) (Operation, []byte, error) {
	if r == nil || r.URL == nil || r.Method != http.MethodPost || r.URL.EscapedPath() != "/v1/messages" || r.URL.RawQuery != "" || r.URL.Fragment != "" || r.URL.User != nil || r.Header.Get("Content-Type") != "application/json" || len(r.TransferEncoding) != 0 || !valid(a.Model) || !valid(a.APIVersion) {
		return Operation{}, nil, ErrInput
	}
	for key := range r.Header {
		if key != "Authorization" && key != "Content-Type" {
			return Operation{}, nil, ErrInput
		}
	}
	if r.Body == nil {
		return Operation{}, nil, ErrInput
	}
	b, e := io.ReadAll(io.LimitReader(r.Body, 65537))
	if e != nil || len(b) > 65536 {
		return Operation{}, nil, ErrInput
	}
	// Require a closed JSON tree. wire.Decode also rejects duplicates, case
	// aliases, null primitives and absent nested members without reflecting bytes.
	var input struct {
		Model    string `json:"model"`
		Max      int    `json:"max_tokens"`
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}
	if wireDecode(b, &input) != nil || input.Model != a.Model || input.Max < 1 || input.Max > 8192 || len(input.Messages) == 0 || len(input.Messages) > 64 {
		return Operation{}, nil, ErrInput
	}
	for _, m := range input.Messages {
		if m.Role != "user" && m.Role != "assistant" || m.Content == "" {
			return Operation{}, nil, ErrInput
		}
	}
	return Operation{Class: "model-provider", Action: "inference", Resource: a.Model}, b, nil
}
func (a Claude) Build(ctx context.Context, body []byte) (*http.Request, error) {
	r, e := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.anthropic.com/v1/messages", bytes.NewReader(body))
	if e != nil {
		return nil, ErrInput
	}
	return r, nil
}
func (a Claude) Attach(r *http.Request, l *Lease) error {
	if r == nil || r.URL == nil || l == nil || l.leaseState == nil || r.URL.String() != "https://api.anthropic.com/v1/messages" || r.Method != http.MethodPost || r.Host != "api.anthropic.com" || !valid(a.APIVersion) {
		return ErrInput
	}
	if len(r.Header) != 0 {
		return ErrInput
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.live() || l.kind != a.Kind() || l.harness != "claude_code" {
		return ErrInactive
	}
	r.Header.Set("Authorization", "Bearer "+string(l.value))
	r.Header.Set("Anthropic-Version", a.APIVersion)
	r.Header.Set("Content-Type", "application/json")
	return nil
}

// wireDecode intentionally validates semantic JSON, not canonical HTTP bodies.
// The copied broker decoder provides the same closed-member/duplicate rules.
func wireDecode(b []byte, out any) error { return wire.Decode(b, out) }

// Drop removes holder-owned authentication after submission or failure. HTTP
// request copies retained by a transport remain its custody responsibility.
func Drop(r *http.Request) {
	if r != nil {
		r.Header.Del("Authorization")
	}
}

var _ Lifecycle = (*Client)(nil)
var _ RequestAdapter = Claude{}
