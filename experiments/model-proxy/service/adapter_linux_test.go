//go:build linux

package service

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

const inferenceBody = `{"model":"qualified-model","max_tokens":12,"messages":[{"role":"user","content":"text"}]}`

var claude = Claude{Model: "qualified-model", APIVersion: "2026-10-21"}

func mapping() Mapping {
	return Mapping{Caller: caller, ServiceGeneration: "service-current", Listener: "listener-current", Policy: "policy-current", Placeholder: "placeholder-current"}
}
func incoming(t *testing.T, body string) *http.Request {
	t.Helper()
	r, e := http.NewRequest("POST", "http://listener/v1/messages", strings.NewReader(body))
	if e != nil {
		t.Fatal("fixture request unavailable")
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer placeholder-current")
	return r
}

type observedLife struct {
	Lifecycle
	events *[]string
}

func (l observedLife) Request(ctx context.Context, op string, caller Caller) (*Lease, error) {
	*l.events = append(*l.events, "material")
	return l.Lifecycle.Request(ctx, op, caller)
}
func (l observedLife) Check(ctx context.Context, lease *Lease) error {
	*l.events = append(*l.events, "poll")
	return l.Lifecycle.Check(ctx, lease)
}

type guard struct {
	events *[]string
	fail   string
	broker *fakeBroker
}

func (g guard) Validate(_ context.Context, m Mapping, op Operation, stage string) error {
	*g.events = append(*g.events, stage)
	if g.fail == stage || m.Listener != "listener-current" || m.Policy != "policy-current" || m.Caller != caller || m.ServiceGeneration != "service-current" || op.Class != "model-provider" || op.Action != "inference" || op.Resource != "qualified-model" {
		return ErrRole
	}
	return nil
}
func (g guard) Scan(_ context.Context, _ Mapping, r *http.Request, body []byte) error {
	*g.events = append(*g.events, "scan")
	if strings.Contains(r.Header.Get("Authorization"), fixtureMaterial) || strings.Contains(string(body), fixtureMaterial) {
		return ErrRole
	}
	if g.fail == "scan" {
		return ErrRole
	}
	return nil
}

// Claim: both current-authority guards and scanning precede material acquisition,
// and a protected placeholder becomes the leased token only on the fixed upstream.
// No provider request is sent; submission and response safety remain caller-owned.
func TestPrepareOrderingAndMapping(t *testing.T) {
	f := startFake(t)
	c := connect(t, f)
	var events []string
	in := incoming(t, inferenceBody)
	out, l, e := Prepare(context.Background(), observedLife{c, &events}, claude, guard{events: &events}, mapping(), in)
	if e != nil || out == nil || l == nil {
		t.Fatal("valid prepared request refused")
	}
	defer Drop(out)
	if strings.Join(events, ",") != "intake,scan,dequeue,material,poll,attachment" {
		t.Fatal("material ordering changed")
	}
	if out.Header.Get("Authorization") != "Bearer "+fixtureMaterial || out.Header.Get("Authorization") == in.Header.Get("Authorization") || in.Header.Get("Authorization") != "Bearer placeholder-current" {
		t.Fatal("placeholder mapping changed")
	}
	if out.URL.String() != "https://api.anthropic.com/v1/messages" || out.Header.Get("Anthropic-Version") != claude.APIVersion || out.Header.Get("Content-Type") != "application/json" || len(out.Header) != 3 {
		t.Fatal("recipient or headers widened")
	}
	b, e := io.ReadAll(out.Body)
	if e != nil || string(b) != inferenceBody {
		t.Fatal("inference bytes changed")
	}
	Drop(out)
	if out.Header.Get("Authorization") != "" {
		t.Fatal("holder authentication retained")
	}
}

// Claim: all pre-material rejections make zero broker lease requests. A final
// authority rejection closes the acquired handle and returns no prepared request.
func TestPrepareRefusalsBeforeMaterial(t *testing.T) {
	for _, mode := range []string{"placeholder", "alternate-auth", "unknown-body", "intake", "scan", "dequeue", "attachment", "listener", "policy", "generation", "caller", "missing-guard"} {
		t.Run(mode, func(t *testing.T) {
			f := startFake(t)
			c := connect(t, f)
			var events []string
			m := mapping()
			in := incoming(t, inferenceBody)
			g := guard{events: &events, fail: mode}
			var useGuard UseGuard = g
			switch mode {
			case "placeholder":
				in.Header.Set("Authorization", "Bearer wrong-placeholder")
			case "alternate-auth":
				in.Header.Set("X-Api-Key", fixtureMaterial)
			case "unknown-body":
				in = incoming(t, strings.Replace(inferenceBody, `"max_tokens":12`, `"max_tokens":12,"store":true`, 1))
			case "listener":
				m.Listener = "listener-stale"
			case "policy":
				m.Policy = "policy-stale"
			case "generation":
				m.ServiceGeneration = "service-stale"
			case "caller":
				m.Caller.Account = "account-b"
			case "missing-guard":
				useGuard = nil
			}
			out, l, e := Prepare(context.Background(), observedLife{c, &events}, claude, useGuard, m, in)
			if e == nil || out != nil || l != nil {
				t.Fatal("invalid prepare released request")
			}
			count := 0
			f.mu.Lock()
			for _, method := range f.calls {
				if method == "service.lease.request" {
					count++
				}
			}
			f.mu.Unlock()
			if mode == "attachment" {
				if count != 1 {
					t.Fatal("final-guard witness missed acquisition")
				}
				c.mu.Lock()
				defer c.mu.Unlock()
				for handle := range c.leases {
					empty(t, handle)
				}
			} else if count != 0 {
				t.Fatal("material requested before rejection")
			}
		})
	}
}

// Claim: only the declared complete inference subset is classified. Unknown or
// mutating members, duplicates, aliases, nulls, alternate routes and auth refuse
// beside the unchanged valid request, before any material can be attached.
func TestClaudeClosedClassification(t *testing.T) {
	for _, mode := range []string{"valid", "store", "tools", "duplicate", "alias", "null", "unknown-model", "stream", "query", "route", "method", "encoding", "framing", "empty", "budget"} {
		t.Run(mode, func(t *testing.T) {
			body := inferenceBody
			switch mode {
			case "store":
				body = strings.Replace(body, `"max_tokens":12`, `"max_tokens":12,"store":true`, 1)
			case "tools":
				body = strings.Replace(body, `"max_tokens":12`, `"max_tokens":12,"tools":[]`, 1)
			case "duplicate":
				body = strings.Replace(body, `"max_tokens":12`, `"max_tokens":12,"max_tokens":12`, 1)
			case "alias":
				body = strings.Replace(body, `"model":`, `"MODEL":`, 1)
			case "null":
				body = strings.Replace(body, `"content":"text"`, `"content":null`, 1)
			case "unknown-model":
				body = strings.Replace(body, "qualified-model", "other-model", 1)
			case "stream":
				body = strings.Replace(body, `"max_tokens":12`, `"max_tokens":12,"stream":true`, 1)
			case "empty":
				body = strings.Replace(body, `"content":"text"`, `"content":""`, 1)
			case "budget":
				body = strings.Repeat(" ", 65537) + body
			}
			r := incoming(t, body)
			switch mode {
			case "query":
				r.URL.RawQuery = "recipient=other"
			case "route":
				r.URL.Path = "/v1/files"
			case "method":
				r.Method = "CONNECT"
			case "encoding":
				r.Header.Set("Content-Encoding", "gzip")
			case "framing":
				r.TransferEncoding = []string{"chunked"}
			}
			op, _, e := claude.Classify(r)
			if mode == "valid" {
				if e != nil || op.Action != "inference" {
					t.Fatal("valid inference refused")
				}
			} else if !errors.Is(e, ErrInput) {
				t.Fatal("unsupported request accepted")
			}
		})
	}
}

// Claim: injection refuses another origin, Host override, existing auth, expired
// or revoked material, and another kind. An unchanged protected recipient works.
func TestClaudeAttachmentBoundaries(t *testing.T) {
	for _, mode := range []string{"valid", "recipient", "host", "auth", "expiry", "revoked", "kind"} {
		t.Run(mode, func(t *testing.T) {
			f := startFake(t)
			c := connect(t, f)
			l := lease(t, c)
			r, e := claude.Build(context.Background(), []byte(inferenceBody))
			if e != nil {
				t.Fatal("fixture build refused")
			}
			switch mode {
			case "recipient":
				r.URL.Host = "other.invalid"
			case "host":
				r.Host = "other.invalid"
			case "auth":
				r.Header.Set("Authorization", "supplied")
			case "expiry":
				l.mu.Lock()
				l.until = l.until.Add(-2e11)
				l.mu.Unlock()
			case "revoked":
				l.close()
			case "kind":
				l.mu.Lock()
				l.kind = "other-kind"
				l.mu.Unlock()
			}
			e = claude.Attach(r, l)
			if mode == "valid" {
				if e != nil {
					t.Fatal("valid injection refused")
				}
				Drop(r)
			} else if e == nil || strings.Contains(r.Header.Get("Authorization"), fixtureMaterial) {
				t.Fatal("invalid injection released material")
			}
		})
	}
}

type emptyLifecycle struct{ Lifecycle }

func (emptyLifecycle) Request(context.Context, string, Caller) (*Lease, error) { return &Lease{}, nil }

// Claim: a broken lifecycle returning an empty handle cannot turn successful
// admission guards into material use or a panic; the valid lifecycle is nearby.
func TestPrepareMissingMaterialHandle(t *testing.T) {
	f := startFake(t)
	c := connect(t, f)
	var events []string
	r, l, e := Prepare(context.Background(), emptyLifecycle{c}, claude, guard{events: &events}, mapping(), incoming(t, inferenceBody))
	if r != nil || l != nil || e != ErrUnavailable {
		t.Fatal("missing material handle accepted")
	}
}

type faultLifecycle struct {
	Lifecycle
	stage string
}

func (f faultLifecycle) Request(ctx context.Context, op string, c Caller) (*Lease, error) {
	if f.stage == "request" {
		return nil, errors.New(fixtureMaterial)
	}
	return f.Lifecycle.Request(ctx, op, c)
}
func (f faultLifecycle) Check(ctx context.Context, l *Lease) error {
	if f.stage == "poll" {
		return Code(fixtureMaterial)
	}
	return f.Lifecycle.Check(ctx, l)
}

type faultAdapter struct {
	RequestAdapter
	stage string
}

func (f faultAdapter) Classify(r *http.Request) (Operation, []byte, error) {
	if f.stage == "classify" {
		return Operation{}, nil, errors.New(fixtureMaterial)
	}
	return f.RequestAdapter.Classify(r)
}
func (f faultAdapter) Build(ctx context.Context, b []byte) (*http.Request, error) {
	if f.stage == "build" {
		return nil, errors.New(fixtureMaterial)
	}
	return f.RequestAdapter.Build(ctx, b)
}
func (f faultAdapter) Attach(r *http.Request, l *Lease) error {
	if f.stage == "attach" {
		return errors.New(fixtureMaterial)
	}
	return f.RequestAdapter.Attach(r, l)
}

// Claim: opaque errors (including a forged Code) from either adapter half are
// sanitized and return no prepared request or handle; the valid seam is nearby.
func TestPrepareErrorSanitization(t *testing.T) {
	for _, stage := range []string{"classify", "request", "poll", "build", "attach"} {
		t.Run(stage, func(t *testing.T) {
			f := startFake(t)
			c := connect(t, f)
			var events []string
			r, l, e := Prepare(context.Background(), faultLifecycle{c, stage}, faultAdapter{claude, stage}, guard{events: &events}, mapping(), incoming(t, inferenceBody))
			want := ErrUnavailable
			if stage == "build" {
				want = ErrInput
			}
			if r != nil || l != nil || e != want || strings.Contains(e.Error(), fixtureMaterial) {
				t.Fatal("opaque adapter error escaped seam")
			}
		})
	}
}

type fixedLeaseLife struct {
	Lifecycle
	lease *Lease
}

func (l fixedLeaseLife) Request(context.Context, string, Caller) (*Lease, error) {
	return l.lease, nil
}

// Claim: Prepare itself rejects a mismatched acquired lease before polling or
// attachment, even when the pre-acquisition fixture guard accepts the mapping.
func TestPrepareLeaseMapping(t *testing.T) {
	for _, mode := range []string{"valid", "generation", "caller"} {
		t.Run(mode, func(t *testing.T) {
			f := startFake(t)
			c := connect(t, f)
			l := lease(t, c)
			switch mode {
			case "generation":
				c.cfg.Generation = "service-retired"
			case "caller":
				l.caller.LaunchID = "other-launch"
			}
			f.mu.Lock()
			before := len(f.calls)
			f.mu.Unlock()
			var events []string
			out, got, err := Prepare(context.Background(), fixedLeaseLife{c, l}, claude, guard{events: &events}, mapping(), incoming(t, inferenceBody))
			if mode == "valid" {
				if err != nil || out == nil || got != l {
					t.Fatal("valid acquired mapping refused")
				}
				Drop(out)
				return
			}
			if err != ErrRole || out != nil || got != nil {
				t.Fatal("mismatched lease reached attachment")
			}
			empty(t, l)
			f.mu.Lock()
			defer f.mu.Unlock()
			if len(f.calls) != before {
				t.Fatal("mismatched lease reached poll")
			}
		})
	}
}
