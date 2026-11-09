package grantcheck

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"relux.works/swarma-chain-lab/experiments/rental"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/kernel"
	"relux.works/swarma-chain-lab/experiments/single-use/durable"
)

type nodeFunc func(context.Context, string, ...any) (json.RawMessage, error)

func (f nodeFunc) Call(ctx context.Context, method string, args ...any) (json.RawMessage, error) {
	return f(ctx, method, args...)
}

func unitConfig(t *testing.T) Config {
	t.Helper()
	return Config{Identity: "test-identity", AgentName: "id/test-agent", LandlordName: "id/test-landlord", IssuerPubkey: xonly(1), StateDir: stateDir(t), Now: func() time.Time { return time.Unix(500, 0) }, Node: nodeFunc(func(context.Context, string, ...any) (json.RawMessage, error) {
		return nil, errors.New("sensitive-node-marker")
	})}
}
func unitChecker(t *testing.T) (*Checker, *kernel.Stub, Presentation) {
	t.Helper()
	c, err := New(unitConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	raw := unitGrant(t)
	id, err := kernel.PresentationID(raw)
	if err != nil {
		t.Fatal(err)
	}
	b := &kernel.Stub{Handler: func(_ context.Context, raw []byte, agent, sender string, now int64) (kernel.Receipt, error) {
		g := proofGrant(t, raw)
		return kernel.Receipt{Verdict: "live", Reason: "LIVE", GrantID: g.ID(), AgentName: agent, LandlordName: g.Grant.LandlordName, Scope: g.Grant.Scope, CheckedAt: now}, nil
	}}
	c.backend = b
	return c, b, Presentation{GrantID: id, Bytes: raw}
}
func assertVerdict(t *testing.T, v Verdict, decision Decision, code Code, closed, retry bool) {
	t.Helper()
	if v.Decision != decision || v.Code != code || v.Closed != closed || v.Retryable != retry {
		t.Fatalf("verdict contract want %s/%s closed=%v retry=%v; got %+v", decision, code, closed, retry, v)
	}
	if v.Decision != Live && len(v.Scope) != 0 {
		t.Fatal("refusal leaked actionable scope")
	}
}

// Explicit bad proofs and keys fail before state/node/backend work and cannot
// replace a valid cache. Exact size boundary reaches framing, never oversize.
func TestInputBoundary(t *testing.T) {
	c, b, p := unitChecker(t)
	ctx := context.Background()
	peer := xonly(2)
	assertVerdict(t, c.Inbound(ctx, peer, &p), Live, CodeLive, false, false)
	before := b.PresentCalls
	for _, tc := range []struct {
		name, peer string
		p          Presentation
		code       Code
	}{
		{"foreign", xonly(3), p, CodeBindingMismatch},
		{"empty", peer, Presentation{}, CodeInvalidPresentation},
		{"malformed", peer, Presentation{Bytes: []byte("{broken")}, CodeInvalidPresentation},
		{"bad-id", peer, Presentation{GrantID: strings.Repeat("0", 64), Bytes: p.Bytes}, CodeInvalidPresentation},
		{"legacy", peer, Presentation{GrantID: p.GrantID, Bytes: []byte(strings.Replace(string(p.Bytes), `"version":3`, `"version":2`, 1))}, CodeInvalidPresentation},
		{"size-limit", peer, Presentation{Bytes: make([]byte, 16384)}, CodeInvalidPresentation},
		{"oversize", peer, Presentation{Bytes: make([]byte, 16385)}, CodeOversize},
		{"peer", strings.ToUpper(peer), p, CodeInvalidPeer},
		{"invalid-curve", strings.Repeat("f", 64), p, CodeInvalidPeer},
		{"peer-bound", strings.Repeat("a", 16385), p, CodeInvalidPeer},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertVerdict(t, c.Inbound(ctx, tc.peer, &tc.p), Refused, tc.code, false, false)
			if b.PresentCalls != before {
				t.Fatal("invalid input reached backend")
			}
			if string(b.Cached[peer]) != string(p.Bytes) {
				t.Fatal("invalid input replaced cache")
			}
		})
	}
	assertVerdict(t, c.Outbound(ctx, peer), Live, CodeLive, false, false)
}

// Cached bytes trigger Check each time; only explicit live inbound uses Present.
// A closed or unavailable fresh result never falls back to a prior live verdict.
func TestFreshCacheAndOutbound(t *testing.T) {
	c, b, p := unitChecker(t)
	ctx := context.Background()
	peer := xonly(2)
	assertVerdict(t, c.Inbound(ctx, peer, nil), Exchange, CodeNoGrant, false, false)
	assertVerdict(t, c.Outbound(ctx, peer), Refused, CodeNoGrant, false, false)
	assertVerdict(t, c.Inbound(ctx, peer, &p), Live, CodeLive, false, false)
	n := b.Calls
	assertVerdict(t, c.Inbound(ctx, peer, nil), Live, CodeLive, false, false)
	assertVerdict(t, c.Outbound(ctx, peer), Live, CodeLive, false, false)
	if b.Calls != n+2 || b.PresentCalls != 1 {
		t.Fatal("cache bypassed fresh check")
	}
	old := b.Handler
	b.Handler = func(ctx context.Context, raw []byte, a, s string, n int64) (kernel.Receipt, error) {
		r, e := old(ctx, raw, a, s, n)
		r.Verdict = "refused"
		r.Reason = "SEAL_SPENT"
		r.Closed = true
		return r, e
	}
	assertVerdict(t, c.Inbound(ctx, peer, nil), Exchange, CodeSealSpent, true, false)
	assertVerdict(t, c.Outbound(ctx, peer), Refused, CodeSealSpent, true, false)
	b.Handler = func(ctx context.Context, raw []byte, a, s string, n int64) (kernel.Receipt, error) {
		r, e := old(ctx, raw, a, s, n)
		r.Verdict = "refused"
		r.Reason = "RPC_UNAVAILABLE"
		return r, e
	}
	assertVerdict(t, c.Inbound(ctx, peer, nil), Refused, CodeVerifierUnavailable, false, true)
	assertVerdict(t, c.Outbound(ctx, xonly(3)), Refused, CodeNoGrant, false, false)
}

// Even an apparently live backend result must match every signed binding and
// fresh time, have the expected scope, no error, and no contradictory closure.
func TestInconsistentReceipts(t *testing.T) {
	for _, name := range []string{"closed-live", "error-live", "grant", "agent", "landlord", "clock", "scope", "unknown", "live-reason", "missing-closure"} {
		t.Run(name, func(t *testing.T) {
			c, b, p := unitChecker(t)
			old := b.Handler
			b.Handler = func(ctx context.Context, raw []byte, a, s string, n int64) (kernel.Receipt, error) {
				r, e := old(ctx, raw, a, s, n)
				switch name {
				case "closed-live":
					r.Closed = true
				case "error-live":
					e = errors.New("sensitive-node-marker")
				case "grant":
					r.GrantID = strings.Repeat("a", 64)
				case "agent":
					r.AgentName = "id/foreign"
				case "landlord":
					r.LandlordName = "id/foreign"
				case "clock":
					r.CheckedAt++
				case "scope":
					r.Scope = []string{"secret.release"}
				case "unknown":
					r.Verdict = "refused"
					r.Reason = "sensitive-node-marker"
				case "live-reason":
					r.Reason = "SEAL_SPENT"
				case "missing-closure":
					r.Verdict = "refused"
					r.Reason = "SEAL_SPENT"
				}
				return r, e
			}
			v := c.Inbound(context.Background(), xonly(2), &p)
			assertVerdict(t, v, Refused, CodeCheckFailed, false, false)
			if strings.Contains(string(jsonBytes(t, v)), "sensitive-node-marker") {
				t.Fatal("backend text escaped")
			}
		})
	}
}

// Identity/policy bindings survive restart. Neither relabeling an existing
// store nor adopting unbound K1 state may create a usable checker.
func TestStateBinding(t *testing.T) {
	config := unitConfig(t)
	c, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = New(config); err != nil {
		t.Fatal("same identity restart refused")
	}
	before, err := os.ReadFile(filepath.Join(config.StateDir, stateName))
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"identity", "agent", "landlord", "issuer"} {
		x := config
		switch field {
		case "identity":
			x.Identity = "other"
		case "agent":
			x.AgentName = "id/other"
		case "landlord":
			x.LandlordName = "id/other"
		case "issuer":
			x.IssuerPubkey = xonly(3)
		}
		if got, e := New(x); got != nil || e != ErrState {
			t.Fatalf("state relabeled through %s", field)
		}
	}
	after, err := os.ReadFile(filepath.Join(config.StateDir, stateName))
	if err != nil || string(after) != string(before) {
		t.Fatal("failed constructor mutated binding")
	}
	if err = os.Remove(filepath.Join(config.StateDir, stateName)); err != nil {
		t.Fatal(err)
	}
	assertVerdict(t, c.Outbound(context.Background(), xonly(2)), Refused, CodeStateUnavailable, false, true)
	if err = os.WriteFile(filepath.Join(config.StateDir, "grant-old.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, e := New(config); e != ErrState {
		t.Fatal("unbound K1 state adopted")
	}
}

// Private state and canonical parsing remain enforced after construction; file
// corruption, broad permissions, symlinks and another holder deny without I/O fallback.
func TestStateFailures(t *testing.T) {
	for _, name := range []string{"mode", "corrupt", "link", "lock"} {
		t.Run(name, func(t *testing.T) {
			c, b, p := unitChecker(t)
			path := filepath.Join(c.config.StateDir, stateName)
			switch name {
			case "mode":
				if e := os.Chmod(path, 0644); e != nil {
					t.Fatal(e)
				}
			case "corrupt":
				if e := os.WriteFile(path, []byte(`{"version":1}`), 0600); e != nil {
					t.Fatal(e)
				}
			case "link":
				if e := os.Rename(path, path+"-old"); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink(path+"-old", path); e != nil {
					t.Fatal(e)
				}
			case "lock":
				s, e := durable.Open(c.config.StateDir, "grantcheck.lock")
				if e != nil {
					t.Fatal(e)
				}
				defer s.Close()
			}
			assertVerdict(t, c.Inbound(context.Background(), xonly(2), &p), Refused, CodeStateUnavailable, false, true)
			if b.Calls != 0 {
				t.Fatal("invalid state reached backend")
			}
		})
	}
}

// Forward time is persisted across restart and rollback cannot revive a grant;
// expiry or rollback during a check rejects even a backend's live result.
func TestClockBoundaries(t *testing.T) {
	for _, name := range []string{"rollback", "expiry", "during-rollback", "restart"} {
		t.Run(name, func(t *testing.T) {
			c, b, p := unitChecker(t)
			now := int64(500)
			c.config.Now = func() time.Time { return time.Unix(now, 0) }
			old := b.Handler
			if name == "rollback" {
				now = 499
			}
			if name == "expiry" || name == "during-rollback" {
				b.Handler = func(ctx context.Context, raw []byte, a, s string, n int64) (kernel.Receipt, error) {
					r, e := old(ctx, raw, a, s, n)
					if name == "expiry" {
						now = 1000
					} else {
						now = 499
					}
					return r, e
				}
			}
			if name == "restart" {
				now = 600
				assertVerdict(t, c.Inbound(context.Background(), xonly(2), &p), Live, CodeLive, false, false)
				config := c.config
				now = 599
				var e error
				c, e = New(config)
				if e != nil {
					t.Fatal(e)
				}
			}
			code := CodeClockInvalid
			retry := true
			if name == "expiry" {
				code = CodeExpired
				retry = false
			}
			assertVerdict(t, c.Inbound(context.Background(), xonly(2), &p), Refused, code, false, retry)
		})
	}
}

// Cancellation, per-instance contention and zero values cannot grant authority.
// The valid neighbour also proves returned scope cannot mutate the next result.
func TestCancellationBusyAndCopies(t *testing.T) {
	c, _, p := unitChecker(t)
	ctx := context.Background()
	peer := xonly(2)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	assertVerdict(t, c.Inbound(cancelled, peer, &p), Refused, CodeCancelled, false, true)
	c.mu.Lock()
	v := c.Inbound(ctx, peer, &p)
	c.mu.Unlock()
	assertVerdict(t, v, Refused, CodeBusy, false, true)
	var zero Checker
	assertVerdict(t, zero.Outbound(ctx, peer), Refused, CodeCheckFailed, false, false)
	v = c.Inbound(ctx, peer, &p)
	assertVerdict(t, v, Live, CodeLive, false, false)
	v.Scope[0] = "secret.release"
	next := c.Outbound(ctx, peer)
	if next.Decision != Live || next.Scope[0] != "deliver" {
		t.Fatal("scope alias escaped")
	}
}

// Production construction uses K1: real signed offline bytes are insufficient
// authority when its own node fails. No sensitive node error reaches the verdict.
func TestProductionReadFailure(t *testing.T) {
	c, err := New(unitConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	raw := unitGrant(t)
	id, _ := kernel.PresentationID(raw)
	v := c.Inbound(context.Background(), xonly(2), &Presentation{GrantID: id, Bytes: raw})
	assertVerdict(t, v, Refused, CodeVerifierUnavailable, false, true)
	if strings.Contains(string(jsonBytes(t, v)), "sensitive-node-marker") {
		t.Fatal("node text leaked")
	}
	assertVerdict(t, c.Outbound(context.Background(), xonly(2)), Refused, CodeNoGrant, false, false)
}

// The real kernel owns window decisions; valid crypto and consent neighbours
// distinguish not-yet and expiry from malformed input without needing a node.
func TestProductionWindow(t *testing.T) {
	for _, tc := range []struct {
		now  int64
		code Code
	}{{299, CodeNotYet}, {1000, CodeExpired}} {
		t.Run(string(tc.code), func(t *testing.T) {
			config := unitConfig(t)
			config.Now = func() time.Time { return time.Unix(tc.now, 0) }
			c, e := New(config)
			if e != nil {
				t.Fatal(e)
			}
			raw := unitGrant(t)
			g := proofGrant(t, raw)
			assertVerdict(t, c.Inbound(context.Background(), xonly(2), &Presentation{GrantID: g.ID(), Bytes: raw}), Exchange, tc.code, false, false)
		})
	}
}

// Every constructor pin is bounded and validated before state publication.
func TestInvalidConfig(t *testing.T) {
	for _, name := range []string{"identity", "agent", "same-name", "issuer", "node", "timeout", "relative"} {
		t.Run(name, func(t *testing.T) {
			c := unitConfig(t)
			switch name {
			case "identity":
				c.Identity = "../foreign"
			case "agent":
				c.AgentName = "ID/Agent"
			case "same-name":
				c.LandlordName = c.AgentName
			case "issuer":
				c.IssuerPubkey = strings.Repeat("f", 64)
			case "node":
				c.Node = nil
			case "timeout":
				c.CheckTimeout = 6 * time.Second
			case "relative":
				c.StateDir = "."
			}
			if checker, e := New(c); checker != nil || e == nil {
				t.Fatal("invalid config admitted")
			}
		})
	}
}

// Signature failure is not just a framing failure: a canonical ID matching the
// tampered signature still fails K1's reused parser before the backend.
func TestInvalidSignature(t *testing.T) {
	c, b, p := unitChecker(t)
	proof, e := rental.ParseGrantPresentation(p.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	proof.SignedGrant.Signature = strings.Repeat("0", 128)
	p.Bytes = jsonBytes(t, proof)
	p.GrantID = proof.SignedGrant.ID()
	assertVerdict(t, c.Inbound(context.Background(), xonly(2), &p), Refused, CodeInvalidPresentation, false, false)
	if b.Calls != 0 {
		t.Fatal("bad signature reached backend")
	}
}

// A context-aware real node call is cancelled within the configured deadline;
// a subsequent attempt can enter (no abandoned worker or held checker lock).
func TestDeadline(t *testing.T) {
	config := unitConfig(t)
	// Leave room for real signature validation under the race detector before
	// exercising the node deadline; a pre-node timeout would not prove this claim.
	config.CheckTimeout = time.Second
	calls := 0
	config.Node = nodeFunc(func(ctx context.Context, _ string, _ ...any) (json.RawMessage, error) {
		calls++
		<-ctx.Done()
		return nil, ctx.Err()
	})
	c, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	raw := unitGrant(t)
	id, _ := kernel.PresentationID(raw)
	for range 2 {
		started := time.Now()
		assertVerdict(t, c.Inbound(context.Background(), xonly(2), &Presentation{GrantID: id, Bytes: raw}), Refused, CodeCancelled, false, true)
		if time.Since(started) > 3*time.Second {
			t.Fatal("check deadline was not bounded")
		}
	}
	if calls != 2 {
		t.Fatal("cancelled operation leaked lock or repeated node call")
	}
}
