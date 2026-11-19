//go:build linux

package service

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/model-proxy/service/internal/wire"
)

// This public fixture is intentionally not a vendor-valid credential. Every
// failure message is fixed; the fixture never becomes a test-output diagnostic.
const fixtureMaterial = "fixture-credential-canary-not-valid"

var caller = Caller{Account: "account-a", UID: 1234, Generation: "agent-current", LaunchID: "launch-a"}

type fakeBroker struct {
	leaseID                                      string
	account, kind, harness, payloadKind          string
	mu                                           sync.Mutex
	lifetime                                     time.Duration
	verdict, requestError, renewError, holdError string
	checkError, releaseError, badReply           string
	tokenExpiry                                  *time.Time
	wrongRole, stale, wrongCorrelation, retarget bool
	wrongName, wrongUID, wrongVersion            bool
	heldAccount                                  string
	calls                                        []string
	params                                       []json.RawMessage
	listener                                     *net.UnixListener
	conn                                         *net.UnixConn
	done                                         chan struct{}
}

func startFake(t *testing.T) *fakeBroker {
	t.Helper()
	directory, e := os.MkdirTemp("", "broker-")
	if e != nil {
		t.Fatal("fake listener scratch unavailable")
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	path := filepath.Join(directory, "broker.sock")
	ln, e := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if e != nil {
		t.Fatal("fake listener unavailable")
	}
	f := &fakeBroker{account: caller.Account, kind: "claude-oauth-token", harness: "claude_code", payloadKind: "claude-oauth-token", lifetime: time.Minute, verdict: "not_revoked", listener: ln, done: make(chan struct{})}
	go func() {
		defer close(f.done)
		c, e := ln.AcceptUnix()
		if e != nil {
			return
		}
		f.mu.Lock()
		f.conn = c
		f.mu.Unlock()
		defer c.Close()
		for {
			b, e := wire.Read(c)
			if e != nil {
				return
			}
			var req struct {
				Method string          `json:"method"`
				Params json.RawMessage `json:"params"`
				ID     string          `json:"request_id"`
			}
			if wire.Decode(b, &req) != nil {
				return
			}
			clear(b)
			f.mu.Lock()
			f.calls = append(f.calls, req.Method)
			f.params = append(f.params, req.Params)
			var result any
			code := ""
			switch req.Method {
			case "hello":
				var p struct {
					Versions []int `json:"versions"`
				}
				if wire.Decode(req.Params, &p) != nil || len(p.Versions) != 1 || p.Versions[0] != 1 {
					f.mu.Unlock()
					return
				}
				if f.wrongRole {
					code = "role_not_permitted"
				} else {
					name, uid, version := "credential-gateway", uint32(os.Geteuid()), 1
					if f.wrongName {
						name = "other-service"
					}
					if f.wrongUID {
						uid++
					}
					if f.wrongVersion {
						version++
					}
					result = map[string]any{"version": version, "principal": map[string]any{"service_name": name, "uid": uid, "service_generation": "service-current"}}
				}
			case "service.lease.request", "service.lease.renew":
				if f.heldAccount != "" && f.heldAccount == f.account {
					code = "account_hold_active"
				} else if req.Method == "service.lease.request" {
					code = f.requestError
				} else {
					code = f.renewError
				}
				if code == "" {
					account := f.account
					if f.retarget {
						account = "account-b"
					}
					id := "lease-a"
					if account != caller.Account {
						id = "lease-b"
					}
					if f.leaseID != "" {
						id = f.leaseID
					}
					result = map[string]any{"service_lease_id": id, "account": account, "harness": f.harness, "kind": f.kind, "payload": map[string]any{"kind": f.payloadKind, "value": fixtureMaterial}, "token_expires_at": f.tokenExpiry, "authorized_until": time.Now().Add(f.lifetime).UTC().Format(time.RFC3339Nano), "renewable": true}
				}
			case "service.revocation.check":
				if f.stale {
					f.mu.Unlock()
					return
				}
				result = map[string]any{"verdict": f.verdict, "revocation_sequence": nil}
				code = f.checkError
			case "account.hold":
				code = f.holdError
				if code == "" {
					f.heldAccount = f.account
					result = map[string]any{"hold_id": "hold-a", "account": f.account, "reason_code": "leak_match", "state": "active", "placed_at": time.Now().UTC()}
				}
			case "service.lease.release":
				var p struct {
					ID string `json:"service_lease_id"`
				}
				if wire.Decode(req.Params, &p) != nil {
					f.mu.Unlock()
					return
				}
				code = f.releaseError
				result = map[string]any{"service_lease_id": p.ID, "state": "released"}
			default:
				f.mu.Unlock()
				return
			}
			id := req.ID
			if f.wrongCorrelation {
				id = "other-request"
			}
			badReply := f.badReply
			f.mu.Unlock()
			if badReply != "" {
				var header [4]byte
				switch badReply {
				case "oversize":
					binary.BigEndian.PutUint32(header[:], wire.MaxPayload+1)
				case "noncanonical":
					binary.BigEndian.PutUint32(header[:], 3)
				}
				_, _ = c.Write(header[:])
				if badReply == "noncanonical" {
					_, _ = c.Write([]byte(" {}"))
				}
				return
			}
			envelope := map[string]any{"request_id": id}
			if code != "" {
				envelope["error"] = map[string]any{"code": code, "message": fixtureMaterial, "details": map[string]any{"opaque": fixtureMaterial}}
			} else {
				envelope["result"] = result
			}
			if wire.Write(c, envelope) != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		f.mu.Lock()
		if f.conn != nil {
			f.conn.Close()
		}
		f.mu.Unlock()
		<-f.done
	})
	return f
}
func (f *fakeBroker) config() Config {
	return Config{Socket: f.listener.Addr().String(), BrokerUID: uint32(os.Geteuid()), ServiceUID: uint32(os.Geteuid()), Generation: "service-current", MaxLifetime: LeaseCeiling}
}
func connect(t *testing.T, f *fakeBroker) *Client {
	t.Helper()
	c, e := Dial(context.Background(), f.config())
	if e != nil {
		t.Fatal("service hello failed")
	}
	t.Cleanup(func() { c.Close() })
	return c
}
func lease(t *testing.T, c *Client) *Lease {
	t.Helper()
	l, e := c.Request(context.Background(), "request-a", caller)
	if e != nil {
		t.Fatal("valid lease refused")
	}
	return l
}
func empty(t *testing.T, l *Lease) {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.closed || len(l.value) != 0 {
		t.Fatal("material survived closure")
	}
}

// Claim: the frame captured with the landed broker's TestFrameBounds fixture
// decodes and re-encodes byte-exactly, including the four-byte length header.
func TestLandedBrokerFrame(t *testing.T) {
	h, e := os.ReadFile("testdata/broker-frame.hex")
	if e != nil {
		t.Fatal("capture missing")
	}
	b, e := hex.DecodeString(strings.TrimSpace(string(h)))
	if e != nil {
		t.Fatal("capture invalid")
	}
	raw, e := wire.Read(bytes.NewReader(b))
	if e != nil || string(raw) != `{"ok":true}` {
		t.Fatal("landed fixture not decoded")
	}
	var rebuilt bytes.Buffer
	if wire.Write(&rebuilt, map[string]any{"ok": true}) != nil || !bytes.Equal(rebuilt.Bytes(), b) {
		t.Fatal("frame bytes differ")
	}
	if binary.BigEndian.Uint32(b[:4]) != uint32(len(b)-4) {
		t.Fatal("length prefix differs")
	}
}

// Claim: exact caller fields and operation IDs reach the broker; no role,
// placeholder or material is sent. Renewal preserves its account and lease.
func TestServiceLifecycleFrames(t *testing.T) {
	f := startFake(t)
	c := connect(t, f)
	l := lease(t, c)
	if c.Check(context.Background(), l) != nil || c.Renew(context.Background(), "renew-a", l) != nil {
		t.Fatal("valid lifecycle refused")
	}
	if c.Release(context.Background(), l) != nil {
		t.Fatal("valid release refused")
	}
	empty(t, l)
	f.mu.Lock()
	defer f.mu.Unlock()
	if strings.Join(f.calls, ",") != "hello,service.lease.request,service.revocation.check,service.lease.renew,service.lease.release" {
		t.Fatal("method sequence differs")
	}
	want := map[string]any{"account": caller.Account, "agent_uid": caller.UID, "agent_generation": caller.Generation, "launch_id": caller.LaunchID, "operation_id": "request-a"}
	b, _ := wire.Encode(want)
	if !bytes.Equal(b, f.params[1]) {
		t.Fatal("caller frame differs")
	}
	want = map[string]any{"operation_id": "renew-a", "service_lease_id": "lease-a"}
	b, _ = wire.Encode(want)
	if !bytes.Equal(b, f.params[3]) {
		t.Fatal("renewal frame differs")
	}
	for _, p := range f.params {
		if bytes.Contains(p, []byte(fixtureMaterial)) || bytes.Contains(p, []byte("placeholder")) || bytes.Contains(p, []byte("role")) {
			t.Fatal("forbidden broker request member")
		}
	}
}

// Claim: the kernel server UID is checked before hello; a nearby actual UID
// admits hello, while a wrong role or stale configured generation admits no lease.
func TestIdentityAndRole(t *testing.T) {
	for _, mode := range []string{"valid", "server-uid", "role", "generation", "service-name", "service-uid", "version"} {
		t.Run(mode, func(t *testing.T) {
			f := startFake(t)
			cfg := f.config()
			switch mode {
			case "server-uid":
				cfg.BrokerUID++
			case "role":
				f.mu.Lock()
				f.wrongRole = true
				f.mu.Unlock()
			case "generation":
				cfg.Generation = "service-retired"
			case "service-name", "service-uid", "version":
				f.mu.Lock()
				f.wrongName = mode == "service-name"
				f.wrongUID = mode == "service-uid"
				f.wrongVersion = mode == "version"
				f.mu.Unlock()
			}
			c, e := Dial(context.Background(), cfg)
			if mode == "valid" {
				if e != nil {
					t.Fatal("valid role refused")
				}
				c.Close()
				return
			}
			want := ErrRole
			if mode == "server-uid" {
				want = ErrIdentity
			}
			if !errors.Is(e, want) || c != nil {
				t.Fatal("wrong identity verdict")
			}
			if mode == "server-uid" {
				f.mu.Lock()
				defer f.mu.Unlock()
				if len(f.calls) != 0 {
					t.Fatal("sent before server UID check")
				}
			}
		})
	}
}

// Claim: valid/ceiling leases succeed; expired and over-ceiling issue/renewal
// replies never yield usable material. Configuration above 900 refuses startup.
func TestLeaseCeilingAndExpiry(t *testing.T) {
	for _, duration := range []time.Duration{-time.Second, time.Minute, LeaseCeiling, LeaseCeiling + time.Second} {
		t.Run(fmt.Sprint(duration), func(t *testing.T) {
			f := startFake(t)
			f.mu.Lock()
			f.lifetime = duration
			f.mu.Unlock()
			c := connect(t, f)
			started := time.Now()
			l, e := c.Request(context.Background(), "request-a", caller)
			if duration <= 0 || duration > LeaseCeiling {
				if !errors.Is(e, ErrInactive) || l != nil {
					t.Fatal("invalid issue bound accepted")
				}
				return
			}
			if e != nil || l.AuthorizedUntil().After(time.Now().Add(LeaseCeiling)) || !l.AuthorizedUntil().After(started.Add(duration-time.Second)) {
				t.Fatal("valid bound refused or widened")
			}
			f.mu.Lock()
			f.lifetime = LeaseCeiling + time.Second
			f.mu.Unlock()
			if !errors.Is(c.Renew(context.Background(), "renew-a", l), ErrInactive) {
				t.Fatal("over-ceiling renewal accepted")
			}
			empty(t, l)
		})
	}
	f := startFake(t)
	cfg := f.config()
	cfg.MaxLifetime = LeaseCeiling + time.Nanosecond
	if c, e := Dial(context.Background(), cfg); !errors.Is(e, ErrInput) || c != nil {
		t.Fatal("over-ceiling configuration started")
	}
}

// Claim: poll refusal or broker closure erases material and cannot be reopened
// by a later good verdict. The fake closes the stale-generation connection.
func TestRevocationAndStaleConnection(t *testing.T) {
	for _, mode := range []string{"valid", "revoked", "unavailable", "stale"} {
		t.Run(mode, func(t *testing.T) {
			f := startFake(t)
			c := connect(t, f)
			l := lease(t, c)
			f.mu.Lock()
			switch mode {
			case "revoked", "unavailable":
				f.verdict = mode
			case "stale":
				f.stale = true
			}
			f.mu.Unlock()
			e := c.Check(context.Background(), l)
			if mode == "valid" {
				if e != nil {
					t.Fatal("live poll refused")
				}
				return
			}
			want := ErrRevoked
			switch mode {
			case "unavailable":
				want = ErrUnavailable
			case "stale":
				want = ErrUnknown
			}
			if !errors.Is(e, want) {
				t.Fatal("poll refusal differs")
			}
			empty(t, l)
			f.mu.Lock()
			f.verdict = "not_revoked"
			f.mu.Unlock()
			if !errors.Is(c.Check(context.Background(), l), ErrInactive) {
				t.Fatal("closed lease reopened")
			}
		})
	}
}

// Claim: held and unknown hold outcomes immediately close every local lease on
// that account. Neither outcome admits new material or renewal; no owner lift exists.
func TestHoldClosesAccount(t *testing.T) {
	for _, mode := range []string{"durable", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			f := startFake(t)
			c := connect(t, f)
			a, b := lease(t, c), lease(t, c)
			other := caller
			other.Account, other.LaunchID = "account-b", "launch-b"
			f.mu.Lock()
			f.account = other.Account
			f.mu.Unlock()
			unrelated, err := c.Request(context.Background(), "other-account", other)
			if err != nil {
				t.Fatal("second-account hold control failed")
			}
			f.mu.Lock()
			f.account = caller.Account
			if mode == "unknown" {
				f.holdError = "account_hold_unknown"
			}
			f.mu.Unlock()
			e := c.Hold(context.Background(), "hold-operation", a)
			if mode == "durable" && e != nil || mode == "unknown" && !errors.Is(e, ErrUnknown) {
				t.Fatal("hold result differs")
			}
			empty(t, a)
			empty(t, b)
			if c.Check(context.Background(), unrelated) != nil {
				t.Fatal("hold closed another account")
			}
			if c.Renew(context.Background(), "renew-a", b) != ErrInactive {
				t.Fatal("hold permitted renewal")
			}
			if l, e := c.Request(context.Background(), "after-hold", caller); l != nil || e != ErrInactive {
				t.Fatal("hold permitted issue")
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			var p map[string]any
			for i, m := range f.calls {
				if m == "account.hold" {
					json.Unmarshal(f.params[i], &p)
				}
			}
			if len(p) != 4 || p["reason_code"] != "leak_match" || p["account"] != caller.Account || p["service_lease_id"] != "lease-a" {
				t.Fatal("hold frame differs")
			}
		})
	}
}

// Claim: expiry and broker refusals have their specified closed code, erase
// material and preserve the original account; a nearby live renew succeeds.
func TestRenewRefusals(t *testing.T) {
	for _, mode := range []string{"valid", "expired", "revoked", "hold", "retarget"} {
		t.Run(mode, func(t *testing.T) {
			f := startFake(t)
			c := connect(t, f)
			l := lease(t, c)
			f.mu.Lock()
			switch mode {
			case "expired":
				f.renewError = "lease_not_active"
			case "revoked":
				f.renewError = "lease_caller_revoked"
			case "hold":
				f.renewError = "account_hold_active"
			case "retarget":
				f.retarget = true
			}
			f.mu.Unlock()
			e := c.Renew(context.Background(), "renew-a", l)
			if mode == "valid" {
				if e != nil {
					t.Fatal("valid renew refused")
				}
				return
			}
			want := error(ErrInactive)
			switch mode {
			case "revoked":
				want = Code("lease_caller_revoked")
			case "hold":
				want = Code("account_hold_active")
			}
			if !errors.Is(e, want) {
				t.Fatal("wrong renewal refusal")
			}
			empty(t, l)
			if l.caller.Account != caller.Account {
				t.Fatal("renew retargeted caller")
			}
		})
	}
}

// Claim: opaque handles and sanitized remote/OS failures do not expose the
// fixture through formatting, JSON, logs, argv, environment or a child environment.
// This is bounded observation of these paths, not a process-memory secrecy proof.
func TestCanarySafety(t *testing.T) {
	f := startFake(t)
	c := connect(t, f)
	l := lease(t, c)
	var logs bytes.Buffer
	old := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(old)
	log.Printf("%v %#v %s %v %#v", l, c, l, *l, *l)
	encoded, e := json.Marshal(l)
	if e != nil {
		t.Fatal("handle encoding failed")
	}
	f.mu.Lock()
	f.renewError = fixtureMaterial
	f.mu.Unlock()
	err := c.Renew(context.Background(), "renew-a", l)
	if err == nil {
		t.Fatal("unknown remote refusal accepted")
	}
	valueJSON, valueErr := json.Marshal(*l)
	if valueErr != nil {
		t.Fatal("copied handle encoding failed")
	}
	observed := logs.String() + string(encoded) + string(valueJSON) + err.Error() + strings.Join(os.Environ(), "\n")
	argv, e := os.ReadFile("/proc/self/cmdline")
	if e != nil {
		t.Fatal("argv observation failed")
	}
	observed += string(argv)
	child := exec.Command("/usr/bin/env")
	out, e := child.Output()
	if e != nil {
		t.Fatal("child environment observation failed")
	}
	observed += string(out)
	if strings.Contains(observed, fixtureMaterial) || strings.Contains(observed, fmt.Sprint([]byte(fixtureMaterial))) || strings.Contains(observed, fmt.Sprintf("%#v", []byte(fixtureMaterial))) {
		t.Fatal("fixture material escaped holder")
	}
	empty(t, l)
}

// Claim: malformed correlation closes the connection instead of releasing a
// successful-looking payload. A normal correlated response is the positive control.
func TestCorrelation(t *testing.T) {
	f := startFake(t)
	c := connect(t, f)
	l := lease(t, c)
	f.mu.Lock()
	f.wrongCorrelation = true
	f.mu.Unlock()
	if c.Renew(context.Background(), "renew-a", l) != ErrFrame {
		t.Fatal("uncorrelated reply accepted")
	}
	empty(t, l)
}

// Claim: the actual poll loop observes broker revocation and closes use; an
// invalid interval starts no polling and a separate current check still works.
func TestPollLoop(t *testing.T) {
	f := startFake(t)
	c := connect(t, f)
	l := lease(t, c)
	if c.Poll(context.Background(), l, 0) != ErrInput || c.Check(context.Background(), l) != nil {
		t.Fatal("poll interval control differs")
	}
	f.mu.Lock()
	f.verdict = "revoked"
	f.mu.Unlock()
	if c.Poll(context.Background(), l, time.Millisecond) != ErrRevoked {
		t.Fatal("poll loop missed revocation")
	}
	empty(t, l)
}

// Claim: actual versions-only hello socket bytes from the landed broker's
// TestServiceSocketStandardHello decode without a role/profile extension and
// re-encode unchanged. The captured numeric UID is not an install identity pin.
func TestLandedServiceHello(t *testing.T) {
	for _, name := range []string{"broker-service-hello-request.hex", "broker-service-hello-response.hex"} {
		h, e := os.ReadFile("testdata/" + name)
		if e != nil {
			t.Fatal("service capture missing")
		}
		b, e := hex.DecodeString(strings.TrimSpace(string(h)))
		if e != nil {
			t.Fatal("service capture invalid")
		}
		raw, e := wire.Read(bytes.NewReader(b))
		if e != nil {
			t.Fatal("service frame rejected")
		}
		var m map[string]any
		if json.Unmarshal(raw, &m) != nil {
			t.Fatal("service frame invalid")
		}
		if m["request_id"] != "standard" {
			t.Fatal("capture correlation changed")
		}
		if name == "broker-service-hello-request.hex" {
			if m["method"] != "hello" || len(m) != 3 {
				t.Fatal("hello request changed")
			}
			p, ok := m["params"].(map[string]any)
			if !ok || len(p) != 1 || p["versions"] == nil {
				t.Fatal("hello invented role/profile")
			}
		} else {
			var envelope struct {
				ID     string          `json:"request_id"`
				Result json.RawMessage `json:"result"`
			}
			var hello helloResult
			if wire.Decode(raw, &envelope) != nil || wire.Decode(envelope.Result, &hello) != nil || hello.Version != 1 || hello.Principal.Name != "credential-gateway" || hello.Principal.Generation != "socket-service-generation" || hello.Principal.UID != 1001 {
				t.Fatal("captured hello failed client decoder")
			}
			result, ok := m["result"].(map[string]any)
			if !ok || len(result) != 2 || result["version"] != float64(1) {
				t.Fatal("hello response changed")
			}
			principal, ok := result["principal"].(map[string]any)
			if !ok || len(principal) != 3 || principal["service_name"] != "credential-gateway" || principal["service_generation"] != "socket-service-generation" {
				t.Fatal("service principal shape changed")
			}
		}
		canonical, e := wire.Parse(raw)
		if e != nil {
			t.Fatal("capture not canonical")
		}
		var rebuilt bytes.Buffer
		if wire.Write(&rebuilt, canonical) != nil || !bytes.Equal(rebuilt.Bytes(), b) {
			t.Fatal("captured service frame changed bytes")
		}
	}
}

// Claim: a monotonic local deadline closes use even while the broker wall
// timestamp remains in the future; the same handle polls successfully before it.
func TestLocalExpiryStopsBeforePoll(t *testing.T) {
	f := startFake(t)
	c := connect(t, f)
	l := lease(t, c)
	if c.Check(context.Background(), l) != nil {
		t.Fatal("valid expiry control refused")
	}
	l.mu.Lock()
	l.localUntil = time.Now().Add(-time.Millisecond)
	l.mu.Unlock()
	f.mu.Lock()
	before := len(f.calls)
	f.mu.Unlock()
	if c.Check(context.Background(), l) != ErrInactive {
		t.Fatal("expired local use admitted")
	}
	empty(t, l)
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) != before {
		t.Fatal("expired use reached broker")
	}
}

// Claim: concurrent renewal and connection closure leave no live material;
// a nearby successful renewal demonstrates this is not a reject-all client.
func TestConcurrentRenewAndClose(t *testing.T) {
	f := startFake(t)
	c := connect(t, f)
	l := lease(t, c)
	if c.Renew(context.Background(), "renew-control", l) != nil {
		t.Fatal("renewal control failed")
	}
	start := make(chan struct{})
	result := make(chan error, 1)
	go func() { <-start; result <- c.Renew(context.Background(), "renew-racing", l) }()
	close(start)
	c.Close()
	e := <-result
	if e != nil && e != ErrInactive && e != ErrUnknown && e != ErrTransport {
		t.Fatal("unexpected concurrent close result")
	}
	empty(t, l)
}

// Claim: broker/1 account labels retain the landed ASCII grammar (including
// slash); unknown kind/harness/payload kind refuses instead of extending v0.
// The interfaces remain kind-agnostic, while this client pins the v0 dialect.
func TestPinnedDialectAndAccountLabel(t *testing.T) {
	for _, mode := range []string{"valid", "account-label", "kind", "harness", "payload-kind"} {
		t.Run(mode, func(t *testing.T) {
			f := startFake(t)
			origin := caller
			f.mu.Lock()
			switch mode {
			case "account-label":
				origin.Account = "owner/claude/service-test"
				f.account = origin.Account
			case "kind":
				f.kind = "other-kind"
				f.payloadKind = f.kind
			case "harness":
				f.harness = "other-harness"
			case "payload-kind":
				f.payloadKind = "other-kind"
			}
			f.mu.Unlock()
			c := connect(t, f)
			l, e := c.Request(context.Background(), "request-a", origin)
			if mode == "valid" || mode == "account-label" {
				if e != nil || l == nil {
					t.Fatal("landed dialect control refused")
				}
			} else if e != ErrInactive || l != nil {
				t.Fatal("unsupported dialect accepted")
			}
		})
	}
}

// Claim: the live broker connection has FD_CLOEXEC set. This checks inheritance
// prevention on that descriptor; it does not model a malicious trusted holder
// deliberately passing it with SCM_RIGHTS.
func TestConnectionCloseOnExec(t *testing.T) {
	f := startFake(t)
	c := connect(t, f)
	raw, e := c.conn.SyscallConn()
	if e != nil {
		t.Fatal("descriptor observation failed")
	}
	var flags uintptr
	var errno syscall.Errno
	e = raw.Control(func(fd uintptr) { flags, _, errno = syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_GETFD, 0) })
	if e != nil || errno != 0 || flags&syscall.FD_CLOEXEC == 0 {
		t.Fatal("broker descriptor can survive exec")
	}
}

// Claim: empty handles are inert and refuse every lifecycle operation without
// dereferencing absent state; ordinary leased handles are covered nearby.
func TestEmptyHandleRefusals(t *testing.T) {
	f := startFake(t)
	c := connect(t, f)
	l := &Lease{}
	if !l.AuthorizedUntil().IsZero() || l.Kind() != "" || c.Check(context.Background(), l) != ErrInput || c.Renew(context.Background(), "renew-a", l) != ErrInput || c.Hold(context.Background(), "hold-a", l) != ErrInput || c.Release(context.Background(), l) != ErrInput {
		t.Fatal("empty handle gained authority")
	}
	l.close()
}

// Claim: ordinary request refusals preserve every lease and the connection;
// lease revocation/release refusals close their target, holds close one account,
// and principal loss closes all cached use. Each case starts with
// valid leases for two callers and accounts and checks the exact refusal code.
func TestRefusalScope(t *testing.T) {
	for _, mode := range []string{"request-lease_unbound", "request-service_operation_conflict", "request-request_malformed", "request-grant_expired", "renew-grant_expired", "release-inactive", "renew-revoked", "check-revoked", "verdict-revoked", "request-hold-active", "request-hold-unknown", "renew-hold", "renew-stale", "check-stale", "release-stale", "hold-stale", "role", "ledger", "unavailable", "unknown-code"} {
		t.Run(mode, func(t *testing.T) {
			f := startFake(t)
			c := connect(t, f)
			a := lease(t, c)
			f.mu.Lock()
			f.leaseID = "lease-peer"
			f.mu.Unlock()
			peer, e := c.Request(context.Background(), "same-account-peer", caller)
			if e != nil {
				t.Fatal("second lease control failed")
			}
			other := caller
			other.Account, other.LaunchID = "account-b", "launch-b"
			f.mu.Lock()
			f.account = other.Account
			f.leaseID = ""
			f.mu.Unlock()
			b, e := c.Request(context.Background(), "second-account", other)
			if e != nil || a.id == peer.id || a.id == b.id || peer.id == b.id || c.Check(context.Background(), a) != nil || c.Check(context.Background(), b) != nil {
				t.Fatal("two-account control failed")
			}
			c.mu.Lock()
			epoch := c.epoch
			c.mu.Unlock()
			f.mu.Lock()
			f.account = caller.Account
			want := Code("lease_unbound")
			targetClosed, accountClosed, allClosed := false, false, false
			switch {
			case strings.HasPrefix(mode, "request-") && !strings.Contains(mode, "hold"):
				want = Code(strings.TrimPrefix(mode, "request-"))
				f.requestError = string(want)
			case mode == "release-inactive":
				want, targetClosed = ErrInactive, true
				f.releaseError = string(want)
			case mode == "renew-revoked":
				want, targetClosed = Code("lease_caller_revoked"), true
				f.renewError = string(want)
			case mode == "renew-grant_expired":
				want, targetClosed = Code("grant_expired"), true
				f.renewError = string(want)
			case strings.HasSuffix(mode, "-stale"):
				want, allClosed = Code("lease_not_owner"), true
				switch mode {
				case "renew-stale":
					f.renewError = string(want)
				case "check-stale":
					f.checkError = string(want)
				case "release-stale":
					f.releaseError = string(want)
				case "hold-stale":
					f.holdError, want = string(want), ErrUnknown
				}
			case mode == "check-revoked":
				want, targetClosed = Code("lease_grant_revoked"), true
				f.checkError = string(want)
			case mode == "verdict-revoked":
				want, targetClosed = ErrRevoked, true
				f.verdict = "revoked"
			case mode == "request-hold-active", mode == "request-hold-unknown", mode == "renew-hold":
				want, accountClosed = Code("account_hold_active"), true
				if mode == "request-hold-unknown" {
					want = Code("account_hold_unknown")
				}
				if mode == "renew-hold" {
					f.renewError = string(want)
				} else {
					f.requestError = string(want)
				}
			case mode == "role", mode == "ledger", mode == "unavailable", mode == "unknown-code":
				allClosed = mode != "unavailable"
				want = ErrUnavailable
				switch mode {
				case "role":
					want = ErrRole
				case "ledger":
					want = Code("principal_ledger_mismatch")
				}
				f.requestError = string(want)
				if mode == "unknown-code" {
					f.requestError = fixtureMaterial
				}
			}
			f.mu.Unlock()
			switch mode {
			case "release-inactive", "release-stale":
				e = c.Release(context.Background(), a)
			case "renew-revoked", "renew-hold", "renew-grant_expired", "renew-stale":
				e = c.Renew(context.Background(), "refused-renew", a)
			case "check-revoked", "verdict-revoked", "check-stale":
				e = c.Check(context.Background(), a)
			case "hold-stale":
				e = c.Hold(context.Background(), "refused-hold", a)
			default:
				var refused *Lease
				refused, e = c.Request(context.Background(), "refused-request", caller)
				if refused != nil {
					t.Fatal("refusal returned a lease")
				}
			}
			if e != want {
				t.Fatal("refusal code changed")
			}
			c.mu.Lock()
			changed, failed := c.epoch != epoch, c.failed
			c.mu.Unlock()
			if changed != allClosed || failed != allClosed {
				t.Fatal("refusal changed connection scope")
			}
			if targetClosed || accountClosed || allClosed {
				empty(t, a)
			}
			if accountClosed || allClosed {
				empty(t, peer)
			}
			if allClosed {
				empty(t, b)
				if next, e := c.Request(context.Background(), "after-authority-loss", other); next != nil || e != ErrInactive {
					t.Fatal("lost authority reopened")
				}
				return
			}
			f.mu.Lock()
			f.requestError, f.renewError, f.releaseError, f.checkError = "", "", "", ""
			f.verdict = "not_revoked"
			f.mu.Unlock()
			if !targetClosed && !accountClosed && c.Check(context.Background(), a) != nil {
				t.Fatal("ordinary refusal closed unrelated lease")
			}
			if !accountClosed && c.Check(context.Background(), peer) != nil {
				t.Fatal("lease refusal closed another lease on the same account")
			}
			if c.Check(context.Background(), b) != nil {
				t.Fatal("refusal closed another account")
			}
			if accountClosed {
				if next, e := c.Request(context.Background(), "held-again", caller); next != nil || e != ErrInactive {
					t.Fatal("hold refusal failed to block account")
				}
			}
			f.mu.Lock()
			f.account = other.Account
			f.mu.Unlock()
			if next, e := c.Request(context.Background(), "after-refusal", other); e != nil || next == nil {
				t.Fatal("ordinary refusal retired usable connection")
			}
		})
	}
}

// Claim: malformed frame bounds and canonical encoding close existing leases
// and prevent retry; the same connection first admits a canonical live lease.
func TestInvalidBrokerFramesCloseUse(t *testing.T) {
	for _, mode := range []string{"oversize", "zero", "noncanonical"} {
		t.Run(mode, func(t *testing.T) {
			f := startFake(t)
			c := connect(t, f)
			l := lease(t, c)
			f.mu.Lock()
			f.badReply = mode
			f.mu.Unlock()
			if c.Check(context.Background(), l) != ErrUnknown {
				t.Fatal("invalid frame did not close connection")
			}
			empty(t, l)
			if next, e := c.Request(context.Background(), "after-frame-fault", caller); next != nil || e != ErrInactive {
				t.Fatal("frame fault permitted retry")
			}
		})
	}
}

// Claim: non-null token expiry bounds issuance and later use; an expiry after
// the authorization deadline is valid, while expired or shorter bounds refuse.
func TestTokenExpiryBounds(t *testing.T) {
	for _, mode := range []string{"valid", "expired", "before-authorization"} {
		t.Run(mode, func(t *testing.T) {
			f := startFake(t)
			expiry := time.Now().Add(2 * time.Minute)
			switch mode {
			case "expired":
				expiry = time.Now().Add(-time.Second)
			case "before-authorization":
				expiry = time.Now().Add(30 * time.Second)
			}
			f.mu.Lock()
			f.tokenExpiry = &expiry
			f.mu.Unlock()
			c := connect(t, f)
			l, e := c.Request(context.Background(), "token-expiry", caller)
			if mode != "valid" {
				if l != nil || e != ErrInactive {
					t.Fatal("invalid token expiry admitted")
				}
				return
			}
			if e != nil || c.Check(context.Background(), l) != nil {
				t.Fatal("valid token expiry refused")
			}
			past := time.Now().Add(-time.Second)
			l.mu.Lock()
			l.tokenExpiry = &past
			l.mu.Unlock()
			if c.Check(context.Background(), l) != ErrInactive {
				t.Fatal("expired token use admitted")
			}
			empty(t, l)
		})
	}
}
