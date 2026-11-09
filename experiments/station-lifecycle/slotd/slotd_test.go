package slotd

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	lifecycle "github.com/relux-works/swarma-chain-lab/experiments/station-lifecycle"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeHelper implements the published transition table, not Linux primitives.
// Its canonical response traverses the actual stream codec used by the client.
type fakeHelper struct {
	mu      sync.Mutex
	now     int64
	bootID  string
	bootNS  uint64
	busy    bool
	payload string
	records map[string]Response
	ops     []string
}

func (h *fakeHelper) reply(q Request) Response {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ops = append(h.ops, q.Op)
	r, ok := h.records[q.Slot]
	if !ok {
		r = Response{V: 1, OK: true, Slot: q.Slot, State: "absent"}
	}
	refuse := func(code string) Response {
		return Response{V: 1, OK: false, Slot: q.Slot, Error: code, NotAfter: r.NotAfter, PayloadSHA256: r.PayloadSHA256, BootstrapSHA256: r.BootstrapSHA256}
	}
	if h.busy {
		return refuse("busy")
	}
	if !ValidRequest(q) {
		return refuse("bad_request")
	}
	switch q.Op {
	case "status":
		return r
	case "create":
		issued, _ := strconv.ParseUint(*q.IssuedBoottimeNS, 10, 64)
		if *q.BootID != h.bootID || (h.bootNS >= issued && h.bootNS-issued > 5_000_000_000) || (issued > h.bootNS && issued-h.bootNS > 1_000_000_000) {
			return refuse("stale_request")
		}
		until, e := time.Parse(time.RFC3339, *q.NotAfter)
		if e != nil || until.Unix() <= h.now+60 || until.Unix() > h.now+7*86400 {
			return refuse("invalid_not_after")
		}
		bootstrap, e := base64.StdEncoding.DecodeString(*q.Bootstrap)
		if e != nil {
			return refuse("invalid_bootstrap")
		}
		if r.State == "created" {
			if r.NotAfter == until.UTC().Format(time.RFC3339) && r.BootstrapSHA256 == sum(bootstrap) {
				return r
			}
			return refuse("conflict")
		}
		if r.State != "absent" && r.State != "destroyed" {
			return refuse("invalid_state")
		}
		r = Response{V: 1, OK: true, Slot: q.Slot, State: "created", NotAfter: until.UTC().Format(time.RFC3339), PayloadSHA256: h.payload, BootstrapSHA256: sum(bootstrap)}
	case "start":
		until, _ := time.Parse(time.RFC3339, r.NotAfter)
		if until.Unix()-h.now < 60 {
			return refuse("expired")
		}
		if r.PayloadSHA256 != h.payload {
			return refuse("invalid_state")
		}
		if r.State != "created" && r.State != "stopped" && r.State != "running" {
			return refuse("invalid_state")
		}
		r.State = "running"
	case "stop":
		if r.State != "running" && r.State != "stopped" {
			return refuse("invalid_state")
		}
		r.State = "stopped"
	case "destroy":
		if r.State == "running" {
			return refuse("unit_active")
		}
		if r.State == "absent" || r.State == "destroyed" {
			return r
		}
		if r.State != "created" && r.State != "stopped" && r.State != "failed" {
			return refuse("invalid_state")
		}
		r.State = "destroyed"
	}
	h.records[q.Slot] = r
	return r
}
func fakeClient(t *testing.T, h *fakeHelper) *Client {
	t.Helper()
	return &Client{timeout: time.Second, dial: func(context.Context) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			raw, e := bufio.NewReader(server).ReadBytes('\n')
			if e != nil {
				return
			}
			var q Request
			if json.Unmarshal(raw, &q) != nil {
				return
			}
			out := append(canonical(h.reply(q)), '\n')
			_, _ = server.Write(out)
		}()
		return client, nil
	}}
}
func fixture(t *testing.T) (*Host, *fakeHelper, lifecycle.Slot) {
	t.Helper()
	h := &fakeHelper{now: 100, bootID: "0f8e1c3a-6b2d-4e7f-9a1b-2c3d4e5f6a7b", bootNS: 10_000_000_000, payload: strings.Repeat("a", 64), records: map[string]Response{}}
	host := &Host{Client: fakeClient(t, h), Now: func() time.Time { return time.Unix(h.now, 0) }, BootClock: func() (lifecycle.CreateFence, error) {
		return lifecycle.CreateFence{BootID: h.bootID, IssuedBoottimeNS: strconv.FormatUint(h.bootNS, 10)}, nil
	}}
	s := lifecycle.Slot{Version: 1, ID: "17", GrantID: strings.Repeat("b", 64), NotBefore: 90, NotAfter: 300, PayloadID: "relay", PayloadSHA256: h.payload, Bootstrap: lifecycle.Secret(strings.Repeat("c", 32))}
	return host, h, s
}

// Real stream encoding reaches a fake helper with the r4 field order/binding.
// Start has no arbitrary arguments; repeated start and cleanup are idempotent.
func TestHostLifecycle(t *testing.T) {
	host, h, s := fixture(t)
	ctx := context.Background()
	if e := host.Start(ctx, s, func(lifecycle.CreateFence) error { return nil }); e != nil {
		t.Fatal(e)
	}
	if h.records[s.ID].State != "running" {
		t.Fatal("not started")
	}
	if e := host.Start(ctx, s, func(lifecycle.CreateFence) error { return nil }); e != nil {
		t.Fatal(e)
	}
	creates := 0
	for _, op := range h.ops {
		if op == "create" {
			creates++
		}
	}
	if creates != 1 {
		t.Fatal("duplicate helper create")
	}
	if e := host.Stop(ctx, s, false, nil); e != nil || h.records[s.ID].State != "destroyed" {
		t.Fatal("cleanup not proven", e)
	}
	if e := host.Stop(ctx, s, false, nil); e != nil {
		t.Fatal("idempotent cleanup", e)
	}
	if state, e := host.Status(ctx, s); e != nil || state != "stopped" {
		t.Fatal(state, e)
	}
}

// A changed payload is never started. Bootstrap/deadline still prove ownership
// for cleaning that partial create. Foreign bindings and failed state do not
// authorize automatic destruction; only explicit helper requests can retry it.
func TestHostBindings(t *testing.T) {
	t.Run("payload", func(t *testing.T) {
		host, h, s := fixture(t)
		s.PayloadSHA256 = strings.Repeat("d", 64)
		if e := host.Start(context.Background(), s, func(lifecycle.CreateFence) error { return nil }); e == nil || e.Error() != "SLOTD_BINDING" {
			t.Fatal("wrong payload started", e)
		}
		for _, op := range h.ops {
			if op == "start" {
				t.Fatal("wrong payload reached start")
			}
		}
		if e := host.Stop(context.Background(), s, false, nil); e != nil || h.records[s.ID].State != "destroyed" {
			t.Fatal("partial owned create not cleaned", e)
		}
	})
	for _, field := range []string{"bootstrap", "deadline", "failed"} {
		t.Run(field, func(t *testing.T) {
			host, h, s := fixture(t)
			if e := host.Start(context.Background(), s, func(lifecycle.CreateFence) error { return nil }); e != nil {
				t.Fatal(e)
			}
			r := h.records[s.ID]
			switch field {
			case "bootstrap":
				r.BootstrapSHA256 = strings.Repeat("d", 64)
			case "deadline":
				r.NotAfter = time.Unix(301, 0).UTC().Format(time.RFC3339)
			case "failed":
				r.State = "failed"
			}
			h.records[s.ID] = r
			before := len(h.ops)
			e := host.Stop(context.Background(), s, false, nil)
			if e == nil {
				t.Fatal("foreign/failed slot automatically destroyed")
			}
			want := "SLOTD_BINDING"
			if field == "failed" {
				want = "SLOTD_RECONCILIATION"
			}
			if e.Error() != want {
				t.Fatal(e)
			}
			for _, op := range h.ops[before:] {
				if op != "status" {
					t.Fatal("unproven destructive operation", op)
				}
			}
		})
	}
}

// The helper's documented refusals are specific, preserve state, and have a
// valid transition neighbor. These are protocol tests, not Linux execution.
func TestHelperTransitions(t *testing.T) {
	host, h, s := fixture(t)
	c := host.Client
	ctx := context.Background()
	if r, e := c.Call(ctx, Request{V: 1, Op: "stop", Slot: s.ID}); e != nil || r.OK || r.Error != "invalid_state" {
		t.Fatal("absent stop", r, e)
	}
	if e := host.Start(ctx, s, func(lifecycle.CreateFence) error { return nil }); e != nil {
		t.Fatal(e)
	}
	if r, e := c.Call(ctx, Request{V: 1, Op: "destroy", Slot: s.ID}); e != nil || r.OK || r.Error != "unit_active" || h.records[s.ID].State != "running" {
		t.Fatal("running destroy", r, e)
	}
	h.now = 241
	if r, e := c.Call(ctx, Request{V: 1, Op: "start", Slot: s.ID}); e != nil || r.OK || r.Error != "expired" {
		t.Fatal("late start", r, e)
	}
	if e := host.Stop(ctx, s, false, nil); e != nil {
		t.Fatal("stop after late refusal", e)
	}
}

// Missing response bindings, extra fields, duplicate keys, altered field order and
// unrecognized errors are not a compatible response. A canonical neighbor is.
func TestResponseRefusals(t *testing.T) {
	good := []byte(`{"v":1,"ok":true,"slot":"17","state":"created","not_after":"1970-01-01T00:05:00Z","payload_sha256":"` + strings.Repeat("a", 64) + `","bootstrap_sha256":"` + strings.Repeat("b", 64) + `"}` + "\n")
	if _, e := decodeResponse(good, "17"); e != nil {
		t.Fatal("binding neighbor", e)
	}
	for _, raw := range []string{
		`{"v":1,"ok":true,"slot":"17","state":"created","not_after":"1970-01-01T00:05:00Z"}` + "\n",
		strings.Replace(string(good), `"v":1`, `"v":1,"v":1`, 1),
		strings.Replace(string(good), `"v":1,"ok":true`, `"ok":true,"v":1`, 1),
		strings.Replace(string(good), `"state":"created"`, `"state":"created","debug":"private"`, 1),
		`{"v":1,"ok":false,"slot":"17","error":"private internal stack"}` + "\n",
		string(good) + "\n",
	} {
		if _, e := decodeResponse([]byte(raw), "17"); e == nil {
			t.Fatal("unverifiable response accepted")
		}
	}
}

// Unknown operations and fields belonging to another operation never dial the
// helper. A correctly shaped status call does reach the stream codec.
func TestRequestRefusals(t *testing.T) {
	host, h, s := fixture(t)
	c := host.Client
	until := "1970-01-01T00:05:00Z"
	for _, r := range []Request{{V: 1, Op: "sh", Slot: s.ID}, {V: 1, Op: "status", Slot: "017"}, {V: 1, Op: "start", Slot: s.ID, NotAfter: &until}, {V: 2, Op: "status", Slot: s.ID}} {
		before := len(h.ops)
		if _, e := c.Call(context.Background(), r); e == nil || e.Error() != "SLOTD_REQUEST" || len(h.ops) != before {
			t.Fatal("unknown helper authority sent", e)
		}
	}
	if r, e := c.Call(context.Background(), Request{V: 1, Op: "status", Slot: s.ID}); e != nil || r.State != "absent" {
		t.Fatal("status neighbor", r, e)
	}
}

// Broker/manager intent crosses the actual r4 stream codec into the fake helper.
// With no further polls, the manager's own expiry tick destroys the helper slot;
// restart preserves the terminal binding. This is not Linux isolation evidence.
func TestBrokerManagerHelper(t *testing.T) {
	host, h, _ := fixture(t)
	private := func() string {
		p := t.TempDir()
		if e := os.Chmod(p, 0700); e != nil {
			t.Fatal(e)
		}
		return p
	}
	now := func() time.Time { return time.Unix(h.now, 0) }
	payload := lifecycle.Payload{ID: "relay", SHA256: h.payload}
	bc := lifecycle.BrokerConfig{StateDir: private(), Range: lifecycle.Range{First: 17, Last: 32}, Payload: payload, Now: now}
	b, e := lifecycle.NewBroker(bc)
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	mc := lifecycle.Config{StateDir: private(), Range: bc.Range, Payload: payload, Host: host, Now: now}
	m, e := lifecycle.New(mc)
	if e != nil {
		t.Fatal(e)
	}
	key := strings.Repeat("e", 64)
	s, e := b.Allocate(key, strings.Repeat("b", 64), 90, 300)
	if e != nil {
		t.Fatal(e)
	}
	if e = b.SetStart(key); e != nil {
		t.Fatal(e)
	}
	p, e := b.Poll(lifecycle.PollRequest{Version: 1, Results: []lifecycle.Status{}})
	if e != nil || len(p.Commands) != 1 {
		t.Fatal("missing command", e)
	}
	r, e := m.Apply(context.Background(), p.Commands[0])
	if e != nil || r.Phase != "running" || h.records[s.ID].State != "running" {
		t.Fatal("real codec did not start fake helper", e)
	}
	if _, e = b.Poll(lifecycle.PollRequest{Version: 1, Results: m.Results()}); e != nil {
		t.Fatal(e)
	}
	if _, e = b.Wait(context.Background(), key, "running"); e != nil {
		t.Fatal(e)
	}
	h.now = 300 // no polls after disconnect
	if e = m.Tick(context.Background()); e != nil {
		t.Fatal(e)
	}
	if h.records[s.ID].State != "destroyed" {
		t.Fatal("disconnected expiry did not destroy helper")
	}
	m.Close()
	m, e = lifecycle.New(mc)
	if e != nil {
		t.Fatal(e)
	}
	defer m.Close()
	if _, e = m.Apply(context.Background(), p.Commands[0]); e == nil || e.Error() != "SLOT_TERMINAL" {
		t.Fatal("restart revived terminal helper", e)
	}
}

type callFunc func(context.Context, Request) (Response, error)

func (f callFunc) Call(ctx context.Context, q Request) (Response, error) { return f(ctx, q) }

// A Create whose response is lost can still execute after a later absent
// observation. Never claim cleanup for that uncertain interval; retry cleans
// the eventual matching created record. No-start absence is the valid neighbor.
func TestUncertainCreateAbsence(t *testing.T) {
	host, h, s := fixture(t)
	ctx := context.Background()
	if e := host.Stop(ctx, s, true, nil); e != nil {
		t.Fatal("no-start absence neighbor", e)
	}
	if e := host.Stop(ctx, s, false, nil); e == nil || e.Error() != "SLOTD_ABSENCE_UNCONFIRMED" {
		t.Fatal("uncertain absence claimed clean", e)
	}
	original := host.Client
	var deferred *Request
	host.Client = callFunc(func(ctx context.Context, q Request) (Response, error) {
		if q.Op == "create" {
			copy := q
			deferred = &copy
			return Response{}, failure("SLOTD_TRANSPORT")
		}
		return original.Call(ctx, q)
	})
	root := t.TempDir()
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	cfg := lifecycle.Config{StateDir: root, Range: lifecycle.Range{First: 1, Last: 64}, Payload: lifecycle.Payload{ID: s.PayloadID, SHA256: s.PayloadSHA256}, Host: host, Now: host.Now}
	m, e := lifecycle.New(cfg)
	if e != nil {
		t.Fatal(e)
	}
	r, e := m.Start(ctx, s)
	if e == nil || e.Error() != "HOST_CLEANUP" || r.Phase != "stopping" || deferred == nil {
		t.Fatal("uncertain create falsely completed", r, e)
	}
	m.Close()
	m, e = lifecycle.New(cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer m.Close()
	if e = m.Tick(ctx); e == nil || e.Error() != "HOST_CLEANUP" {
		t.Fatal("restart forgot uncertain create", e)
	}
	// Delayed helper processing is still fresh under r4; status=absent did not fence it.
	if created := h.reply(*deferred); !created.OK || created.State != "created" {
		t.Fatal("fault fixture did not create")
	}
	if e = m.Tick(ctx); e != nil {
		t.Fatal(e)
	}
	r, e = m.Status(ctx, s.ID)
	if e != nil || r.Phase != "stopped" || h.records[s.ID].State != "destroyed" {
		t.Fatal("late create not cleaned", r, e)
	}
}
