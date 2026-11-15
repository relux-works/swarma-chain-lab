package modelproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func dailyFixture(t *testing.T, ceiling uint64, now ...int64) *harness {
	t.Helper()
	h := fixture(t)
	h.s.Close()
	h.c.StateDir = t.TempDir()
	if e := os.Chmod(h.c.StateDir, 0700); e != nil {
		t.Fatal(e)
	}
	h.c.DailyCostCeilingNanoUSD = ceiling
	if len(now) != 0 {
		h.now.Store(now[0])
		h.b.NotBefore = now[0] - 10
		h.b.NotAfter = now[0] + 1000
	}
	if e := InitializeAccounting(h.c); e != nil {
		t.Fatal(e)
	}
	var e error
	h.s, e = New(h.c)
	if e != nil {
		t.Fatal(e)
	}
	h.cred, e = h.s.Prepare(h.b)
	if e != nil {
		t.Fatal(e)
	}
	if e = h.s.Activate(h.b); e != nil {
		t.Fatal(e)
	}
	return h
}

func fullCostReply(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, reply(100, 10))
}

func assertDaily(t *testing.T, h *harness, ceiling, spent uint64) Budget {
	t.Helper()
	b, e := h.s.DailyBudget()
	if e != nil || b.CeilingNanoUSD != ceiling || b.CommittedNanoUSD != spent || b.RemainingNanoUSD != ceiling-spent {
		t.Fatalf("daily budget mismatch: %+v error=%v", b, e)
	}
	return b
}

// Equality admits; a reservation one nano-unit over the sealed ceiling refuses before provider I/O or a booking charge.
func TestDailyCeilingBoundary(t *testing.T) {
	for _, ceiling := range []uint64{230, 229, 0} {
		t.Run(fmt.Sprint(ceiling), func(t *testing.T) {
			h := dailyFixture(t, ceiling)
			h.response = fullCostReply
			w := h.send(request(false))
			if ceiling == 230 {
				if w.Code != 200 || h.calls.Load() != 1 {
					t.Fatal("exact daily ceiling refused", w.Code, w.Body.String())
				}
				assertDaily(t, h, ceiling, 230)
			} else {
				if w.Code != 403 || w.Body.String() != `{"error":"DAILY_COST_CEILING"}` || h.calls.Load() != 0 || h.status(t).Exposure != (Counts{}) {
					t.Fatal("daily ceiling+1 forwarded or charged", w.Code, w.Body.String())
				}
				assertDaily(t, h, ceiling, 0)
			}
		})
	}
}

// Restart retains verified spend and full unresolved reservations; neither path buys a second admission beyond the ceiling.
func TestDailyRestartPreservesSpend(t *testing.T) {
	for _, pending := range []bool{false, true} {
		t.Run(fmt.Sprint(pending), func(t *testing.T) {
			h := dailyFixture(t, 230)
			spent := uint64(23)
			if pending {
				p, e := (Messages{}).Parse([]byte(request(false)))
				if e != nil {
					t.Fatal(e)
				}
				_, cancel, e := h.s.reserve(context.Background(), h.b.SlotID, h.cred.Bearer.Reveal(), p)
				if e != nil {
					t.Fatal(e)
				}
				defer cancel()
				spent = 230
			} else if h.send(request(false)).Code != 200 {
				t.Fatal("settlement control refused")
			}
			before := h.calls.Load()
			h.reopen(t)
			assertDaily(t, h, 230, spent)
			if w := h.send(request(false)); w.Code != 403 || w.Body.String() != `{"error":"DAILY_COST_CEILING"}` || h.calls.Load() != before {
				t.Fatal("restart erased daily spend", w.Code, w.Body.String())
			}
		})
	}
}

// Only a forward UTC midnight resets spend; restart keeps the new day, and clock rollback cannot reopen the old budget.
func TestDailyUTCRollover(t *testing.T) {
	h := dailyFixture(t, 230, 86399)
	h.response = fullCostReply
	if h.send(request(false)).Code != 200 {
		t.Fatal("pre-midnight control refused")
	}
	if b := assertDaily(t, h, 230, 230); b.UTCDay != "1970-01-01" {
		t.Fatal("wrong UTC day")
	}
	h.now.Store(86400)
	if b := assertDaily(t, h, 230, 0); b.UTCDay != "1970-01-02" {
		t.Fatal("UTC rollover missing")
	}
	if h.send(request(false)).Code != 200 {
		t.Fatal("new day did not admit")
	}
	h.reopen(t)
	assertDaily(t, h, 230, 230)
	h.now.Store(86399)
	if _, e := h.s.DailyBudget(); e == nil || e.Error() != "CLOCK" {
		t.Fatal("clock rollback reset budget")
	}
	h.now.Store(86400)
	assertDaily(t, h, 230, 230)
}

// A prior-day in-flight settlement cannot refund today's reservations.
func TestDailyRolloverPendingSettlement(t *testing.T) {
	h := dailyFixture(t, 460, 86399)
	p, e := (Messages{}).Parse([]byte(request(false)))
	if e != nil {
		t.Fatal(e)
	}
	_, cancel, e := h.s.reserve(context.Background(), h.b.SlotID, h.cred.Bearer.Reveal(), p)
	if e != nil {
		t.Fatal(e)
	}
	defer cancel()
	h.now.Store(86400)
	assertDaily(t, h, 460, 0)
	b := h.b
	b.SlotID = strings.Repeat("d", 64)
	cred, e := h.s.Prepare(b)
	if e != nil {
		t.Fatal(e)
	}
	if e = h.s.Activate(b); e != nil {
		t.Fatal(e)
	}
	h.response = fullCostReply
	if h.sendAs(request(false), b.SlotID, cred.Bearer.Reveal()).Code != 200 {
		t.Fatal("new-day neighbor refused")
	}
	if e = h.s.settle(h.b.SlotID, &Usage{7, 3}); e != nil {
		t.Fatal(e)
	}
	assertDaily(t, h, 460, 230)
	h.reopen(t)
	assertDaily(t, h, 460, 230)
}

// Sixteen simultaneous bookings competing for three full reservations admit exactly three, with no provider call for any refusal.
func TestDailyParallelReservations(t *testing.T) {
	const admitted = 3
	h := dailyFixture(t, admitted*230)
	h.response = fullCostReply
	type auth struct {
		id     string
		bearer Secret
	}
	creds := []auth{{h.b.SlotID, h.cred.Bearer.Reveal()}}
	for i := 1; i < MaxLive; i++ {
		b := h.b
		b.SlotID = fmt.Sprintf("%064x", i)
		cred, e := h.s.Prepare(b)
		if e != nil {
			t.Fatal(e)
		}
		if e = h.s.Activate(b); e != nil {
			t.Fatal(e)
		}
		creds = append(creds, auth{b.SlotID, cred.Bearer.Reveal()})
	}
	start := make(chan struct{})
	replies := make(chan *httptest.ResponseRecorder, len(creds))
	var wg sync.WaitGroup
	for _, c := range creds {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; replies <- h.sendAs(request(false), c.id, c.bearer) }()
	}
	close(start)
	wg.Wait()
	close(replies)
	successes := 0
	for w := range replies {
		if w.Code == 200 {
			successes++
		} else if w.Code != 403 || w.Body.String() != `{"error":"DAILY_COST_CEILING"}` {
			t.Fatal("unexpected parallel refusal", w.Code, w.Body.String())
		}
	}
	if successes != admitted || h.calls.Load() != admitted {
		t.Fatal("parallel requests overshot daily ceiling", successes, h.calls.Load())
	}
	assertDaily(t, h, admitted*230, admitted*230)
	h.reopen(t)
	assertDaily(t, h, admitted*230, admitted*230)
}

// Both public request dialects reject a caller-supplied ceiling rather than forwarding it or changing accounting.
func TestDailyCeilingCannotBeRaisedByRequestField(t *testing.T) {
	h := dailyFixture(t, 230)
	for _, field := range []string{"daily_cost_ceiling_nano_usd", "ceiling_nano_usd"} {
		body := strings.Replace(request(false), `"model":`, `"`+field+`":1000000,"model":`, 1)
		if w := h.send(body); w.Code != 400 || w.Body.String() != `{"error":"REQUEST"}` || h.calls.Load() != 0 {
			t.Fatal("request raised ceiling")
		}
		body = strings.Replace(responsesRequest(false, false), `"model":`, `"`+field+`":1000000,"model":`, 1)
		if _, e := (Responses{}).Parse([]byte(body)); e == nil {
			t.Fatal("Responses request raised ceiling")
		}
	}
	assertDaily(t, h, 230, 0)
	h.response = fullCostReply
	if h.send(request(false)).Code != 200 {
		t.Fatal("valid field-free neighbor refused")
	}
}

// Environment values are never configuration authority; changing the constructor's copied value also cannot change a live service.
func TestDailyCeilingCannotBeRaisedByEnvironment(t *testing.T) {
	t.Setenv("MODEL_PROXY_DAILY_COST_CEILING_NANO_USD", "1000000")
	t.Setenv("DAILY_COST_CEILING_NANO_USD", "1000000")
	h := dailyFixture(t, 229)
	h.c.DailyCostCeilingNanoUSD = 1000000
	if w := h.send(request(false)); w.Code != 403 || w.Body.String() != `{"error":"DAILY_COST_CEILING"}` || h.calls.Load() != 0 {
		t.Fatal("environment raised ceiling")
	}
	assertDaily(t, h, 229, 0)
	h.c.DailyCostCeilingNanoUSD = 229
	h.reopen(t)
	assertDaily(t, h, 229, 0)
}

// Even the authorized registrar cannot raise the ceiling through admin fields, an operation, or newly minted large booking caps.
func TestDailyCeilingCannotBeRaisedByGateway(t *testing.T) {
	h := dailyFixture(t, 230)
	h.response = fullCostReply
	if h.send(request(false)).Code != 200 {
		t.Fatal("gateway positive control refused")
	}
	b := h.b
	b.SlotID = strings.Repeat("d", 64)
	b.Caps.CostNanoUSD = 1000000
	raw := privateCanonical(adminRequest{1, "prepare", b})
	for _, body := range []string{strings.TrimSuffix(string(raw), "}") + `,"daily_cost_ceiling_nano_usd":1000000}`, string(privateCanonical(adminRequest{1, "set-budget", b}))} {
		r := httptest.NewRequest("POST", "http://local/v1/registry", strings.NewReader(body))
		r = r.WithContext(context.WithValue(r.Context(), peerKey{}, true))
		w := httptest.NewRecorder()
		h.s.adminHandler(w, r)
		if w.Code != 400 || w.Body.String() != `{"error":"ADMIN"}` {
			t.Fatal("gateway config mutation accepted")
		}
	}
	cred, e := h.s.Prepare(b)
	if e != nil {
		t.Fatal(e)
	}
	if e = h.s.Activate(b); e != nil {
		t.Fatal(e)
	}
	if w := h.sendAs(request(false), b.SlotID, cred.Bearer.Reveal()); w.Code != 403 || w.Body.String() != `{"error":"DAILY_COST_CEILING"}` || h.calls.Load() != 1 {
		t.Fatal("gateway booking bypassed ceiling")
	}
	assertDaily(t, h, 230, 230)
}

// Missing or corrupt accounting refuses both live admission and restart without rewriting bytes or recreating a zero-spend ledger.
func TestDailyAccountingFailsClosed(t *testing.T) {
	for _, kind := range []string{"missing", "corrupt", "missing-daily", "over-ceiling", "day-mismatch", "spend-zeroed"} {
		t.Run(kind, func(t *testing.T) {
			h := dailyFixture(t, 230)
			if h.send(request(false)).Code != 200 {
				t.Fatal("accounting positive control refused")
			}
			path := filepath.Join(h.c.StateDir, "registry.json")
			good, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			bad := []byte("corrupt")
			want := "DAILY_ACCOUNTING_CORRUPT"
			if kind == "missing" {
				if e = os.Remove(path); e != nil {
					t.Fatal(e)
				}
				want = "DAILY_ACCOUNTING_MISSING"
			} else {
				if kind != "corrupt" {
					var v ledger
					if json.Unmarshal(good, &v) != nil {
						t.Fatal("fixture decode")
					}
					switch kind {
					case "missing-daily":
						v.Daily = nil
					case "over-ceiling":
						v.Daily.Committed = 231
					case "day-mismatch":
						v.Daily.Day++
					case "spend-zeroed":
						v.Daily.Committed = 0
					default:
						t.Fatal("unknown corruption plant")
					}
					bad = privateCanonical(v)
				}
				if e = os.WriteFile(path, bad, 0600); e != nil {
					t.Fatal(e)
				}
			}
			// Valid-shaped tampering is caught by the live integrity check as well as restart validation.
			if w := h.send(request(false)); w.Code != 503 || w.Body.String() != `{"error":"`+want+`"}` || h.calls.Load() != 1 {
				t.Fatal("live accounting failed open", w.Code, w.Body.String())
			}
			if b, e := h.s.DailyBudget(); e == nil || e.Error() != want || b != (Budget{}) {
				t.Fatal("failed accounting readback returned budget", b, e)
			}
			r := httptest.NewRequest("GET", "http://local/v1/budget", nil)
			r = r.WithContext(context.WithValue(r.Context(), peerKey{}, true))
			w := httptest.NewRecorder()
			h.s.adminHandler(w, r)
			if w.Code != 503 || w.Body.String() != `{"error":"`+want+`"}` {
				t.Fatal("failed accounting readback failed open", w.Code, w.Body.String())
			}
			h.s.Close()
			s, e := New(h.c)
			if s != nil {
				s.Close()
			}
			if e == nil || e.Error() != want || s != nil {
				t.Fatal("accounting failed open on restart", e)
			}
			after, e := os.ReadFile(path)
			if kind == "missing" {
				if !os.IsNotExist(e) {
					t.Fatal("missing accounting recreated")
				}
			} else if e != nil || !bytes.Equal(after, bad) {
				t.Fatal("corrupt accounting overwritten")
			}
			if e = InitializeAccounting(h.c); e == nil || e.Error() != "DAILY_ACCOUNTING_INIT_REFUSED" {
				t.Fatal("initialization reset existing state")
			}
			if e = os.WriteFile(path, good, 0600); e != nil {
				t.Fatal(e)
			}
			h.reopen(t)
			assertDaily(t, h, 230, 23)
		})
	}
}

// Ordinary startup never initializes absent accounting, and explicit provisioning refuses a used directory; a fresh empty directory works.
func TestDailyAccountingInitialization(t *testing.T) {
	h := dailyFixture(t, 230)
	c := h.c
	c.StateDir = t.TempDir()
	if e := os.Chmod(c.StateDir, 0700); e != nil {
		t.Fatal(e)
	}
	s, e := New(c)
	if s != nil {
		s.Close()
	}
	if e == nil || e.Error() != "DAILY_ACCOUNTING_MISSING" || s != nil {
		t.Fatal("missing accounting initialized as zero")
	}
	if e = InitializeAccounting(c); e == nil || e.Error() != "DAILY_ACCOUNTING_INIT_REFUSED" {
		t.Fatal("used root reinitialized")
	}
	c.StateDir = t.TempDir()
	if e = os.Chmod(c.StateDir, 0700); e != nil {
		t.Fatal(e)
	}
	if e = InitializeAccounting(c); e != nil {
		t.Fatal("empty root initialization refused", e)
	}
	s, e = New(c)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if b, e := s.DailyBudget(); e != nil || b.CommittedNanoUSD != 0 || b.CeilingNanoUSD != 230 {
		t.Fatal("initial accounting mismatch")
	}
}

// The peer-checked endpoint prints only the configured ceiling, conservative spend, remainder and UTC day; forbidden methods/peers cannot mutate it.
func TestDailyReadback(t *testing.T) {
	h := dailyFixture(t, 230)
	if h.send(request(false)).Code != 200 {
		t.Fatal("readback spend control refused")
	}
	send := func(method, path, body string, peer bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if peer {
			r = r.WithContext(context.WithValue(r.Context(), peerKey{}, true))
		}
		w := httptest.NewRecorder()
		h.s.adminHandler(w, r)
		return w
	}
	w := send("GET", "http://local/v1/budget", "", true)
	if w.Code != 200 || w.Body.String() != `{"utc_day":"1970-01-01","ceiling_nano_usd":230,"committed_nano_usd":23,"remaining_nano_usd":207}` || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("readback output mismatch", w.Code, w.Body.String())
	}
	for _, marker := range []string{keyMarker, string(h.cred.Bearer.Reveal()), h.c.StateDir, h.b.SlotID} {
		if strings.Contains(w.Body.String(), marker) {
			t.Fatal("readback disclosed private data")
		}
	}
	if w = send("GET", "http://local/v1/budget", "", false); w.Code != 403 || w.Body.String() != `{"error":"PEER"}` {
		t.Fatal("readback accepted unverified peer")
	}
	for _, q := range [][3]string{{"POST", "http://local/v1/budget", ""}, {"GET", "http://local/v1/budget?ceiling=1000000", ""}, {"GET", "http://local/v1/budget?", ""}, {"GET", "http://local/v1/budget", "{}"}} {
		if w = send(q[0], q[1], q[2], true); w.Code != 400 || w.Body.String() != `{"error":"ADMIN"}` {
			t.Fatal("readback accepted mutation input")
		}
	}
	assertDaily(t, h, 230, 23)
	h.now.Store(86400)
	w = send("GET", "http://local/v1/budget", "", true)
	if w.Code != 200 || w.Body.String() != `{"utc_day":"1970-01-02","ceiling_nano_usd":230,"committed_nano_usd":0,"remaining_nano_usd":230}` {
		t.Fatal("readback rollover mismatch", w.Body.String())
	}
}

// The installed canonical parser retains the sealed field; omitted values mean zero, and configuration drift never reopens the ledger.
func TestDailySealedConfiguration(t *testing.T) {
	h := dailyFixture(t, 230)
	c := FileConfig{DailyCostCeilingNanoUSD: 230}
	path := filepath.Join(t.TempDir(), "config.json")
	writeInstalled(t, path, privateCanonical(c))
	got, e := LoadConfig(path)
	if e != nil || got.DailyCostCeilingNanoUSD != 230 {
		t.Fatal("sealed ceiling not loaded", e)
	}
	if c, e = ParseConfig(privateCanonical(FileConfig{})); e != nil || c.DailyCostCeilingNanoUSD != 0 {
		t.Fatal("missing sealed field is not zero")
	}
	h.s.Close()
	changed := h.c
	changed.DailyCostCeilingNanoUSD++
	s, e := New(changed)
	if s != nil {
		s.Close()
	}
	if e == nil || e.Error() != "STATE" || s != nil {
		t.Fatal("sealed ceiling drift accepted", e)
	}
	h.reopen(t)
	assertDaily(t, h, 230, 0)
}

// The cost ceiling uses checked arithmetic even at the integer maximum, rather than wrapping an exhausted budget to zero.
func TestDailyCostOverflow(t *testing.T) {
	h := dailyFixture(t, ^uint64(0))
	h.s.mu.Lock()
	h.s.state.Daily.Committed = ^uint64(0) - 100
	e := h.s.save()
	h.s.mu.Unlock()
	if e != nil {
		t.Fatal(e)
	}
	if w := h.send(request(false)); w.Code != 403 || w.Body.String() != `{"error":"DAILY_COST_CEILING"}` || h.calls.Load() != 0 {
		t.Fatal("daily overflow forwarded")
	}
	assertDaily(t, h, ^uint64(0), ^uint64(0)-100)
}

// The Responses handler shares the same pre-I/O boundary for both JSON and streaming requests, including exact equality.
func TestDailyResponsesCeilingBoundary(t *testing.T) {
	for _, stream := range []bool{false, true} {
		for _, ceiling := range []uint64{229, 230} {
			t.Run(fmt.Sprintf("%t/%d", stream, ceiling), func(t *testing.T) {
				h := responsesFixture(t)
				h.s.Close()
				h.c.StateDir = t.TempDir()
				if e := os.Chmod(h.c.StateDir, 0700); e != nil {
					t.Fatal(e)
				}
				h.c.DailyCostCeilingNanoUSD = ceiling
				if e := InitializeAccounting(h.c); e != nil {
					t.Fatal(e)
				}
				var e error
				h.s, e = New(h.c)
				if e != nil {
					t.Fatal(e)
				}
				h.cred, e = h.s.Prepare(h.b)
				if e != nil {
					t.Fatal(e)
				}
				if e = h.s.Activate(h.b); e != nil {
					t.Fatal(e)
				}
				h.reply = func(w http.ResponseWriter, _ *http.Request) {
					if stream {
						w.Header().Set("Content-Type", "text/event-stream")
						_, _ = io.WriteString(w, responseFrames(false, 100, 10))
					} else {
						w.Header().Set("Content-Type", "application/json")
						_, _ = w.Write(privateCanonical(responseJSON(false, false, 100, 10)))
					}
				}
				w := h.send(responsesRequest(stream, false))
				if ceiling == 230 {
					if w.Code != 200 || h.calls.Load() != 1 {
						t.Fatal("Responses exact daily ceiling refused", w.Code, w.Body.String())
					}
				} else if w.Code != 403 || w.Body.String() != `{"error":"DAILY_COST_CEILING"}` || h.calls.Load() != 0 {
					t.Fatal("Responses daily ceiling+1 forwarded", w.Code, w.Body.String())
				}
				b, e := h.s.DailyBudget()
				want := uint64(0)
				if ceiling == 230 {
					want = 230
				}
				if e != nil || b.CommittedNanoUSD != want {
					t.Fatal("Responses daily budget mismatch", b, e)
				}
			})
		}
	}
}

// Settlement itself advances midnight before applying a prior-day refund; no other request or readback is needed for rollover.
func TestDailySettlementFirstAfterMidnight(t *testing.T) {
	h := dailyFixture(t, 230, 86399)
	p, e := (Messages{}).Parse([]byte(request(false)))
	if e != nil {
		t.Fatal(e)
	}
	_, cancel, e := h.s.reserve(context.Background(), h.b.SlotID, h.cred.Bearer.Reveal(), p)
	if e != nil {
		t.Fatal(e)
	}
	defer cancel()
	h.now.Store(86400)
	if e = h.s.settle(h.b.SlotID, &Usage{7, 3}); e != nil {
		t.Fatal(e)
	}
	assertDaily(t, h, 230, 0)
	if h.send(request(false)).Code != 200 {
		t.Fatal("new day valid control refused")
	}
	assertDaily(t, h, 230, 23)
}

type accountingLossBody struct {
	io.Reader
	once sync.Once
	lose func()
}

func (b *accountingLossBody) Read(p []byte) (int, error) { b.once.Do(b.lose); return b.Reader.Read(p) }
func (*accountingLossBody) Close() error                 { return nil }

// Loss between initial auth and reservation still returns the named unavailable refusal, with no provider call or recreated accounting.
func TestDailyAccountingLostDuringAdmission(t *testing.T) {
	h := dailyFixture(t, 230)
	path := filepath.Join(h.c.StateDir, "registry.json")
	r := httptest.NewRequest("POST", "https://proxy.example/slots/"+h.b.SlotID+"/v1/messages", strings.NewReader(request(false)))
	r.Header.Set("Authorization", "Bearer "+string(h.cred.Bearer.Reveal()))
	r.Body = &accountingLossBody{Reader: strings.NewReader(request(false)), lose: func() {
		if e := os.Remove(path); e != nil {
			t.Fatal(e)
		}
	}}
	w := httptest.NewRecorder()
	h.s.ServeHTTP(w, r)
	if w.Code != 503 || w.Body.String() != `{"error":"DAILY_ACCOUNTING_MISSING"}` || h.calls.Load() != 0 {
		t.Fatal("mid-admission accounting loss failed open", w.Code, w.Body.String())
	}
	if _, e := os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("mid-admission missing accounting recreated")
	}
}
