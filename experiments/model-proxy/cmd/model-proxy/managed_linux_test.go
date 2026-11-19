//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	proxy "github.com/relux-works/swarma-chain-lab/experiments/model-proxy"
)

const brokerCanary = "fixture-leased-material-not-a-provider-token"
const renewedCanary = "fixture-renewed-material-not-a-provider-token"

type brokerFixture struct {
	mu                                     sync.Mutex
	verdict, refusal                       string
	renewRefusal, checkRefusal, generation string
	lease, idle, checkDelay                time.Duration
	requests, renewals, checks, releases   int
	connections                            int
	params                                 []json.RawMessage
	listener                               *net.UnixListener
	conn                                   *net.UnixConn
	conns                                  map[*net.UnixConn]bool
	done                                   chan struct{}
	config                                 brokerFile
}

func startBroker(t *testing.T) *brokerFixture {
	t.Helper()
	dir, e := os.MkdirTemp("", "b")
	if e != nil {
		t.Fatal("fake broker directory failed")
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "broker.sock")
	ln, e := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if e != nil {
		t.Fatal("fake broker listen failed")
	}
	f := &brokerFixture{verdict: "not_revoked", lease: 30 * time.Second, conns: map[*net.UnixConn]bool{}, listener: ln, done: make(chan struct{}), config: brokerFile{Socket: path, BrokerUID: uint32(os.Geteuid()), ServiceGeneration: "service-current", Account: strings.Repeat("a", 64), AgentUID: 1234, AgentGeneration: "worker-current", LaunchID: "launch-current", MaxLifetimeSeconds: 60}}
	var workers sync.WaitGroup
	serve := func(c *net.UnixConn) {
		defer c.Close()
		for {
			f.mu.Lock()
			idle := f.idle
			f.mu.Unlock()
			if idle > 0 {
				_ = c.SetReadDeadline(time.Now().Add(idle))
			}
			var size [4]byte
			if _, err := io.ReadFull(c, size[:]); err != nil {
				return
			}
			n := binary.BigEndian.Uint32(size[:])
			if n == 0 || n > 65536 {
				return
			}
			b := make([]byte, n)
			if _, err := io.ReadFull(c, b); err != nil {
				return
			}
			var req struct {
				Method string          `json:"method"`
				Params json.RawMessage `json:"params"`
				ID     string          `json:"request_id"`
			}
			if json.Unmarshal(b, &req) != nil {
				return
			}
			f.mu.Lock()
			f.params = append(f.params, req.Params)
			var result any
			var delay time.Duration
			code := ""
			switch req.Method {
			case "hello":
				if string(req.Params) != `{"versions":[1]}` {
					f.mu.Unlock()
					return
				}
				generation := f.generation
				if generation == "" {
					generation = f.config.ServiceGeneration
				}
				result = map[string]any{"version": 1, "principal": map[string]any{"service_name": "credential-gateway", "uid": uint32(os.Geteuid()), "service_generation": generation}}
			case "service.lease.request", "service.lease.renew":
				if req.Method == "service.lease.request" {
					f.requests++
					var p struct {
						Account    string `json:"account"`
						UID        uint32 `json:"agent_uid"`
						Generation string `json:"agent_generation"`
						Launch     string `json:"launch_id"`
						Operation  string `json:"operation_id"`
					}
					if json.Unmarshal(req.Params, &p) != nil || p.Account != f.config.Account || p.UID != f.config.AgentUID || p.Generation != f.config.AgentGeneration || p.Launch != f.config.LaunchID || p.Operation == "" {
						f.mu.Unlock()
						return
					}
				} else {
					f.renewals++
				}
				code = f.refusal
				if req.Method == "service.lease.renew" && f.renewRefusal != "" {
					code = f.renewRefusal
				}
				value := brokerCanary
				if f.renewals > 0 {
					value = renewedCanary
				}
				result = map[string]any{"service_lease_id": "lease-current", "account": f.config.Account, "harness": "claude_code", "kind": "claude-oauth-token", "payload": map[string]any{"kind": "claude-oauth-token", "value": value}, "token_expires_at": nil, "authorized_until": time.Now().Add(f.lease).UTC().Format(time.RFC3339Nano), "renewable": true}
			case "service.revocation.check":
				f.checks++
				code = f.checkRefusal
				delay, f.checkDelay = f.checkDelay, 0
				result = map[string]any{"verdict": f.verdict, "revocation_sequence": nil}
			case "service.lease.release":
				f.releases++
				result = map[string]any{"service_lease_id": "lease-current", "state": "released"}
			default:
				f.mu.Unlock()
				return
			}
			f.mu.Unlock()
			time.Sleep(delay)
			out := map[string]any{"request_id": req.ID}
			if code != "" {
				out["error"] = map[string]any{"code": code, "message": brokerCanary, "details": map[string]any{"opaque": brokerCanary}}
			} else {
				out["result"] = result
			}
			b, err := json.Marshal(out)
			if err != nil {
				return
			}
			binary.BigEndian.PutUint32(size[:], uint32(len(b)))
			if _, err := io.Copy(c, io.MultiReader(bytes.NewReader(size[:]), bytes.NewReader(b))); err != nil {
				return
			}
		}
	}
	go func() {
		defer close(f.done)
		for {
			connection, err := ln.AcceptUnix()
			if err != nil {
				return
			}
			f.mu.Lock()
			f.conn = connection
			f.conns[connection] = true
			f.connections++
			f.mu.Unlock()
			workers.Add(1)
			go func() {
				defer workers.Done()
				serve(connection)
			}()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		<-f.done
		f.mu.Lock()
		for connection := range f.conns {
			connection.Close()
		}
		f.mu.Unlock()
		workers.Wait()
	})
	return f
}

type providerTransport func(*http.Request) (*http.Response, error)

func (f providerTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// The actual cmd wiring connects model-proxy's managed path to the separable
// service and a Unix fake broker. A worker sees only its binding placeholder;
// leased material appears solely at the fake provider authentication boundary.
// Wrong worker auth, broker refusal and revocation cause no provider request.
func TestManagedBrokerGateway(t *testing.T) {
	for _, scenario := range []string{"mapping", "renewal", "broker-refusal", "revocation"} {
		t.Run(scenario, func(t *testing.T) {
			f := startBroker(t)
			raw, _ := json.Marshal(f.config)
			source, closeSource, e := managedSource(context.Background(), raw)
			if e != nil {
				t.Fatal("cmd source refused valid broker")
			}
			defer closeSource()
			var calls atomic.Int32
			var audits bytes.Buffer
			root := t.TempDir()
			if e := os.Chmod(root, 0700); e != nil {
				t.Fatal("private state directory failed")
			}
			cfg := proxy.Config{StateDir: root, DailyCostCeilingNanoUSD: 1000000, Endpoint: proxy.Endpoint{URL: "https://gateway.example", CertSHA256: strings.Repeat("b", 64)}, Upstream: "https://api.anthropic.com/v1/messages", Source: source, Mode: proxy.ModeManaged, RunMaxWindowSeconds: 3600, Models: map[string]proxy.Model{"test-model-1": {ContextTokens: 100, InputNanoUSD: 2, OutputNanoUSD: 3, Source: "fixture bound"}}, Now: time.Now, Audit: func(a proxy.Audit) { _ = json.NewEncoder(&audits).Encode(a) }}
			cfg.Transport = providerTransport(func(r *http.Request) (*http.Response, error) {
				n := calls.Add(1)
				want := brokerCanary
				if scenario == "renewal" && n > 1 {
					want = renewedCanary
				}
				if r.URL.String() != cfg.Upstream || r.Header.Get("Authorization") != "Bearer "+want || r.Header.Get("X-Api-Key") != "" {
					t.Error("provider credential boundary mismatch")
				}
				status := 200
				body := `{"id":"msg_fixture","type":"message","role":"assistant","model":"test-model-1","content":[{"type":"text","text":"answer"}],"stop_reason":"end_turn","usage":{"input_tokens":7,"output_tokens":3,"service_tier":"standard","inference_geo":"global","speed":"standard"}}`
				if scenario == "renewal" && n == 1 {
					status = 401
					body = `{"error":"unauthorized"}`
				}
				return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
			})
			if e = proxy.InitializeAccounting(cfg); e != nil {
				t.Fatal("accounting initialization failed")
			}
			s, e := proxy.New(cfg)
			if e != nil {
				t.Fatal("managed construction failed")
			}
			defer s.Close()
			now := time.Now().Unix()
			binding := proxy.Binding{SlotID: strings.Repeat("1", 64), GrantID: strings.Repeat("2", 64), NotBefore: now - 1, NotAfter: now + 600, Caps: proxy.Caps{InputTokens: 1000, OutputTokens: 1000, Requests: 10, MaxTokens: 10, CostNanoUSD: 10000}, Run: proxy.RunBinding{Generation: strings.Repeat("3", 64), RunID: strings.Repeat("4", 64), Account: f.config.Account}}
			credential, e := s.Prepare(binding)
			if e != nil || s.Activate(binding) != nil {
				t.Fatal("managed binding failed")
			}
			placeholder := string(credential.Bearer.Reveal())
			if placeholder == brokerCanary || strings.Contains(fmt.Sprintf("%#v", credential), brokerCanary) {
				t.Fatal("worker credential contains material")
			}
			observed := []string{fmt.Sprintf("%#v %+v", source, source)}
			send := func(bearer string) *httptest.ResponseRecorder {
				r := httptest.NewRequest("POST", "https://gateway.example/slots/"+binding.SlotID+"/v1/messages", strings.NewReader(`{"model":"test-model-1","messages":[{"role":"user","content":"hello"}],"max_tokens":10,"stream":false}`))
				r.Header.Set("Authorization", "Bearer "+bearer)
				w := httptest.NewRecorder()
				s.ServeHTTP(w, r)
				if r.Header.Get("Authorization") != "Bearer "+bearer {
					t.Fatal("worker request changed to material")
				}
				observed = append(observed, w.Body.String(), fmt.Sprint(w.Header()), fmt.Sprint(r.Header))
				return w
			}
			if w := send("wrong-placeholder"); w.Code != 401 || calls.Load() != 0 {
				t.Fatal("wrong placeholder forwarded")
			}
			f.mu.Lock()
			requests := f.requests
			f.mu.Unlock()
			if requests != 0 {
				t.Fatal("wrong placeholder requested a lease")
			}
			if scenario == "broker-refusal" {
				f.mu.Lock()
				f.refusal = "role_not_permitted"
				f.mu.Unlock()
			}
			w := send(placeholder)
			if scenario == "broker-refusal" {
				if w.Code != 503 || calls.Load() != 0 {
					t.Fatal("broker refusal forwarded")
				}
			} else {
				wantCalls := int32(1)
				if scenario == "renewal" {
					wantCalls = 2
				}
				if w.Code != 200 || calls.Load() != wantCalls {
					t.Fatal("valid managed request failed")
				}
				if scenario == "revocation" {
					f.mu.Lock()
					f.verdict = "revoked"
					f.mu.Unlock()
					if w = send(placeholder); w.Code != 503 || calls.Load() != wantCalls {
						t.Fatal("revoked lease forwarded")
					}
				}
			}
			status, e := s.Status(binding.SlotID)
			if e != nil {
				t.Fatal("status unavailable")
			}
			b, _ := json.Marshal(status)
			observed = append(observed, string(b), audits.String())
			entries, e := os.ReadDir(root)
			if e != nil {
				t.Fatal("state inspection failed")
			}
			for _, entry := range entries {
				b, e := os.ReadFile(filepath.Join(root, entry.Name()))
				if e != nil {
					t.Fatal("state read failed")
				}
				observed = append(observed, string(b))
			}
			f.mu.Lock()
			for _, p := range f.params {
				observed = append(observed, string(p))
			}
			if scenario == "renewal" && f.renewals != 1 {
				t.Error("renewal count changed")
			}
			f.mu.Unlock()
			for _, text := range observed {
				if strings.Contains(text, brokerCanary) || strings.Contains(text, renewedCanary) {
					t.Fatal("canary escaped gateway material boundary")
				}
			}
			for _, variable := range os.Environ() {
				if strings.Contains(variable, brokerCanary) || strings.Contains(variable, renewedCanary) {
					t.Fatal("canary escaped into environment")
				}
			}
		})
	}
}

// Closed config parsing rejects unknown/duplicate members, noncanonical bytes
// and lifetime overflow before dialing; the end-to-end test is the valid control.
func TestManagedBrokerConfigRefusals(t *testing.T) {
	base := brokerFile{Socket: "/nonexistent/broker.sock", BrokerUID: 1000, ServiceGeneration: "service-current", Account: "account-current", AgentUID: 1234, AgentGeneration: "worker-current", LaunchID: "launch-current", MaxLifetimeSeconds: 60}
	b, _ := json.Marshal(base)
	over := base
	over.MaxLifetimeSeconds = 901
	o, _ := json.Marshal(over)
	for _, raw := range [][]byte{nil, []byte(`{}`), o, bytes.Replace(b, []byte(`"socket":`), []byte(`"extra":1,"socket":`), 1), bytes.Replace(b, []byte(`"socket":`), []byte(`"socket":"/other","socket":`), 1)} {
		if s, close, e := managedSource(context.Background(), raw); s != nil || close != nil || e == nil || e.Error() != "CREDENTIAL_SOURCE" {
			t.Fatal("invalid broker mapping admitted")
		}
	}
}
