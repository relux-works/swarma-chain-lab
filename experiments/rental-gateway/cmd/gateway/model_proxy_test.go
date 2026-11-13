package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	proxy "github.com/relux-works/swarma-chain-lab/experiments/model-proxy"
	pc "github.com/relux-works/swarma-chain-lab/experiments/payment-chain"
	booking "github.com/relux-works/swarma-chain-lab/experiments/rental-booking"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/journal"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/station"
	lifecycle "github.com/relux-works/swarma-chain-lab/experiments/station-lifecycle"
	"github.com/relux-works/swarma-chain-lab/experiments/station-lifecycle/gatewaybind"
)

func modelConfig(t *testing.T) *modelProxyConfig {
	uid := uint32(os.Getuid())
	return &modelProxyConfig{AdminSocket: filepath.Join(testRoot(t), "admin.sock"), ServerUID: &uid, Origin: "https://proxy.example", CertSHA256: strings.Repeat("0123456789abcdef", 4), Caps: proxy.Caps{InputTokens: 1000, OutputTokens: 100, Requests: 10, MaxTokens: 10, CostNanoUSD: 10000, DefaultMaxOutputTokens: 5}}
}

// Every explicit field is required; nil preserves v1. Bad config refuses before
// reading keys, opening listeners or creating state. JSON null is not omission.
func TestModelProxyConfig(t *testing.T) {
	c := remoteConfig(t)
	c.ModelProxy = modelConfig(t)
	if e := c.validate(true); e != nil {
		t.Fatal("valid model config", e)
	}
	for _, name := range []string{"admin_socket", "server_uid", "origin", "cert_sha256", "caps"} {
		raw, _ := json.Marshal(c)
		var fields map[string]json.RawMessage
		_ = json.Unmarshal(raw, &fields)
		var m map[string]json.RawMessage
		_ = json.Unmarshal(fields["model_proxy"], &m)
		delete(m, name)
		fields["model_proxy"], _ = json.Marshal(m)
		raw, _ = json.Marshal(fields)
		path := filepath.Join(testRoot(t), "config.json")
		writeInstalled(t, path, raw)
		if _, e := loadConfig(path, true); e != errConfig {
			t.Fatal("partial model config accepted", name, e)
		}
	}
	for _, change := range []func(*modelProxyConfig){
		func(m *modelProxyConfig) { m.AdminSocket = "relative" }, func(m *modelProxyConfig) { m.ServerUID = nil }, func(m *modelProxyConfig) { m.Origin += "/path" }, func(m *modelProxyConfig) { m.CertSHA256 = strings.Repeat("0", 64) }, func(m *modelProxyConfig) { m.Caps.MaxTokens = 101 }, func(m *modelProxyConfig) { m.Caps.CostNanoUSD = 0 }, func(m *modelProxyConfig) { m.Caps.DefaultMaxOutputTokens = 0 }, func(m *modelProxyConfig) { m.Caps.DefaultMaxOutputTokens = 11 },
	} {
		bad := c
		v := *c.ModelProxy
		bad.ModelProxy = &v
		change(&v)
		if e := serve(context.Background(), bad); e != errConfig {
			t.Fatal("model config guard missing", e)
		}
	}
	bad := c
	bad.Mode = "test"
	bad.Station.Driver = "local-test"
	if bad.validate(true) != errConfig {
		t.Fatal("local model accepted")
	}
	raw, _ := json.Marshal(c)
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	fields["model_proxy"] = json.RawMessage("null")
	raw, _ = json.Marshal(fields)
	path := filepath.Join(testRoot(t), "null.json")
	writeInstalled(t, path, raw)
	if _, e := loadConfig(path, true); e != errConfig {
		t.Fatal("null model config accepted")
	}
	c.ModelProxy = nil
	if c.validate(true) != nil {
		t.Fatal("absent model refused")
	}
	for _, mode := range []string{"", "off", "when_challenged", "required"} {
		c.RelayAuth = mode
		if c.validate(true) != nil {
			t.Fatal("valid relay mode")
		}
	}
	c.RelayAuth = "optional"
	if c.validate(true) != errConfig {
		t.Fatal("invalid relay auth mode accepted")
	}
}

type serviceRegistrar struct {
	s          *proxy.Service
	credential proxy.Credential
	wrong      string
}

func (r *serviceRegistrar) Prepare(_ context.Context, b proxy.Binding) (proxy.Credential, error) {
	c, e := r.s.Prepare(b)
	r.credential = c
	if r.wrong == "origin" {
		c.Endpoint.URL = "https://other.example"
	}
	if r.wrong == "pin" {
		c.Endpoint.CertSHA256 = strings.Repeat("f", 64)
	}
	return c, e
}
func (r *serviceRegistrar) Activate(_ context.Context, b proxy.Binding) error { return r.s.Activate(b) }
func (r *serviceRegistrar) Revoke(_ context.Context, b proxy.Binding) error   { return r.s.Revoke(b) }
func modelSlot(t *testing.T, j *journal.Store, now int64) (station.SlotSpec, station.SessionInfo) {
	t.Helper()
	id := strings.Repeat("b", 64)
	// Canonical contract + matching grant fields; this wiring fixture does not
	// exercise kernel signature or chain verification.
	pub := "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	caps := modelConfig(t).Caps
	c := booking.ContractV2{Version: 2, BookingID: id, RenterPubkey: pub, AgentPubkey: pub, StationName: "id/model-fixture", NotBefore: now, NotAfter: now + 100, Allowed: []string{"deliver"}, Forbidden: []string{"pay", "publish", "repository.push", "secret.release"}, TemplateID: "model", TemplateSHA256: booking.Hash([]byte("model template")), ProfileID: "model", ProfileVersion: "2", ProfileSHA256: booking.Hash([]byte("model profile")), Payment: pc.Terms{Coin: "nmc", Network: "regtest", Genesis: "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206", PriceUSDCents: 100, USDMicrosPerCoin: 1000000, RateAsOf: 90, MaxRateAgeSeconds: 60, AmountAtoms: 100000000, Address: "muowReuD37GjLG1KPJxYR7RGf5C9tZc3z6", MinConfirmations: 2}, PaymentPolicy: "advance", PrivacySHA256: booking.Hash([]byte(booking.PrivacyNotice)), ModelCaps: &booking.ModelCaps{InputTokens: caps.InputTokens, OutputTokens: caps.OutputTokens, Requests: caps.Requests, MaxTokens: caps.MaxTokens, CostNanoUSD: caps.CostNanoUSD, DefaultMaxOutputTokens: caps.DefaultMaxOutputTokens}}
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	grant, _ := json.Marshal(map[string]any{"version": 3, "contract_sha256": c.Hash(), "grantee_key": c.RenterPubkey, "agent_name": c.StationName, "not_before": c.NotBefore, "not_after": c.NotAfter})
	cert := []byte(`{"signed_grant":{"grant":` + string(grant) + `,"signature":"` + strings.Repeat("0", 128) + `"},"issuance":{"txid":"` + strings.Repeat("0", 64) + `"}}`)
	s := &journal.Slot{ID: id, BookingID: id, StationName: c.StationName, RenterPubKey: pub, CertificateB64: base64.StdEncoding.EncodeToString(cert), ContractSHA256: c.Hash(), ContractB64: base64.StdEncoding.EncodeToString(c.Bytes()), NotBefore: now, NotAfter: now + 100}
	if e := j.Put(s); e != nil {
		t.Fatal(e)
	}
	return station.SlotSpec{SlotID: id, BookingID: id, StationName: s.StationName}, station.SessionInfo{RenterPubKey: s.RenterPubKey, ContractSHA256: s.ContractSHA256, NotAfter: s.NotAfter}
}

// The production serve constructor must select the registrar. A missing socket
// fails Create before a v2 bootstrap can be issued, on either supported OS. The
// real socket/peer success path is Linux-only; local lifecycle uses real Service.
func TestModelRuntimeWiring(t *testing.T) {
	c, j, mtls, ptls, _, _, _ := remoteFixture(t)
	c.ModelProxy = modelConfig(t)
	r, e := newStationRuntime(c, j, mtls, ptls)
	if e != nil {
		t.Fatal(e)
	}
	defer r.close()
	spec, _ := modelSlot(t, j, time.Now().Unix())
	if _, e = r.driver.Create(context.Background(), spec); e == nil || e.Error() != "BOOTSTRAP" {
		t.Fatal("runtime omitted registrar", e)
	}
	cfg := stationDriverConfig(c, j)
	p, ok := cfg.ModelRegistrar.(*pinnedRegistrar)
	if !ok {
		t.Fatal("registrar missing")
	}
	client, ok := p.client.(proxy.Client)
	if !ok || client.SocketPath != c.ModelProxy.AdminSocket || client.ServerUID != *c.ModelProxy.ServerUID || cfg.ModelCaps != c.ModelProxy.Caps {
		t.Fatal("admin binding mismatch")
	}
}

// Real proxy registry/HTTPS upstream, native gateway config factory, durable
// gatewaybind and mTLS manager transport exercise v1/v2, start/end/expiry and
// Recoverer destruction after restart. Only the Unix peer transport is replaced
// by a direct Service registrar on Darwin; no host helper or real API is used.
func TestModelConfiguredLifecycle(t *testing.T) {
	for _, mode := range []string{"v1", "end", "restart-destroy", "wrong-origin", "wrong-pin", "linux-runtime"} {
		t.Run(mode, func(t *testing.T) {
			if mode == "linux-runtime" && runtime.GOOS != "linux" {
				t.Skip("production admin peer credentials require Linux")
			}
			c, j, mtls, ptls, manager, roots, _ := remoteFixture(t)
			var clock atomic.Int64
			clock.Store(time.Now().Unix())
			now := func() time.Time { return time.Unix(clock.Load(), 0) }
			var upstreamCalls atomic.Int32
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamCalls.Add(1)
				_, _ = io.Copy(io.Discard, r.Body)
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"id":"fixture","type":"message","role":"assistant","model":"fixture-model","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":7,"output_tokens":3}}`)
			}))
			defer upstream.Close()
			c.ModelProxy = modelConfig(t)
			service, e := proxy.New(proxy.Config{StateDir: testRoot(t), Endpoint: proxy.Endpoint{URL: c.ModelProxy.Origin, CertSHA256: c.ModelProxy.CertSHA256}, Upstream: upstream.URL + "/v1/messages", APIKey: "synthetic-fixture", Models: map[string]proxy.Model{"fixture-model": {ContextTokens: 100, InputNanoUSD: 2, OutputNanoUSD: 3, Source: "synthetic fixture"}}, Now: now, Transport: upstream.Client().Transport})
			if e != nil {
				t.Fatal(e)
			}
			defer service.Close()
			registrar := &serviceRegistrar{s: service}
			if mode == "wrong-origin" {
				registrar.wrong = "origin"
			}
			if mode == "wrong-pin" {
				registrar.wrong = "pin"
			}
			if mode == "v1" {
				c.ModelProxy = nil
			}
			cfg := stationDriverConfig(c, j)
			cfg.Now = now
			if mode != "v1" && mode != "linux-runtime" {
				cfg.ModelRegistrar.(*pinnedRegistrar).client = registrar
			}
			if mode == "linux-runtime" {
				if e = os.Chmod(filepath.Dir(c.ModelProxy.AdminSocket), 0750); e != nil {
					t.Fatal(e)
				}
				adminCtx, adminCancel := context.WithCancel(context.Background())
				adminDone := make(chan error, 1)
				go func() { adminDone <- service.ServeAdmin(adminCtx, c.ModelProxy.AdminSocket, *c.ModelProxy.ServerUID) }()
				defer func() {
					adminCancel()
					select {
					case e := <-adminDone:
						if e != nil {
							t.Error(e)
						}
					case <-time.After(3 * time.Second):
						t.Error("admin did not stop")
					}
				}()
				ready := time.Now().Add(time.Second)
				for {
					if st, e := os.Stat(c.ModelProxy.AdminSocket); e == nil && st.Mode()&os.ModeSocket != 0 && st.Mode().Perm() == 0660 {
						break
					}
					if time.Now().After(ready) {
						t.Fatal("admin socket not ready")
					}
					time.Sleep(time.Millisecond)
				}
			}
			var d *gatewaybind.Driver
			if mode == "linux-runtime" {
				r, err := newStationRuntime(c, j, mtls, ptls)
				if err != nil {
					t.Fatal(err)
				}
				defer r.close()
				d = r.driver.(*gatewaybind.Driver)
			} else {
				d, e = gatewaybind.New(cfg)
			}
			if e != nil {
				t.Fatal(e)
			}
			defer func() { d.Close() }()
			spec, info := modelSlot(t, j, clock.Load())
			st, e := d.Create(context.Background(), spec)
			if strings.HasPrefix(mode, "wrong-") {
				if e == nil || e.Error() != "BOOTSTRAP" {
					t.Fatal("endpoint pin guard missing", e)
				}
				status, e := service.Status(spec.SlotID)
				if e != nil || status.Phase != "prepared" || upstreamCalls.Load() != 0 {
					t.Fatal("pin refusal activated credential")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			if mode == "linux-runtime" {
				status, err := service.Status(spec.SlotID)
				if err != nil {
					t.Fatal(err)
				}
				registrar.credential, e = service.Prepare(status.Binding)
				if e != nil {
					t.Fatal(e)
				}
			}
			send := func() int {
				req := httptest.NewRequest("POST", "https://proxy.example/slots/"+spec.SlotID+"/v1/messages", strings.NewReader(`{"model":"fixture-model","messages":[{"role":"user","content":"hello"}],"max_tokens":10}`))
				req.Header.Set("Authorization", "Bearer "+string(registrar.credential.Bearer))
				w := httptest.NewRecorder()
				service.ServeHTTP(w, req)
				return w.Code
			}
			if mode != "v1" && (send() != 401 || upstreamCalls.Load() != 0) {
				t.Fatal("prepared bearer usable")
			}
			var srv *httptest.Server
			var poll *lifecycle.PollClient
			connect := func() {
				srv = httptest.NewUnstartedServer(d.Handler())
				srv.TLS = mtls.Clone()
				srv.StartTLS()
				var e error
				poll, e = lifecycle.NewPollClient(srv.URL+lifecycle.PollPath, manager, roots, c.Station.Manager.TLS.CertSHA256)
				if e != nil {
					t.Fatal(e)
				}
			}
			connect()
			defer func() { poll.Close(); srv.Close() }()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			command := func(done <-chan error) lifecycle.Command {
				t.Helper()
				for {
					p, e := poll.Poll(ctx, nil)
					if e != nil {
						t.Fatal(e)
					}
					if len(p.Commands) > 0 {
						return p.Commands[0]
					}
					select {
					case e := <-done:
						t.Fatal("operation returned before report", e)
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					case <-time.After(time.Millisecond):
					}
				}
			}
			report := func(cmd lifecycle.Command, phase string) {
				t.Helper()
				if _, e := poll.Poll(ctx, []lifecycle.Status{{SlotID: cmd.Slot.ID, Binding: cmd.Binding, Phase: phase, NotAfter: cmd.Slot.NotAfter}}); e != nil {
					t.Fatal(e)
				}
			}
			done := make(chan error, 1)
			go func() { done <- d.StartSession(ctx, st, info) }()
			cmd := command(done)
			doc, e := gatewaybind.DecodeBootstrap(cmd.Slot.Bootstrap)
			if e != nil {
				t.Fatal("bootstrap decode")
			}
			if mode == "v1" {
				expected := `{"v":1,"booking_id":"` + spec.BookingID + `","station_name":"` + spec.StationName + `","channel_secret":"` + base64.StdEncoding.EncodeToString(doc.ChannelSecret.Reveal()) + `"}`
				if doc.V != 1 || !bytes.Equal(cmd.Slot.Bootstrap, []byte(expected)) {
					t.Fatal("v1 bytes changed")
				}
			} else {
				if doc.V != 2 || doc.ModelBearer.Reveal() != registrar.credential.Bearer || doc.ModelEndpoint != c.ModelProxy.Origin || doc.ModelCertSHA256 != c.ModelProxy.CertSHA256 {
					t.Fatal("configured v2 bootstrap missing")
				}
			}
			report(cmd, "running")
			if e = <-done; e != nil {
				t.Fatal(e)
			}
			if mode == "v1" {
				return
			}
			if got := send(); got != 200 || upstreamCalls.Load() != 1 {
				t.Fatal("active bearer refused", got)
			}
			if mode == "restart-destroy" {
				clock.Store(info.NotAfter)
				if send() != 401 || upstreamCalls.Load() != 1 {
					t.Fatal("expired bearer forwarded")
				}
				poll.Close()
				srv.Close()
				d.Close()
				d, e = gatewaybind.New(cfg)
				if e != nil {
					t.Fatal(e)
				}
				connect()
				recoverer, ok := any(d).(station.Recoverer)
				if !ok {
					t.Fatal("recoverer absent")
				}
				st, e = recoverer.Reattach(ctx, spec)
				if e != nil {
					t.Fatal(e)
				}
				go func() { _, e := d.Destroy(ctx, st); done <- e }()
			} else {
				go func() { done <- d.End(ctx, st, "fixture end") }()
			}
			cmd = command(done)
			report(cmd, "stopped")
			if e = <-done; e != nil {
				t.Fatal("terminal cleanup", e)
			}
			status, e := service.Status(spec.SlotID)
			if e != nil || status.Phase != "revoked" || send() != 401 || upstreamCalls.Load() != 1 {
				t.Fatal("terminal path failed revoke", e)
			}
		})
	}
}
