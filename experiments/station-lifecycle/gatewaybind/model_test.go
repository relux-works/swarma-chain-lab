package gatewaybind

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	proxy "github.com/relux-works/swarma-chain-lab/experiments/model-proxy"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/gateway"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/journal"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/station"
	lifecycle "github.com/relux-works/swarma-chain-lab/experiments/station-lifecycle"
)

// V1 stays byte-identical; v2 is closed and requires the exact private credential,
// canonical HTTPS origin and leaf pin. Unknown versions and authority fields refuse.
func TestBootstrapV2Schema(t *testing.T) {
	b := PayloadBootstrap{V: 2, BookingID: strings.Repeat("a", 64), StationName: "id/fixture", ChannelSecret: lifecycle.Secret(strings.Repeat("x", 32)), ModelBearer: proxy.Secret(base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("y", 32)))), ModelEndpoint: "https://proxy.example", ModelCertSHA256: strings.Repeat("b", 64)}
	raw, e := EncodeBootstrap(b)
	if e != nil {
		t.Fatal(e)
	}
	expected := `{"v":2,"booking_id":"` + b.BookingID + `","station_name":"id/fixture","channel_secret":"` + base64.StdEncoding.EncodeToString(b.ChannelSecret) + `","model_bearer":"` + string(b.ModelBearer) + `","model_endpoint":"https://proxy.example","model_cert_sha256":"` + b.ModelCertSHA256 + `"}`
	if string(raw) != expected {
		t.Fatal("v2 canonical field order")
	}
	decoded, e := DecodeBootstrap(raw)
	if e != nil || decoded.ModelBearer != b.ModelBearer || decoded.ModelEndpoint != b.ModelEndpoint {
		t.Fatal("valid v2 neighbor")
	}
	for _, bad := range [][]byte{
		bytes.Replace(raw, []byte(`"v":2`), []byte(`"v":3`), 1),
		bytes.Replace(raw, []byte(`"v":2`), []byte(`"v":1`), 1),
		bytes.Replace(raw, []byte(`"v":2`), []byte(`"v":2,"v":2`), 1),
		bytes.Replace(raw, []byte(`"v":2`), []byte(`"v":2,"upstream_key":"forbidden"`), 1),
		bytes.Replace(raw, []byte(`https://proxy.example`), []byte(`https://proxy.example/slots/x`), 1),
		bytes.Replace(raw, []byte(`https://proxy.example`), []byte(`http://proxy.example`), 1),
		bytes.Replace(raw, []byte(b.ModelBearer), []byte("short"), 1),
		bytes.Replace(raw, []byte(b.ModelCertSHA256), []byte("short"), 1),
	} {
		if _, e = DecodeBootstrap(bad); e == nil || e.Error() != "PAYLOAD_BOOTSTRAP" {
			t.Fatal("invalid bootstrap accepted")
		}
	}
	b.V = 1
	b.ModelBearer = ""
	b.ModelEndpoint = ""
	b.ModelCertSHA256 = ""
	raw, e = EncodeBootstrap(b)
	if e != nil || bytes.Contains(raw, []byte("model_")) {
		t.Fatal("v1 shape changed")
	}
}

type registrar struct {
	service                               *proxy.Service
	prepareFail, activateFail, revokeFail bool
	prepare, activate, revoke             int
}

func (r *registrar) Prepare(ctx context.Context, b proxy.Binding) (proxy.Credential, error) {
	r.prepare++
	if r.prepareFail {
		return proxy.Credential{}, errors.New("private failure marker")
	}
	return r.service.Prepare(b)
}
func (r *registrar) Activate(ctx context.Context, b proxy.Binding) error {
	r.activate++
	if r.activateFail {
		return errors.New("private failure marker")
	}
	return r.service.Activate(b)
}
func (r *registrar) Revoke(ctx context.Context, b proxy.Binding) error {
	r.revoke++
	if r.revokeFail {
		return errors.New("private failure marker")
	}
	return r.service.Revoke(b)
}
func modelFixture(t *testing.T) (*fixture, *registrar) {
	t.Helper()
	f := setup(t)
	f.d.Close()
	s, e := proxy.New(proxy.Config{StateDir: privateDir(t), Endpoint: proxy.Endpoint{URL: "https://proxy.example", CertSHA256: strings.Repeat("d", 64)}, Upstream: "https://upstream.example/v1/messages", APIKey: "synthetic-test-key", Models: map[string]proxy.Model{"test-model": {ContextTokens: 100, InputNanoUSD: 2, OutputNanoUSD: 3, Source: "synthetic fixture"}}, Now: f.c.Now})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	r := &registrar{service: s}
	f.c.ModelRegistrar = r
	f.c.ModelCaps = proxy.Caps{InputTokens: 1000, OutputTokens: 100, Requests: 10, MaxTokens: 10, CostNanoUSD: 10000}
	f.d, e = New(f.c)
	if e != nil {
		t.Fatal(e)
	}
	f.gcfg.Driver = f.d
	f.g, e = gateway.New(f.gcfg)
	if e != nil {
		t.Fatal(e)
	}
	return f, r
}
func modelPhase(t *testing.T, r *registrar, id string) string {
	t.Helper()
	v, e := r.service.Status(id)
	if e != nil {
		t.Fatal(e)
	}
	return v.Phase
}

// Real proxy registry, gateway adapter and broker preserve inactive bootstrap on
// Prepare/restart, activate before manager start and revoke before terminal ACK.
// Peer authentication and payload TLS are outside this injected registrar test.
func TestModelLifecycle(t *testing.T) {
	f, r := modelFixture(t)
	spec := station.SlotSpec{SlotID: f.id, BookingID: f.id, StationName: "id/fixture"}
	if _, e := f.d.Create(context.Background(), spec); e != nil {
		t.Fatal(e)
	}
	v, e := f.d.broker.Lookup(f.id)
	if e != nil {
		t.Fatal(e)
	}
	doc, e := DecodeBootstrap(v.Bootstrap)
	if e != nil || doc.V != 2 || modelPhase(t, r, f.id) != "prepared" {
		t.Fatal("model prepared wrong state")
	}
	req := httptest.NewRequest("POST", doc.ModelEndpoint+"/slots/"+f.id+"/v1/messages", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+string(doc.ModelBearer))
	w := httptest.NewRecorder()
	r.service.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Fatal("prepared bearer already usable")
	}
	saved := append([]byte(nil), v.Bootstrap...)
	f.restart(t)
	if _, e = f.d.Create(context.Background(), spec); e != nil {
		t.Fatal(e)
	}
	v, e = f.d.broker.Lookup(f.id)
	if e != nil || !bytes.Equal(v.Bootstrap, saved) || r.prepare != 1 {
		t.Fatal("restart reminted bootstrap")
	}
	stop := f.pump(t)
	defer stop()
	if e = f.g.StartSlot(context.Background(), f.id); e != nil {
		t.Fatal(e)
	}
	if modelPhase(t, r, f.id) != "active" || r.activate != 1 {
		t.Fatal("start omitted model activation")
	}
	if _, e = f.g.EndSlot(context.Background(), f.id, "fixture", "model cleanup"); e != nil {
		t.Fatal(e)
	}
	if modelPhase(t, r, f.id) != "revoked" || r.revoke != 1 {
		t.Fatal("end omitted model revoke")
	}
}

// Prepare/Activate failures never start a host. Revoke failure still requests host
// stop, but cannot complete the gateway closer until revocation retry succeeds.
func TestModelLifecycleFailures(t *testing.T) {
	for _, kind := range []string{"prepare", "activate", "revoke"} {
		t.Run(kind, func(t *testing.T) {
			f, r := modelFixture(t)
			stop := f.pump(t)
			defer stop()
			switch kind {
			case "prepare":
				r.prepareFail = true
			case "activate":
				r.activateFail = true
			}
			e := f.g.StartSlot(context.Background(), f.id)
			if kind != "revoke" {
				f.host.mu.Lock()
				starts := f.host.starts
				f.host.mu.Unlock()
				if e == nil || starts != 0 || strings.Contains(e.Error(), "private failure") {
					t.Fatal("failed registration started host")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			r.revokeFail = true
			pending, e := f.g.EndSlot(context.Background(), f.id, "fixture", "model cleanup")
			if !errors.Is(e, gateway.ErrOperationUncertain) || pending.State != journal.OpStateStarted {
				t.Fatal("failed revoke claimed complete")
			}
			f.host.mu.Lock()
			active, stops := f.host.active, f.host.stops
			f.host.mu.Unlock()
			if active || stops == 0 {
				t.Fatal("proxy outage suppressed host stop")
			}
			j, _ := f.c.Journal.Get(f.id)
			if !j.Ended || j.ChannelSecretHex != "" {
				t.Fatal("pending cleanup retained gateway channel")
			}
			persisted, ok := f.g.LookupOperation(f.id, "fixture")
			if !ok || persisted.State != journal.OpStateStarted {
				t.Fatal("gateway completed without model revoke")
			}
			r.revokeFail = false
			done, e := f.g.EndSlot(context.Background(), f.id, "fixture", "model cleanup")
			if e != nil || done.State != journal.OpStateDone {
				t.Fatal("revoke retry did not complete closer", e)
			}
			if modelPhase(t, r, f.id) != "revoked" {
				t.Fatal("revoke retry failed")
			}
		})
	}
}
