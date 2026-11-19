package modelproxy

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

type standardSource struct {
	material []byte
	err      error
}

func (s *standardSource) CredentialValue(context.Context) (string, []byte, string, error) {
	s.material = []byte(sourceMarker)
	return SchemeOAuthBearer, s.material, "broker-version-1", s.err
}
func (s *standardSource) RenewValue(context.Context, string) (string, []byte, string, error) {
	return s.CredentialValue(context.Background())
}

// The structural seam admits a valid standard-library-only source, erases its
// temporary material and sanitizes errors. Non-conforming and typed-nil sources
// cannot acquire the private marker; their existing New refusal is unchanged.
func TestManagedSourceAdmission(t *testing.T) {
	valid := &standardSource{}
	adapted, e := AdaptManagedSource(valid)
	if e != nil {
		t.Fatal("valid source refused")
	}
	g := gatewayFixture(t, ModeManaged, adapted)
	g.mu.Lock()
	g.bearer = true
	g.mu.Unlock()
	if w := g.send(request(false)); w.Code != 200 || g.calls.Load() != 1 {
		t.Fatal("valid structural source did not serve")
	}
	if strings.Trim(string(valid.material), "\x00") != "" {
		t.Fatal("temporary material retained")
	}
	if strings.Contains(fmt.Sprintf("%#v", adapted), string(sourceMarker)) {
		t.Fatal("source formatting exposed material")
	}
	g.s.Close()
	nonconforming := wrappedSource{newFakeSource(sourceMarker)}
	for _, source := range []any{nonconforming, NewFileSource("/unused/key"), nil, (*standardSource)(nil)} {
		if out, err := AdaptManagedSource(source); out != nil || err == nil || err.Error() != "CONFIG_MODE_NO_BROKER" {
			t.Fatal("non-conforming source admitted")
		}
	}
	c := g.c
	c.Source = nonconforming
	if s, err := New(c); s != nil || err == nil || err.Error() != "CONFIG_MODE_NO_BROKER" {
		t.Fatal("existing managed refusal changed")
	}
	valid.err = errors.New(string(sourceMarker))
	for _, call := range []func() (UpstreamCredential, error){
		func() (UpstreamCredential, error) { return adapted.Credential(context.Background()) },
		func() (UpstreamCredential, error) { return adapted.Renew(context.Background(), "broker-version-1") },
	} {
		cred, err := call()
		if err == nil || err.Error() != "CREDENTIAL_UNAVAILABLE" || !cred.Value.IsZero() || strings.Trim(string(valid.material), "\x00") != "" {
			t.Fatal("source error exposed or retained material")
		}
	}
}

// Managed credentials cannot be routed to another recipient or a Responses
// profile, even by a library caller that bypasses command configuration.
func TestManagedRecipient(t *testing.T) {
	gateway := gatewayFixture(t, ModeManaged, newFakeSource(sourceMarker))
	if response := gateway.send(request(false)); response.Code != 200 {
		t.Fatal("valid pinned recipient refused")
	}
	gateway.s.Close()
	for _, scenario := range []string{"upstream", "profiles"} {
		t.Run(scenario, func(t *testing.T) {
			config := gateway.c
			if scenario == "upstream" {
				config.Upstream = "https://other-recipient.example/v1/messages"
			} else {
				config.ModelProfiles = map[string]ModelProfile{modelID: {Profile: "openai-responses-functions-default-v1", Upstream: "https://other-recipient.example/v1/responses"}}
			}
			before := gateway.calls.Load()
			service, err := New(config)
			if service != nil {
				service.Close()
			}
			if service != nil || err == nil || err.Error() != "CONFIG_MODE" || gateway.calls.Load() != before {
				t.Fatal("managed recipient bypass")
			}
		})
	}
}
