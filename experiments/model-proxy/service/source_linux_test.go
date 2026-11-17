//go:build linux

package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// Source returns only a fresh material copy after a live revocation check,
// renews the same lease with a distinct version, and stays closed after revoke
// or release. The fake broker supplies no real provider credential.
func TestSourceLifecycle(t *testing.T) {
	f := startFake(t)
	c := connect(t, f)
	s, e := NewSource(c, caller)
	if e != nil {
		t.Fatal("source creation refused")
	}
	ctx := context.Background()
	scheme, material, version, e := s.CredentialValue(ctx)
	if e != nil || scheme != "oauth-bearer" || string(material) != fixtureMaterial || version == "" {
		t.Fatal("source positive control failed")
	}
	clear(material)
	_, material, same, e := s.CredentialValue(ctx)
	if e != nil || string(material) != fixtureMaterial || same != version {
		t.Fatal("material copy changed lease")
	}
	clear(material)
	_, material, renewed, e := s.RenewValue(ctx, version)
	if e != nil || renewed == version || string(material) != fixtureMaterial {
		t.Fatal("source renewal failed")
	}
	clear(material)
	for _, value := range []any{s, *s} {
		b, e := json.Marshal(value)
		if e != nil || strings.Contains(string(b)+fmt.Sprintf("%#v %+v", value, value), fixtureMaterial) {
			t.Fatal("source diagnostic leaked material")
		}
	}
	f.mu.Lock()
	f.verdict = "revoked"
	f.mu.Unlock()
	for i := 0; i < 2; i++ {
		_, material, _, e = s.CredentialValue(ctx)
		if e == nil || len(material) != 0 {
			t.Fatal("revoked source returned material")
		}
	}
	if e := s.Close(ctx); e != nil {
		t.Fatal("release failed")
	}
	_, material, _, e = s.CredentialValue(ctx)
	if e != ErrInactive || len(material) != 0 {
		t.Fatal("released source reacquired")
	}
}

// Invalid constructors and empty handles refuse without dereferencing missing
// broker state; the lifecycle test is their nearby valid control.
func TestSourceRefusals(t *testing.T) {
	if s, e := NewSource(nil, caller); s != nil || e != ErrInput {
		t.Fatal("nil client admitted")
	}
	f := startFake(t)
	c := connect(t, f)
	if s, e := NewSource(c, Caller{}); s != nil || e != ErrInput {
		t.Fatal("empty caller admitted")
	}
	var s *Source
	if _, b, _, e := s.CredentialValue(context.Background()); e != ErrInput || len(b) != 0 {
		t.Fatal("nil source admitted")
	}
	s, e := NewSource(c, caller)
	if e != nil {
		t.Fatal("valid source refused")
	}
	if _, b, _, e := s.RenewValue(context.Background(), "unknown"); e != ErrInactive || len(b) != 0 {
		t.Fatal("renewal without lease admitted")
	}
}
