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
	origin := caller
	origin.Account = "owner/claude/service-test"
	f.mu.Lock()
	f.account = origin.Account
	f.mu.Unlock()
	s, e := NewSource(c, origin)
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

// Claim: Source and Request share the broker's exact nonempty ASCII bounds on
// all caller strings. Invalid fields have no broker effects; slash labels and
// 128-byte controls are admitted without imposing a path-component grammar.
func TestSourceCallerGrammar(t *testing.T) {
	f := startFake(t)
	c := connect(t, f)
	for _, field := range []string{"account", "generation", "launch"} {
		for _, mode := range []string{"slash", "ascii", "boundary", "empty", "overlength", "unicode", "high-byte"} {
			t.Run(field+"/"+mode, func(t *testing.T) {
				value := "owner/claude/service-test"
				valid := true
				switch mode {
				case "ascii":
					value = "label :\x00\x7f"
				case "boundary":
					value = strings.Repeat("a", 128)
				case "empty":
					value, valid = "", false
				case "overlength":
					value, valid = strings.Repeat("a", 129), false
				case "unicode":
					value, valid = "label-\u00e9", false
				case "high-byte":
					value, valid = string([]byte{0xff}), false
				}
				origin := caller
				switch field {
				case "account":
					origin.Account = value
				case "generation":
					origin.Generation = value
				case "launch":
					origin.LaunchID = value
				}
				f.mu.Lock()
				before := len(f.calls)
				f.account = origin.Account
				f.mu.Unlock()
				s, e := NewSource(c, origin)
				if valid {
					if e != nil || s == nil {
						t.Fatal("broker caller grammar refused")
					}
					_, material, _, e := s.CredentialValue(context.Background())
					if e != nil || string(material) != fixtureMaterial {
						t.Fatal("valid caller did not acquire material")
					}
					clear(material)
					if s.Close(context.Background()) != nil {
						t.Fatal("valid caller release refused")
					}
					return
				}
				if s != nil || e != ErrInput {
					t.Fatal("invalid caller admitted by source")
				}
				if l, e := c.Request(context.Background(), "invalid-caller", origin); l != nil || e != ErrInput {
					t.Fatal("invalid caller admitted by client")
				}
				f.mu.Lock()
				defer f.mu.Unlock()
				if len(f.calls) != before {
					t.Fatal("invalid caller reached broker")
				}
			})
		}
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
