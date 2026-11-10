package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every repeated-byte placeholder is refused at all configurable SHA256 pin
// fields, before serve effects. One differing byte restores syntactic validity;
// this does not claim that the resulting pin matches an actual external object.
func TestConfigPlaceholderPins(t *testing.T) {
	c := remoteConfig(t)
	fields := []struct {
		name string
		pin  *string
	}{
		{"template", &c.Exchange.TemplateSHA256},
		{"profile", &c.Exchange.ProfileSHA256},
		{"payload", &c.Station.Manager.PayloadSHA256},
		{"server", &c.Station.Manager.TLS.CertSHA256},
		{"manager", &c.Station.Manager.TLS.ManagerCertSHA256},
	}
	if e := c.validate(false); e != nil {
		t.Fatal("valid control", e)
	}
	for _, field := range fields {
		t.Run(field.name, func(t *testing.T) {
			saved := *field.pin
			defer func() { *field.pin = saved }()
			for value := range 256 {
				b := bytes.Repeat([]byte{byte(value)}, 32)
				*field.pin = hex.EncodeToString(b)
				if e := c.validate(false); e != errConfig {
					t.Fatalf("placeholder pin accepted: byte=%02x error=%v", value, e)
				}
				if e := serve(context.Background(), c); e != errConfig {
					t.Fatalf("placeholder reached startup: %v", e)
				}
				b[31] ^= 1
				*field.pin = hex.EncodeToString(b)
				if e := c.validate(false); e != nil {
					t.Fatalf("different-byte neighbour refused: %02x %v", value, e)
				}
			}
		})
	}
	entries, e := os.ReadDir(filepath.Dir(c.AgentKeyFile))
	if e != nil || len(entries) != 0 {
		t.Fatal("pin refusal caused effects")
	}
	// Exercise the actual public-config command boundary, including valid before
	// and after controls; invalid input must return only the fixed config error.
	path := filepath.Join(filepath.Dir(c.AgentKeyFile), "public.json")
	for _, value := range []string{c.Station.Manager.TLS.ManagerCertSHA256, strings.Repeat("00", 32), strings.Repeat("ab", 32), strings.Repeat("ff", 32), c.Station.Manager.TLS.ManagerCertSHA256} {
		original := c.Station.Manager.TLS.ManagerCertSHA256
		c.Station.Manager.TLS.ManagerCertSHA256 = value
		raw, e := json.Marshal(c)
		if e != nil {
			t.Fatal(e)
		}
		writeInstalled(t, path, raw)
		e = runValidate([]string{"-config", path})
		if (value == original && e != nil) || (value != original && e != errConfig) {
			t.Fatal("public pin validator", e)
		}
		c.Station.Manager.TLS.ManagerCertSHA256 = original
	}
}

// Pin placeholder policy must not tighten the unrelated booking-ID syntax.
// Canonical lowercase length/hex checks still apply to identifiers and pins.
func TestPinSyntaxAndIdentifierBoundary(t *testing.T) {
	for _, s := range []string{"", "xyz", strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("AB", 32), strings.Repeat("ab", 31) + "zz"} {
		if digest(s) || pinDigest(s) {
			t.Fatal("malformed digest accepted")
		}
	}
	for value := range 256 {
		s := hex.EncodeToString(bytes.Repeat([]byte{byte(value)}, 32))
		if !digest(s) || pinDigest(s) {
			t.Fatal("pin and identifier policy conflated")
		}
	}
}
