//go:build !darwin || !slotdfake

package main

import (
	"context"
	"encoding/json"
	"os"
	"testing"
)

// The production schema accepts its valid config and rejects even an empty fake_clock before runtime effects.
func TestProductionConfigRejectsFakeClock(t *testing.T) {
	c, path := checkConfigFixture(t)
	if e := run(context.Background(), []string{"check-config", "--config", path}); e != nil {
		t.Fatal("valid production config", e)
	}
	for _, value := range []string{"", c.Socket + ".clock"} {
		raw, e := json.Marshal(c)
		if e != nil {
			t.Fatal(e)
		}
		field, e := json.Marshal(value)
		if e != nil {
			t.Fatal(e)
		}
		raw = append(raw[:len(raw)-1], []byte(`,"fake_clock":`)...)
		raw = append(raw, field...)
		raw = append(raw, '}')
		writeInstalled(t, path, raw)
		if e = run(context.Background(), []string{"check-config", "--config", path}); e == nil || e.Error() != "CONFIG" {
			t.Fatal("production accepted fake_clock", e)
		}
	}
	for _, p := range []string{c.StateDir, c.Socket} {
		if _, e := os.Lstat(p); !os.IsNotExist(e) {
			t.Fatal("config check created runtime state", e)
		}
	}
}
