package executor

import (
	"encoding/json"
	pc "github.com/relux-works/swarma-chain-lab/experiments/payment-chain"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// privateRouteFixture is a test-only legacy config writer. Generic Route JSON
// intentionally redacts; genuine private fixture files need their original
// credentials. Never use this projection in logging or production output.
func privateRouteFixture(value any) any {
	type legacy struct {
		Host     string `json:"host"`
		Port     int    `json:"port"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	switch r := value.(type) {
	case su.Route:
		return legacy{r.Host, r.Port, r.Username, r.Password.RevealForBasicAuth()}
	case pc.Route:
		return legacy{r.Host, r.Port, r.Username, r.Password.RevealForBasicAuth()}
	default:
		return value
	}
}

func privateRouteFixtureJSON(value any) []byte {
	raw, err := json.Marshal(privateRouteFixture(value))
	if err != nil {
		panic("private route fixture refused")
	}
	return raw
}

// privateProcessConfigFixture is the encoder used by the real Core process
// fixture. Project both private routes before invoking the generic encoder.
func privateProcessConfigFixture(config map[string]any) []byte {
	projected := make(map[string]any, len(config))
	for key, value := range config {
		projected[key] = value
	}
	for _, key := range []string{"observer", "broadcast"} {
		projected[key] = privateRouteFixture(projected[key])
	}
	return canonical(projected)
}

// The process fixture writes real credentials that Strict restores byte for
// byte. The old generic encoder writes the placeholder and cannot authenticate;
// this test does not exercise a Core node or spawn the executor binary.
func TestPrivateProcessConfigFixture(t *testing.T) {
	const password = "synthetic-process-password-42798136"
	route := su.Route{Host: "127.0.0.1", Port: 18443, Username: "m4a-broadcast", Password: su.NewRPCPassword(password)}
	input := map[string]any{"observer": route, "broadcast": route}
	type config struct {
		Observer  su.Route `json:"observer"`
		Broadcast su.Route `json:"broadcast"`
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, privateProcessConfigFixture(input), 0600); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got config
	if err := Strict(raw, &got); err != nil {
		t.Fatal("private fixture refused", err)
	}
	for _, r := range []su.Route{got.Observer, got.Broadcast} {
		if r.Password.RevealForBasicAuth() != password {
			t.Fatal("private fixture changed password")
		}
	}
	if _, err := NewBroadcaster(got.Broadcast); err != nil {
		t.Fatal("private broadcast route refused", err)
	}
	var old config
	oldRaw := canonical(input)
	if err := Strict(oldRaw, &old); err != nil {
		t.Fatal("old-path control did not decode", err)
	}
	if !strings.Contains(string(oldRaw), "[private RPC password]") || old.Broadcast.Password.RevealForBasicAuth() != "[private RPC password]" {
		t.Fatal("old-path control did not write placeholder")
	}
	if _, err := NewBroadcaster(old.Broadcast); err == nil || err.Error() != "BROADCAST_ROUTE" {
		t.Fatal("old-path control did not reach broadcast refusal", err)
	}
}
