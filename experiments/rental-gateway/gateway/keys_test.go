package gateway_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/gateway"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
)

// TestLoadAgentKeyModes proves the agent key loads only from a
// 0600-or-stricter regular file: a group/other-readable key file is
// refused (the gateway side of "stations must not read the key";
// the linux-user side is a separate UID, tested in station).
func TestLoadAgentKeyModes(t *testing.T) {
	key, _ := nostr.GeneratePrivKey()
	path := filepath.Join(t.TempDir(), "agent.key")
	if err := gateway.SaveAgentKey(path, key); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatalf("saved key mode %04o, want 0600", info.Mode().Perm())
	}
	loaded, err := gateway.LoadAgentKey(path)
	if err != nil || loaded.PubKeyHex() != key.PubKeyHex() {
		t.Fatalf("0600 load = %v", err)
	}
	if err := gateway.SaveAgentKey(path, key); err == nil {
		t.Fatal("SaveAgentKey overwrote an existing key")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := gateway.LoadAgentKey(path); err == nil {
		t.Fatal("0644 agent key accepted")
	}
}

// TestLoadZeroKeyRefused proves a zero-filled key file (corrupt or
// wiped) cannot start a gateway with identity 000...0 (RM2 M5).
func TestLoadZeroKeyRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "zero.key")
	if err := os.WriteFile(path, []byte(strings.Repeat("0", 64)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := gateway.LoadAgentKey(path); err == nil {
		t.Fatal("zero agent key accepted")
	}
}
