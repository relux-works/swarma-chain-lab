package main

import (
	"context"
	"encoding/json"
	relay "github.com/relux-works/swarma-chain-lab/experiments/relay"
	"os"
	"path/filepath"
	"testing"
)

// Check validates the actual CLI's public config without creating relay state;
// wildcard/bad ports, malformed config and unknown flags fail before effects.
func TestCheck(t *testing.T) {
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	os.Chmod(root, 0750)
	cfg := relay.Defaults(filepath.Join(root, "state"), "ws://127.0.0.1:18818")
	raw, _ := json.Marshal(cfg)
	path := filepath.Join(root, "config")
	if e = os.WriteFile(path, raw, 0640); e != nil {
		t.Fatal(e)
	}
	args := []string{"-config", path, "-check"}
	if e = run(context.Background(), args); e != nil {
		t.Fatal("valid check", e)
	}
	for _, listen := range []string{"0.0.0.0:18818", "127.0.0.1:abc", "127.0.0.1:0", "127.0.0.1:65536"} {
		if e = run(context.Background(), append(args, "-listen", listen)); e == nil || e.Error() != "LISTEN" {
			t.Fatal("invalid listen", e)
		}
	}
	if e = run(context.Background(), append(args, "-unknown")); e == nil {
		t.Fatal("unknown flag")
	}
	if _, e = os.Stat(cfg.StateDir); !os.IsNotExist(e) {
		t.Fatal("check created state")
	}
	if e = os.WriteFile(path, []byte(`{"sensitive_marker":true}`), 0640); e != nil {
		t.Fatal(e)
	}
	if e = run(context.Background(), args); e == nil || e.Error() != "CONFIG" {
		t.Fatal("malformed config", e)
	}
}
