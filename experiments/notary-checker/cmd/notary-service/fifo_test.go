package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/notary-checker/internal/service"
)

// This helper executes the actual CLI path in a separately killable process.
func TestServeProcessHelper(t *testing.T) {
	if os.Getenv("NOTARY_TEST_CHILD") != "1" {
		return
	}
	os.Exit(run(context.Background(), []string{"serve", "-config", os.Getenv("NOTARY_TEST_CONFIG")}, os.Stdout))
}

// Claim: serve loads regular private files, but promptly refuses a FIFO config, policy, key or
// credential. A canceled valid configuration exercises the successful load.
// The fixture flag must be rejected as ARGUMENTS before touching that config.
func TestServeFIFOAndFixtureFlag(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "key")
	if _, err := service.Keygen(key); err != nil {
		t.Fatal(err)
	}
	cred := filepath.Join(dir, "credential")
	if err := os.WriteFile(cred, []byte("u:p"), 0600); err != nil {
		t.Fatal(err)
	}
	policy := filepath.Join(dir, "policy")
	if err := os.WriteFile(policy, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := service.Config{Listen: "127.0.0.1:0", KeyFile: key, RPCEndpoint: "http://127.0.0.1:1", RPCCredentialFile: cred, DeploymentPolicyFile: policy, Limits: service.Limits{RequestBytes: 65536, RequestsPerSecond: 100, Burst: 100, TimeoutMS: 1000, Concurrent: 2}}
	path := filepath.Join(dir, "config")
	write := func(c service.Config) {
		raw, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out bytes.Buffer
	if code := run(ctx, []string{"serve", "-config", path}, &out); code != 0 {
		t.Fatalf("regular control: code %d", code)
	}
	out.Reset()
	if code := run(ctx, []string{"serve", "-config", path, "-offline-name-fixture", "x"}, &out); code != 1 || out.String() != "ARGUMENTS\n" {
		t.Fatalf("fixture flag: code=%d output=%q", code, out.String())
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"config", "policy", "key", "credential"} {
		t.Run(kind, func(t *testing.T) {
			fifo := filepath.Join(t.TempDir(), "fifo")
			if err := syscall.Mkfifo(fifo, 0600); err != nil {
				t.Fatal(err)
			}
			c := cfg
			want := "KEY_FILE"
			target := path
			switch kind {
			case "config":
				target = fifo
				want = "CONFIG"
			case "policy":
				c.DeploymentPolicyFile = fifo
				want = "POLICY_FILE"
			case "key":
				c.KeyFile = fifo
			case "credential":
				c.RPCCredentialFile = fifo
				want = "NODE_CREDENTIALS"
			}
			write(c)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, exe, "-test.run=^TestServeProcessHelper$")
			cmd.Env = append(os.Environ(), "NOTARY_TEST_CHILD=1", "NOTARY_TEST_CONFIG="+target)
			var output bytes.Buffer
			cmd.Stdout = &output
			cmd.Stderr = &output
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Logf("owned CLI helper PID %d", cmd.Process.Pid)
			err := cmd.Wait()
			if ctx.Err() != nil {
				t.Fatal("serve failed to refuse FIFO within 3s")
			}
			if e, ok := err.(*exec.ExitError); !ok || e.ExitCode() != 1 || strings.TrimSpace(output.String()) != want {
				t.Fatalf("serve refusal: err=%v output=%q", err, output.String())
			}
		})
	}
}
