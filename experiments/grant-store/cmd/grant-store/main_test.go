package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	store "github.com/relux-works/swarma-chain-lab/experiments/grant-store"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
)

func commandOutput(t *testing.T, cmd *exec.Cmd) ([]byte, error) {
	t.Helper()
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if e := cmd.Start(); e != nil {
		return nil, e
	}
	t.Logf("owned command PID %d", cmd.Process.Pid)
	e := cmd.Wait()
	return output.Bytes(), e
}

// CLI key loading rejects public/linked/malformed files beside a valid private
// key. No private key values or auth headers are included in failure messages.
func TestSigningKeyFiles(t *testing.T) {
	k, e := nostr.GeneratePrivKey()
	if e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"valid", "permissions", "symlink", "hardlink", "short", "invalid"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, "key")
			b := []byte(k.Hex())
			if kind == "short" {
				b = b[:63]
			}
			if kind == "invalid" {
				b = bytes.Repeat([]byte("z"), 64)
			}
			if e := os.WriteFile(p, b, 0600); e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "permissions":
				if e := os.Chmod(p, 0644); e != nil {
					t.Fatal(e)
				}
			case "symlink":
				q := filepath.Join(dir, "link")
				if e := os.Symlink(p, q); e != nil {
					t.Fatal(e)
				}
				p = q
			case "hardlink":
				if e := os.Link(p, filepath.Join(dir, "link")); e != nil {
					t.Fatal(e)
				}
			}
			got, e := signingKey(p)
			if kind == "valid" {
				if e != nil || got.PubKeyHex() != k.PubKeyHex() {
					t.Fatal("valid private key refused")
				}
			} else if e == nil {
				t.Fatal("unsafe key accepted")
			}
		})
	}
}

// A test child runs the real server CLI with synthetic root ownership; compiled
// client CLIs put/get/list/delete bytes against its real loopback server. This
// rejects a non-reader, and preserves an existing output file. Its owned PID
// is terminated and waited on; no daemon or external network is involved.
func TestCLIProcess(t *testing.T) {
	dir := t.TempDir()
	bin := os.Getenv("GRANT_STORE_CLI_BINARY")
	if bin == "" {
		bin = filepath.Join(dir, "grant-store")
		cmd := exec.Command("go", "build", "-trimpath", "-o", bin, ".")
		if out, e := commandOutput(t, cmd); e != nil {
			t.Fatalf("build CLI: %v %s", e, out)
		}
	}
	root := filepath.Join(dir, "store")
	if e := os.Mkdir(root, 0700); e != nil {
		t.Fatal(e)
	}
	keys := map[string]string{}
	pub := map[string]string{}
	for _, name := range []string{"writer", "reader", "outsider"} {
		k, e := nostr.GeneratePrivKey()
		if e != nil {
			t.Fatal(e)
		}
		p := filepath.Join(dir, name)
		if e = os.WriteFile(p, []byte(k.Hex()), 0600); e != nil {
			t.Fatal(e)
		}
		keys[name] = p
		pub[name] = k.PubKeyHex()
	}
	cfg, _ := json.Marshal(store.Config{Root: root, Writers: []string{pub["writer"]}})
	configDir := filepath.Join(dir, "static")
	if e := os.Mkdir(configDir, 0750); e != nil {
		t.Fatal(e)
	}
	os.Chmod(configDir, 0750)
	config := filepath.Join(configDir, "config.json")
	if e := os.WriteFile(config, cfg, 0640); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	testBin, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.CommandContext(ctx, testBin, "-test.run=^TestDK5ServerChild$")
	childArgs, _ := json.Marshal([]string{"serve", "-config", config})
	cmd.Env = append(os.Environ(), "DK5_STORE_CHILD=1", "DK5_STORE_ARGS="+string(childArgs))
	stdout, e := cmd.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	pid := cmd.Process.Pid
	t.Logf("owned CLI PID %d", pid)
	waited := false
	t.Cleanup(func() {
		if !waited {
			_ = cmd.Process.Signal(syscall.SIGTERM)
			_ = cmd.Wait()
		}
	})
	line, e := bufio.NewReader(stdout).ReadBytes('\n')
	if e != nil {
		t.Fatal("server startup failed")
	}
	var ready struct {
		URL string `json:"url"`
		PID int    `json:"pid"`
	}
	if json.Unmarshal(line, &ready) != nil || ready.PID != pid || !strings.HasPrefix(ready.URL, "http://127.0.0.1:") {
		t.Fatal("invalid startup record")
	}
	invoke := func(wantOK bool, args ...string) []byte {
		t.Helper()
		c := exec.CommandContext(ctx, bin, args...)
		b, e := commandOutput(t, c)
		if (e == nil) != wantOK {
			t.Fatalf("CLI %s success=%v expected=%v: %s", args[0], e == nil, wantOK, b)
		}
		return b
	}
	input := filepath.Join(dir, "input")
	if e = os.WriteFile(input, []byte("cli blob"), 0600); e != nil {
		t.Fatal(e)
	}
	b := invoke(true, "put", "-server", ready.URL, "-key", keys["writer"], "-in", input, "-readers", pub["reader"])
	var d store.Descriptor
	if json.Unmarshal(b, &d) != nil || d.SHA256 != store.Hash([]byte("cli blob")) {
		t.Fatal("CLI upload descriptor")
	}
	output := filepath.Join(dir, "output")
	invoke(false, "get", "-server", ready.URL, "-key", keys["outsider"], "-hash", d.SHA256, "-out", output)
	if _, e = os.Stat(output); !os.IsNotExist(e) {
		t.Fatal("rejected download wrote output")
	}
	invoke(true, "get", "-server", ready.URL, "-key", keys["reader"], "-hash", d.SHA256, "-out", output)
	b, e = os.ReadFile(output)
	info, se := os.Stat(output)
	if e != nil || se != nil || string(b) != "cli blob" || info.Mode().Perm() != 0600 {
		t.Fatal("CLI output mismatch")
	}
	invoke(false, "get", "-server", ready.URL, "-key", keys["reader"], "-hash", d.SHA256, "-out", output)
	b, _ = os.ReadFile(output)
	if string(b) != "cli blob" {
		t.Fatal("existing output overwritten")
	}
	b = invoke(true, "list", "-server", ready.URL, "-key", keys["writer"])
	var list []store.Descriptor
	if json.Unmarshal(b, &list) != nil || len(list) != 1 || list[0].SHA256 != d.SHA256 {
		t.Fatal("CLI owner list")
	}
	invoke(false, "delete", "-server", ready.URL, "-key", keys["reader"], "-hash", d.SHA256)
	invoke(true, "delete", "-server", ready.URL, "-key", keys["writer"], "-hash", d.SHA256)
	invoke(false, "get", "-server", ready.URL, "-key", keys["writer"], "-hash", d.SHA256, "-out", filepath.Join(dir, "deleted"))
	invoke(false, "serve", "-config", config, "-listen", "0.0.0.0:0")
	if e = cmd.Process.Signal(syscall.SIGTERM); e != nil {
		t.Fatal(e)
	}
	_, _ = io.Copy(io.Discard, stdout)
	e = cmd.Wait()
	waited = true
	if e != nil {
		t.Fatalf("server exit: %v", e)
	}
	if e = syscall.Kill(pid, 0); e != syscall.ESRCH {
		t.Fatal("owned server PID remains")
	}
}

// Test-only entry point; production binaries have no ownership bypass flag.
func TestDK5ServerChild(t *testing.T) {
	if os.Getenv("DK5_STORE_CHILD") != "1" {
		t.Skip("parent-owned child")
	}
	var args []string
	if json.Unmarshal([]byte(os.Getenv("DK5_STORE_ARGS")), &args) != nil {
		os.Exit(2)
	}
	os.Args = append([]string{"grant-store"}, args...)
	main()
	os.Exit(0)
}
