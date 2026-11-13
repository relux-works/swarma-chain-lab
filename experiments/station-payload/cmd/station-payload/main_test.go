package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/stationlink"
	"github.com/relux-works/swarma-chain-lab/experiments/station-lifecycle/gatewaybind"
	payload "github.com/relux-works/swarma-chain-lab/experiments/station-payload"
)

// The child executes the actual CLI main and captures its public output. This
// branch is entered only by the bounded parent test, never by ordinary startup.
func TestCLIChild(t *testing.T) {
	if os.Getenv("PAYLOAD_CLI_TEST") != "1" {
		t.Skip("parent-owned subprocess only")
	}
	var args []string
	if json.Unmarshal([]byte(os.Getenv("PAYLOAD_CLI_ARGS")), &args) != nil {
		os.Exit(2)
	}
	os.Args = append([]string{"station-payload"}, args...)
	main()
	os.Exit(0)
}

// Real CLI v1 startup reads protected bootstrap/CA files and completes TLS/HMAC
// against a scripted channel. Rejected paths, modes, symlinks, fields and flags
// produce only fixed errors and no public path, secret or parser diagnostics.
func TestCLI(t *testing.T) {
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	static := filepath.Join(root, "static")
	if e := os.Mkdir(static, 0750); e != nil {
		t.Fatal(e)
	}
	os.Chmod(static, 0750)
	ca := filepath.Join(static, "ca.pem")
	writeInstalled(t, ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	doc := gatewaybind.PayloadBootstrap{V: 1, BookingID: strings.Repeat("b", 64), StationName: "id/cli", ChannelSecret: gatewaybind.NewChannelSecret([]byte(strings.Repeat("s", 32)))}
	raw, e := gatewaybind.EncodeBootstrap(doc)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(root, "private-path-marker.json")
	if os.WriteFile(path, raw, 0600) != nil {
		t.Fatal("bootstrap write")
	}
	leaf := sha256.Sum256(server.Certificate().Raw)
	ln, e := tls.Listen("tcp", "127.0.0.1:0", server.TLS.Clone())
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	done := make(chan bool, 1)
	go func() {
		c, e := ln.Accept()
		if e != nil {
			done <- false
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		hello, e := stationlink.ReadFrame(c)
		if e != nil || hello.Type != stationlink.TypeHello {
			done <- false
			return
		}
		nonce := strings.Repeat("a", 64)
		stationlink.WriteFrame(c, &stationlink.Frame{Type: stationlink.TypeChallenge, Nonce: nonce})
		auth, e := stationlink.ReadFrame(c)
		if e != nil || !stationlink.VerifyResponse(doc.ChannelSecret.Reveal(), nonce, doc.BookingID, doc.StationName, auth.Response) {
			done <- false
			return
		}
		stationlink.WriteFrame(c, &stationlink.Frame{Type: stationlink.TypeSystem, RelayMaxEventBytes: 65536, SlotID: doc.BookingID})
		pull, e := stationlink.ReadFrame(c)
		if e != nil || pull.Type != stationlink.TypePull {
			done <- false
			return
		}
		e = stationlink.WriteFrame(c, &stationlink.Frame{Type: stationlink.TypeEnd})
		done <- e == nil
	}()
	args := []string{"-journal-dir", journalRoot(t), "-bootstrap", path, "-ca", ca, "-gateway", ln.Addr().String(), "-gateway-pin", hex.EncodeToString(leaf[:])}
	child := func(a []string) (string, int) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		q, _ := json.Marshal(a)
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCLIChild$")
		cmd.Env = append(os.Environ(), "PAYLOAD_CLI_TEST=1", "PAYLOAD_CLI_ARGS="+string(q))
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &out
		if e := cmd.Start(); e != nil {
			t.Fatal("CLI start")
		}
		t.Logf("owned CLI PID %d", cmd.Process.Pid)
		err := cmd.Wait()
		if ctx.Err() != nil {
			t.Fatal("CLI timed out")
		}
		code := 0
		if err != nil {
			code = cmd.ProcessState.ExitCode()
		}
		return out.String(), code
	}
	if out, code := child(args); code != 0 || out != "" {
		t.Fatal("CLI valid neighbor refused")
	}
	if !<-done {
		t.Fatal("CLI handshake")
	}
	for _, mode := range []string{"missing", "mode", "symlink", "unknown", "flag"} {
		t.Run(mode, func(t *testing.T) {
			a := append([]string{}, args...)
			want := payload.ErrBootstrap
			switch mode {
			case "missing":
				a[3] = path + "-absent"
			case "mode":
				if os.Chmod(path, 0644) != nil {
					t.Fatal("chmod")
				}
				defer os.Chmod(path, 0600)
			case "symlink":
				p := path + "-link"
				if os.Symlink(path, p) != nil {
					t.Fatal("symlink")
				}
				a[3] = p
			case "unknown":
				bad := bytes.Replace(raw, []byte(`"v":1`), []byte(`"v":1,"private-field-marker":1`), 1)
				p := path + "-bad"
				if os.WriteFile(p, bad, 0600) != nil {
					t.Fatal("write")
				}
				a[3] = p
			case "flag":
				a = append(a, "-private-flag-marker")
				want = payload.ErrConfig
			}
			out, code := child(a)
			if code != 1 || out != want.Error()+"\n" {
				t.Fatal("CLI refusal leaked or changed code")
			}
		})
	}
}

// Malformed public arguments fail before private file reads or network effects.
func TestFlags(t *testing.T) {
	for _, args := range [][]string{{"-max-tokens", "invalid-secret-marker"}, {"extra-secret-marker"}, {"-unknown"}} {
		if e := run(context.Background(), args); e != payload.ErrConfig {
			t.Fatal("flag refusal")
		}
	}
}

// Journal fixtures use private task-local scratch: the system temp directory
// may have writable ancestors (for example /tmp), which production must refuse.
func journalRoot(t *testing.T) string {
	t.Helper()
	base, e := filepath.Abs(".temp")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.MkdirAll(base, 0700); e != nil {
		t.Fatal(e)
	}
	base, e = filepath.EvalSymlinks(base)
	if e != nil {
		t.Fatal(e)
	}
	p, e := os.MkdirTemp(base, "delivery-test-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(p) })
	if e = os.Chmod(p, 0700); e != nil {
		t.Fatal(e)
	}
	for parent := p; ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
			t.Fatalf("journal fixture requires nonwritable ancestry: %s (%v)", parent, err)
		}
		if parent == filepath.Dir(parent) {
			break
		}
	}
	return p
}
