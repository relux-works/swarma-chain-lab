package wallet

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

type actionCrashFixture struct {
	Service ServiceConfig `json:"service"`
	Wallet  Config        `json:"wallet"`
	Stage   string        `json:"stage"`
}

// Child-only process exits at an actual durable reservation in the socket path.
// No production environment variable or flag can install this hook.
func TestActionCrashChild(t *testing.T) {
	path := os.Getenv("W2_CRASH_FIXTURE")
	if path == "" {
		t.Skip("isolated process crash child")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal("private crash fixture")
	}
	var f actionCrashFixture
	if json.Unmarshal(b, &f) != nil {
		t.Fatal("crash fixture schema")
	}
	w, e := Open(f.Wallet)
	if e != nil {
		t.Fatal(e)
	}
	w.clock = func() int64 { return 500 }
	key, _ := testKey(7)
	s, e := openActionService(f.Service, w, key)
	if e != nil {
		w.Close()
		t.Fatal(e)
	}
	defer s.Close()
	s.clock = func() int64 { return 500 }
	if f.Stage == "wallet" {
		w.hook = func(stage string) {
			if stage == "after-reservation" {
				os.Exit(77)
			}
		}
	} else {
		s.hook = func(stage string) {
			if stage == "after-service-reservation" {
				os.Exit(77)
			}
		}
	}
	if e = s.Serve(context.Background()); e != nil {
		t.Fatal(e)
	}
}
func awaitActionSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		i, e := os.Stat(path)
		if e == nil && i.Mode().Perm() == 0660 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("socket startup deadline")
		}
		time.Sleep(time.Millisecond)
	}
}
func runExistingSocket(t *testing.T, s *ActionService) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()
	awaitActionSocket(t, s.config.Socket)
	return func() {
		cancel()
		if e := <-done; e != nil {
			t.Error(e)
		}
		s.Close()
	}
}

// Actual process exits after wallet reservation, after service reservation and
// before receive allocation leave uncertainty. Reopening the socket never sends
// a second transaction or allocates an address; exact duplicate receipt persists.
func TestCoreActionCrash(t *testing.T) {
	l := newCore(t)
	for _, stage := range []string{"wallet", "service", "receive"} {
		t.Run(stage, func(t *testing.T) {
			terms := Terms{Version: 1, Recipients: []string{testAddress(3)}, SpendCap: 1000000}
			raw, c := l.grant(terms, []string{"pay"}, 1000000)
			id := installActionObjects(t, c, raw, terms)
			root := filepath.Join(l.private, "crash-"+stage)
			if e := os.Mkdir(root, 0700); e != nil {
				t.Fatal(e)
			}
			_, grantee := testKey(2)
			sc := ServiceConfig{Version: 1, Service: WalletServiceID, Socket: filepath.Join(l.root, "crash.sock"), SocketGID: uint32(os.Getgid()), PeerUID: uint32(os.Getuid()), Grantee: grantee, SkewSeconds: 60, TimeoutSeconds: 2, StateDir: root, WalletConfig: filepath.Join(root, "wallet-config.json"), ReceiptKeyFile: filepath.Join(root, "key")}
			fixture := filepath.Join(root, "fixture.json")
			if e := os.WriteFile(fixture, canonical(actionCrashFixture{sc, c, stage}), 0600); e != nil {
				t.Fatal(e)
			}
			request := actionFixture(t, "spend")
			request.Grant.ID = id
			if stage == "receive" {
				request = actionFixture(t, "receive")
			}
			message := actionEnvelope(t, request)
			pool := string(l.rpc("", "getrawmempool"))
			addresses := string(l.rpc("agent", "getaddressesbylabel", ""))
			executable, e := os.Executable()
			if e != nil {
				t.Fatal(e)
			}
			cmd := exec.Command(executable, "-test.run", "^TestActionCrashChild$")
			cmd.Env = append(os.Environ(), "W2_CRASH_FIXTURE="+fixture)
			if e = cmd.Start(); e != nil {
				t.Fatal(e)
			}
			pid := cmd.Process.Pid
			l.commands = append(l.commands, map[string]any{"crash_child_pid": pid, "stage": stage})
			waited := false
			defer func() {
				if !waited {
					cmd.Process.Kill()
					cmd.Wait()
				}
			}()
			awaitActionSocket(t, sc.Socket)
			conn, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: sc.Socket, Net: "unix"})
			if e != nil {
				t.Fatal(e)
			}
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			if e = writeActionFrame(conn, message); e != nil {
				t.Fatal(e)
			}
			if _, e = readActionFrame(conn); e == nil {
				t.Fatal("crash returned success")
			}
			conn.Close()
			e = cmd.Wait()
			waited = true
			exit, ok := e.(*exec.ExitError)
			if !ok || exit.ExitCode() != 77 {
				t.Fatal("intended reservation crash not reached")
			}
			l.commands = append(l.commands, map[string]any{"crash_child_waited": pid, "exit": 77})
			if pool != string(l.rpc("", "getrawmempool")) || addresses != string(l.rpc("agent", "getaddressesbylabel", "")) {
				t.Fatal("reservation crash already caused effect")
			}
			if stage != "receive" {
				if _, e = os.Stat(filepath.Join(c.StateDir, "wallet.json")); e != nil {
					t.Fatal("wallet reservation missing after crash")
				}
			}
			// Only this known fixture socket is removed, after its owned PID has exited.
			if e = os.Remove(sc.Socket); e != nil {
				t.Fatal(e)
			}
			w, e := Open(c)
			if e != nil {
				t.Fatal(e)
			}
			w.clock = func() int64 { return 500 }
			key, _ := testKey(7)
			s, e := openActionService(sc, w, key)
			if e != nil {
				w.Close()
				t.Fatal(e)
			}
			s.clock = func() int64 { return 500 }
			stop := runExistingSocket(t, s)
			defer stop()
			got, one := socketRaw(t, s, message)
			expectAction(t, got, "uncertain", "DURABLE_RESERVATION_NO_RETRY")
			_, two := socketRaw(t, s, message)
			if !bytes.Equal(one, two) {
				t.Fatal("uncertainty receipt changed")
			}
			if pool != string(l.rpc("", "getrawmempool")) || addresses != string(l.rpc("agent", "getaddressesbylabel", "")) {
				t.Fatal("crash retry caused effect")
			}
			l.save("socket-crash-"+stage+".json", got)
		})
	}
}

// Real seal revocation injected after durable reservation must be seen by the
// final chain check. Only the fixture revocation enters the mempool, not payment.
func TestCoreActionFinalCheck(t *testing.T) {
	l := newCore(t)
	terms := Terms{Version: 1, Recipients: []string{testAddress(3)}, SpendCap: 1000000}
	raw, c := l.grant(terms, []string{"pay"}, 1000000)
	id := installActionObjects(t, c, raw, terms)
	f := coreSocket(t, l, c)
	s := f.service
	r := actionFixture(t, "spend")
	r.Grant.ID = id
	reached := false
	s.mu.Lock()
	s.hook = func(stage string) {
		if stage == "after-service-reservation" {
			reached = true
			l.revoke(raw)
		}
	}
	s.mu.Unlock()
	got, _ := socketRequest(t, s, r)
	expectAction(t, got, "refused", "GRANT_SEAL_SPENT")
	s.mu.Lock()
	if !reached {
		t.Fatal("post-reservation witness not applied")
	}
	var pool []string
	if json.Unmarshal(l.rpc("", "getrawmempool"), &pool) != nil || len(pool) != 1 {
		t.Fatal("final recheck allowed payment effect")
	}
	if len(s.wallet.state.Records) != 1 || s.wallet.state.Records[0].Phase != "reserved" {
		t.Fatal("final refusal lost reservation")
	}
	s.mu.Unlock()
	// A second distinct request observes the same real mempool revocation before planning.
	r.Nonce = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	got, _ = socketRequest(t, s, r)
	expectAction(t, got, "refused", "GRANT_SEAL_SPENT")
	l.save("socket-final-check.json", got)
}
