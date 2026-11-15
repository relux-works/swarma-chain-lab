package g2ledger

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Claim: all combinations of accepted replay poststates (absent file/dir, removed membership, disabled unit, restored config) keep the node restart obligation.
func TestRollbackReplayPoststateCombinations(t *testing.T) {
	for mask := 0; mask < 32; mask++ {
		t.Run(fmt.Sprintf("mask-%02d", mask), func(t *testing.T) {
			f, n := rollbackFixture(t, true)
			must(t, f.l.CreateAccount("group", "demo", "state", 0, 301))
			must(t, f.l.CreateAccount("group", "access", "state", 0, 302))
			must(t, f.l.CreateAccount("user", "demo", "state", 301, 301))
			var commits []Record
			save := func() { commits = append(commits, f.l.rows[len(f.l.rows)-1]) }
			f.create(t, "ordinary", "file", "remove")
			save()
			f.create(t, "directory", "dir", "remove")
			save()
			must(t, f.l.AddMember("demo", "access"))
			save()
			must(t, f.l.Enable("demo.service"))
			save()
			installRollbackConfig(t, f, n, true)
			save()
			for i, r := range commits {
				if mask&(1<<i) == 0 {
					continue
				}
				a := *f.l.rows[r.Body.Result.Intent].Body.Action
				must(t, f.l.startParentWatch(a, r.Body.Result.Identities))
				must(t, f.l.undo(a, r.Body.Result.Identities[0], "station", map[string]string{}))
				parents, e := f.l.finishParentWatch()
				must(t, e)
				if len(parents) > 0 {
					must(t, f.l.append(Body{Op: "parent-replay", ParentReplay: &ParentReplay{Commit: r.Seq, Parents: parents}}))
				}
			}
			f.reopen(t)
			must(t, f.l.Rollback("station", n))
			assertRollbackTerminal(t, f, n, true)
		})
	}
}

// Claim: the native CLI adapter uses only injected systemctl calls and names its unreadable-policy stopped outcome; rehearsal makes no node calls.
func TestRollbackNativeAdapterAndRehearsal(t *testing.T) {
	f, n := rollbackFixture(t, true)
	installRollbackConfig(t, f, n, false)
	original := f.sys.fault
	f.sys.fault = func(cmd string, args []string) (fakeReply, bool) {
		if cmd == "/usr/bin/systemctl" && len(args) == 2 && args[1] == "node.service" {
			var err error
			switch args[0] {
			case "start":
				err = n.Start(args[1])
			case "stop":
				err = n.Stop(args[1])
			default:
				return original(cmd, args)
			}
			return fakeReply{err: err}, true
		}
		return original(cmd, args)
	}
	f.l.Close()
	var out bytes.Buffer
	must(t, RunRollback([]string{"-dir", f.dir, "-mode", "station"}, f.sys, &out))
	if n.running || !strings.Contains(out.String(), "LIVE_POLICY_UNREADABLE") {
		t.Fatal("native runtime policy was implicitly trusted")
	}
	f.reopen(t)
	assertRollbackTerminal(t, f, n, false)
	r := setupWith(t, "rehearsal", nil)
	p := r.create(t, "ordinary", "file", "remove")
	before := len(r.sys.calls)
	must(t, r.l.Rollback("rehearsal", nil))
	absent(t, p)
	for _, c := range r.sys.calls[before:] {
		if strings.Contains(c, "systemctl show") || strings.Contains(c, "systemctl start") || strings.Contains(c, "systemctl stop") {
			t.Fatal("rehearsal touched node")
		}
	}
}

// Claim: missing node authority, wrong purpose, unsafe preimage and forward mutations after rollback are refused before an unauthorized effect.
func TestRollbackAuthorityBoundaries(t *testing.T) {
	f, n := rollbackFixture(t, true)
	code(t, f.l.Rollback("rehearsal", n), 1)
	if len(n.calls) != 0 {
		t.Fatal("wrong mode touched node")
	}
	code(t, f.l.Replay("station"), 1)
	must(t, f.l.Rollback("station", n))
	code(t, f.l.CreateFS(filepath.Join(f.root, "ordinary"), f.src, "file", "remove", uint32(os.Geteuid()), uint32(os.Getegid()), 0600), 1)
	absent(t, filepath.Join(f.root, "ordinary"))
	legacy := setup(t)
	e := legacy.l.Rollback("station", n)
	code(t, e, 1)
	if !strings.Contains(e.Error(), "NODE_DECLARATION_REQUIRED") {
		t.Fatal(e)
	}
	for _, shape := range []string{"outside-config", "relative-preimage", "non-service", "unit-enable-overlap"} {
		scope := f.scope
		node := *scope.Node
		scope.Node = &node
		switch shape {
		case "outside-config":
			node.Config = filepath.Join(f.root, "outside")
		case "relative-preimage":
			node.Preimage = "relative"
		case "non-service":
			node.Unit = "node.socket"
		case "unit-enable-overlap":
			scope.Units = append(append([]string(nil), scope.Units...), node.Unit)
		}
		if validateScope(scope) == nil {
			t.Fatalf("scope admitted %s", shape)
		}
	}
}

// Claim: the native unit readback accepts only active with a PID or inactive/failed with zero; malformed/transitional/status-error controls refuse.
func TestRollbackNodeStatusControls(t *testing.T) {
	for _, tc := range []struct {
		name, out        string
		status           int
		wantErr, running bool
	}{
		{"active", "LoadState=loaded\nActiveState=active\nMainPID=31\n", 0, false, true},
		{"inactive", "LoadState=loaded\nActiveState=inactive\nMainPID=0\n", 0, false, false},
		{"failed", "LoadState=loaded\nActiveState=failed\nMainPID=0\n", 0, false, false},
		{"active-zero", "LoadState=loaded\nActiveState=active\nMainPID=0\n", 0, true, false},
		{"stopped-with-process", "LoadState=loaded\nActiveState=inactive\nMainPID=31\n", 0, true, false},
		{"not-loaded", "LoadState=not-found\nActiveState=inactive\nMainPID=0\n", 0, true, false},
		{"operational", "LoadState=loaded\nActiveState=inactive\nMainPID=0\n", 77, true, false},
		{"duplicate", "LoadState=loaded\nActiveState=inactive\nMainPID=0\nMainPID=0\n", 0, true, false},
		{"transitional", "LoadState=loaded\nActiveState=activating\nMainPID=31\n", 0, true, false},
		{"empty", "", 0, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sys := newSystem()
			sys.fault = func(string, []string) (fakeReply, bool) { return fakeReply{out: tc.out, status: tc.status}, true }
			running, e := (systemNode{sys}).Observe("node.service")
			if (e != nil) != tc.wantErr || !tc.wantErr && running != tc.running {
				t.Fatalf("running=%v err=%v", running, e)
			}
		})
	}
}

// Claim: unresolved intent (with/without a physical effect), unsealed, truncated and mismatched HEAD ledgers refuse on every retry without node or filesystem effects.
func TestRollbackUnverifiedJournalRefuses(t *testing.T) {
	for _, shape := range []string{"intent-no-effect", "intent-with-effect", "unsealed", "truncated", "head-mismatch"} {
		t.Run(shape, func(t *testing.T) {
			f, n := rollbackFixture(t, true)
			before, e := os.ReadFile(n.config)
			must(t, e)
			want := 1
			switch shape {
			case "intent-no-effect", "intent-with-effect":
				id, e := observe(n.config, "modify")
				must(t, e)
				a := Action{Kind: "modify", Ret: "state", Paths: []string{n.config}, Backup: f.scope.Node.Preimage, BackupSHA256: digest(rollbackOld), NewSHA256: digest(rollbackNew), UID: id.FS.UID, GID: id.FS.GID, Mode: id.FS.Mode, Before: []Identity{*id}}
				_, e = f.l.begin(a)
				must(t, e)
				if shape == "intent-with-effect" {
					_, e = f.l.atomicReplace(n.config, *id, rollbackNew, a.UID, a.GID, a.Mode)
					must(t, e)
					before = rollbackNew
				}
				want = 3
			case "unsealed":
				must(t, os.WriteFile(filepath.Join(f.dir, unsealedName), nil, 0600))
			case "truncated":
				raw, e := os.ReadFile(filepath.Join(f.dir, recordsName))
				must(t, e)
				must(t, os.WriteFile(filepath.Join(f.dir, recordsName), raw[:len(raw)-1], 0600))
			case "head-mismatch":
				must(t, os.WriteFile(filepath.Join(f.dir, "HEAD"), canonical(head{Count: 999, Hash: zeroHash}), 0600))
			}
			f.l.Close()
			for retry := 0; retry < 2; retry++ {
				e := RunRollback([]string{"-dir", f.dir, "-mode", "station"}, f.sys, io.Discard)
				code(t, e, want)
				if !strings.Contains(e.Error(), "phase=validate") {
					t.Fatal("missing validation phase", e)
				}
				b, e := os.ReadFile(n.config)
				must(t, e)
				if !bytes.Equal(before, b) || len(n.calls) != 0 {
					t.Fatal("unverified journal changed target or node")
				}
			}
		})
	}
}

// Claim: a restore write failure leaves the node stopped with the installed file; a fresh handle retries safely and restores the baseline.
func TestRollbackRestoreWriteFailureConverges(t *testing.T) {
	f, n := rollbackFixture(t, true)
	installRollbackConfig(t, f, n, true)
	realWrite := f.l.write
	f.l.write = func(w io.Writer, b []byte) error {
		if file, ok := w.(*os.File); ok && file.Name() == filepath.Base(n.config) {
			return errors.New("injected write failure")
		}
		return realWrite(w, b)
	}
	e := f.l.Rollback("station", n)
	code(t, e, 1)
	if !strings.Contains(e.Error(), "RESTORE_FAILED") || n.running {
		t.Fatal("unsafe restore failure", e)
	}
	for _, c := range n.calls {
		if strings.HasPrefix(c, "start") {
			t.Fatal("started after failed restore")
		}
	}
	f.reopen(t)
	must(t, f.l.Rollback("station", n))
	assertRollbackTerminal(t, f, n, true)
}

// Claim: interruption during an in-place restore is recoverable by its durable inode receipt; a replacement inode is refused, and completed receipts grant no future rewrite authority.
func TestRollbackPartialWriteIdentityRecovery(t *testing.T) {
	for _, variant := range []string{"partial-write", "replacement", "changed-after-verified"} {
		t.Run(variant, func(t *testing.T) {
			f, n := rollbackFixture(t, true)
			installRollbackConfig(t, f, n, true)
			if variant == "changed-after-verified" {
				must(t, f.l.Rollback("station", n))
				must(t, os.WriteFile(n.config, []byte("foreign policy\n"), 0640))
				e := f.l.Rollback("station", n)
				code(t, e, 1)
				if !strings.Contains(e.Error(), "CONFIG_MISMATCH") {
					t.Fatal(e)
				}
				b, e := os.ReadFile(n.config)
				must(t, e)
				if string(b) != "foreign policy\n" {
					t.Fatal("completed restore authorized a later write")
				}
				return
			}
			realWrite := f.l.write
			f.l.write = func(w io.Writer, b []byte) error {
				if file, ok := w.(*os.File); ok && file.Name() == filepath.Base(n.config) {
					if _, e := file.Write([]byte("partial\n")); e != nil {
						return e
					}
					return io.ErrShortWrite
				}
				return realWrite(w, b)
			}
			code(t, f.l.Rollback("station", n), 1)
			if n.running {
				t.Fatal("partial config left running")
			}
			if variant == "replacement" {
				must(t, os.Rename(n.config, n.config+".displaced"))
				must(t, os.WriteFile(n.config, []byte("partial\n"), 0640))
			}
			f.reopen(t)
			e := f.l.Rollback("station", n)
			if variant == "replacement" {
				code(t, e, 1)
				if !strings.Contains(e.Error(), "CONFIG_MISMATCH") {
					t.Fatal(e)
				}
				b, readErr := os.ReadFile(n.config)
				must(t, readErr)
				if string(b) != "partial\n" {
					t.Fatal("replacement overwritten")
				}
				return
			} else {
				must(t, e)
			}
			assertRollbackTerminal(t, f, n, true)
		})
	}
}

// Claim: a successful command status cannot replace stop/start effect readback; clearing an ineffective controller fault converges safely.
func TestRollbackIneffectiveCommandsRefuse(t *testing.T) {
	for _, variant := range []string{"stop", "start", "stop-unreadable"} {
		t.Run(variant, func(t *testing.T) {
			f, n := rollbackFixture(t, true)
			installRollbackConfig(t, f, n, true)
			reason := "STOP_READBACK"
			switch variant {
			case "stop":
				n.stopNoop = true
			case "start":
				n.startNoop = true
				reason = "NODE_STATE_MISMATCH"
			case "stop-unreadable":
				n.readable = false
				f.l.rollbackHook = func(p string) error {
					if p == "started" {
						n.stopNoop = true
					}
					return nil
				}
			}
			e := f.l.Rollback("station", n)
			code(t, e, 1)
			if !strings.Contains(e.Error(), reason) {
				t.Fatal(e)
			}
			n.stopNoop = false
			n.startNoop = false
			f.reopen(t)
			must(t, f.l.Rollback("station", n))
			assertRollbackTerminal(t, f, n, n.readable)
		})
	}
}

// Claim: config metadata drift introduced at the final readback is a named nonzero refusal, and repairing the injected mode fault permits retry.
func TestRollbackFinalConfigReadbackMismatch(t *testing.T) {
	f, n := rollbackFixture(t, true)
	installRollbackConfig(t, f, n, true)
	f.l.rollbackHook = func(p string) error {
		if p == "check-intent" {
			return os.Chmod(n.config, 0600)
		}
		return nil
	}
	e := f.l.Rollback("station", n)
	code(t, e, 1)
	if !strings.Contains(e.Error(), "ROLLBACK_CONFIG_MISMATCH phase=check-intent") {
		t.Fatal(e)
	}
	must(t, os.Chmod(n.config, 0640))
	f.reopen(t)
	must(t, f.l.Rollback("station", n))
	assertRollbackTerminal(t, f, n, true)
}

// Claim: malformed or out-of-scope restore receipts refuse during journal validation, while an unchanged sealed positive control reopens.
func TestRollbackJournalSchemaControls(t *testing.T) {
	for _, variant := range []string{"positive", "missing-receipt", "outside-path", "nil-fs", "unknown-phase", "first-record"} {
		t.Run(variant, func(t *testing.T) {
			f, n := rollbackFixture(t, true)
			installRollbackConfig(t, f, n, false)
			target, e := observe(n.config, "modify")
			must(t, e)
			step := &RollbackStep{Phase: "restore-intent", Disk: "installed", Node: "stopped", Restore: target}
			switch variant {
			case "missing-receipt":
				step.Restore = nil
			case "outside-path":
				target.Path = filepath.Join(f.root, "foreign")
			case "nil-fs":
				target.FS = nil
			case "unknown-phase":
				step.Phase = "skip-restore"
			}
			rows := append(append([]Record(nil), f.l.rows...), Record{Body: Body{Op: "rollback", Rollback: step}})
			if variant == "first-record" {
				rows = rows[len(rows)-1:]
			}
			f.l.Close()
			writeRows(t, f, rows, true)
			opened, e := Open(f.dir, f.sys)
			if variant == "positive" {
				must(t, e)
				opened.Close()
			} else {
				code(t, e, 1)
			}
		})
	}
}

// Claim: an error after payload sync never becomes success merely because bytes match on retry; the retry syncs the restored inode again before any start.
func TestRollbackRestoredFileSyncRetried(t *testing.T) {
	f, n := rollbackFixture(t, true)
	installRollbackConfig(t, f, n, true)
	calls := 0
	f.l.payloadSync = func(file *os.File) error { calls++; return errors.New("injected payload sync failure") }
	e := f.l.Rollback("station", n)
	code(t, e, 1)
	if calls != 1 || n.running || !strings.Contains(e.Error(), "RESTORE_FAILED") {
		t.Fatal("sync failure did not stop recovery", e)
	}
	if f.l.nodeDisk() != "preinstall" {
		t.Fatal("witness must already have restored bytes and metadata")
	}
	f.reopen(t)
	retrySyncs := 0
	f.l.payloadSync = func(file *os.File) error { retrySyncs++; return nil }
	must(t, f.l.Rollback("station", n))
	if retrySyncs != 1 {
		t.Fatalf("matching restored inode was not synced on retry: %d", retrySyncs)
	}
	assertRollbackTerminal(t, f, n, true)
}
