package g2ledger

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Synthetic policy strings exercise byte identity without carrying credentials.
var rollbackOld = []byte("rpcauth=baseline-fixture\nrpcwhitelist=baseline-fixture:read\n")
var rollbackNew = []byte("rpcauth=install-fixture\nrpcwhitelist=install-fixture:write\n")

type rollbackNode struct {
	stopNoop, startNoop                  bool
	config                               string
	running, readable, sticky, rejectNew bool
	loaded                               []byte
	calls                                []string
	fault                                string
	applied                              bool
}

func (n *rollbackNode) Observe(string) (bool, error) {
	if n.fault == "observe" {
		return false, errors.New("synthetic sensitive diagnostic")
	}
	return n.running, nil
}
func (n *rollbackNode) Stop(string) error {
	n.calls = append(n.calls, "stop")
	if n.stopNoop {
		return nil
	}
	if n.fault == "stop" && !n.applied {
		return errors.New("synthetic sensitive diagnostic")
	}
	n.running = false
	if n.fault == "stop" {
		return errors.New("synthetic sensitive diagnostic")
	}
	return nil
}
func (n *rollbackNode) Start(string) error {
	if n.startNoop {
		n.calls = append(n.calls, "start-noop")
		return nil
	}
	b, e := os.ReadFile(n.config)
	if e != nil {
		return e
	}
	defer clear(b)
	if bytes.Equal(b, rollbackNew) {
		n.calls = append(n.calls, "start-installed")
	} else {
		n.calls = append(n.calls, "start-preinstall")
	}
	if n.rejectNew && bytes.Equal(b, rollbackNew) {
		return errors.New("new policy rejected")
	}
	if n.fault == "start" && !n.applied {
		return errors.New("synthetic sensitive diagnostic")
	}
	n.running = true
	if !n.sticky {
		n.loaded = append(n.loaded[:0], b...)
	}
	if n.fault == "start" {
		return errors.New("synthetic sensitive diagnostic")
	}
	return nil
}
func (n *rollbackNode) Policy(string) (NodePolicy, error) {
	n.calls = append(n.calls, "policy")
	if n.fault == "policy" {
		return NodePolicy{}, errors.New("synthetic sensitive diagnostic")
	}
	return NodePolicy{Readable: n.readable, ConfigSHA256: digest(n.loaded)}, nil
}
func rollbackFixture(t *testing.T, baselineRunning bool) (*fixture, *rollbackNode) {
	t.Helper()
	n := &rollbackNode{running: baselineRunning, readable: true, loaded: append([]byte(nil), rollbackOld...)}
	f := setupWith(t, "station", func(f *fixture) {
		n.config = filepath.Join(f.root, "config")
		must(t, os.WriteFile(n.config, rollbackOld, 0640))
		must(t, os.Chmod(n.config, 0640))
		backup := filepath.Join(f.root, "baseline", "node.conf")
		must(t, os.WriteFile(backup, rollbackOld, 0600))
		f.scope.Node = &NodeScope{Unit: "node.service", Config: n.config, Preimage: backup}
		f.sys.fault = func(cmd string, args []string) (fakeReply, bool) {
			if cmd == "/usr/bin/systemctl" && len(args) > 0 && args[0] == "show" {
				active, pid := "inactive", 0
				if n.running {
					active, pid = "active", 73
				}
				return fakeReply{out: fmt.Sprintf("LoadState=loaded\nActiveState=%s\nMainPID=%d\n", active, pid)}, true
			}
			return fakeReply{}, false
		}
	})
	return f, n
}
func installRollbackConfig(t *testing.T, f *fixture, n *rollbackNode, running bool) {
	t.Helper()
	n.running = false
	must(t, os.WriteFile(f.src, rollbackNew, 0600))
	must(t, f.l.ModifyFile(n.config, f.scope.Node.Preimage, f.src))
	n.running = running
	if running {
		n.loaded = append(n.loaded[:0], rollbackNew...)
	}
}
func assertRollbackTerminal(t *testing.T, f *fixture, n *rollbackNode, wantRunning bool) {
	t.Helper()
	b, e := os.ReadFile(n.config)
	must(t, e)
	if !bytes.Equal(b, rollbackOld) || n.running != wantRunning {
		t.Fatalf("unsafe terminal disk=%s running=%v", f.l.nodeDisk(), n.running)
	}
	if wantRunning && !bytes.Equal(n.loaded, rollbackOld) {
		t.Fatal("success with stale loaded policy")
	}
	if f.l.nodeDisk() != "preinstall" {
		t.Fatal("preinstall metadata not restored")
	}
	for _, call := range n.calls {
		if call == "start-installed" {
			t.Fatal("node started before restoring config")
		}
	}
	f.reopen(t)
	last := f.l.rows[len(f.l.rows)-1].Body.Rollback
	if last == nil || last.Phase != "verified" {
		t.Fatal("missing durable final readback")
	}
}

// Claim: each install boundary and accepted reverse-replay shape restores bytes/metadata before start, including old disk with new live policy.
func TestRollbackInstallFailuresAndReplayShapes(t *testing.T) {
	for _, shape := range []string{"before-stop", "after-stop", "backup-failed", "before-config-intent", "config-committed", "node-start-failed", "node-readiness-failed", "replay-newer-removed", "replay-config-restored-before-error", "replay-config-restored-before-reload-error", "replay-all-effects-done"} {
		t.Run(shape, func(t *testing.T) {
			f, n := rollbackFixture(t, true)
			switch shape {
			case "before-stop", "before-config-intent":
			case "after-stop", "backup-failed":
				n.running = false
			default:
				// An older and a newer record put config restore in the middle of replay.
				older := f.create(t, "older", "file", "remove")
				installRollbackConfig(t, f, n, shape != "config-committed" && shape != "node-start-failed")
				newer := f.create(t, "newer", "file", "remove")
				switch shape {
				case "replay-newer-removed":
					r := f.l.rows[len(f.l.rows)-1]
					a := *f.l.rows[r.Body.Result.Intent].Body.Action
					must(t, f.l.startParentWatch(a, r.Body.Result.Identities))
					must(t, f.l.undo(a, r.Body.Result.Identities[0], "station", map[string]string{}))
					p, e := f.l.finishParentWatch()
					must(t, e)
					must(t, f.l.append(Body{Op: "parent-replay", ParentReplay: &ParentReplay{Commit: r.Seq, Parents: p}}))
					absent(t, newer)
				case "replay-config-restored-before-error", "replay-config-restored-before-reload-error", "replay-all-effects-done":
					// This is the old engine's permitted nontransactional replay, not a shell model.
					must(t, f.l.replay("station", true))
					absent(t, older)
					absent(t, newer)
					if !bytes.Equal(n.loaded, rollbackNew) {
						t.Fatal("witness did not retain the installed live policy")
					}
				}
			}
			n.rejectNew = true
			f.reopen(t)
			must(t, f.l.Rollback("station", n))
			assertRollbackTerminal(t, f, n, true)
			must(t, f.l.Rollback("station", n))
			assertRollbackTerminal(t, f, n, true)
		})
	}
}

// Claim: retry after restore/replay or reload failure refuses a stale loaded policy; removing the runtime fault converges without a shell hash comparison.
func TestRollbackResumeRejectsStaleLivePolicy(t *testing.T) {
	for _, shape := range []string{"restore-then-error", "replay-then-reload-error"} {
		t.Run(shape, func(t *testing.T) {
			f, n := rollbackFixture(t, true)
			if shape == "restore-then-error" {
				must(t, f.l.CreateAccount("group", "demo", "state", 0, 301))
			} else {
				must(t, f.l.Enable("demo.service"))
			}
			installRollbackConfig(t, f, n, true)
			originalFault := f.sys.fault
			f.sys.fault = func(cmd string, args []string) (fakeReply, bool) {
				if shape == "restore-then-error" && cmd == "/usr/bin/getent" {
					return fakeReply{status: 73}, true
				}
				if shape == "replay-then-reload-error" && cmd == "/usr/bin/systemctl" && args[0] == "daemon-reload" {
					return fakeReply{status: 77}, true
				}
				return originalFault(cmd, args)
			}
			// Actual replay restores config and then stops at the older effect.
			code(t, f.l.replay("station", true), 1)
			current, e := os.ReadFile(n.config)
			must(t, e)
			if !bytes.Equal(current, rollbackOld) || !bytes.Equal(n.loaded, rollbackNew) {
				t.Fatal("partial replay witness missing")
			}
			f.sys.fault = originalFault
			n.sticky = true
			f.reopen(t)
			err := f.l.Rollback("station", n)
			code(t, err, 1)
			if !strings.Contains(err.Error(), "ROLLBACK_LIVE_POLICY_MISMATCH phase=check-intent") {
				t.Fatalf("wrong refusal: %v", err)
			}
			if !n.running || !bytes.Equal(n.loaded, rollbackNew) {
				t.Fatal("stale live policy witness missing")
			}
			n.sticky = false
			f.reopen(t)
			must(t, f.l.Rollback("station", n))
			assertRollbackTerminal(t, f, n, true)
		})
	}
}

// Claim: a failed post-change start is recovered by restoring first; an interrupted restore remains recoverable on the next invocation.
func TestRollbackFailedNewStartRestoresBeforeStart(t *testing.T) {
	f, n := rollbackFixture(t, true)
	installRollbackConfig(t, f, n, false)
	n.rejectNew = true
	fired := false
	f.l.rollbackHook = func(phase string) error {
		if phase == "restored" && !fired {
			fired = true
			return errors.New("interruption")
		}
		return nil
	}
	code(t, f.l.Rollback("station", n), 1)
	if n.running || len(n.calls) != 1 || n.calls[0] != "stop" {
		t.Fatal("start occurred before restored checkpoint")
	}
	b, e := os.ReadFile(n.config)
	must(t, e)
	if !bytes.Equal(b, rollbackOld) {
		t.Fatal("failed start config not restored")
	}
	f.reopen(t)
	must(t, f.l.Rollback("station", n))
	assertRollbackTerminal(t, f, n, true)
}

// Claim: every sealed rollback checkpoint can be interrupted and reopened; retry reestablishes stop/restore and converges.
func TestRollbackCheckpointInterruptions(t *testing.T) {
	for _, point := range []string{"stop-intent", "stopped", "restore-intent", "restored", "replay-intent", "replayed", "start-intent", "started", "check-intent", "verified"} {
		t.Run(point, func(t *testing.T) {
			f, n := rollbackFixture(t, true)
			installRollbackConfig(t, f, n, true)
			fired := false
			f.l.rollbackHook = func(p string) error {
				if p == point && !fired {
					fired = true
					return errors.New("interrupt")
				}
				return nil
			}
			code(t, f.l.Rollback("station", n), 1)
			if !fired {
				t.Fatal("boundary not exercised")
			}
			f.reopen(t)
			must(t, f.l.Rollback("station", n))
			assertRollbackTerminal(t, f, n, true)
		})
	}
}

// Claim: stop/start/readback failures, including commands that took effect before failing, report phase/state without diagnostics and converge on retry.
func TestRollbackControllerRefusalsConverge(t *testing.T) {
	for _, fault := range []string{"stop", "start", "observe", "policy"} {
		for _, applied := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/applied=%v", fault, applied), func(t *testing.T) {
				f, n := rollbackFixture(t, true)
				installRollbackConfig(t, f, n, true)
				n.fault = fault
				n.applied = applied
				e := f.l.Rollback("station", n)
				code(t, e, 1)
				if !strings.Contains(e.Error(), "phase=") || !strings.Contains(e.Error(), "disk=") || !strings.Contains(e.Error(), "node=") || strings.Contains(e.Error(), "sensitive") {
					t.Fatalf("unbounded refusal: %v", e)
				}
				n.fault = ""
				f.reopen(t)
				must(t, f.l.Rollback("station", n))
				assertRollbackTerminal(t, f, n, true)
			})
		}
	}
}

// Claim: a baseline-stopped node is never started; unavailable live policy yields a named, read-back stopped outcome instead of unverified running success.
func TestRollbackDeliberatelyStopped(t *testing.T) {
	for _, baseline := range []bool{false, true} {
		t.Run(fmt.Sprintf("baseline-running=%v", baseline), func(t *testing.T) {
			f, n := rollbackFixture(t, baseline)
			installRollbackConfig(t, f, n, true)
			n.readable = false
			var out bytes.Buffer
			f.l.output = &out
			must(t, f.l.Rollback("station", n))
			reason := "BASELINE_STOPPED"
			if baseline {
				reason = "LIVE_POLICY_UNREADABLE"
			}
			if !strings.Contains(out.String(), reason) {
				t.Fatal("missing named stopped outcome")
			}
			if !baseline {
				for _, c := range n.calls {
					if strings.HasPrefix(c, "start") {
						t.Fatal("baseline-stopped node started")
					}
				}
			}
			assertRollbackTerminal(t, f, n, false)
			must(t, f.l.Rollback("station", n))
			assertRollbackTerminal(t, f, n, false)
		})
	}
}

// Claim: changed config bytes, changed preimage and metadata drift refuse without overwriting foreign state; restoring evidence permits a safe retry.
func TestRollbackConfigMismatchRefuses(t *testing.T) {
	for _, drift := range []string{"bytes", "preimage", "mode"} {
		t.Run(drift, func(t *testing.T) {
			f, n := rollbackFixture(t, true)
			installRollbackConfig(t, f, n, false)
			saved, e := observe(n.config, "modify")
			must(t, e)
			switch drift {
			case "bytes":
				must(t, os.WriteFile(n.config, []byte("foreign\n"), 0640))
			case "preimage":
				must(t, os.WriteFile(f.scope.Node.Preimage, []byte("foreign\n"), 0600))
			case "mode":
				must(t, os.Chmod(n.config, 0600))
			}
			e = f.l.Rollback("station", n)
			code(t, e, 1)
			if !strings.Contains(e.Error(), "CONFIG_MISMATCH") {
				t.Fatalf("wrong refusal: %v", e)
			}
			for _, c := range n.calls {
				if strings.HasPrefix(c, "start") {
					t.Fatal("started on mismatch")
				}
			}
			// Repair only the injected fault, retaining the original inode/mtime receipt.
			if drift == "preimage" {
				must(t, os.WriteFile(f.scope.Node.Preimage, rollbackOld, 0600))
			} else {
				must(t, os.WriteFile(n.config, rollbackNew, 0640))
				must(t, os.Chmod(n.config, 0640))
				must(t, os.Chtimes(n.config, time.Unix(0, saved.FS.MtimeNS), time.Unix(0, saved.FS.MtimeNS)))
			}
			f.reopen(t)
			must(t, f.l.Rollback("station", n))
			assertRollbackTerminal(t, f, n, true)
		})
	}
}
