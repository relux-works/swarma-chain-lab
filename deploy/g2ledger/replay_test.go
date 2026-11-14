//go:build linux

package g2ledger

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// Claim: changing only a committed user's primary GID stops before userdel
// and before older effects. The unchanged UID+GID neighbour is removable.
func TestLedgerChangedPrimaryGIDStopsD9_5(t *testing.T) {
	for _, drift := range []bool{true, false} {
		t.Run(map[bool]string{true: "changed-gid", false: "matching"}[drift], func(t *testing.T) {
			f := setupWith(t, "station", func(f *fixture) { f.sys.groups["demo"] = Account{Name: "demo", GID: 301} })
			older := f.create(t, "older", "file", "remove")
			must(t, f.l.CreateAccount("user", "demo", "remove", 301, 301))
			if drift {
				a := f.sys.users["demo"]
				a.GID = 999
				f.sys.users["demo"] = a
				code(t, f.l.Replay("station-remove"), 1)
				if f.sys.called("/usr/sbin/userdel") {
					t.Fatal("changed gid deleted")
				}
				exists(t, older)
			} else {
				must(t, f.l.Replay("station-remove"))
				if _, ok := f.sys.users["demo"]; ok {
					t.Fatal("owned user retained")
				}
				absent(t, older)
			}
		})
	}
}

// Claim: empty is-enabled output with status 73/127/0 and unknown state/status
// pairs are errors that stop reverse replay immediately; disabled/1 is valid.
func TestLedgerUnitLookupErrorStopsD9_4(t *testing.T) {
	for _, reply := range []fakeReply{{"", 73, nil}, {"", 127, nil}, {"", 0, nil}, {"UNKNOWN\n", 73, nil}, {"disabled\n", 0, nil}, {"enabled\n", 1, nil}, {"masked\n", 1, nil}, {"enabled-runtime\n", 0, nil}, {"not-found\n", 4, nil}} {
		t.Run(fmt.Sprintf("%s/status-%d", strings.TrimSpace(reply.out), reply.status), func(t *testing.T) {
			f := setup(t)
			older := f.create(t, "older", "file", "remove")
			f.sys.units["demo.service"] = "disabled"
			must(t, f.l.Enable("demo.service"))
			f.sys.fault = func(cmd string, args []string) (fakeReply, bool) {
				return reply, cmd == "/usr/bin/systemctl" && args[0] == "is-enabled"
			}
			code(t, f.l.Replay("station-remove"), 1)
			exists(t, older)
			if f.sys.called("/usr/bin/systemctl disable") {
				t.Fatal("effect after inspection failure")
			}
		})
	}
	f := setup(t)
	p := f.create(t, "ordinary", "file", "remove")
	f.sys.units["demo.service"] = "disabled"
	must(t, f.l.Enable("demo.service"))
	must(t, f.l.Replay("station"))
	if f.sys.units["demo.service"] != "disabled" {
		t.Fatal("state not restored")
	}
	absent(t, p)
}

// Claim: getent operational errors and malformed output never become absence;
// pre-existing account identities cannot be admitted by after-baseline lookup.
func TestLedgerGetentFailureNeverAbsenceG2(t *testing.T) {
	for _, reply := range []fakeReply{{"", 1, nil}, {"", 73, nil}, {"", 127, nil}, {"garbage\n", 0, nil}, {"data\n", 2, nil}, {"", -1, syscall.EACCES}, {"demo:x:301:301::/nonexistent:/usr/sbin/nologin\nother:x:302:302::/nonexistent:/usr/sbin/nologin\n", 0, nil}} {
		f := setup(t)
		f.sys.fault = func(cmd string, args []string) (fakeReply, bool) { return reply, cmd == "/usr/bin/getent" }
		code(t, f.l.CreateAccount("user", "demo", "remove", 301, 301), 1)
		if f.sys.called("/usr/sbin/useradd") {
			t.Fatal("creation after failing lookup")
		}
		if len(f.l.rows) != 1 {
			t.Fatal("failed inspection entered intent")
		}
	}
	f := setupWith(t, "station", func(f *fixture) { f.sys.groups["demo"] = Account{Name: "demo", GID: 301} })
	must(t, f.l.CreateAccount("user", "demo", "remove", 301, 301))
	must(t, f.l.Replay("station-remove"))
}

// Claim: a group or user created by another actor after baseline or during
// intent is refused, never adopted; exclusive tool EEXIST semantics are modeled.
func TestLedgerForeignAccountsNeverAdoptedD9_1(t *testing.T) {
	for _, kind := range []string{"user", "group"} {
		for _, when := range []string{"after-baseline", "after-intent"} {
			t.Run(kind+"/"+when, func(t *testing.T) {
				f := setupWith(t, "station", func(f *fixture) {
					if kind == "user" {
						f.sys.groups["primary"] = Account{Name: "primary", GID: 301}
					}
				})
				plant := func() {
					a := Account{Name: "foreign", GID: 301}
					if kind == "user" {
						a.UID = 301
						a.Shell = "/usr/sbin/nologin"
						f.sys.users[a.Name] = a
					} else {
						f.sys.groups[a.Name] = a
					}
				}
				if when == "after-baseline" {
					plant()
				} else {
					f.l.afterIntent = func(Action) error { plant(); return nil }
				}
				uid := uint32(0)
				if kind == "user" {
					uid = 301
				}
				code(t, f.l.CreateAccount(kind, "foreign", "remove", uid, 301), 1)
				f.l.afterIntent = nil
				f.reopen(t)
				code(t, f.l.Replay("station-remove"), 1)
				a, _, e := lookup(f.sys, kind, "foreign")
				must(t, e)
				if a == nil {
					t.Fatal("foreign account lost")
				}
			})
		}
	}
}

// Claim: station-remove never deletes pre-existing key/config files; adjacent
// files created and committed by this engine can be removed.
func TestLedgerPreexistingKeysConfigsSurviveG1(t *testing.T) {
	f := setupWith(t, "station", func(f *fixture) {
		for _, n := range []string{"old.key", "wallet.json", "service.json"} {
			foreign(t, filepath.Join(f.root, n), "file")
		}
	})
	paths := []string{filepath.Join(f.root, "old.key"), filepath.Join(f.root, "wallet.json"), filepath.Join(f.root, "service.json")}
	for _, p := range paths {
		code(t, f.l.CreateFS(p, f.src, "file", "remove", uint32(os.Geteuid()), uint32(os.Getegid()), 0600), 1)
	}
	own := f.create(t, "own", "file", "remove")
	must(t, f.l.Replay("station-remove"))
	absent(t, own)
	for _, p := range paths {
		exists(t, p)
	}
}

// Claim: a real live child and its key/marker survive an inspection error, and
// the older entered probe also survives. No process cleanup is inferred from
// a failed account inspection; native process/tree policy is outside this API.
func TestLedgerLiveWriterSurvivesInspectionFailureG3(t *testing.T) {
	f := setupWith(t, "station", func(f *fixture) {
		must(t, os.WriteFile(filepath.Join(f.root, "IN-PROGRESS"), []byte("fixture writer\n"), 0600))
		f.sys.groups["demo"] = Account{Name: "demo", GID: 301}
	})
	probe := f.create(t, "probe", "file", "remove")
	key := f.create(t, "writer.key", "secret", "d6")
	marker := filepath.Join(f.root, "IN-PROGRESS")
	must(t, os.WriteFile(marker, []byte("fixture writer\n"), 0600))
	cmd := exec.Command("/usr/bin/sleep", "120")
	must(t, cmd.Start())
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	must(t, f.l.CreateAccount("user", "demo", "remove", 301, 301))
	f.sys.fault = func(command string, args []string) (fakeReply, bool) {
		return fakeReply{"", 73, nil}, command == "/usr/bin/getent"
	}
	code(t, f.l.Replay("station-remove"), 1)
	must(t, syscall.Kill(cmd.Process.Pid, 0))
	exists(t, key)
	exists(t, marker)
	exists(t, probe)
	f.sys.fault = nil
	must(t, f.l.Replay("station-remove"))
	absent(t, probe)
	exists(t, key)
	must(t, syscall.Kill(cmd.Process.Pid, 0))
}

// Claim: modify-file replaces only a matching S0 copy and restores exactly the
// committed new file. Changed backups, changed/replaced files and symlinks stop
// before older effects; an already-restored exact copy permits a replay retry.
func TestLedgerModifyFileRestoresExactCommittedNew(t *testing.T) {
	for _, change := range []string{"none", "content", "inode", "backup", "symlink", "before"} {
		t.Run(change, func(t *testing.T) {
			f := setupWith(t, "station", func(f *fixture) {
				must(t, os.WriteFile(filepath.Join(f.root, "config"), []byte("old config\n"), 0640))
				must(t, os.Chmod(filepath.Join(f.root, "config"), 0640))
				must(t, os.WriteFile(filepath.Join(f.root, "backup"), []byte("old config\n"), 0600))
				must(t, os.WriteFile(filepath.Join(f.root, "staged"), []byte("new config\n"), 0600))
			})
			older := f.create(t, "older", "file", "remove")
			p := filepath.Join(f.root, "config")
			backup := filepath.Join(f.root, "backup")
			staged := filepath.Join(f.root, "staged")
			if change == "before" {
				must(t, os.WriteFile(p, []byte("foreign before edit\n"), 0640))
				code(t, f.l.ModifyFile(p, backup, staged), 1)
				exists(t, older)
				return
			}
			must(t, f.l.ModifyFile(p, backup, staged))
			got, e := os.ReadFile(p)
			must(t, e)
			if !bytes.Equal(got, []byte("new config\n")) {
				t.Fatal("new not installed")
			}
			switch change {
			case "content":
				must(t, os.WriteFile(p, []byte("foreign edit\n"), 0640))
			case "inode":
				must(t, os.Rename(p, p+".original"))
				must(t, os.WriteFile(p, []byte("new config\n"), 0640))
			case "backup":
				must(t, os.WriteFile(backup, []byte("changed backup\n"), 0600))
			case "symlink":
				must(t, os.Rename(p, p+".original"))
				must(t, os.Symlink(staged, p))
			}
			if change != "none" {
				code(t, f.l.Replay("station-remove"), 1)
				exists(t, older)
				return
			}
			must(t, f.l.Replay("station-remove"))
			got, e = os.ReadFile(p)
			must(t, e)
			if !bytes.Equal(got, []byte("old config\n")) {
				t.Fatal("backup not restored")
			}
			s, e := os.Stat(p)
			must(t, e)
			if s.Mode().Perm() != 0640 {
				t.Fatal("mode lost")
			}
			absent(t, older)
			must(t, f.l.Replay("station-remove"))
		})
	}
}

// Claim: membership creation calls usermod between intent and commit; rollback
// requires both account identities and removes only the new membership.
func TestLedgerMembershipIDsAndEnableState(t *testing.T) {
	for _, drift := range []bool{false, true} {
		f := setupWith(t, "station", func(f *fixture) {
			f.sys.groups["primary"] = Account{Name: "primary", GID: 301}
			f.sys.groups["access"] = Account{Name: "access", GID: 302}
			f.sys.users["demo"] = Account{Name: "demo", UID: 301, GID: 301, Shell: "/bin/sh"}
		})
		must(t, f.l.AddMember("demo", "access"))
		if !f.sys.called("/usr/sbin/usermod -aG access demo") {
			t.Fatal("usermod not called")
		}
		code(t, f.l.AddMember("demo", "access"), 1)
		if drift {
			g := f.sys.groups["access"]
			g.GID = 999
			f.sys.groups["access"] = g
			code(t, f.l.Replay("station-remove"), 1)
			if !f.sys.members["access"]["demo"] {
				t.Fatal("changed membership removed")
			}
		} else {
			must(t, f.l.Replay("station-remove"))
			if f.sys.members["access"]["demo"] {
				t.Fatal("membership retained")
			}
			must(t, f.l.Replay("station-remove"))
		}
	}
}

// Claim: retained objects still require matching identities; d6 keys/data are
// kept in every mode, while remove objects are undone and state is restored.
func TestLedgerRetentionModes(t *testing.T) {
	for _, mode := range []string{"station", "station-remove", "rehearsal"} {
		t.Run(mode, func(t *testing.T) {
			purpose := "station"
			if mode == "rehearsal" {
				purpose = mode
			}
			f := setupWith(t, purpose, nil)
			key := f.create(t, "key", "secret", "d6")
			state := f.create(t, "state", "dir", "state")
			remove := f.create(t, "remove", "file", "remove")
			must(t, f.l.Replay(mode))
			exists(t, key)
			if mode == "rehearsal" {
				absent(t, state)
			} else {
				exists(t, state)
			}
			absent(t, remove)
			must(t, os.Chmod(key, 0644))
			code(t, f.l.Replay(mode), 1)
		})
	}
}

// Claim: successful tool status alone cannot admit a missing declared output or
// undeclared sibling; either leaves a named unresolved intent and keeps objects.
func TestLedgerExecMissingExtraAndToolFailure(t *testing.T) {
	for _, scenario := range []string{"missing", "extra", "tool-failure", "foreign-before-tool", "valid"} {
		t.Run(scenario, func(t *testing.T) {
			f := setupWith(t, "station", func(f *fixture) { must(t, os.Mkdir(filepath.Join(f.root, "outputs"), 0700)) })
			outputs := filepath.Join(f.root, "outputs")
			p := filepath.Join(outputs, "key")
			extra := filepath.Join(outputs, "extra")
			f.sys.tool = func(_ string, _ []string) (string, int, error) {
				if scenario == "missing" {
					return "", 0, nil
				}
				if scenario == "foreign-before-tool" {
					cmd := exec.Command(os.Args[0], "-test.run=^TestLedgerCreatorProcess$")
					cmd.Env = append(os.Environ(), "G2_LEDGER_TEST_CREATE="+p)
					if e := cmd.Run(); e != nil {
						return "", -1, e
					}
					file, e := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
					if e != nil {
						return "", 1, nil
					}
					file.Close()
					return "", 0, nil
				}
				must(t, os.WriteFile(p, []byte("private fixture"), 0600))
				if scenario == "extra" {
					must(t, os.WriteFile(extra, []byte("unlisted"), 0600))
				}
				if scenario == "tool-failure" {
					return "", 1, nil
				}
				return "PUBLIC_FIXTURE\n", 0, nil
			}
			e := f.l.execCreate("secret", "d6", []string{p}, []string{"fixture-exclusive-tool", "g2-keygen", "-out", p})
			if scenario == "valid" {
				must(t, e)
				f.reopen(t)
				must(t, f.l.Replay("station-remove"))
				exists(t, p)
			} else {
				code(t, e, 3)
				if scenario == "extra" && !strings.Contains(e.Error(), extra) {
					t.Fatal("extra orphan not named")
				}
				f.l.Close()
				_, e = Open(f.dir, f.sys)
				code(t, e, 3)
				if scenario != "missing" {
					exists(t, p)
				}
			}
		})
	}
}

// Claim: a no-op or arbitrary external creator is refused before any intent;
// supported tools must be this executable and declare their exact output flag.
func TestLedgerExecRejectsUnauditedOrUndeclaredCreator(t *testing.T) {
	f := setup(t)
	p := filepath.Join(f.root, "foreign")
	foreign(t, p, "file")
	code(t, f.l.ExecCreate("file", "remove", []string{p}, []string{"/usr/bin/true", "-out", p}), 1)
	if len(f.l.rows) != 1 {
		t.Fatal("unaudited intent")
	}
	exists(t, p)
	self, e := os.Executable()
	must(t, e)
	must(t, creatorCommand([]string{self, "g2-keygen", "-out", p}, []string{p}))
	if creatorCommand([]string{self, "g2-keygen", "-out", p + ".other"}, []string{p}) == nil {
		t.Fatal("undeclared output admitted")
	}
}

// Claim: invalid modes, missing required flags, unknown options and malformed
// account names are usage errors; the valid CLI filesystem path is exercised.
func TestLedgerCLIUsageAndValidNeighbour(t *testing.T) {
	f := setup(t)
	for _, args := range [][]string{nil, {"unknown"}, {"verify", "-dir", f.dir, "-unknown"}, {"create-file", "-dir", f.dir}, {"replay", "-dir", f.dir, "-mode", "unknown"}, {"create-user", "-dir", f.dir, "-name", "-bad", "-uid", "301", "-gid", "301", "-ret", "remove"}} {
		code(t, Run(args, f.sys, &bytes.Buffer{}), 2)
	}
	f.l.Close()
	code(t, Run([]string{"verify", "-dir", f.dir}, f.sys, &bytes.Buffer{}), 0)
	p := filepath.Join(f.root, "cli-file")
	code(t, Run([]string{"create-file", "-dir", f.dir, "-path", p, "-src", f.src, "-owner", stringID(os.Geteuid()), "-group", stringID(os.Getegid()), "-mode", "0600", "-ret", "remove"}, f.sys, &bytes.Buffer{}), 0)
	code(t, Run([]string{"replay", "-dir", f.dir, "-mode", "station-remove"}, f.sys, &bytes.Buffer{}), 0)
	absent(t, p)
}
func stringID(n int) string {
	if n == 0 {
		return "0"
	}
	const ds = "0123456789"
	s := ""
	for n > 0 {
		s = string(ds[n%10]) + s
		n /= 10
	}
	return s
}

// Claim: all account/membership/unit transitions compose in reverse dependency
// order; repeated replay accepts proven absence without touching foreign state.
func TestLedgerAccountMembershipUnitRoundTrip(t *testing.T) {
	f := setupWith(t, "rehearsal", nil)
	must(t, f.l.CreateAccount("group", "primary", "remove", 0, 301))
	must(t, f.l.CreateAccount("user", "demo", "remove", 301, 301))
	must(t, f.l.CreateAccount("group", "access", "remove", 0, 302))
	must(t, f.l.AddMember("demo", "access"))
	f.sys.units["demo.service"] = "disabled"
	must(t, f.l.Enable("demo.service"))
	p := f.create(t, "file", "file", "remove")
	f.reopen(t)
	must(t, f.l.Replay("rehearsal"))
	if len(f.sys.users) != 0 || len(f.sys.groups) != 0 || f.sys.units["demo.service"] != "disabled" {
		t.Fatal("transition not reversed")
	}
	absent(t, p)
	must(t, f.l.Replay("rehearsal"))
}

// Claim: EACCES during an account lookup stops before deletion and older
// effects, whereas an exactly missing account is a harmless absence.
func TestLedgerAccountLookupErrorStops(t *testing.T) {
	f := setupWith(t, "station", func(f *fixture) { f.sys.groups["primary"] = Account{Name: "primary", GID: 301} })
	older := f.create(t, "older", "file", "remove")
	must(t, f.l.CreateAccount("user", "demo", "remove", 301, 301))
	f.sys.fault = func(cmd string, args []string) (fakeReply, bool) {
		return fakeReply{"", -1, syscall.EACCES}, cmd == "/usr/bin/getent"
	}
	code(t, f.l.Replay("station-remove"), 1)
	exists(t, older)
	if f.sys.called("/usr/sbin/userdel") {
		t.Fatal("effect after lookup error")
	}
	f.sys.fault = nil
	delete(f.sys.users, "demo")
	must(t, f.l.Replay("station-remove"))
	absent(t, older)
}

// Claim: journal appends in a sibling ledger directory do not look like tool
// output drift; undeclared tool-created siblings remain named orphans.
func TestLedgerExecInventorySeparatesJournalWrites(t *testing.T) {
	for _, extra := range []bool{false, true} {
		t.Run(fmt.Sprint(extra), func(t *testing.T) {
			f := setup(t)
			p := filepath.Join(f.root, "key")
			sibling := filepath.Join(f.root, "unexpected")
			f.sys.tool = func(_ string, _ []string) (string, int, error) {
				file, e := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
				if e != nil {
					return "", 1, nil
				}
				e = checkedWrite(file, []byte("private fixture"))
				if e == nil {
					e = file.Sync()
				}
				ce := file.Close()
				if e != nil || ce != nil {
					return "", 1, nil
				}
				if extra {
					must(t, os.WriteFile(sibling, []byte("undeclared"), 0600))
				}
				return "", 0, nil
			}
			e := f.l.execCreate("secret", "d6", []string{p}, []string{"exclusive-fixture", "g2-keygen", "-out", p})
			if extra {
				code(t, e, 3)
				if !strings.Contains(e.Error(), sibling) {
					t.Fatal("sibling orphan not named")
				}
				exists(t, p)
				exists(t, sibling)
			} else {
				must(t, e)
				f.reopen(t)
				must(t, f.l.Replay("station"))
				exists(t, p)
			}
		})
	}
}
