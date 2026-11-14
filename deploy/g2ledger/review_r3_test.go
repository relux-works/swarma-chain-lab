//go:build linux

package g2ledger

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func protectedCreate(t *testing.T, f *fixture, kind, ret string) error {
	t.Helper()
	switch kind {
	case "user":
		return f.l.CreateAccount("user", "demo", ret, 301, 301)
	case "group":
		return f.l.CreateAccount("group", "access", ret, 0, 302)
	case "secret":
		return f.l.CreateFS(filepath.Join(f.root, "key"), f.src, "secret", ret, uint32(os.Geteuid()), uint32(os.Getegid()), 0600)
	case "exec-secret":
		p := filepath.Join(f.root, "key")
		f.sys.tool = func(string, []string) (string, int, error) {
			return "", 0, os.WriteFile(p, []byte("private fixture"), 0600)
		}
		self, err := os.Executable()
		must(t, err)
		return f.l.ExecCreate("secret", ret, []string{p}, []string{self, "g2-keygen", "-out", p})
	}
	t.Fatal("unknown fixture kind")
	return nil
}
func protectedPresent(t *testing.T, f *fixture, kind string, present bool) {
	t.Helper()
	got := false
	switch kind {
	case "user":
		_, got = f.sys.users["demo"]
	case "group":
		_, got = f.sys.groups["access"]
	default:
		_, err := os.Lstat(filepath.Join(f.root, "key"))
		got = err == nil
	}
	if got != present {
		t.Fatalf("%s present=%v want=%v", kind, got, present)
	}
}
func protectedFixture(t *testing.T, purpose string) *fixture {
	return setupWith(t, purpose, func(f *fixture) { f.sys.groups["primary"] = Account{Name: "primary", GID: 301} })
}

// Claim: each account/key creation surface refuses station/remove with a named
// exit 1 before journal or external effects. Station state/d6 keeps each kind;
// rehearsal/remove undoes matching identities. Membership undo remains covered
// by TestLedgerMembershipIDsAndEnableState and preserves both account subjects.
func TestLedgerStationProtectedCreation(t *testing.T) {
	for _, kind := range []string{"user", "group", "secret", "exec-secret"} {
		for _, scenario := range []string{"station-remove", "station-state", "station-d6", "rehearsal-remove"} {
			t.Run(kind+"/"+scenario, func(t *testing.T) {
				purpose, ret, _ := strings.Cut(scenario, "-")
				f := protectedFixture(t, purpose)
				before, err := os.ReadFile(filepath.Join(f.dir, recordsName))
				must(t, err)
				calls := len(f.sys.calls)
				err = protectedCreate(t, f, kind, ret)
				if scenario == "station-remove" {
					code(t, err, 1)
					if !strings.Contains(err.Error(), "STATION_PROTECTED_RETENTION") || !strings.Contains(err.Error(), map[string]string{"user": "demo", "group": "access", "secret": "key", "exec-secret": "key"}[kind]) {
						t.Fatal(err)
					}
					after, e := os.ReadFile(filepath.Join(f.dir, recordsName))
					must(t, e)
					if !bytes.Equal(before, after) || len(f.sys.calls) != calls {
						t.Fatal("refusal crossed effect boundary")
					}
					protectedPresent(t, f, kind, false)
				} else {
					must(t, err)
					must(t, f.l.Replay(purpose))
					protectedPresent(t, f, kind, purpose == "station" || ret == "d6")
				}
			})
		}
	}
}

// Claim: a schema-valid, resealed legacy/forged station/remove action for every
// protected surface stops load/verify/replay with exit 1 before even NEWER undo.
// Untouched state records are valid station neighbours. No root-writer
// authentication claim: the reseal deliberately changes the policy field only.
func TestLedgerStationProtectedReplay(t *testing.T) {
	for _, kind := range []string{"user", "group", "secret", "exec-secret"} {
		for _, forge := range []bool{false, true} {
			t.Run(kind+map[bool]string{false: "/valid", true: "/forged-remove"}[forge], func(t *testing.T) {
				f := protectedFixture(t, "station")
				must(t, protectedCreate(t, f, kind, "state"))
				newer := f.create(t, "newer", "file", "remove")
				rows := append([]Record(nil), f.l.rows...)
				if forge {
					rows[1].Body.Action.Ret = "remove"
				}
				f.l.Close()
				if forge {
					writeRows(t, f, rows, true)
				}
				for _, op := range []string{"verify", "replay"} {
					args := []string{op, "-dir", f.dir}
					if op == "replay" {
						args = append(args, "-mode", "station")
					}
					err := Run(args, f.sys, io.Discard)
					if forge {
						code(t, err, 1)
						if !strings.Contains(err.Error(), "STATION_PROTECTED_RETENTION") {
							t.Fatal(err)
						}
						exists(t, newer)
					} else {
						must(t, err)
					}
					protectedPresent(t, f, kind, true)
				}
				if !forge {
					absent(t, newer)
				}
			})
		}
	}
}

// Claim: a same-text replacement inode survives in station and rehearsal and
// stops before older work. UID/GID/dev receipt edits isolate each comparison
// without root chown. Valid links remove; changed target/regular file/whole-set
// checks remain in unit_effects_test.go. No concurrent privileged-writer claim.
func TestLedgerUnitLinkReceiptIdentity(t *testing.T) {
	for _, purpose := range []string{"station", "rehearsal"} {
		for _, field := range []string{"valid", "same-text-replacement", "uid", "gid", "dev", "ino", "target"} {
			t.Run(purpose+"/"+field, func(t *testing.T) {
				f := setupWith(t, purpose, nil)
				older := f.create(t, "older", "file", "remove")
				must(t, f.l.Enable("demo.service"))
				rows := append([]Record(nil), f.l.rows...)
				link := &rows[4].Body.Result.Identities[0].Unit.Links[0]
				got, present, err := observeUnitLink(*link)
				must(t, err)
				if !present || got != *link || link.Mode != syscall.S_IFLNK|0777 {
					t.Fatal("receipt did not capture lstat")
				}
				switch field {
				case "same-text-replacement":
					must(t, os.Rename(link.Path, link.Path+".saved")) // held original prevents inode reuse
					must(t, os.Symlink(link.Target, link.Path))
				case "uid":
					link.UID++
				case "gid":
					link.GID++
				case "dev":
					link.Dev++
				case "ino":
					link.Ino++
				case "target":
					link.Target += ".other"
				}
				f.l.Close()
				if field != "valid" && field != "same-text-replacement" {
					writeRows(t, f, rows, true)
				}
				err = Run([]string{"replay", "-dir", f.dir, "-mode", purpose}, f.sys, io.Discard)
				if field == "valid" {
					must(t, err)
					absent(t, link.Path)
					absent(t, older)
				} else {
					code(t, err, 1)
					reason := "UNIT_LINK_REPLACED"
					if field == "target" {
						reason = "UNIT_LINK_RETARGETED"
					}
					if !strings.Contains(err.Error(), reason) || !strings.Contains(err.Error(), link.Path) {
						t.Fatal(err)
					}
					exists(t, link.Path)
					exists(t, older)
					target, e := os.Readlink(link.Path)
					must(t, e)
					expectedTarget := link.Target
					if field == "target" {
						expectedTarget = strings.TrimSuffix(expectedTarget, ".other")
					}
					if target != expectedTarget {
						t.Fatal("foreign link changed")
					}
					if f.sys.called("/usr/bin/systemctl daemon-reload") {
						t.Fatal("effect after refusal")
					}
				}
			})
		}
	}
}

// Claim: injecting EIO only at CreateFS's payload-file or parent-directory
// fsync leaves a named orphan (exit 3), poisons this handle, and fresh verify
// and replay also refuse with exit 3 while preserving target and older work.
// The identical no-fault neighbour seals and reverses both creations.
func TestLedgerCreateFSSyncOnlyFailures(t *testing.T) {
	for _, checkpoint := range []string{"control", "payload", "parent"} {
		t.Run(checkpoint, func(t *testing.T) {
			f := setup(t)
			older := f.create(t, "older", "file", "remove")
			target := filepath.Join(f.root, "target")
			calls, applied := 0, 0
			f.l.payloadSync = func(file *os.File) error {
				calls++
				info, err := file.Stat()
				if err != nil {
					return err
				}
				if checkpoint == "payload" && !info.IsDir() || checkpoint == "parent" && info.IsDir() {
					applied++
					return syscall.EIO
				}
				return file.Sync()
			}
			err := f.l.CreateFS(target, f.src, "file", "remove", uint32(os.Geteuid()), uint32(os.Getegid()), 0600)
			if checkpoint == "control" {
				must(t, err)
				if calls != 2 || applied != 0 {
					t.Fatal("missing successful sync neighbour")
				}
			} else {
				code(t, err, 3)
				if err.Error() != "g2-ledger: ORPHAN "+target || applied != 1 {
					t.Fatalf("fault not applied exactly once: %v applied=%d", err, applied)
				}
				if checkpoint == "payload" && calls != 1 || checkpoint == "parent" && calls != 2 {
					t.Fatal("wrong sync checkpoint")
				}
				if !f.l.poisoned {
					t.Fatal("failed creation did not poison handle")
				}
			}
			exists(t, target)
			exists(t, older)
			f.l.Close()
			for _, op := range []string{"verify", "replay"} {
				args := []string{op, "-dir", f.dir}
				if op == "replay" {
					args = append(args, "-mode", "station")
				}
				err := Run(args, f.sys, io.Discard)
				if checkpoint == "control" {
					must(t, err)
				} else {
					code(t, err, 3)
					if err.Error() != "g2-ledger: ORPHAN "+target {
						t.Fatal(err)
					}
					exists(t, target)
					exists(t, older)
				}
			}
			if checkpoint == "control" {
				absent(t, target)
				absent(t, older)
			}
		})
	}
}
