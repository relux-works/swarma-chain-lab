package g2ledger

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Claim: missing/unknown roles are usage refusals before any ledger or system
// access; both exact permitted spellings create committed role identities.
func TestLedgerUserRoleRequired(t *testing.T) {
	for _, role := range []string{"", "operator", "tree_owner", "tree-owner", "service"} {
		t.Run("role="+role, func(t *testing.T) {
			f := setup(t)
			must(t, f.l.CreateAccount("group", "primary", "state", 0, 230302))
			f.l.Close()
			args := []string{"create-user", "-dir", f.dir, "-name", "demo", "-uid", "230301", "-gid", "230302", "-ret", "state"}
			if role != "" {
				args = append(args, "-role", role)
			}
			before, err := os.ReadFile(filepath.Join(f.dir, recordsName))
			must(t, err)
			calls := len(f.sys.calls)
			err = Run(args, f.sys, io.Discard)
			if !validUserRole(role) {
				code(t, err, 2)
				if !strings.Contains(err.Error(), "USAGE_USER_ROLE") {
					t.Fatal(err)
				}
				after, e := os.ReadFile(filepath.Join(f.dir, recordsName))
				must(t, e)
				if !bytes.Equal(before, after) || len(f.sys.calls) != calls {
					t.Fatal("usage refusal changed state")
				}
				return
			}
			must(t, err)
			f.reopen(t)
			if f.l.rows[3].Body.Action.Role != role || f.l.rows[4].Body.Result.Identities[0].Role != role {
				t.Fatal("role not committed")
			}
			must(t, f.l.Replay("station"))
		})
	}
}

// Claim: a committed service user with no memberships/files cannot own a tree,
// independently of the UID denylist. The same-ledger tree-owner control passes.
func TestLedgerTreeServiceRoleOwnerRefused(t *testing.T) {
	for _, uid := range []uint32{230401, 210201} {
		t.Run(strconv.FormatUint(uint64(uid), 10), func(t *testing.T) {
			f := setupWith(t, "rehearsal", func(f *fixture) { f.declare("tree", "tree"); f.scope.Users = append(f.scope.Users, "swarma-wallet") })
			must(t, f.l.CreateAccount("group", "primary", "state", 0, 230402))
			must(t, f.l.CreateAccount("user", "swarma-wallet", "state", uid, 230402, "service"))
			p := filepath.Join(f.root, "tree")
			called := false
			f.l.afterIntent = func(Action) error { called = true; return os.ErrPermission }
			n := len(f.l.rows)
			err := f.l.CreateTree(p, "swarma-wallet", "rehearsal", 0700, nil)
			if called {
				t.Fatal("service owner reached durable tree intent")
			}
			code(t, err, 1)
			reason := "TREE_OWNER_NOT_DEDICATED"
			if uid == 210201 {
				reason = "TREE_OWNER_FORBIDDEN"
			}
			if !strings.Contains(err.Error(), reason) || len(f.l.rows) != n {
				t.Fatal("service owner acquired tree", err)
			}
			absent(t, p)
		})
	}
	validTreeNeighbour(t)
}

// Claim: a tree-owner's first membership, directory, file or modified-file
// ownership is refused before intent or mutation, even before its first tree.
// Service-role positive controls exercise each operation with the same UID.
func TestLedgerTreeOwnerStructuralRolesRefused(t *testing.T) {
	for _, kind := range []string{"membership", "dir", "file", "modify"} {
		for _, role := range []string{"tree-owner", "service"} {
			t.Run(kind+"/"+role, func(t *testing.T) {
				f := setupWith(t, "station", nil)
				must(t, f.l.CreateAccount("group", "primary", "state", 0, uint32(os.Getegid())))
				must(t, f.l.CreateAccount("user", "demo", "state", uint32(os.Geteuid()), uint32(os.Getegid()), role))
				must(t, f.l.CreateAccount("group", "access", "state", 0, 230402))
				p := filepath.Join(f.root, "owned")
				if kind == "dir" {
					p = filepath.Join(f.root, "directory")
				}
				backup, newFile := filepath.Join(f.root, "baseline", "backup"), filepath.Join(f.root, "baseline", "new")
				if kind == "modify" {
					must(t, os.WriteFile(p, []byte("old"), 0600))
					must(t, os.WriteFile(backup, []byte("old"), 0600))
					must(t, os.WriteFile(newFile, []byte("new"), 0600))
				}
				before, e := os.ReadFile(filepath.Join(f.dir, recordsName))
				must(t, e)
				var err error
				switch kind {
				case "membership":
					err = f.l.AddMember("demo", "access")
				case "modify":
					err = f.l.ModifyFile(p, backup, newFile)
				default:
					mode := uint32(0600)
					if kind == "dir" {
						mode = 0700
					}
					err = f.l.CreateFS(p, f.src, kind, "state", uint32(os.Geteuid()), uint32(os.Getegid()), mode)
				}
				if role == "service" {
					must(t, err)
					return
				}
				code(t, err, 1)
				if !strings.Contains(err.Error(), "TREE_OWNER_NOT_DEDICATED") {
					t.Fatal(err)
				}
				after, e := os.ReadFile(filepath.Join(f.dir, recordsName))
				must(t, e)
				if !bytes.Equal(before, after) || f.sys.members["access"]["demo"] {
					t.Fatal("structural refusal changed state")
				}
				if kind == "modify" {
					b, e := os.ReadFile(p)
					must(t, e)
					if string(b) != "old" {
						t.Fatal("modified on refusal")
					}
				} else if kind != "membership" {
					absent(t, p)
				}
			})
		}
	}
	validTreeNeighbour(t)
}

// Claim: hand-edited roles fail the hash chain; even a resealed intent must
// match its independently committed role identity before any replay effect.
// The unchanged service receipt is a valid control in both replay modes.
func TestLedgerUserRoleReplayTamperRefused(t *testing.T) {
	for _, mode := range []string{"station", "rehearsal"} {
		for _, edit := range []string{"none", "chain", "resealed"} {
			t.Run(mode+"/"+edit, func(t *testing.T) {
				f := profileFixtureFor(t, "/", "", mode)
				f.l.Close()
				if edit == "chain" {
					raw, e := os.ReadFile(filepath.Join(f.dir, recordsName))
					must(t, e)
					changed := bytes.Replace(raw, []byte(`"role":"service"`), []byte(`"role":"tree-owner"`), 1)
					if bytes.Equal(raw, changed) {
						t.Fatal("plant not applied")
					}
					must(t, os.WriteFile(filepath.Join(f.dir, recordsName), changed, 0600))
				} else if edit == "resealed" {
					rows := append([]Record(nil), f.l.rows...)
					a := *rows[3].Body.Action
					a.Role = "tree-owner"
					rows[3].Body.Action = &a
					writeRows(t, f, rows, true)
				}
				calls := len(f.sys.calls)
				err := Run([]string{"replay", "-dir", f.dir, "-mode", mode}, f.sys, io.Discard)
				if edit == "none" {
					must(t, err)
					return
				}
				code(t, err, 1)
				reason := "LEDGER_CHAIN"
				if edit == "resealed" {
					reason = "RESULT_USER_ROLE"
				}
				if !strings.Contains(err.Error(), reason) || len(f.sys.calls) != calls || len(f.sys.users) != 1 || len(f.sys.groups) != 1 {
					t.Fatal("role edit accepted or caused effects", err)
				}
			})
		}
	}
}

// Claim: audited creator outputs cannot be owned by a tree-owner, for default
// caller ownership or explicit #98 owner/group flags, before intent/tool effects.
// The service-role controls exercise the same output metadata successfully.
func TestLedgerTreeOwnerExecOutputRefused(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		for _, role := range []string{"tree-owner", "service"} {
			t.Run(role+"/explicit="+strconv.FormatBool(explicit), func(t *testing.T) {
				f := setup(t)
				must(t, f.l.CreateAccount("group", "primary", "state", 0, uint32(os.Getegid())))
				must(t, f.l.CreateAccount("user", "demo", "state", uint32(os.Geteuid()), uint32(os.Getegid()), role))
				p := filepath.Join(f.root, "key")
				self, e := os.Executable()
				must(t, e)
				argv := []string{self, "g2-keygen", "-out", p}
				if explicit {
					argv = append(argv, "-owner", strconv.Itoa(os.Geteuid()), "-group", strconv.Itoa(os.Getegid()))
				}
				called := false
				f.sys.tool = func(string, []string) (string, int, error) {
					called = true
					return "", 0, os.WriteFile(p, []byte("fixture"), 0600)
				}
				before, e := os.ReadFile(filepath.Join(f.dir, recordsName))
				must(t, e)
				err := f.l.ExecCreate("secret", "state", []string{p}, argv)
				if role == "service" {
					must(t, err)
					if !called {
						t.Fatal("control did not run audited creator")
					}
					return
				}
				code(t, err, 1)
				if !strings.Contains(err.Error(), "TREE_OWNER_NOT_DEDICATED") || called {
					t.Fatal("tree owner output allowed", err)
				}
				after, e := os.ReadFile(filepath.Join(f.dir, recordsName))
				must(t, e)
				if !bytes.Equal(before, after) {
					t.Fatal("refusal wrote intent")
				}
				absent(t, p)
			})
		}
	}
}

// Claim: replay rejects a forbidden membership or ordinary object relation even
// when a former service receipt is resealed consistently as tree-owner. This
// isolates structural chain validation from hashes and from live tree behavior.
func TestLedgerTreeOwnerStructuralReplayRefused(t *testing.T) {
	for _, kind := range []string{"membership", "dir", "file", "modify"} {
		t.Run(kind, func(t *testing.T) {
			f := setup(t)
			must(t, f.l.CreateAccount("group", "primary", "state", 0, uint32(os.Getegid())))
			must(t, f.l.CreateAccount("user", "demo", "state", uint32(os.Geteuid()), uint32(os.Getegid()), "service"))
			p := filepath.Join(f.root, "owned")
			switch kind {
			case "membership":
				must(t, f.l.CreateAccount("group", "access", "state", 0, 230402))
				must(t, f.l.AddMember("demo", "access"))
			case "modify":
				backup, newFile := filepath.Join(f.root, "baseline", "backup"), filepath.Join(f.root, "baseline", "new")
				must(t, os.WriteFile(p, []byte("old"), 0600))
				must(t, os.WriteFile(backup, []byte("old"), 0600))
				must(t, os.WriteFile(newFile, []byte("new"), 0600))
				must(t, f.l.ModifyFile(p, backup, newFile))
			default:
				if kind == "dir" {
					p = filepath.Join(f.root, "directory")
				}
				mode := uint32(0600)
				if kind == "dir" {
					mode = 0700
				}
				must(t, f.l.CreateFS(p, f.src, kind, "state", uint32(os.Geteuid()), uint32(os.Getegid()), mode))
			}
			rows := append([]Record(nil), f.l.rows...)
			a := *rows[3].Body.Action
			a.Role = "tree-owner"
			rows[3].Body.Action = &a
			r := *rows[4].Body.Result
			r.Identities = append([]Identity(nil), r.Identities...)
			r.Identities[0].Role = "tree-owner"
			rows[4].Body.Result = &r
			f.l.Close()
			writeRows(t, f, rows, true)
			before, e := os.ReadFile(filepath.Join(f.dir, recordsName))
			must(t, e)
			calls := len(f.sys.calls)
			err := Run([]string{"replay", "-dir", f.dir, "-mode", "station"}, f.sys, io.Discard)
			code(t, err, 1)
			if !strings.Contains(err.Error(), "TREE_OWNER_NOT_DEDICATED") || len(f.sys.calls) != calls {
				t.Fatal("structural replay allowed effects", err)
			}
			after, e := os.ReadFile(filepath.Join(f.dir, recordsName))
			must(t, e)
			if !bytes.Equal(before, after) {
				t.Fatal("replay changed journal")
			}
			if kind != "membership" {
				exists(t, p)
			}
		})
	}
}
