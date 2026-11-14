//go:build linux

package g2ledger

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func comparisonRows(t *testing.T, b *bytes.Buffer) []CompareRow {
	t.Helper()
	var rows []CompareRow
	dec := json.NewDecoder(b)
	for {
		var r CompareRow
		e := dec.Decode(&r)
		if e == io.EOF {
			break
		}
		must(t, e)
		if r.Type != "baseline_summary" {
			rows = append(rows, r)
		}
	}
	return rows
}
func callIndex(s *fakeSystem, prefix string) int {
	for j, c := range s.calls {
		if strings.HasPrefix(c, prefix) {
			return j
		}
	}
	return -1
}

// Claim: rehearsal removes matching state accounts, membership, created unit file, regtest dir and fixture files in dependency order; retries accept absence.
func TestLedgerRehearsalRemovesCreatedObjects(t *testing.T) {
	f := setupWith(t, "rehearsal", func(f *fixture) {
		f.declare("regtest", "dir")
		f.declare("regtest/block", "file")
		f.declare("out", "dir")
		f.declare("out/result", "file")
		f.declare("demo.service", "file")
		unitPath := filepath.Join(f.root, "demo.service")
		f.sys.fault = func(cmd string, args []string) (fakeReply, bool) {
			if cmd == "/usr/bin/systemctl" && args[0] == "is-enabled" {
				if _, e := os.Lstat(unitPath); os.IsNotExist(e) {
					return fakeReply{"not-found\n", 4, nil}, true
				}
			}
			return fakeReply{}, false
		}
	})
	must(t, f.l.CreateAccount("group", "primary", "state", 0, 301))
	must(t, f.l.CreateAccount("user", "demo", "state", 301, 301))
	must(t, f.l.CreateAccount("group", "access", "state", 0, 302))
	must(t, f.l.AddMember("demo", "access"))
	regtest := f.create(t, "regtest", "dir", "state")
	block := f.create(t, "regtest/block", "file", "state")
	out := f.create(t, "out", "dir", "state")
	result := f.create(t, "out/result", "file", "state")
	unit := f.create(t, "demo.service", "file", "state")
	must(t, f.l.Enable("demo.service"))
	initialFault := f.sys.fault
	f.sys.fault = func(cmd string, args []string) (fakeReply, bool) {
		if cmd == "/usr/bin/systemctl" && args[0] == "disable" {
			exists(t, unit)
		}
		return initialFault(cmd, args)
	}
	f.reopen(t)
	var stdout, stderr bytes.Buffer
	f.l.output = &stdout
	f.l.summary = &stderr
	must(t, f.l.Replay("rehearsal"))
	for _, p := range []string{regtest, block, out, result, unit} {
		absent(t, p)
	}
	if len(f.sys.users) != 0 || len(f.sys.groups) != 0 || f.sys.units["demo.service"] != "disabled" {
		t.Fatal("rehearsal state retained")
	}
	member := callIndex(f.sys, "/usr/bin/gpasswd -d demo access")
	if member < 0 || callIndex(f.sys, "/usr/sbin/userdel demo") <= member || callIndex(f.sys, "/usr/sbin/groupdel access") <= member {
		t.Fatal("membership not removed first")
	}
	if len(comparisonRows(t, &stdout)) != 0 || !strings.Contains(stderr.String(), "unlisted=0") {
		t.Fatal("baseline not restored")
	}
	must(t, f.l.Replay("rehearsal"))
}

// Claim: changed UID/GID or a replaced directory stops rehearsal preflight before even a newer valid removal; unchanged neighbours remove all three entries.
func TestLedgerRehearsalPreflightKeepsEveryEntry(t *testing.T) {
	for _, variant := range []string{"gid", "uid", "group-gid", "replaced-dir", "valid-user", "valid-dir"} {
		t.Run(variant, func(t *testing.T) {
			f := setupWith(t, "rehearsal", nil)
			older := f.create(t, "older", "file", "remove")
			var dir string
			if strings.Contains(variant, "dir") {
				dir = f.create(t, "state", "dir", "state")
			} else {
				must(t, f.l.CreateAccount("group", "primary", "state", 0, 301))
				must(t, f.l.CreateAccount("user", "demo", "state", 301, 301))
			}
			newer := f.create(t, "newer", "file", "remove")
			switch variant {
			case "gid":
				a := f.sys.users["demo"]
				a.GID = 999
				f.sys.users["demo"] = a
			case "uid":
				a := f.sys.users["demo"]
				a.UID = 999
				f.sys.users["demo"] = a
			case "group-gid":
				a := f.sys.groups["primary"]
				a.GID = 999
				f.sys.groups["primary"] = a
			case "replaced-dir":
				must(t, os.Rename(dir, dir+".original"))
				must(t, os.Mkdir(dir, 0700))
			}
			f.reopen(t)
			if strings.HasPrefix(variant, "valid") {
				must(t, f.l.Replay("rehearsal"))
				absent(t, older)
				absent(t, newer)
				if dir != "" {
					absent(t, dir)
				}
			} else {
				e := f.l.Replay("rehearsal")
				code(t, e, 1)
				if !strings.Contains(e.Error(), "IDENTITY_MISMATCH") {
					t.Fatal(e)
				}
				exists(t, older)
				exists(t, newer)
				if dir != "" {
					exists(t, dir)
				}
				if f.sys.called("/usr/sbin/userdel") || f.sys.called("/usr/sbin/groupdel") {
					t.Fatal("account removal before mismatch")
				}
			}
		})
	}
}

// Claim: rehearsal preserves d6 key/wallet identities while explicit rehearsal secrets are removed; state objects are removable neighbours.
func TestLedgerRehearsalD6AndExplicitRetention(t *testing.T) {
	f := setupWith(t, "rehearsal", func(f *fixture) { f.declare("wallet", "secret"); f.declare("temporary-key", "secret") })
	key := f.create(t, "key", "secret", "d6")
	wallet := f.create(t, "wallet", "secret", "d6")
	temporary := f.create(t, "temporary-key", "secret", "rehearsal")
	state := f.create(t, "state", "dir", "state")
	var out bytes.Buffer
	f.l.output = &out
	must(t, f.l.Replay("rehearsal"))
	exists(t, key)
	exists(t, wallet)
	absent(t, temporary)
	absent(t, state)
	rows := comparisonRows(t, &out)
	seen := map[string]bool{}
	for _, r := range rows {
		if r.Type != "retained" || r.Retention != "d6" || r.Rule != "retain-d6" {
			t.Fatalf("unexpected row %+v", r)
		}
		seen[r.Object] = true
	}
	for _, p := range []string{key, wallet} {
		if !seen[objectKey("secret", p)] {
			t.Fatal("retained secret omitted", p)
		}
	}
}

// Claim: station genesis rejects rehearsal retention before intent or creation, while a rehearsal ledger accepts the same requested object.
func TestLedgerRehearsalClassRefusedOnStation(t *testing.T) {
	for _, purpose := range []string{"station", "rehearsal"} {
		t.Run(purpose, func(t *testing.T) {
			f := setupWith(t, purpose, nil)
			before := len(f.l.rows)
			p := filepath.Join(f.root, "key")
			e := f.l.CreateFS(p, f.src, "secret", "rehearsal", uint32(os.Geteuid()), uint32(os.Getegid()), 0600)
			if purpose == "station" {
				code(t, e, 1)
				if !strings.Contains(e.Error(), "REHEARSAL_RETENTION_REQUIRES_REHEARSAL_PURPOSE") {
					t.Fatal(e)
				}
				absent(t, p)
				if len(f.l.rows) != before {
					t.Fatal("refused class wrote intent")
				}
				e = f.l.CreateAccount("group", "primary", "rehearsal", 0, 301)
				code(t, e, 1)
				if f.sys.called("/usr/sbin/groupadd") {
					t.Fatal("refused account class executed")
				}
			} else {
				must(t, e)
				must(t, f.l.Replay("rehearsal"))
				absent(t, p)
			}
		})
	}
	for _, mode := range []string{"station", "station-remove"} {
		if effect, _ := retentionPolicy("secret", "rehearsal", mode); effect == "remove" {
			t.Fatal("rehearsal class deletable in", mode)
		}
	}
}

// Claim: every mode/purpose mismatch is exit 1 before lookup or removal; matching modes retain station state and remove rehearsal state.
func TestLedgerModePurposeMismatch(t *testing.T) {
	for _, purpose := range []string{"station", "rehearsal"} {
		for _, mode := range []string{"station", "station-remove", "rehearsal"} {
			t.Run(purpose+"/"+mode, func(t *testing.T) {
				f := setupWith(t, purpose, nil)
				p := f.create(t, "state", "dir", "state")
				before := len(f.sys.calls)
				f.reopen(t)
				e := f.l.Replay(mode)
				if !purposeMatches(purpose, mode) {
					code(t, e, 1)
					if !strings.Contains(e.Error(), "MODE_PURPOSE_MISMATCH") {
						t.Fatal(e)
					}
					exists(t, p)
					if len(f.sys.calls) != before {
						t.Fatal("mismatch performed system lookup")
					}
				} else {
					must(t, e)
					if mode == "rehearsal" {
						absent(t, p)
					} else {
						exists(t, p)
					}
				}
			})
		}
	}
}

// Claim: both station modes retain state accounts/directories and d6 files, listing every difference with a real result sequence and its policy rule.
func TestLedgerFinalCompareExplainsEveryRetention(t *testing.T) {
	for _, mode := range []string{"station", "station-remove"} {
		t.Run(mode, func(t *testing.T) {
			f := setup(t)
			key := f.create(t, "key", "secret", "d6")
			dir := f.create(t, "state", "dir", "state")
			must(t, f.l.CreateAccount("group", "primary", "state", 0, 301))
			must(t, f.l.CreateAccount("user", "demo", "state", 301, 301))
			var out, summary bytes.Buffer
			f.l.output = &out
			f.l.summary = &summary
			must(t, f.l.Replay(mode))
			exists(t, key)
			exists(t, dir)
			rows := comparisonRows(t, &out)
			seen := map[string]bool{}
			for _, r := range rows {
				if r.Type != "retained" || r.Seq == nil || *r.Seq >= uint64(len(f.l.rows)) || f.l.rows[*r.Seq].Body.Op != "commit" || r.Mode != mode || r.Rule == "" || r.Retention == "" {
					t.Fatalf("unexplained row %+v", r)
				}
				seen[r.Object] = true
			}
			for _, key := range []string{objectKey("secret", key), objectKey("dir", dir), "user:demo", "group:primary"} {
				if !seen[key] {
					t.Fatal("retention omitted", key)
				}
			}
			if len(rows) != 6 || !strings.Contains(summary.String(), "retained=6 unlisted=0") {
				t.Fatalf("incomplete comparison rows=%d summary=%s", len(rows), summary.String())
			}
		})
	}
}

// Claim: every mode names foreign children, parent entries, extra group members and changed unused declarations at final compare; unchanged neighbours succeed.
func TestLedgerFinalCompareRejectsUnlistedDifferences(t *testing.T) {
	for _, mode := range []string{"station", "station-remove", "rehearsal"} {
		t.Run(mode, func(t *testing.T) {
			for _, variant := range []string{"file", "member", "parent-file", "unused-unit", "valid"} {
				t.Run(variant, func(t *testing.T) {
					purpose, ret := "station", "state"
					if mode == "rehearsal" {
						purpose = mode
						ret = "d6"
					}
					f := setupWith(t, purpose, nil)
					dir := f.create(t, "state", "dir", ret)
					must(t, f.l.CreateAccount("group", "primary", ret, 0, 301))
					object := ""
					switch variant {
					case "file":
						object = filepath.Join(dir, "foreign.txt")
						must(t, os.WriteFile(object, []byte("foreign public fixture"), 0600))
					case "parent-file":
						object = filepath.Join(f.root, "foreign.txt")
						must(t, os.WriteFile(object, []byte("foreign public fixture"), 0600))
					case "member":
						object = "group:primary/member:intruder"
						f.sys.members["primary"] = map[string]bool{"intruder": true}
					case "unused-unit":
						object = "unit:demo.service"
						f.sys.units["demo.service"] = "enabled"
					}
					var out, summary bytes.Buffer
					f.l.output = &out
					f.l.summary = &summary
					e := f.l.Replay(mode)
					if variant == "valid" {
						must(t, e)
						return
					}
					code(t, e, 1)
					if !strings.Contains(e.Error(), "UNLISTED_DIFFERENCE") || !strings.Contains(e.Error(), object) {
						t.Fatal("unlisted object not named", e)
					}
					found := false
					for _, r := range comparisonRows(t, &out) {
						if r.Type == "unlisted_difference" && strings.Contains(r.Object, object) {
							found = true
							if r.Seq != nil {
								t.Fatal("foreign object gained authority")
							}
						}
					}
					if !found || !strings.Contains(summary.String(), "unlisted=1") {
						t.Fatal("missing compare evidence")
					}
					if variant == "file" || variant == "parent-file" {
						exists(t, object)
					} else if variant == "member" && !f.sys.members["primary"]["intruder"] {
						t.Fatal("foreign member removed")
					}
				})
			}
		})
	}
}

// Claim: a nonempty rehearsal directory and a foreign group member stop without recursive deletion or account deletion; removing the foreign delta permits retry.
func TestLedgerRehearsalRefusesUnrecordedChildrenAndMembers(t *testing.T) {
	for _, variant := range []string{"child", "member"} {
		t.Run(variant, func(t *testing.T) {
			f := setupWith(t, "rehearsal", nil)
			older := f.create(t, "older", "file", "remove")
			if variant == "child" {
				dir := f.create(t, "state", "dir", "state")
				foreign := filepath.Join(dir, "unrecorded")
				must(t, os.WriteFile(foreign, []byte("foreign fixture"), 0600))
				e := f.l.Replay("rehearsal")
				code(t, e, 1)
				if !strings.Contains(e.Error(), "DIRECTORY_NOT_EMPTY") || !strings.Contains(e.Error(), foreign) {
					t.Fatal(e)
				}
				exists(t, foreign)
				exists(t, older)
				must(t, os.Remove(foreign))
			} else {
				must(t, f.l.CreateAccount("group", "access", "state", 0, 302))
				f.sys.members["access"] = map[string]bool{"intruder": true}
				e := f.l.Replay("rehearsal")
				code(t, e, 1)
				if !strings.Contains(e.Error(), "group:access/member:intruder") {
					t.Fatal(e)
				}
				if f.sys.called("/usr/sbin/groupdel") {
					t.Fatal("foreign membership erased")
				}
				exists(t, older)
				delete(f.sys.members["access"], "intruder")
			}
			must(t, f.l.Replay("rehearsal"))
			absent(t, older)
		})
	}
}

// Claim: undeclared filesystem/account targets refuse before intent or mutation, while a declared creation succeeds and reverses.
func TestLedgerInitScopeCannotExpand(t *testing.T) {
	f := setupWith(t, "rehearsal", nil)
	before := len(f.l.rows)
	p := filepath.Join(f.root, "undeclared")
	code(t, f.l.CreateFS(p, f.src, "file", "rehearsal", uint32(os.Geteuid()), uint32(os.Getegid()), 0600), 1)
	absent(t, p)
	if len(f.l.rows) != before {
		t.Fatal("undeclared scope wrote intent")
	}
	code(t, f.l.CreateAccount("group", "undeclared", "rehearsal", 0, 304), 1)
	if f.sys.called("/usr/sbin/groupadd") {
		t.Fatal("undeclared account created")
	}
	own := f.create(t, "own", "file", "rehearsal")
	must(t, f.l.Replay("rehearsal"))
	absent(t, own)
}

// Claim: changing a rehearsal genesis to station cannot admit existing rehearsal records, even with recomputed chain/HEAD; the original purpose replays normally.
func TestLedgerRehearsalClassCannotBeReclassified(t *testing.T) {
	for _, tamper := range []bool{false, true} {
		t.Run(stringID(map[bool]int{false: 0, true: 1}[tamper]), func(t *testing.T) {
			f := setupWith(t, "rehearsal", nil)
			p := f.create(t, "key", "secret", "rehearsal")
			if !tamper {
				must(t, f.l.Replay("rehearsal"))
				absent(t, p)
				return
			}
			rows := append([]Record(nil), f.l.rows...)
			g := *rows[0].Body.Genesis
			g.Purpose = "station"
			rows[0].Body.Genesis = &g
			f.l.Close()
			writeRows(t, f, rows, true)
			_, e := Open(f.dir, f.sys)
			code(t, e, 1)
			if !strings.Contains(e.Error(), "REHEARSAL_RETENTION_REQUIRES_REHEARSAL_PURPOSE") {
				t.Fatal(e)
			}
			exists(t, p)
		})
	}
}

// Claim: init refuses ambiguous, escaped, aliased, unknown or duplicate scope keys before creating a ledger; ordinary indented scope JSON remains valid.
func TestLedgerInitScopeJSONBoundary(t *testing.T) {
	for _, variant := range []string{"duplicate", "escaped", "alias", "unknown", "duplicate-path", "valid"} {
		t.Run(variant, func(t *testing.T) {
			f := setup(t)
			p := filepath.Join(f.root, "scope-input.json")
			dir := filepath.Join(f.root, "scoped-ledger")
			pathJSON := string(canonical(filepath.Join(f.root, "new-file")))
			entry := `{"path":` + pathJSON + `,"kind":"file"}`
			raw := `{"paths":[` + entry + `]}`
			switch variant {
			case "duplicate":
				raw = `{"paths":[],"paths":[` + entry + `]}`
			case "escaped":
				raw = `{"\u0070aths":[` + entry + `]}`
			case "alias":
				raw = `{"Paths":[` + entry + `]}`
			case "unknown":
				raw = `{"paths":[` + entry + `],"policy":"erase"}`
			case "duplicate-path":
				raw = `{"paths":[` + entry + `,` + entry + `]}`
			case "valid":
				raw = "\n  " + raw + "\n"
			}
			must(t, os.WriteFile(p, []byte(raw), 0600))
			e := Run([]string{"init", "-dir", dir, "-manifest", filepath.Join(f.root, "manifest.json"), "-baseline", f.l.rows[0].Body.Genesis.Baseline, "-scope", p, "-purpose", "rehearsal"}, f.sys, io.Discard)
			if variant == "valid" {
				must(t, e)
				l, e := Open(dir, f.sys)
				must(t, e)
				defer l.Close()
				if l.rows[0].Body.Genesis.Purpose != "rehearsal" {
					t.Fatal("purpose missing")
				}
			} else {
				code(t, e, 1)
				absent(t, dir)
			}
		})
	}
}

// Claim: final comparison uses init's S0, rejecting a later modified-file backup that would otherwise launder post-init drift; exact S0 restores are explained.
func TestLedgerFinalCompareUsesInitSnapshot(t *testing.T) {
	for _, drift := range []bool{false, true} {
		t.Run(stringID(map[bool]int{false: 0, true: 1}[drift]), func(t *testing.T) {
			f := setupWith(t, "station", func(f *fixture) {
				must(t, os.WriteFile(filepath.Join(f.root, "config"), []byte("original config\n"), 0600))
				must(t, os.WriteFile(filepath.Join(f.root, "backup"), []byte("original config\n"), 0600))
				must(t, os.WriteFile(filepath.Join(f.root, "staged"), []byte("installed config\n"), 0600))
			})
			path := filepath.Join(f.root, "config")
			backup := filepath.Join(f.root, "backup")
			if drift {
				for _, p := range []string{path, backup} {
					must(t, os.WriteFile(p, []byte("post-init config\n"), 0600))
				}
			}
			must(t, f.l.ModifyFile(path, backup, filepath.Join(f.root, "staged")))
			var out bytes.Buffer
			f.l.output = &out
			e := f.l.Replay("station")
			if drift {
				code(t, e, 1)
				if !strings.Contains(e.Error(), "UNLISTED_DIFFERENCE path:"+path) {
					t.Fatal(e)
				}
			} else {
				must(t, e)
			}
			rows := comparisonRows(t, &out)
			if len(rows) != 1 {
				t.Fatal("missing restore difference", len(rows))
			}
			if drift && rows[0].Type != "unlisted_difference" || !drift && (rows[0].Type != "retained" || rows[0].Retention != "state" || rows[0].Rule != "restore-attempt-transition-replacement-inode-or-mtime") {
				t.Fatalf("wrong restore explanation %+v", rows[0])
			}
		})
	}
}

// Claim: S0 records sticky parent permissions without granting mutation authority, and detects a later parent permission change.
func TestLedgerFinalCompareParentMetadata(t *testing.T) {
	for _, drift := range []bool{false, true} {
		t.Run(stringID(map[bool]int{false: 0, true: 1}[drift]), func(t *testing.T) {
			f := setupWith(t, "station", func(f *fixture) { must(t, os.Chmod(f.root, os.ModeSticky|0700)) })
			p := f.create(t, "own", "file", "remove")
			if drift {
				must(t, os.Chmod(f.root, 0700))
			}
			e := f.l.Replay("station")
			if drift {
				code(t, e, 1)
				if !strings.Contains(e.Error(), f.root) {
					t.Fatal(e)
				}
			} else {
				must(t, e)
			}
			absent(t, p)
		})
	}
}
