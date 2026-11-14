//go:build linux

package g2ledger

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func directParentCompare(t *testing.T, l *Ledger, mode string) ([]CompareRow, error) {
	t.Helper()
	var out bytes.Buffer
	l.output = &out
	err := l.compareBaseline(mode)
	return comparisonRows(t, &out), err
}

// Claim: only exact retained station children allow the named parent; foreign, type-replaced, and non-retained leftovers reject beside the valid control.
func TestLedgerStationParentRetainedEntries(t *testing.T) {
	for _, variant := range []string{"valid", "unrecorded", "non-retained", "type-change", "identity-change", "undeclared"} {
		t.Run(variant, func(t *testing.T) {
			f := newParentFixtureMode(t, variant != "undeclared", false, "station")
			if variant == "undeclared" {
				f.l.entryCheck = func(string) error { return nil }
			}
			ret := "state"
			if variant == "non-retained" {
				ret = "remove"
			}
			must(t, f.l.CreateFS(f.child, f.foreign, "file", ret, uint32(os.Geteuid()), uint32(os.Getegid()), 0600))
			switch variant {
			case "unrecorded":
				must(t, os.WriteFile(filepath.Join(f.parent, "extra"), []byte("foreign"), 0600))
			case "type-change":
				must(t, os.Remove(f.child))
				must(t, os.Mkdir(f.child, 0700))
			case "identity-change":
				must(t, os.Chmod(f.child, 0640))
			}
			rows, err := directParentCompare(t, f.l, "station")
			row := parentRow(t, rows, f.parent)
			if variant == "valid" {
				must(t, err)
				if row.Verdict != "ALLOWED-NAMED" || len(row.Causes) != 1 || row.Causes[0].Object != f.child {
					t.Fatalf("missing retained cause: %+v", row)
				}
			} else {
				code(t, err, 1)
				if row.Verdict != "VIOLATION" {
					t.Fatalf("accepted %s: %+v", variant, row)
				}
				if variant == "undeclared" && row.Rule != "parent-not-declared-reused" {
					t.Fatal(row)
				}
			}
		})
	}
}

// Claim: atomic replacement temporaries require the same declared parent as the target; the declared control names the modify intent.
func TestLedgerModifyTemporaryParentDeclaration(t *testing.T) {
	for _, reused := range []bool{false, true} {
		t.Run(map[bool]string{false: "undeclared", true: "declared"}[reused], func(t *testing.T) {
			f := newParentFixtureMode(t, reused, false, "station")
			if !reused {
				f.l.entryCheck = func(string) error { return nil }
			}
			root := filepath.Dir(f.parent)
			backup := filepath.Join(root, "backup")
			next := filepath.Join(root, "next")
			raw, err := os.ReadFile(f.foreign)
			must(t, err)
			must(t, os.WriteFile(backup, raw, 0600))
			must(t, os.WriteFile(next, []byte("replacement\n"), 0600))
			must(t, f.l.ModifyFile(f.foreign, backup, next))
			var out bytes.Buffer
			f.l.output = &out
			err = f.l.Replay("station")
			row := parentRow(t, comparisonRows(t, &out), f.parent)
			if reused {
				must(t, err)
				if row.Verdict != "ALLOWED-NAMED" || len(row.Causes) != 1 || row.Causes[0].Object != f.foreign {
					t.Fatal(row)
				}
			} else {
				code(t, err, 1)
				if row.Rule != "parent-not-declared-reused" {
					t.Fatal(row)
				}
			}
			found := false
			for _, r := range f.l.rows {
				if r.Body.Op == "commit" {
					for _, p := range r.Body.Result.Parents {
						if len(p.Temporary) > 0 {
							found = true
						}
					}
				}
			}
			if !found {
				t.Fatal("no real rename temporary receipt")
			}
		})
	}
}

// Claim: a state-class child left behind cannot use station retention during rehearsal comparison.
func TestLedgerRehearsalLeftoverRetainedClass(t *testing.T) {
	f := newParentFixture(t, true, false)
	must(t, f.l.CreateFS(f.child, f.foreign, "file", "state", uint32(os.Geteuid()), uint32(os.Getegid()), 0600))
	rows, err := directParentCompare(t, f.l, "rehearsal")
	code(t, err, 1)
	if row := parentRow(t, rows, f.parent); row.Verdict != "VIOLATION" || row.Rule != "reused-parent-baseline-invariant" {
		t.Fatal(row)
	}
}

func unitParentFixture(t *testing.T, declared, existing bool) (*fixture, UnitLink) {
	t.Helper()
	f := setupWith(t, "rehearsal", func(f *fixture) {
		f.scope.Reused = []string{f.sys.unitRoot}
		dir := filepath.Join(f.sys.unitRoot, "multi-user.target.wants")
		if existing {
			f.scope.Reused = []string{}
			must(t, os.Mkdir(dir, 0700))
			if declared {
				f.scope.Reused = append(f.scope.Reused, dir)
			}
		}
	})
	link := UnitLink{Path: filepath.Join(f.sys.unitRoot, "multi-user.target.wants", "demo.service"), Target: filepath.Join(f.sys.unitRoot, "demo.service")}
	installReply(t, f, []UnitLink{link}, []UnitLink{link})
	return f, link
}

// Claim: a pre-existing undeclared wants parent refuses before intent/link effects; bypassing only that check still yields a named final violation.
func TestLedgerUnitLinkParentDeclaration(t *testing.T) {
	for _, bypass := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-effect", true: "compare-backstop"}[bypass], func(t *testing.T) {
			f, link := unitParentFixture(t, false, true)
			if bypass {
				f.l.unitParentCheck = func(string) error { return nil }
			}
			err := f.l.Enable("demo.service")
			if !bypass {
				code(t, err, 1)
				if !strings.Contains(err.Error(), "UNIT_LINK_PARENT_NOT_DECLARED "+filepath.Dir(link.Path)) || f.sys.called("/usr/bin/systemctl enable") || len(f.l.rows) != 1 {
					t.Fatal(err)
				}
				absent(t, link.Path)
				return
			}
			must(t, err)
			var out bytes.Buffer
			f.l.output = &out
			err = f.l.Replay("rehearsal")
			code(t, err, 1)
			row := parentRow(t, comparisonRows(t, &out), filepath.Dir(link.Path))
			if row.Verdict != "VIOLATION" || row.Rule != "parent-not-declared-reused" {
				t.Fatal(row)
			}
			absent(t, link.Path)
		})
	}
}

// Claim: a declared wants parent names the link cause and returns to its S0 entry set after rehearsal rollback.
func TestLedgerUnitLinkParentDeclared(t *testing.T) {
	f, link := unitParentFixture(t, true, true)
	must(t, f.l.Enable("demo.service"))
	var out bytes.Buffer
	f.l.output = &out
	must(t, f.l.Replay("rehearsal"))
	row := parentRow(t, comparisonRows(t, &out), filepath.Dir(link.Path))
	if row.Verdict != "ALLOWED-NAMED" || len(row.Causes) != 1 || row.Causes[0].Object != link.Path {
		t.Fatal(row)
	}
	entries, err := os.ReadDir(filepath.Dir(link.Path))
	must(t, err)
	if len(entries) != 0 {
		t.Fatal(entries)
	}
}

// Claim: an absent wants directory is recorded as attempt-created, never reused, and removed with its link on rollback.
func TestLedgerUnitLinkParentCreated(t *testing.T) {
	f, link := unitParentFixture(t, false, false)
	must(t, f.l.Enable("demo.service"))
	unit := f.l.rows[len(f.l.rows)-1].Body.Result.Identities[0].Unit
	if len(unit.Directories) != 1 || unit.Directories[0].Path != filepath.Dir(link.Path) {
		t.Fatalf("missing created directory: %+v", unit)
	}
	must(t, f.l.Replay("rehearsal"))
	absent(t, filepath.Dir(link.Path))
}

// Claim: link identities independently inventory their parent even when all parent receipts are removed through a compare-only test seam.
func TestLedgerUnitLinkParentInventoryWithoutReceipt(t *testing.T) {
	f, link := unitParentFixture(t, false, true)
	f.l.unitParentCheck = func(string) error { return nil }
	must(t, f.l.Enable("demo.service"))
	var discard bytes.Buffer
	f.l.output = &discard
	code(t, f.l.Replay("rehearsal"), 1)
	for j := range f.l.rows {
		if f.l.rows[j].Body.Op == "commit" {
			f.l.rows[j].Body.Result.Parents = nil
		}
		if f.l.rows[j].Body.Op == "parent-replay" {
			f.l.rows[j].Body.ParentReplay.Parents = nil
		}
	}
	rows, err := directParentCompare(t, f.l, "rehearsal")
	code(t, err, 1)
	row := parentRow(t, rows, filepath.Dir(link.Path))
	if row.Verdict != "VIOLATION" || row.Rule != "parent-not-declared-reused" {
		t.Fatal(row)
	}
}

// Claim: a newly appeared install directory after intent is refused before enable and is never adopted as attempt-created.
func TestLedgerUnitLinkParentAppearsAfterIntent(t *testing.T) {
	f, link := unitParentFixture(t, false, false)
	f.l.afterIntent = func(Action) error { return os.Mkdir(filepath.Dir(link.Path), 0700) }
	code(t, f.l.Enable("demo.service"), 3)
	if f.sys.called("/usr/bin/systemctl enable") || len(f.l.rows) != 2 {
		t.Fatal("enable/adoption after foreign mkdir")
	}
	absent(t, link.Path)
	exists(t, filepath.Dir(link.Path))
}

// Claim: scope creates and modify rename temporaries refuse an undeclared existing parent before any intent or filesystem effect.
func TestLedgerEntryParentDeclarationBeforeEffect(t *testing.T) {
	for _, kind := range []string{"create", "modify"} {
		t.Run(kind, func(t *testing.T) {
			f := newParentFixtureMode(t, false, false, "station")
			var err error
			if kind == "create" {
				err = f.l.CreateFS(f.child, f.foreign, "file", "state", uint32(os.Geteuid()), uint32(os.Getegid()), 0600)
			} else {
				root := filepath.Dir(f.parent)
				backup := filepath.Join(root, "backup")
				next := filepath.Join(root, "next")
				raw, e := os.ReadFile(f.foreign)
				must(t, e)
				must(t, os.WriteFile(backup, raw, 0600))
				must(t, os.WriteFile(next, []byte("new\n"), 0600))
				err = f.l.ModifyFile(f.foreign, backup, next)
				after, e := os.ReadFile(f.foreign)
				must(t, e)
				if !bytes.Equal(after, raw) {
					t.Fatal("modify before parent refusal")
				}
			}
			code(t, err, 1)
			if !strings.Contains(err.Error(), "ENTRY_PARENT_NOT_DECLARED "+f.parent) || len(f.l.rows) != 1 {
				t.Fatal(err)
			}
			absent(t, f.child)
			entries, e := os.ReadDir(f.parent)
			must(t, e)
			if len(entries) != 1 || entries[0].Name() != "foreign" {
				t.Fatal("unexpected entry effect", entries)
			}
		})
	}
}

// Claim: rollback never recursively deletes foreign children of an attempt-created wants directory; the exact empty positive is covered beside it.
func TestLedgerUnitLinkCreatedParentForeignChild(t *testing.T) {
	f, link := unitParentFixture(t, false, false)
	must(t, f.l.Enable("demo.service"))
	foreign := filepath.Join(filepath.Dir(link.Path), "foreign")
	must(t, os.WriteFile(foreign, []byte("foreign fixture\n"), 0600))
	err := f.l.Replay("rehearsal")
	code(t, err, 1)
	if !strings.Contains(err.Error(), "DIRECTORY_NOT_EMPTY "+foreign) {
		t.Fatal(err)
	}
	exists(t, foreign)
	exists(t, filepath.Dir(link.Path))
}

type installPathSystem struct {
	*fakeSystem
	search []string
	config string
}

func (s installPathSystem) UnitPaths() ([]string, string, error) { return s.search, s.config, nil }

// Claim: multiple links in a new install hierarchy record every directory and rollback removes descendants first, preserving the reused ancestor and source.
func TestLedgerUnitLinkCreatedHierarchy(t *testing.T) {
	var vendor string
	f := setupWith(t, "rehearsal", func(f *fixture) {
		vendor = filepath.Join(f.root, "vendor-units")
		must(t, os.Mkdir(vendor, 0700))
		must(t, os.WriteFile(filepath.Join(vendor, "demo.service"), []byte("[Install]\nWantedBy=a.target b.target\nAlias=alias.service\n"), 0600))
		f.sys.unitRoot = filepath.Join(f.root, "install", "config")
	})
	f.l.sys = installPathSystem{f.sys, []string{vendor}, f.sys.unitRoot}
	source := filepath.Join(vendor, "demo.service")
	links := []UnitLink{
		{Path: filepath.Join(f.sys.unitRoot, "a.target.wants", "demo.service"), Target: source},
		{Path: filepath.Join(f.sys.unitRoot, "b.target.wants", "demo.service"), Target: source},
		{Path: filepath.Join(f.sys.unitRoot, "alias.service"), Target: source},
	}
	installReply(t, f, links, links)
	must(t, f.l.Enable("demo.service"))
	dirs := f.l.rows[len(f.l.rows)-1].Body.Result.Identities[0].Unit.Directories
	if len(dirs) != 4 {
		t.Fatalf("missing install directory identities: %+v", dirs)
	}
	must(t, f.l.Replay("rehearsal"))
	absent(t, filepath.Join(f.root, "install"))
	exists(t, source)
	exists(t, f.root)
}
