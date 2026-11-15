//go:build linux

package g2ledger

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Claim: legacy init needs installed plans only for reuse not justified by path parents;
// future plans may be partial, explicitly empty, or carry an empty link inventory.
// Never-enabled units roll back with the wants directory exactly unchanged and no row;
// enabling neighbours declare their prospective link and name it as the parent cause.
func TestLedgerRehearsalUnitShapes(t *testing.T) {
	for _, shape := range []string{"legacy", "no-entry-other", "no-entry-empty", "empty-links", "declared-link"} {
		for _, enable := range []bool{false, true} {
			activity := "never-enabled"
			if enable {
				activity = "enabled"
			}
			t.Run(shape+"/"+activity, func(t *testing.T) {
				f := newFutureFixture(t)
				unit := f.scope.FutureUnits[1]
				target := unit.Links[0].Target
				link := unit.Links[0]
				wants := filepath.Dir(link.Path)
				// A pre-existing unrelated entry is part of the exact unchanged inventory.
				must(t, os.Chmod(wants, 0755))
				must(t, os.WriteFile(filepath.Join(wants, "existing-entry"), []byte("fixture\n"), 0600))
				f.scope.Reused = []string{f.sys.unitRoot}
				f.scope.Units = []string{unit.Name}
				f.scope.Paths = []ScopePath{{Path: target, Kind: "file"}}
				switch shape {
				case "legacy":
					f.scope.FutureUnits = nil
				case "no-entry-other":
					f.scope.Units = append(f.scope.Units, f.scope.FutureUnits[0].Name)
					f.scope.FutureUnits = f.scope.FutureUnits[:1]
					f.scope.FutureUnits[0].Links = []FutureUnitLink{{Path: filepath.Join(f.sys.unitRoot, "other-alias.service"), Target: f.scope.FutureUnits[0].Links[0].Target}}
				case "no-entry-empty":
					f.scope.FutureUnits = []FutureUnit{}
				case "empty-links":
					unit.Links = []FutureUnitLink{}
					f.scope.FutureUnits = []FutureUnit{unit}
				case "declared-link":
					f.scope.FutureUnits = []FutureUnit{unit}
					f.scope.Reused = append(f.scope.Reused, wants)
				}
				if enable {
					if shape != "declared-link" {
						f.scope.Reused = append(f.scope.Reused, wants)
					}
					if shape == "empty-links" {
						// Enabling has a nonempty inventory; the sealed control must declare it.
						f.scope.FutureUnits[0].Links = []FutureUnitLink{link}
					} else if shape != "declared-link" {
						// Unbound units use an explicit path to justify this existing parent.
						f.scope.Paths = append(f.scope.Paths, ScopePath{Path: link.Path, Kind: "file"})
					}
				}
				before, err := snapshotObject(BaselineObject{Kind: "dir", Name: wants}, f.sys, f.dir, f.baseline)
				must(t, err)
				for _, name := range f.scope.Units {
					absent(t, filepath.Join(f.sys.unitRoot, name))
				}
				for _, planned := range f.scope.FutureUnits {
					if digest(mustRead(t, planned.Source)) != planned.SHA256 {
						t.Fatal("staged digest differs")
					}
				}
				raw := canonical(f.scope)
				if shape == "no-entry-empty" {
					raw = bytes.Replace(raw, []byte(`"reused":`), []byte(`"future_units":[],"reused":`), 1)
				}
				must(t, os.WriteFile(f.scopeFile, raw, 0600))
				code(t, Run([]string{"init", "-dir", f.dir, "-manifest", f.manifest, "-baseline", f.baseline, "-purpose", "rehearsal", "-scope", f.scopeFile}, f.sys, &bytes.Buffer{}), 0)
				f.open(t)
				must(t, f.l.CreateFS(target, unit.Source, "file", "state", uint32(os.Geteuid()), uint32(os.Getegid()), 0600))
				f.sys.units[unit.Name] = "disabled"
				if !bytes.Equal(mustRead(t, target), mustRead(t, unit.Source)) {
					t.Fatal("installer did not copy staged bytes")
				}
				if enable {
					code(t, f.l.Enable(unit.Name), 0)
				}
				f.reopen(t)
				var out bytes.Buffer
				f.l.output = &out
				code(t, f.l.Replay("rehearsal"), 0)
				rows := comparisonRows(t, &out)
				after, err := snapshotObject(before, f.sys, f.dir, f.baseline)
				must(t, err)
				if enable {
					row := parentRow(t, rows, wants)
					if row.Verdict != "ALLOWED-NAMED" || row.Rule != "allowed-named-reused-parent" || len(row.Causes) != 1 || row.Causes[0].Object != link.Path {
						t.Fatalf("missing link cause: %+v", row)
					}
					if !parentStable(before, after) {
						t.Fatal("enabling control did not restore parent invariants/entries")
					}
				} else {
					// Canonical snapshots include existence, mode, uid/gid, inode, mtime, ctime and entries.
					if !bytes.Equal(canonical(before), canonical(after)) {
						t.Fatalf("untouched wants changed: before=%s after=%s", canonical(before), canonical(after))
					}
					for _, row := range rows {
						if row.Object == "path:"+wants {
							t.Fatalf("unchanged wants has a row: %+v", row)
						}
					}
					if f.sys.called("/usr/bin/systemctl enable") {
						t.Fatal("never-enabled shape enabled a unit")
					}
				}
				absent(t, target)
				absent(t, link.Path)
				_, err = directParentCompare(t, f.l, "rehearsal")
				code(t, err, 0)
				code(t, f.l.Replay("rehearsal"), 0)
			})
		}
	}
}

// Claim: truly unused wants reuse refuses by name before ledger creation;
// a declared prospective link admits init but never authorizes a foreign link.
func TestLedgerRehearsalUnitWantsNegatives(t *testing.T) {
	for _, variant := range []string{"unused", "declared-unchanged", "undeclared-link"} {
		t.Run(variant, func(t *testing.T) {
			f := newFutureFixture(t)
			wants := filepath.Dir(f.scope.FutureUnits[0].Links[0].Path)
			if variant == "unused" {
				for i := range f.scope.FutureUnits {
					f.scope.FutureUnits[i].Links = []FutureUnitLink{}
				}
			}
			err := f.init(t)
			if variant == "unused" {
				code(t, err, 1)
				if !strings.Contains(err.Error(), "REUSED_PARENT_NOT_PROSPECTIVE "+wants) {
					t.Fatal(err)
				}
				absent(t, f.dir)
				return
			}
			code(t, err, 0)
			f.open(t)
			foreign := filepath.Join(wants, "undeclared.service")
			if variant == "undeclared-link" {
				must(t, os.Symlink(filepath.Join(f.sys.unitRoot, "undeclared.service"), foreign))
			}
			rows, err := directParentCompare(t, f.l, "station")
			if variant == "declared-unchanged" {
				code(t, err, 0)
				if len(rows) != 0 {
					t.Fatal(rows)
				}
			} else {
				code(t, err, 1)
				row := parentRow(t, rows, wants)
				if row.Verdict != "VIOLATION" || !strings.Contains(err.Error(), "path:"+wants) {
					t.Fatalf("unnamed violation: %+v %v", row, err)
				}
				found := false
				for _, entry := range rows {
					if entry.Object == "path:"+foreign && entry.Type == "unlisted_difference" && entry.Difference == "directory-entry" && entry.Rule == "unrecorded-directory-entry" {
						found = true
					}
				}
				if !found {
					t.Fatalf("foreign link not named: %+v", rows)
				}
				exists(t, foreign)
				if len(f.l.rows) != 1 || f.sys.called("/usr/bin/systemctl enable") {
					t.Fatal("foreign link gained an effect receipt")
				}
			}
		})
	}
}
