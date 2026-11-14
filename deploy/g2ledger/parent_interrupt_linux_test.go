//go:build linux

package g2ledger

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Claim: replay after S0, S1 and every fixture engine boundary restores entries and invariants; unreached parents retain even ctime, and reached parents require named causes.
func TestLedgerReusedParentInterruptReplay(t *testing.T) {
	const steps = 9
	for prefix := 0; prefix <= steps; prefix++ {
		name := fmt.Sprintf("boundary-%d", prefix)
		if prefix == 0 {
			name = "S0"
		}
		if prefix == 4 {
			name = "S1"
		}
		t.Run(name, func(t *testing.T) {
			var parents []string
			var backup, replacement, modified string
			f := setupWith(t, "rehearsal", func(f *fixture) {
				f.scope.Paths = nil
				f.scope.Reused = nil
				for i := 0; i < 7; i++ {
					p := filepath.Join(f.root, fmt.Sprintf("parent-%d", i))
					must(t, os.Mkdir(p, 0700))
					parents = append(parents, p)
					f.scope.Reused = append(f.scope.Reused, p)
					kind := "file"
					if i == 0 {
						kind = "dir"
					}
					f.scope.Paths = append(f.scope.Paths, ScopePath{Path: filepath.Join(p, "created"), Kind: kind})
				}
				modified = filepath.Join(parents[0], "existing-config")
				must(t, os.WriteFile(modified, []byte("old\n"), 0600))
				backup, replacement = filepath.Join(f.root, "backup"), filepath.Join(f.root, "replacement")
				must(t, os.WriteFile(backup, []byte("old\n"), 0600))
				must(t, os.WriteFile(replacement, []byte("new\n"), 0600))
				f.scope.Paths = append(f.scope.Paths, ScopePath{Path: modified, Kind: "file"})
				// Only the declared unit's derived link justifies this reused parent.
				wants := filepath.Join(f.sys.unitRoot, "multi-user.target.wants")
				must(t, os.Mkdir(wants, 0700))
				parents = append(parents, wants)
				f.scope.Reused = append(f.scope.Reused, wants)
			})
			for step := 0; step < prefix; step++ {
				switch {
				case step < 7:
					kind, mode := "file", uint32(0600)
					if step == 0 {
						kind, mode = "dir", 0700
					}
					must(t, f.l.CreateFS(filepath.Join(parents[step], "created"), f.src, kind, "remove", uint32(os.Geteuid()), uint32(os.Getegid()), mode))
				case step == 7:
					must(t, f.l.ModifyFile(modified, backup, replacement))
				case step == 8:
					must(t, f.l.Enable("demo.service"))
				}
				f.reopen(t) // Each step is a completed command, not a fabricated receipt.
			}
			f.reopen(t) // Stop the producer and replay through a fresh ledger handle.
			touched := f.l.touchedParents()
			var out, summary bytes.Buffer
			f.l.output, f.l.summary = &out, &summary
			err := f.l.Replay("rehearsal")
			code(t, err, 0)
			rawOutput := append([]byte(nil), out.Bytes()...)
			rows := comparisonRows(t, &out)
			var total CompareSummary
			for _, line := range bytes.Split(bytes.TrimSpace(rawOutput), []byte{'\n'}) {
				var row CompareSummary
				must(t, json.Unmarshal(line, &row))
				if row.Type == "baseline_summary" {
					total = row
				}
			}
			if total.Type != "baseline_summary" || total.Unlisted != 0 || total.ParentViolations != 0 || !strings.Contains(summary.String(), "unlisted=0") || !strings.Contains(summary.String(), "parent_violations=0") {
				t.Fatalf("bad replay result: %+v %s", total, summary.String())
			}
			allowed := 0
			for _, p := range parents {
				var base BaselineObject
				for _, b := range f.l.rows[0].Body.Genesis.S0 {
					if b.Name == p {
						base = b
					}
				}
				now, err := snapshotObject(base, f.sys, f.dir, f.l.rows[0].Body.Genesis.Baseline)
				must(t, err)
				if !parentStable(base, now) {
					t.Fatalf("parent invariants or entries changed: %s", p)
				}
				if !touched[p] {
					if !baselineEqual(base, now) {
						t.Fatalf("unreached parent changed, including timestamps: %s", p)
					}
					for _, row := range rows {
						if row.Object == "path:"+p {
							t.Fatalf("row for unchanged prospective parent: %+v", row)
						}
					}
				} else {
					row := parentRow(t, rows, p)
					if row.Verdict != "ALLOWED-NAMED" || len(row.Causes) == 0 {
						t.Fatalf("missing named causes: %+v", row)
					}
					allowed++
				}
			}
			if total.ReusedParentChanges != allowed {
				t.Fatalf("named count: %+v want=%d", total, allowed)
			}
			for i := 0; i < 7; i++ {
				absent(t, filepath.Join(parents[i], "created"))
			}
			raw, err := os.ReadFile(modified)
			must(t, err)
			if string(raw) != "old\n" {
				t.Fatal("config not restored")
			}
		})
	}
}

// Claim: unrelated and ancestor-only reuse declarations refuse by exact name at init without creating journal state; the immediate-parent neighbour initializes.
func TestLedgerReusedParentProspectiveDeclaration(t *testing.T) {
	for _, variant := range []string{"immediate", "unrelated", "ancestor"} {
		t.Run(variant, func(t *testing.T) {
			f := newParentFixture(t, true, false)
			root := filepath.Dir(f.parent)
			unused := filepath.Join(root, "unused")
			must(t, os.Mkdir(unused, 0700))
			declared := f.parent
			if variant == "unrelated" {
				declared = unused
			}
			if variant == "ancestor" {
				declared = root
			}
			scope := Scope{Reused: []string{declared}, Paths: []ScopePath{{Path: f.child, Kind: "file"}}}
			dir := filepath.Join(root, "second-ledger")
			err := Init(dir, filepath.Join(root, "manifest.json"), filepath.Join(root, "baseline"), InitOptions{Purpose: "rehearsal", Scope: scope, System: newSystem()})
			if variant == "immediate" {
				must(t, err)
				return
			}
			code(t, err, 1)
			if !strings.Contains(err.Error(), "REUSED_PARENT_NOT_PROSPECTIVE "+declared) {
				t.Fatal(err)
			}
			absent(t, dir)
		})
	}
}

// Claim: a prospective but unreached parent cannot hide an unrecorded entry; its unchanged neighbour replays without a row.
func TestLedgerReusedParentUnreachedEntryViolation(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(fmt.Sprint(changed), func(t *testing.T) {
			f := newParentFixture(t, true, false)
			extra := filepath.Join(f.parent, "unrecorded")
			if changed {
				must(t, os.WriteFile(extra, []byte("foreign\n"), 0600))
			}
			rows, total, err := f.compare(t)
			if !changed {
				must(t, err)
				if len(rows) != 0 || total.Unlisted != 0 || total.ParentViolations != 0 {
					t.Fatal(rows, total)
				}
				return
			}
			code(t, err, 1)
			row := parentRow(t, rows, f.parent)
			if row.Verdict != "VIOLATION" || total.ParentViolations != 1 || total.Unlisted < 1 || total.ReusedParentChanges != 0 {
				t.Fatal(rows, total)
			}
			exists(t, extra)
		})
	}
}
