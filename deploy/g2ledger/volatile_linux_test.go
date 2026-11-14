package g2ledger

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func volatileTargets(t *testing.T) []string {
	t.Helper()
	root := t.TempDir()
	alias := filepath.Join(root, "runtime-alias")
	must(t, os.Symlink("/run", alias))
	dangling := filepath.Join(root, "dangling-alias")
	must(t, os.Symlink("/run/g2-ledger-nonexistent-target/child", dangling))
	relative := filepath.Join(root, "relative-alias")
	must(t, os.Symlink("runtime-alias", relative))
	return []string{"/run", "/run/g2-ledger-volatile-test", "/var/run", "/var/run/g2-ledger-volatile-test", alias, filepath.Join(alias, "missing", "child"), dangling, filepath.Join(dangling, "missing"), filepath.Join(relative, "missing")}
}

// Claim: init refuses every filesystem scope kind at /run, /var/run and resolved/dangling aliases before creating the ledger, while /var/lib targets pass the same path policy.
func TestLedgerVolatileScopeRefused(t *testing.T) {
	for _, path := range volatileTargets(t) {
		for _, kind := range []string{"dir", "tree", "file", "secret"} {
			t.Run(kind+path, func(t *testing.T) {
				f := setup(t)
				target := filepath.Join(f.root, "refused-ledger")
				err := Init(target, filepath.Join(f.root, "manifest.json"), filepath.Join(f.root, "baseline"), InitOptions{Purpose: "station", Scope: Scope{Paths: []ScopePath{{Path: path, Kind: kind}}}, System: f.sys})
				code(t, err, 1)
				if !strings.Contains(err.Error(), volatileRuntimeReason) {
					t.Fatal(err)
				}
				absent(t, target)
			})
		}
	}
	for _, path := range []string{"/var/lib/swarma-wallet", "/var/lib/g2-ledger-test/missing", "/runtime/g2", "/var/runner/g2"} {
		must(t, targetPathPolicy(path))
		must(t, validateScope(Scope{Paths: []ScopePath{{Path: path, Kind: "dir"}}}))
	}
}

// Claim: all filesystem creators refuse runtime targets before durable intent, writes or creator execution even if an in-memory scope is corrupted; a persistent real directory/file/tree neighbour remains usable.
func TestLedgerVolatileCreatorsRefused(t *testing.T) {
	for _, path := range volatileTargets(t) {
		for _, kind := range []string{"dir", "file", "secret", "tree", "exec-create"} {
			t.Run(kind+path, func(t *testing.T) {
				f, _ := treeFixture(t, "rehearsal")
				// Bypass only scope membership in this hostile in-memory fixture to prove
				// the creator's own refusal, independently of the init guard.
				scopedKind := kind
				if kind == "exec-create" {
					scopedKind = "secret"
				}
				f.l.rows[0].Body.Genesis.Scope.Paths = append(f.l.rows[0].Body.Genesis.Scope.Paths, ScopePath{Path: path, Kind: scopedKind})
				before, err := os.ReadFile(filepath.Join(f.dir, "records.jsonl"))
				must(t, err)
				head, err := os.ReadFile(filepath.Join(f.dir, "HEAD"))
				must(t, err)
				n := len(f.l.rows)
				calls := len(f.sys.calls)
				switch kind {
				case "tree":
					err = f.l.CreateTree(path, "demo", "rehearsal", 0700, nil)
				case "exec-create":
					self, e := os.Executable()
					must(t, e)
					err = f.l.ExecCreate("secret", "rehearsal", []string{path}, []string{self, "g2-keygen", "-out", path})
				default:
					err = f.l.CreateFS(path, f.src, kind, "rehearsal", uint32(os.Geteuid()), uint32(os.Getegid()), 0700)
				}
				code(t, err, 1)
				if !strings.Contains(err.Error(), volatileRuntimeReason) {
					t.Fatal(err)
				}
				after, e := os.ReadFile(filepath.Join(f.dir, "records.jsonl"))
				must(t, e)
				afterHead, e := os.ReadFile(filepath.Join(f.dir, "HEAD"))
				must(t, e)
				if !bytes.Equal(before, after) || !bytes.Equal(head, afterHead) || len(f.l.rows) != n {
					t.Fatal("runtime refusal changed journal")
				}
				for _, call := range f.sys.calls[calls:] {
					if !strings.HasPrefix(call, "/usr/bin/getent ") {
						t.Fatal("runtime refusal invoked creator", call)
					}
				}
			})
		}
	}
	t.Run("persistent-neighbour", func(t *testing.T) {
		f := setupWith(t, "rehearsal", func(f *fixture) { f.declare("persistent", "dir"); f.declare("persistent-file", "file") })
		must(t, f.l.CreateFS(filepath.Join(f.root, "persistent"), "", "dir", "rehearsal", uint32(os.Geteuid()), uint32(os.Getegid()), 0700))
		must(t, f.l.CreateFS(filepath.Join(f.root, "persistent-file"), f.src, "file", "rehearsal", uint32(os.Geteuid()), uint32(os.Getegid()), 0600))
		must(t, f.l.Replay("rehearsal"))
		validTreeNeighbour(t)
	})
}

// Claim: baseline comparison emits /run as excluded volatile, and parent inventories omit runtime aliases while retaining persistent children.
func TestLedgerVolatileBaselineExclusion(t *testing.T) {
	f := setup(t)
	var out, summary bytes.Buffer
	f.l.output = &out
	f.l.summary = &summary
	must(t, f.l.Replay("station"))
	dec := json.NewDecoder(&out)
	found := false
	for dec.More() {
		var row CompareSummary
		must(t, dec.Decode(&row))
		if row.Type == "baseline_summary" {
			found = true
			if !slices.Contains(row.ExcludedVolatile, "/run") {
				t.Fatal("missing volatile exclusion", row)
			}
		}
	}
	if !found || !strings.Contains(summary.String(), "excluded_volatile=/run") {
		t.Fatal("missing baseline exclusion", summary.String())
	}
	root := t.TempDir()
	must(t, os.Symlink("/run", filepath.Join(root, "volatile")))
	must(t, os.Mkdir(filepath.Join(root, "persistent"), 0700))
	snapshot, err := snapshotObject(BaselineObject{Kind: "dir", Name: root}, f.sys, f.dir, filepath.Join(f.root, "baseline"))
	must(t, err)
	if len(snapshot.Children) != 1 || snapshot.Children[0].Name != "persistent" {
		t.Fatal("wrong inventory", snapshot.Children)
	}
	if !excludedPath("/run", f.dir, "") || !excludedPath("/var/run", f.dir, "") {
		t.Fatal("runtime root not excluded")
	}
}

// Claim: link expansion precedes dot-dot, for relative/absolute and nested
// targets; dangling /run suffixes refuse and persistent /var/lib neighbours
// pass. A loop returns ELOOP and exactly 40 expansions are allowed.
func TestLedgerVolatileComponentWalk(t *testing.T) {
	root := t.TempDir()
	links := map[string]string{
		"bridge": "/run/lock", "absolute": root + "/bridge/..", "relative": "bridge/..",
		"nested": "relative", "missing-run": "/run/g2-ledger-missing-r2/..",
		"persistent": "/var/lib", "persistent-dotdot": "/var/lib/../lib",
		"escape-run": "bridge/../../var/lib", "loop": "loop",
		"missing-back": "missing/../relative", "root-parent": "/../../var/lib",
	}
	for name, target := range links {
		must(t, os.Symlink(target, filepath.Join(root, name)))
	}
	for _, name := range []string{"absolute", "relative", "nested", "missing-run", "missing-back"} {
		t.Run(name, func(t *testing.T) {
			err := targetPathPolicy(filepath.Join(root, name))
			if !errors.Is(err, errVolatileRuntime) {
				t.Fatalf("missing runtime refusal: %v", err)
			}
		})
	}
	for _, name := range []string{"persistent", "persistent-dotdot", "escape-run", "root-parent"} {
		t.Run(name, func(t *testing.T) { must(t, targetPathPolicy(filepath.Join(root, name))) })
	}
	t.Run("loop", func(t *testing.T) {
		err := targetPathPolicy(filepath.Join(root, "loop"))
		if !errors.Is(err, unix.ELOOP) {
			t.Fatalf("want ELOOP: %v", err)
		}
	})
	for i := 40; i >= 1; i-- {
		target := "/var/lib"
		if i < 40 {
			target = fmt.Sprintf("hop%d", i+1)
		}
		must(t, os.Symlink(target, filepath.Join(root, fmt.Sprintf("hop%d", i))))
	}
	must(t, targetPathPolicy(filepath.Join(root, "hop1")))
	must(t, os.Symlink("hop1", filepath.Join(root, "hop0")))
	if err := targetPathPolicy(filepath.Join(root, "hop0")); !errors.Is(err, unix.ELOOP) {
		t.Fatalf("41 hops accepted: %v", err)
	}
}
