//go:build linux

package g2ledger

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type parentFixture struct {
	l                      *Ledger
	parent, child, foreign string
}

func newParentFixture(t *testing.T, reused bool, secret bool) *parentFixture {
	t.Helper()
	return newParentFixtureMode(t, reused, secret, "rehearsal")
}
func newParentFixtureMode(t *testing.T, reused, secret bool, purpose string) *parentFixture {
	t.Helper()
	root := t.TempDir()
	p := filepath.Join(root, "reused")
	must(t, os.Mkdir(p, 0700))
	base := filepath.Join(root, "baseline")
	must(t, os.Mkdir(base, 0700))
	must(t, os.WriteFile(filepath.Join(base, "taken-at.txt"), []byte("fixture\n"), 0600))
	must(t, os.WriteFile(filepath.Join(base, "errors.txt"), nil, 0600))
	manifest := filepath.Join(root, "manifest.json")
	raw, e := os.ReadFile("testdata/release-manifest.json")
	must(t, e)
	must(t, os.WriteFile(manifest, raw, 0600))
	foreign := filepath.Join(p, "foreign")
	must(t, os.WriteFile(foreign, []byte("public fixture\n"), 0600))
	// A secret-scope control permits a later read to exercise real atime without init reading it.
	old := time.Unix(1, 0)
	must(t, os.Chtimes(foreign, old, old))
	kind := "file"
	if secret {
		kind = "secret"
	}
	scope := Scope{Reused: []string{}, Paths: []ScopePath{{Path: filepath.Join(p, "child"), Kind: "file"}, {Path: foreign, Kind: kind}}}
	if reused {
		scope.Reused = append(scope.Reused, p)
	}
	dir := filepath.Join(root, "ledger")
	must(t, Init(dir, manifest, base, InitOptions{Purpose: purpose, Scope: scope, System: newSystem()}))
	l, e := Open(dir, newSystem())
	must(t, e)
	t.Cleanup(l.Close)
	return &parentFixture{l: l, parent: p, child: filepath.Join(p, "child"), foreign: foreign}
}
func (f *parentFixture) create(t *testing.T) {
	t.Helper()
	must(t, f.l.CreateFS(f.child, f.foreign, "file", "remove", uint32(os.Geteuid()), uint32(os.Getegid()), 0600))
}
func (f *parentFixture) compare(t *testing.T) ([]CompareRow, CompareSummary, error) {
	t.Helper()
	var out, summary bytes.Buffer
	f.l.output = &out
	f.l.summary = &summary
	e := f.l.Replay("rehearsal")
	raw := out.Bytes()
	rows := comparisonRows(t, &out)
	var total CompareSummary
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte{'\n'}) {
		var r CompareSummary
		must(t, json.Unmarshal(line, &r))
		if r.Type == "baseline_summary" {
			total = r
		}
	}
	if !strings.Contains(summary.String(), "reused_parent_changes=") || !strings.Contains(summary.String(), "parent_violations=") {
		t.Fatalf("missing text counts: %s, err=%v", summary.String(), e)
	}
	return rows, total, e
}
func parentRow(t *testing.T, rows []CompareRow, path string) CompareRow {
	t.Helper()
	var got []CompareRow
	for _, r := range rows {
		if r.Object == "path:"+path && r.Difference == "parent-metadata" {
			got = append(got, r)
		}
	}
	if len(got) != 1 {
		t.Fatalf("want one named parent row, got %+v", rows)
	}
	return got[0]
}

// Claim: a declared reused parent restored after a recorded child cycle names the intent/path and counts once, across reopened commands and replay retry.
func TestLedgerReusedParentAllowedNamed(t *testing.T) {
	f := newParentFixture(t, true, false)
	f.create(t)
	f.l.Close()
	var e error
	f.l, e = Open(f.l.root, newSystem())
	must(t, e)
	defer f.l.Close()
	for i := 0; i < 2; i++ {
		rows, total, e := f.compare(t)
		must(t, e)
		r := parentRow(t, rows, f.parent)
		if r.Type != "reused_parent_change" || r.Verdict != "ALLOWED-NAMED" || r.Rule != "allowed-named-reused-parent" || len(r.Causes) != 1 || r.Causes[0].Intent != 1 || r.Causes[0].Object != f.child || total.ReusedParentChanges != 1 || total.ParentViolations != 0 || total.Unlisted != 0 {
			t.Fatalf("wrong named allowance: %+v %+v", r, total)
		}
		absent(t, f.child)
	}
}

// Claim: the same sealed snapshot/intent chain yields the same named allowance with every event removed; events supply no authority.
func TestLedgerReusedParentSnapshotsAloneAllow(t *testing.T) {
	f := newParentFixture(t, true, false)
	f.create(t)
	rows, _, e := f.compare(t)
	must(t, e)
	want := parentRow(t, rows, f.parent)
	for i := range f.l.rows {
		row := &f.l.rows[i]
		if row.Body.Op == "commit" {
			for j := range row.Body.Result.Parents {
				row.Body.Result.Parents[j].Events = []ParentEvent{}
			}
		}
		if row.Body.Op == "parent-replay" {
			for j := range row.Body.ParentReplay.Parents {
				row.Body.ParentReplay.Parents[j].Events = []ParentEvent{}
			}
		}
	}
	var out bytes.Buffer
	f.l.output = &out
	must(t, f.l.compareBaseline("rehearsal"))
	got := parentRow(t, comparisonRows(t, &out), f.parent)
	if !bytes.Equal(canonical(got), canonical(want)) {
		t.Fatalf("event-dependent allowance: got %+v want %+v", got, want)
	}
}

// Claim: real armed intervals with empty event receipts still allow their sealed snapshot/intent chain after reopening the ledger.
func TestLedgerReusedParentEmptyEventsAllowedNamed(t *testing.T) {
	f := newParentFixture(t, true, false)
	f.l.parentWatchRead = func(int, []byte) (int, error) { return -1, unix.EAGAIN }
	f.create(t)
	f.l.Close()
	var e error
	f.l, e = Open(f.l.root, newSystem())
	must(t, e)
	defer f.l.Close()
	f.l.parentWatchRead = func(int, []byte) (int, error) { return -1, unix.EAGAIN }
	rows, total, e := f.compare(t)
	must(t, e)
	r := parentRow(t, rows, f.parent)
	if r.Verdict != "ALLOWED-NAMED" || len(r.Causes) != 1 || r.Causes[0].Object != f.child || total.ReusedParentChanges != 1 || total.ParentViolations != 0 {
		t.Fatalf("empty events denied: %+v %+v", r, total)
	}
}

func plantedParentEvent(wd int, mask uint32, name []byte) []byte {
	raw := make([]byte, unix.SizeofInotifyEvent+len(name))
	binary.NativeEndian.PutUint32(raw, uint32(wd))
	binary.NativeEndian.PutUint32(raw[4:], mask)
	binary.NativeEndian.PutUint32(raw[12:], uint32(len(name)))
	copy(raw[unix.SizeofInotifyEvent:], name)
	return raw
}
func injectParentEvent(f *parentFixture, mask uint32) {
	injected := false
	f.l.parentWatchRead = func(fd int, buf []byte) (int, error) {
		if injected {
			return unix.Read(fd, buf)
		}
		injected = true
		wd := -1
		if mask != unix.IN_Q_OVERFLOW {
			for key := range f.l.parentWatch.dirs {
				wd = key
				break
			}
		}
		return copy(buf, plantedParentEvent(wd, mask, nil)), nil
	}
}
func assertParentFailure(t *testing.T, f *parentFixture, reason string) {
	t.Helper()
	rows, total, e := f.compare(t)
	code(t, e, 1)
	r := parentRow(t, rows, f.parent)
	if r.Verdict != "VIOLATION" || r.Type != "unlisted_difference" || !strings.Contains(r.Rule, reason) || !strings.Contains(e.Error(), reason) || total.ParentViolations != 1 || total.Unlisted != 1 || total.ReusedParentChanges != 0 {
		t.Fatalf("want named %s violation: row=%+v total=%+v err=%v", reason, r, total, e)
	}
	for _, row := range rows {
		if row.Verdict == "ALLOWED-NAMED" {
			t.Fatalf("allowed row after watch failure: %+v", row)
		}
	}
}

// Claim: a test-seam IN_Q_OVERFLOW record aborts replay with a named parent violation, never an allowance.
func TestLedgerReusedParentOverflowViolation(t *testing.T) {
	f := newParentFixture(t, true, false)
	f.create(t)
	injectParentEvent(f, unix.IN_Q_OVERFLOW)
	assertParentFailure(t, f, "PARENT_EVENTS_OVERFLOW")
	absent(t, f.child) // The effect preceded the read failure; no successful compare or receipt is claimed.
	if len(f.l.rows) != 3 {
		t.Fatalf("failed evidence was sealed: rows=%d", len(f.l.rows))
	}
	f.l.parentWatchRead = nil
	assertParentFailure(t, f, "unrecorded-parent-transition")
}

// Claim: real watch removal and injected watched-parent lifecycle events each abort with their specific named violation.
func TestLedgerReusedParentLostWatchViolation(t *testing.T) {
	for _, variant := range []string{"removed-watch", "ignored", "deleted", "moved", "unmounted"} {
		t.Run(variant, func(t *testing.T) {
			f := newParentFixture(t, true, false)
			f.create(t)
			reason := "PARENT_WATCH_IGNORED"
			if variant == "removed-watch" {
				removed := false
				f.l.parentWatchRead = func(fd int, buf []byte) (int, error) {
					if !removed {
						removed = true
						for wd := range f.l.parentWatch.dirs {
							_, e := unix.InotifyRmWatch(fd, uint32(wd))
							must(t, e)
						}
					}
					return unix.Read(fd, buf)
				}
			} else {
				masks := map[string]uint32{"ignored": unix.IN_IGNORED, "deleted": unix.IN_DELETE_SELF, "moved": unix.IN_MOVE_SELF, "unmounted": unix.IN_UNMOUNT}
				reason = map[string]string{"ignored": "PARENT_WATCH_IGNORED", "deleted": "PARENT_WATCH_DELETE_SELF", "moved": "PARENT_WATCH_MOVE_SELF", "unmounted": "PARENT_WATCH_UNMOUNT"}[variant]
				injectParentEvent(f, masks[variant])
			}
			assertParentFailure(t, f, reason)
		})
	}
}

// Claim: EMFILE at init or ENOSPC when adding a watch fails retry comparison despite an otherwise allowed snapshot chain.
func TestLedgerReusedParentUnarmedViolation(t *testing.T) {
	for _, variant := range []string{"init-emfile", "add-enospc"} {
		t.Run(variant, func(t *testing.T) {
			f := newParentFixture(t, true, false)
			f.create(t)
			_, _, e := f.compare(t)
			must(t, e)
			if variant == "init-emfile" {
				f.l.parentWatchInit = func(int) (int, error) { return -1, unix.EMFILE }
			} else {
				f.l.parentWatchAdd = func(int, string, uint32) (int, error) { return -1, unix.ENOSPC }
			}
			assertParentFailure(t, f, "PARENT_WATCH_UNARMED")
			absent(t, f.child)
		})
	}
}

// Claim: failed arming during creation stops before the intent hook and first filesystem effect, so there is no late-armed interval.
func TestLedgerReusedParentArmedBeforeFirstEffect(t *testing.T) {
	f := newParentFixture(t, true, false)
	called := false
	f.l.afterIntent = func(Action) error { called = true; return nil }
	f.l.parentWatchAdd = func(int, string, uint32) (int, error) { return -1, unix.ENOSPC }
	e := f.l.CreateFS(f.child, f.foreign, "file", "remove", uint32(os.Geteuid()), uint32(os.Getegid()), 0600)
	code(t, e, 1)
	if !strings.Contains(e.Error(), "PARENT_WATCH_UNARMED") || called || len(f.l.rows) != 1 {
		t.Fatalf("effect before arming: called=%v rows=%d err=%v", called, len(f.l.rows), e)
	}
	absent(t, f.child)
}

// Claim: fd errors, EOF, short headers/payloads and malformed names fail replay with named violations; EINTR retries the real fd.
func TestLedgerReusedParentEventReadViolation(t *testing.T) {
	for _, variant := range []string{"eio", "ebadf", "eof", "short-header", "short-name", "bad-name", "nul-padding", "unknown-watch", "zero-mask", "eintr-control"} {
		t.Run(variant, func(t *testing.T) {
			f := newParentFixture(t, true, false)
			f.create(t)
			injected := false
			f.l.parentWatchRead = func(fd int, buf []byte) (int, error) {
				if injected {
					return unix.Read(fd, buf)
				}
				injected = true
				wd := 0
				for key := range f.l.parentWatch.dirs {
					wd = key
					break
				}
				switch variant {
				case "eio":
					return -1, unix.EIO
				case "ebadf":
					return -1, unix.EBADF
				case "eof":
					return 0, nil
				case "eintr-control":
					return -1, unix.EINTR
				case "short-header":
					return copy(buf, []byte{1}), nil
				case "short-name":
					raw := plantedParentEvent(wd, unix.IN_CREATE, nil)
					binary.NativeEndian.PutUint32(raw[12:], 8)
					return copy(buf, raw), nil
				case "bad-name":
					return copy(buf, plantedParentEvent(wd, unix.IN_CREATE, []byte("../x\x00"))), nil
				case "nul-padding":
					return copy(buf, plantedParentEvent(wd, unix.IN_CREATE, []byte("x\x00y\x00"))), nil
				case "unknown-watch":
					return copy(buf, plantedParentEvent(-2, unix.IN_CREATE, nil)), nil
				default:
					return copy(buf, plantedParentEvent(wd, 0, nil)), nil
				}
			}
			if variant == "eintr-control" {
				_, _, e := f.compare(t)
				must(t, e)
				return
			}
			reasons := map[string]string{"eio": "PARENT_EVENTS:", "ebadf": "PARENT_EVENTS:", "eof": "PARENT_EVENTS_EOF", "short-header": "PARENT_EVENTS_TRUNCATED", "short-name": "PARENT_EVENTS_TRUNCATED", "bad-name": "PARENT_EVENTS_MALFORMED", "nul-padding": "PARENT_EVENTS_MALFORMED", "unknown-watch": "PARENT_EVENTS_UNKNOWN_WATCH", "zero-mask": "PARENT_EVENTS_MALFORMED"}
			assertParentFailure(t, f, reasons[variant])
		})
	}
}

// Claim: named allowed-path events cannot bridge a real timestamp gap between sealed snapshots.
func TestLedgerReusedParentEventsCannotBridgeSnapshotGap(t *testing.T) {
	f := newParentFixture(t, true, false)
	f.create(t)
	p := filepath.Join(f.parent, "gap")
	must(t, os.WriteFile(p, nil, 0600))
	must(t, os.Remove(p))
	assertParentFailure(t, f, "unrecorded-parent-transition")
}

// Claim: even allowed-path events cannot authorize timestamp changes when the sealed snapshots show no corresponding entry transition.
func TestLedgerReusedParentEventsCannotInventCause(t *testing.T) {
	f := newParentFixture(t, true, false)
	f.create(t)
	_, _, e := f.compare(t)
	must(t, e)
	for _, row := range f.l.rows {
		if row.Body.Op == "commit" {
			for j := range row.Body.Result.Parents {
				r := &row.Body.Result.Parents[j]
				r.After.Children = append([]DirectoryEntry(nil), r.Before.Children...)
				r.Events = []ParentEvent{{Path: f.child, Mask: unix.IN_CREATE}}
			}
		}
	}
	var out bytes.Buffer
	f.l.output = &out
	e = f.l.compareBaseline("rehearsal")
	code(t, e, 1)
	r := parentRow(t, comparisonRows(t, &out), f.parent)
	if r.Verdict != "VIOLATION" || r.Rule != "parent-snapshot-intent-mismatch" {
		t.Fatalf("events invented cause: %+v", r)
	}
}

// Claim: a recorded child cycle cannot authorize timestamp drift on an undeclared reused parent.
func TestLedgerReusedParentRequiresDeclaration(t *testing.T) {
	f := newParentFixture(t, false, false)
	f.l.entryCheck = func(string) error { return nil } // Exercise the independent final compare backstop.
	f.create(t)
	rows, total, e := f.compare(t)
	code(t, e, 1)
	r := parentRow(t, rows, f.parent)
	if r.Type != "unlisted_difference" || r.Verdict != "VIOLATION" || r.Rule != "parent-not-declared-reused" || total.Unlisted != 1 || total.ParentViolations != 1 || total.ReusedParentChanges != 0 {
		t.Fatalf("undeclared parent accepted: %+v %+v", r, total)
	}
}

// Claim: an unrecorded create/delete inside the recorded creator interval remains a violation even after the original entry set is restored.
func TestLedgerReusedParentRejectsUnrecordedEntryDuringCreate(t *testing.T) {
	for _, removeExisting := range []bool{false, true} {
		t.Run(map[bool]string{false: "created-removed", true: "removed-restored"}[removeExisting], func(t *testing.T) {
			f := newParentFixture(t, true, false)
			unknown := filepath.Join(f.parent, "unrecorded")
			f.l.afterIntent = func(Action) error {
				if removeExisting {
					data, e := os.ReadFile(f.foreign)
					if e != nil {
						return e
					}
					if e = os.Remove(f.foreign); e != nil {
						return e
					}
					return os.WriteFile(f.foreign, data, 0600)
				}
				if e := os.WriteFile(unknown, nil, 0600); e != nil {
					return e
				}
				return os.Remove(unknown)
			}
			f.create(t)
			rows, total, e := f.compare(t)
			code(t, e, 1)
			r := parentRow(t, rows, f.parent)
			if r.Type != "unlisted_difference" || !strings.HasPrefix(r.Rule, "unrecorded-parent-entry:") || total.ParentViolations != 1 || total.ReusedParentChanges != 0 {
				t.Fatalf("unrecorded entry accepted: %+v %+v", r, total)
			}
		})
	}
}

// Claim: transient unrecorded entry cycles before, between, or after sealed command intervals cannot be laundered by a later recorded child.
func TestLedgerReusedParentRejectsUnrecordedGap(t *testing.T) {
	for _, when := range []string{"before-create", "before-replay", "after-replay"} {
		t.Run(when, func(t *testing.T) {
			f := newParentFixture(t, true, false)
			churn := func() {
				p := filepath.Join(f.parent, "unrecorded")
				must(t, os.WriteFile(p, nil, 0600))
				must(t, os.Remove(p))
			}
			if when == "before-create" {
				churn()
			}
			f.create(t)
			if when == "before-replay" {
				churn()
			}
			if when == "after-replay" {
				_, _, e := f.compare(t)
				must(t, e)
				churn()
			}
			rows, total, e := f.compare(t)
			code(t, e, 1)
			r := parentRow(t, rows, f.parent)
			if r.Rule != "unrecorded-parent-transition" || total.ParentViolations != 1 {
				t.Fatalf("gap accepted: %+v %+v", r, total)
			}
		})
	}
}

// Claim: mode, inode and entry-set changes on real reused directories violate baseline invariants after rollback.
func TestLedgerReusedParentRejectsInvariantDrift(t *testing.T) {
	for _, variant := range []string{"mode", "inode", "entries"} {
		t.Run(variant, func(t *testing.T) {
			f := newParentFixture(t, true, false)
			f.create(t)
			switch variant {
			case "mode":
				must(t, os.Chmod(f.parent, 0750))
			case "inode":
				must(t, os.Rename(f.parent, f.parent+"-old"))
				must(t, os.Mkdir(f.parent, 0700))
				must(t, os.Link(filepath.Join(f.parent+"-old", "foreign"), f.foreign))
				must(t, os.Remove(filepath.Join(f.parent+"-old", "foreign")))
			case "entries":
				must(t, os.WriteFile(filepath.Join(f.parent, "unknown"), nil, 0600))
			}
			rows, total, e := f.compare(t)
			code(t, e, 1)
			r := parentRow(t, rows, f.parent)
			if r.Rule != "reused-parent-baseline-invariant" || total.ParentViolations != 1 || total.ReusedParentChanges != 0 {
				t.Fatalf("invariant accepted: %+v %+v", r, total)
			}
		})
	}
}

// Claim: owner/group and directory-size differences are rejected against a real directory snapshot; synthetic baseline deltas avoid privileged chown or filesystem-specific shrinking assumptions.
func TestLedgerReusedParentRejectsOwnerAndSize(t *testing.T) {
	for _, field := range []string{"uid", "gid", "size"} {
		t.Run(field, func(t *testing.T) {
			f := newParentFixture(t, true, false)
			f.create(t)
			_, _, e := f.compare(t)
			must(t, e)
			for j := range f.l.rows[0].Body.Genesis.S0 {
				base := &f.l.rows[0].Body.Genesis.S0[j]
				if base.Name != f.parent {
					continue
				}
				switch field {
				case "uid":
					base.Identity.FS.UID++
				case "gid":
					base.Identity.FS.GID++
				case "size":
					base.Metadata.Size++
				}
			}
			var out bytes.Buffer
			f.l.output = &out
			e = f.l.compareBaseline("rehearsal")
			code(t, e, 1)
			r := parentRow(t, comparisonRows(t, &out), f.parent)
			if r.Rule != "reused-parent-baseline-invariant" {
				t.Fatalf("%s accepted: %+v", field, r)
			}
		})
	}
}

// Claim: an unused reuse declaration is refused by its exact name without inventing a parent change.
func TestLedgerReusedParentUntouched(t *testing.T) {
	f := newParentFixture(t, true, false)
	rows, total, e := f.compare(t)
	code(t, e, 1)
	if len(rows) != 1 || rows[0].Object != "path:"+f.parent || rows[0].Rule != "reused-parent-not-touched" || total.ReusedParentChanges != 0 || total.ParentViolations != 0 || total.Unlisted != 1 {
		t.Fatalf("untouched changed: %+v %+v", rows, total)
	}
}

// Claim: ctime-only drift of a foreign file is rejected even with a recorded sibling cycle and unchanged content, mode, inode, size and mtime.
func TestLedgerForeignFileCtimeViolation(t *testing.T) {
	f := newParentFixture(t, true, false)
	f.create(t)
	var before, after unix.Stat_t
	must(t, unix.Stat(f.foreign, &before))
	time.Sleep(2 * time.Millisecond)
	must(t, os.Chmod(f.foreign, 0640))
	must(t, os.Chmod(f.foreign, 0600))
	must(t, unix.Stat(f.foreign, &after))
	if before.Ctim == after.Ctim || before.Mtim != after.Mtim || before.Ino != after.Ino || before.Size != after.Size || before.Mode != after.Mode {
		t.Fatal("invalid ctime-only control")
	}
	rows, total, e := f.compare(t)
	code(t, e, 1)
	found := false
	for _, r := range rows {
		if r.Object == "path:"+f.foreign && r.Type == "unlisted_difference" {
			found = true
		}
	}
	if !found || total.Unlisted != 1 || total.ReusedParentChanges != 1 {
		t.Fatalf("foreign ctime ignored: %+v %+v", rows, total)
	}
}

// Claim: a real read changing only atime on a metadata-only file is ignored; ctime/mtime and the parent remain unchanged.
func TestLedgerAtimeOnlyIgnored(t *testing.T) {
	f := newParentFixture(t, false, true)
	var before, after unix.Stat_t
	must(t, unix.Stat(f.foreign, &before))
	_, e := os.ReadFile(f.foreign)
	must(t, e)
	must(t, unix.Stat(f.foreign, &after))
	if before.Atim == after.Atim || before.Ctim != after.Ctim || before.Mtim != after.Mtim {
		t.Fatal("invalid atime-only control")
	}
	rows, total, e := f.compare(t)
	must(t, e)
	if len(rows) != 0 || total.Unlisted != 0 || total.ReusedParentChanges != 0 {
		t.Fatalf("atime counted: %+v %+v", rows, total)
	}
}

// Claim: init requires an explicit reused array and refuses duplicate, relative, missing, non-directory and symlink entries without creating a ledger.
func TestLedgerReusedInputRequired(t *testing.T) {
	for _, variant := range []string{"omitted", "null", "duplicate", "relative", "absent", "file", "symlink", "valid-empty", "valid"} {
		t.Run(variant, func(t *testing.T) {
			f := newParentFixture(t, true, false)
			scope := Scope{Users: []string{}, Groups: []string{}, Units: []string{}, Reused: []string{f.parent}, Paths: []ScopePath{{Path: f.child, Kind: "file"}}}
			switch variant {
			case "null":
				scope.Reused = nil
			case "duplicate":
				scope.Reused = append(scope.Reused, f.parent)
			case "relative":
				scope.Reused = []string{"relative"}
			case "absent":
				scope.Reused = []string{f.parent + "-missing"}
			case "file":
				scope.Reused = []string{f.foreign}
			case "symlink":
				p := filepath.Join(filepath.Dir(f.parent), "alias")
				must(t, os.Symlink(f.parent, p))
				scope.Reused = []string{p}
			case "valid-empty":
				scope.Reused = []string{}
			}
			root := filepath.Dir(f.parent)
			dir := filepath.Join(root, "second-ledger")
			raw, e := json.Marshal(scope)
			must(t, e)
			if variant == "omitted" {
				var fields map[string]json.RawMessage
				must(t, json.Unmarshal(raw, &fields))
				delete(fields, "reused")
				raw, e = json.Marshal(fields)
				must(t, e)
			}
			input := filepath.Join(root, "scope.json")
			must(t, os.WriteFile(input, raw, 0600))
			e = Run([]string{"init", "-dir", dir, "-manifest", filepath.Join(root, "manifest.json"), "-baseline", filepath.Join(root, "baseline"), "-purpose", "rehearsal", "-scope", input}, newSystem(), &bytes.Buffer{})
			if strings.HasPrefix(variant, "valid") {
				must(t, e)
			} else {
				code(t, e, 1)
				want := map[string]string{"omitted": "REUSED_SET_REQUIRED", "null": "SCOPE_SCHEMA", "duplicate": "REUSED_PATH_INVALID_OR_DUPLICATE", "relative": "REUSED_PATH_INVALID_OR_DUPLICATE", "absent": "REUSED_NOT_BASELINE_DIRECTORY", "file": "REUSED_DIRECTORY_LOOKUP", "symlink": "REUSED_DIRECTORY_LOOKUP"}[variant]
				if !strings.Contains(e.Error(), want) {
					t.Fatalf("want %s, got %v", want, e)
				}
				absent(t, dir)
			}
		})
	}
}

// Claim: ctime-only directory drift has no blanket reuse exception, even when mode and the entry set return to baseline.
func TestLedgerReusedParentCtimeOnlyViolation(t *testing.T) {
	f := newParentFixture(t, true, false)
	var before, after unix.Stat_t
	must(t, unix.Stat(f.parent, &before))
	time.Sleep(2 * time.Millisecond)
	must(t, os.Chmod(f.parent, 0750))
	must(t, os.Chmod(f.parent, 0700))
	must(t, unix.Stat(f.parent, &after))
	if before.Ctim == after.Ctim || before.Mtim != after.Mtim || before.Mode != after.Mode || before.Size != after.Size || before.Ino != after.Ino {
		t.Fatal("invalid parent ctime-only control")
	}
	rows, total, e := f.compare(t)
	code(t, e, 1)
	r := parentRow(t, rows, f.parent)
	if r.Rule != "unrecorded-parent-transition" || total.ParentViolations != 1 {
		t.Fatalf("parent ctime ignored: %+v %+v", r, total)
	}
}

// Claim: a removal lacking its sealed reversal receipt remains unexplained on retry; committed child identity alone never invents history.
func TestLedgerReusedParentMissingReplayReceipt(t *testing.T) {
	f := newParentFixture(t, true, false)
	f.create(t)
	must(t, os.Remove(f.child))
	f.l.Close()
	var e error
	f.l, e = Open(f.l.root, newSystem())
	must(t, e)
	defer f.l.Close()
	rows, total, e := f.compare(t)
	code(t, e, 1)
	r := parentRow(t, rows, f.parent)
	if r.Rule != "unrecorded-parent-transition" || total.ParentViolations != 1 {
		t.Fatalf("missing receipt accepted: %+v %+v", r, total)
	}
}
