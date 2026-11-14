package g2ledger

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

// Each command watches its mutation interval. Sealed before/after receipts join
// those intervals to S0; timestamp gaps are unexplained, even if names vanished.
type parentWatch struct {
	fd        int
	dirs      map[int]BaselineObject
	temporary []string
	names     []string
}

func (l *Ledger) startParentWatch(a Action, ids []Identity) (err error) {
	l.closeParentWatch()
	paths := append([]string(nil), a.Paths...)
	if a.Kind == "unit" && len(ids) == 0 {
		plan, e := expectedUnitInstall(l.sys, a.Name)
		if e != nil {
			return stopped("PARENT_UNIT_PLAN", e)
		}
		for _, link := range plan.Missing {
			paths = append(paths, link.Path)
		}
	}
	for _, id := range ids {
		if id.Unit != nil {
			for _, link := range id.Unit.Links {
				paths = append(paths, link.Path)
			}
		}
	}
	parents := map[string]bool{}
	for _, path := range paths {
		parents[filepath.Dir(path)] = true
	}
	w := &parentWatch{fd: -1, dirs: map[int]BaselineObject{}}
	l.parentWatch = w
	for _, base := range l.rows[0].Body.Genesis.S0 {
		if parents[base.Name] && base.Identity != nil && base.Identity.FS != nil && base.Identity.FS.Type == "dir" {
			w.names = append(w.names, base.Name)
		}
	}
	defer func() {
		if err != nil {
			err = &parentEvidenceFailure{err, w.names}
			l.closeParentWatch()
		}
	}()
	for _, base := range l.rows[0].Body.Genesis.S0 {
		if !parents[base.Name] || base.Identity == nil || base.Identity.FS == nil || base.Identity.FS.Type != "dir" {
			continue
		}
		if w.fd < 0 {
			init := unix.InotifyInit1
			if l.parentWatchInit != nil {
				init = l.parentWatchInit
			}
			fd, e := init(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
			if e != nil {
				return stopped("PARENT_WATCH_UNARMED", e)
			}
			w.fd = fd
		}
		d, e := openDir(base.Name)
		if e != nil {
			return stopped("PARENT_WATCH_UNARMED "+base.Name, e)
		}
		add := unix.InotifyAddWatch
		if l.parentWatchAdd != nil {
			add = l.parentWatchAdd
		}
		wd, e := add(w.fd, fmt.Sprintf("/proc/self/fd/%d", d.Fd()), unix.IN_CREATE|unix.IN_DELETE|unix.IN_MOVED_FROM|unix.IN_MOVED_TO|unix.IN_ATTRIB|unix.IN_DELETE_SELF|unix.IN_MOVE_SELF|unix.IN_UNMOUNT|unix.IN_ONLYDIR)
		d.Close()
		if e != nil {
			return stopped("PARENT_WATCH_UNARMED "+base.Name, e)
		}
		before, e := snapshotObject(base, l.sys, l.root, l.rows[0].Body.Genesis.Baseline)
		if e != nil {
			return stopped("PARENT_SNAPSHOT "+base.Name, e)
		}
		w.dirs[wd] = before
	}
	return nil
}
func (l *Ledger) closeParentWatch() {
	if l.parentWatch != nil && l.parentWatch.fd >= 0 {
		unix.Close(l.parentWatch.fd)
	}
	l.parentWatch = nil
}
func (l *Ledger) finishParentWatch() (out []ParentReceipt, err error) {
	w := l.parentWatch
	if w == nil {
		return nil, fail(1, "PARENT_WATCH_UNARMED")
	}
	defer func() {
		if err != nil {
			err = &parentEvidenceFailure{err, w.names}
		}
		l.closeParentWatch()
	}()
	if len(w.names) > 0 && (w.fd < 0 || len(w.dirs) != len(w.names)) {
		return nil, fail(1, "PARENT_WATCH_UNARMED")
	}
	receipts := map[int]*ParentReceipt{}
	for wd, before := range w.dirs {
		after, e := snapshotObject(before, l.sys, l.root, l.rows[0].Body.Genesis.Baseline)
		if e != nil {
			return nil, stopped("PARENT_SNAPSHOT "+before.Name, e)
		}
		receipts[wd] = &ParentReceipt{Before: before, After: after, Events: []ParentEvent{}}
		for _, path := range w.temporary {
			if filepath.Dir(path) == before.Name {
				receipts[wd].Temporary = append(receipts[wd].Temporary, path)
			}
		}
	}
	buf := make([]byte, 64*1024)
	for w.fd >= 0 {
		read := unix.Read
		if l.parentWatchRead != nil {
			read = l.parentWatchRead
		}
		n, e := read(w.fd, buf)
		if n <= 0 && errors.Is(e, unix.EAGAIN) {
			break
		}
		if errors.Is(e, unix.EINTR) {
			continue
		}
		if e != nil {
			return nil, stopped("PARENT_EVENTS", e)
		}
		if n < 0 || n > len(buf) {
			return nil, fail(1, "PARENT_EVENTS_INVALID_READ")
		}
		if n == 0 {
			return nil, fail(1, "PARENT_EVENTS_EOF")
		}
		for offset := 0; offset < n; {
			if n-offset < unix.SizeofInotifyEvent {
				return nil, fail(1, "PARENT_EVENTS_TRUNCATED")
			}
			wd := int(int32(binary.NativeEndian.Uint32(buf[offset:])))
			mask := binary.NativeEndian.Uint32(buf[offset+4:])
			length := uint64(binary.NativeEndian.Uint32(buf[offset+12:]))
			if length > uint64(n-offset-unix.SizeofInotifyEvent) {
				return nil, fail(1, "PARENT_EVENTS_TRUNCATED")
			}
			end := offset + unix.SizeofInotifyEvent + int(length)
			rawName := buf[offset+unix.SizeofInotifyEvent : end]
			name := ""
			if length > 0 {
				nul := bytes.IndexByte(rawName, 0)
				if nul <= 0 || bytes.IndexAny(rawName[:nul], "/") >= 0 || string(rawName[:nul]) == "." || string(rawName[:nul]) == ".." || len(bytes.Trim(rawName[nul:], "\x00")) != 0 {
					return nil, fail(1, "PARENT_EVENTS_MALFORMED")
				}
				name = string(rawName[:nul])
			}
			if mask&unix.IN_Q_OVERFLOW != 0 {
				return nil, fail(1, "PARENT_EVENTS_OVERFLOW")
			}
			if mask&unix.IN_IGNORED != 0 {
				return nil, fail(1, "PARENT_WATCH_IGNORED")
			}
			if mask&unix.IN_DELETE_SELF != 0 {
				return nil, fail(1, "PARENT_WATCH_DELETE_SELF")
			}
			if mask&unix.IN_MOVE_SELF != 0 {
				return nil, fail(1, "PARENT_WATCH_MOVE_SELF")
			}
			if mask&unix.IN_UNMOUNT != 0 {
				return nil, fail(1, "PARENT_WATCH_UNMOUNT")
			}
			if mask == 0 {
				return nil, fail(1, "PARENT_EVENTS_MALFORMED")
			}
			if r := receipts[wd]; r != nil {
				// Child chmod/write metadata does not mutate the directory entry set.
				if name == "" || mask & ^uint32(unix.IN_ATTRIB|unix.IN_ISDIR) != 0 {
					r.Events = append(r.Events, ParentEvent{Path: filepath.Join(r.Before.Name, name), Mask: mask})
				}
			} else {
				return nil, fail(1, "PARENT_EVENTS_UNKNOWN_WATCH")
			}
			offset = end
		}
	}
	out = make([]ParentReceipt, 0, len(receipts))
	for _, r := range receipts {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Before.Name < out[j].Before.Name })
	return out, nil
}

func baselineEqual(a, b BaselineObject) bool { return bytes.Equal(canonical(a), canonical(b)) }
func parentStable(a, b BaselineObject) bool {
	return bytes.Equal(canonical(a.Identity), canonical(b.Identity)) && a.Metadata != nil && b.Metadata != nil && a.Metadata.Size == b.Metadata.Size && bytes.Equal(canonical(a.Children), canonical(b.Children))
}

type ParentCause struct {
	Intent uint64 `json:"intent"`
	Object string `json:"object"`
}

// parentExplanation requires an unbroken chain of recorded entry transitions;
// declaring reuse alone, or a child receipt alone, never excuses timestamp drift.
func (l *Ledger) parentExplanation(base, now BaselineObject) ([]ParentCause, string) {
	reused := false
	for _, path := range l.rows[0].Body.Genesis.Scope.Reused {
		if path == base.Name {
			reused = true
		}
	}
	if !reused {
		return nil, "parent-not-declared-reused"
	}
	if !parentStable(base, now) {
		return nil, "reused-parent-baseline-invariant"
	}
	expected := base
	causes := []ParentCause{}
	seen := map[string]bool{}
	for _, row := range l.rows {
		var receipts []ParentReceipt
		var intent uint64
		var result *Result
		if row.Body.Op == "commit" {
			result = row.Body.Result
			receipts = row.Body.Result.Parents
			intent = row.Body.Result.Intent
		}
		if row.Body.Op == "parent-replay" {
			receipts = row.Body.ParentReplay.Parents
			result = l.rows[row.Body.ParentReplay.Commit].Body.Result
			intent = result.Intent
		}
		for _, r := range receipts {
			if r.Before.Name != base.Name {
				continue
			}
			if !baselineEqual(expected, r.Before) {
				return nil, "unrecorded-parent-transition"
			}
			a := l.rows[intent].Body.Action
			allowed := map[string]bool{}
			for _, path := range a.Paths {
				allowed[path] = true
			}
			for _, path := range r.Temporary {
				allowed[path] = true
			}
			for _, id := range result.Identities {
				if id.Unit != nil {
					for _, link := range id.Unit.Links {
						allowed[link.Path] = true
					}
				}
			}
			// Events can veto this independently justified transition, never supply a cause.
			objects, reason := parentSnapshotCauses(r, *a, result.Identities, row.Body.Op == "parent-replay")
			if reason != "" {
				return nil, reason
			}
			for _, event := range r.Events {
				if !allowed[event.Path] || event.Path == base.Name || event.Mask & ^uint32(unix.IN_CREATE|unix.IN_DELETE|unix.IN_MOVED_FROM|unix.IN_MOVED_TO|unix.IN_ISDIR) != 0 {
					return nil, "unrecorded-parent-entry:" + event.Path
				}
			}
			for _, path := range objects {
				key := fmt.Sprintf("%d:%s", intent, path)
				if !seen[key] {
					causes = append(causes, ParentCause{Intent: intent, Object: path})
					seen[key] = true
				}
			}
			expected = r.After
		}
	}
	if !baselineEqual(expected, now) {
		return nil, "unrecorded-parent-transition"
	}
	if len(causes) == 0 {
		return nil, "parent-change-without-ledger-cause"
	}
	return causes, "allowed-named-reused-parent"
}

// Only sealed snapshot entry deltas matching the recorded operation justify
// directory timestamp changes. Atomic modify is an explicit replacement intent.
func parentSnapshotCauses(r ParentReceipt, a Action, ids []Identity, replay bool) ([]string, string) {
	if !bytes.Equal(canonical(r.Before.Identity), canonical(r.After.Identity)) || r.After.Metadata == nil {
		return nil, "parent-interval-invariant"
	}
	before, after := map[string]uint32{}, map[string]uint32{}
	for _, e := range r.Before.Children {
		before[e.Name] = e.Type
	}
	for _, e := range r.After.Children {
		after[e.Name] = e.Type
	}
	expected := map[string]uint32{}
	for name, kind := range before {
		expected[name] = kind
	}
	causes := []string{}
	apply := func(path string, kind uint32) bool {
		if filepath.Dir(path) != r.Before.Name {
			return true
		}
		name := filepath.Base(path)
		if replay {
			if expected[name] != 0 && after[name] == 0 {
				delete(expected, name)
				causes = append(causes, path)
			}
		} else {
			if expected[name] != 0 || after[name] != kind {
				return false
			}
			expected[name] = kind
			causes = append(causes, path)
		}
		return true
	}
	for _, id := range ids {
		if id.FS != nil && a.Kind != "modify" {
			kind := uint32(unix.S_IFREG)
			if id.FS.Type == "dir" {
				kind = unix.S_IFDIR
			}
			if !apply(id.Path, kind) {
				return nil, "parent-snapshot-intent-mismatch"
			}
		}
		if id.Unit != nil {
			for _, link := range id.Unit.Links {
				if !apply(link.Path, unix.S_IFLNK) {
					return nil, "parent-snapshot-intent-mismatch"
				}
			}
		}
	}
	if len(expected) != len(after) {
		return nil, "parent-snapshot-intent-mismatch"
	}
	for name, kind := range after {
		if expected[name] != kind {
			return nil, "parent-snapshot-intent-mismatch"
		}
	}
	if a.Kind == "modify" && len(a.Paths) == 1 && filepath.Dir(a.Paths[0]) == r.Before.Name && before[filepath.Base(a.Paths[0])] == unix.S_IFREG && after[filepath.Base(a.Paths[0])] == unix.S_IFREG && !baselineEqual(r.Before, r.After) {
		causes = append(causes, a.Paths[0])
	}
	if !baselineEqual(r.Before, r.After) && len(causes) == 0 {
		return nil, "parent-change-without-ledger-cause"
	}
	return causes, ""
}

// A watch-health failure aborts the operation/compare, with no ALLOWED rows.
// Its summary covers only the affected parents; no successful full compare is claimed.
type parentEvidenceFailure struct {
	err     error
	parents []string
}

func (e *parentEvidenceFailure) Error() string { return e.err.Error() }
func (e *parentEvidenceFailure) Unwrap() error { return e.err }
func (l *Ledger) reportParentFailure(err error, mode string) error {
	var failure *parentEvidenceFailure
	if !errors.As(err, &failure) {
		return err
	}
	out, summary := l.output, l.summary
	if out == nil {
		out = io.Discard
	}
	if summary == nil {
		summary = io.Discard
	}
	enc := json.NewEncoder(out)
	reason := failure.err.Error()
	var named *Failure
	if errors.As(failure.err, &named) {
		reason = named.Reason
	}
	for _, name := range failure.parents {
		if e := enc.Encode(CompareRow{Verdict: "VIOLATION", Type: "unlisted_difference", Object: "path:" + name, Difference: "parent-metadata", Mode: mode, Rule: reason}); e != nil {
			return stopped("COMPARE_OUTPUT", e)
		}
	}
	n := len(failure.parents)
	if e := enc.Encode(CompareSummary{Type: "baseline_summary", Mode: mode, Compared: n, Unlisted: n, ParentViolations: n, ExcludedVolatile: []string{"/run"}}); e != nil {
		return stopped("COMPARE_OUTPUT", e)
	}
	if _, e := fmt.Fprintf(summary, "g2-ledger: BASELINE_COMPARE_ABORTED mode=%s compared=%d unlisted=%d reused_parent_changes=0 parent_violations=%d reason=%s\n", mode, n, n, n, failure.err); e != nil {
		return stopped("COMPARE_SUMMARY", e)
	}
	return err
}

func validateParentReceipts(receipts []ParentReceipt, a Action) error {
	previous := ""
	for _, r := range receipts {
		name := r.Before.Name
		if name <= previous || r.After.Name != name || r.Before.Kind != r.After.Kind || r.Before.Identity == nil || r.Before.Identity.FS == nil || r.Before.Identity.FS.Type != "dir" || r.Before.Metadata == nil || r.Events == nil {
			return errors.New("PARENT_RECEIPT_SCHEMA")
		}
		previous = name
		for _, snapshot := range []BaselineObject{r.Before, r.After} {
			if snapshot.Kind != "dir" && snapshot.Kind != "tree" || len(snapshot.Members) != 0 {
				return errors.New("PARENT_RECEIPT_KIND")
			}
			if snapshot.Identity == nil {
				if snapshot.Metadata != nil || len(snapshot.Children) != 0 {
					return errors.New("PARENT_RECEIPT_ABSENT")
				}
				continue
			}
			if snapshot.Identity.Path != name || validateIdentity(*snapshot.Identity, snapshot.Kind) != nil || snapshot.Metadata == nil || snapshot.Metadata.Size < 0 {
				return errors.New("PARENT_RECEIPT_IDENTITY")
			}
			prev := ""
			for _, entry := range snapshot.Children {
				if entry.Name <= prev || entry.Name == "." || entry.Name == ".." || strings.ContainsAny(entry.Name, "/\x00") || entry.Type == 0 || entry.Type & ^uint32(unix.S_IFMT) != 0 {
					return errors.New("PARENT_RECEIPT_CHILD")
				}
				prev = entry.Name
			}
		}
		for _, path := range r.Temporary {
			if a.Kind != "modify" || filepath.Dir(path) != name || !strings.HasPrefix(filepath.Base(path), ".g2-ledger-") || !isHex(strings.TrimPrefix(filepath.Base(path), ".g2-ledger-"), 16) {
				return errors.New("PARENT_TEMPORARY_SCHEMA")
			}
		}
		for _, event := range r.Events {
			if !validPath(event.Path) || event.Path != name && filepath.Dir(event.Path) != name || event.Mask == 0 {
				return errors.New("PARENT_EVENT_SCHEMA")
			}
		}
	}
	return nil
}
