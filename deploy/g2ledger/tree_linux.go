package g2ledger

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// CreateTree creates only the empty root. Workload writers must start after
// this call commits, and use this attempt's dedicated, non-login account.
func (l *Ledger) CreateTree(path, owner, ret string, mode uint32, sockets []string) error {
	account, _, e := lookup(l.sys, "user", owner)
	if e != nil {
		return stopped("TREE_OWNER_LOOKUP "+owner, e)
	}
	if account == nil {
		return fail(1, "TREE_OWNER_MISSING "+owner)
	}
	sockets = append([]string(nil), sockets...)
	sort.Strings(sockets)
	a := Action{Kind: "tree", Ret: ret, Paths: []string{path}, UID: account.UID, GID: account.GID, Mode: mode, User: owner, Before: []Identity{{Account: account}}, Sockets: sockets}
	if e := validateAction(&a); e != nil {
		return stopped("TREE_ACTION", e)
	}
	if e := treeAuthority(a, l.rows); e != nil {
		return e
	}
	return l.createFS(a, "")
}

// processIDs enumerates the complete real process census, without reading
// status yet. Disappearing entries remain errors at the later checked read.
func processIDs() ([]string, error) {
	entries, e := os.ReadDir("/proc")
	if e != nil {
		return nil, e
	}
	pids := []string{}
	for _, entry := range entries {
		if _, e := strconv.ParseUint(entry.Name(), 10, 32); e == nil {
			pids = append(pids, entry.Name())
		}
	}
	return pids, nil
}

// scanOwnerProcesses is deliberately strict: even a disappearing process's
// unreadable status refuses this pass. Real/effective/saved IDs all count.
func scanOwnerProcesses(uid uint32, read func(string) ([]byte, error)) error {
	pids, e := processIDs()
	if e != nil {
		return fmt.Errorf("PROC_ENUM: %w", e)
	}
	return scanProcessUIDs(uid, pids, read)
}

// scanProcessUIDs reads real process and task status for every enumerated PID.
// The separate census seam lets non-root tests use a controlled set of real
// live processes, without mocking status reads or ignoring kernel errors.
func scanProcessUIDs(uid uint32, pids []string, read func(string) ([]byte, error)) error {
	if read == nil {
		read = os.ReadFile
	}
	for _, pid := range pids {
		if _, e := strconv.ParseUint(pid, 10, 32); e != nil {
			return errors.New("PROC_PID_SCHEMA")
		}
		paths := []string{"/proc/" + pid + "/status"}
		tasks, e := os.ReadDir("/proc/" + pid + "/task")
		if e != nil {
			return fmt.Errorf("PROC_READ pid=%s: %w", pid, e)
		}
		for _, task := range tasks {
			if _, e := strconv.ParseUint(task.Name(), 10, 32); e != nil {
				return errors.New("PROC_TASK_SCHEMA")
			}
			paths = append(paths, "/proc/"+pid+"/task/"+task.Name()+"/status")
		}
		for _, path := range paths {
			raw, e := read(path)
			if e != nil {
				return fmt.Errorf("PROC_READ pid=%s: %w", pid, e)
			}
			found := false
			for _, line := range bytes.Split(raw, []byte{'\n'}) {
				if !bytes.HasPrefix(line, []byte("Uid:")) {
					continue
				}
				if found {
					return errors.New("PROC_UID_DUPLICATE")
				}
				found = true
				fields := strings.Fields(string(line))
				if len(fields) != 5 {
					return errors.New("PROC_UID_SCHEMA")
				}
				for j, field := range fields[1:] {
					n, e := number(field)
					if e != nil {
						return errors.New("PROC_UID_SCHEMA")
					}
					if j < 3 && n == uid {
						return fmt.Errorf("LIVE_OWNER_PROCESS pid=%s", pid)
					}
				}
			}
			if !found {
				return errors.New("PROC_UID_MISSING")
			}
		}
	}
	return nil
}
func (l *Ledger) noTreeProcesses(uid uint32) error {
	if l.procUID != nil {
		uid = l.procUID(uid)
	}
	var e error
	if l.procPIDs == nil {
		e = scanOwnerProcesses(uid, l.procRead)
	} else {
		pids, err := l.procPIDs()
		if err != nil {
			return stopped("TREE_PROCESS_CHECK_PROC_ENUM", err)
		}
		e = scanProcessUIDs(uid, pids, l.procRead)
	}
	if e != nil {
		return stopped("TREE_PROCESS_CHECK", e)
	}
	return nil
}

// realTreeStat observes the link itself, never its target. Mount IDs detect
// same-device bind mounts as well as ordinary st_dev crossings. Unsupported
// statx/mount-ID lookup is a refusal, never permission to walk a mount.
func realTreeStat(dir *os.File, name string) (unix.Stat_t, uint64, error) {
	var st unix.Stat_t
	if e := unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); e != nil {
		return st, 0, e
	}
	var sx unix.Statx_t
	if e := unix.Statx(int(dir.Fd()), name, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_INO|unix.STATX_TYPE|unix.STATX_MNT_ID, &sx); e != nil {
		return st, 0, e
	}
	if sx.Mask&unix.STATX_MNT_ID == 0 || sx.Mnt_id == 0 || sx.Ino != st.Ino || uint32(sx.Mode)&unix.S_IFMT != st.Mode&unix.S_IFMT {
		return st, 0, errors.New("TREE_STAT_CHANGED_OR_MOUNT_ID_UNAVAILABLE")
	}
	return st, sx.Mnt_id, nil
}
func (l *Ledger) statTree(dir *os.File, name string) (unix.Stat_t, uint64, error) {
	if l.treeStat != nil {
		return l.treeStat(dir, name)
	}
	return realTreeStat(dir, name)
}

type treeEntry struct {
	parent         *os.File
	name, relative string
	stat           unix.Stat_t
	mount          uint64
	dir            *os.File // pinned for directories; never opened for a symlink
	children       []string
	deleted        bool
}
type treePlan struct {
	action  Action
	entries []*treeEntry // postorder: children before their parent
	parent  *os.File
}

func (p *treePlan) close() {
	for _, entry := range p.entries {
		if entry.dir != nil {
			entry.dir.Close()
		}
	}
	if p.parent != nil {
		p.parent.Close()
	}
}
func treeRootMatches(st unix.Stat_t, want Identity) bool {
	f := want.FS
	return f != nil && st.Dev == f.Dev && st.Ino == f.Ino && st.Mode&unix.S_IFMT == unix.S_IFDIR && st.Mode&07777 == f.Mode && st.Uid == f.UID && st.Gid == f.GID
}
func treeNames(dir *os.File) ([]string, error) {
	f, e := at(dir, ".", unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	names, e := f.Readdirnames(-1)
	sort.Strings(names)
	return names, e
}
func (l *Ledger) planTree(a Action, want Identity) (*treePlan, error) {
	d, n, e := parent(want.Path)
	if errors.Is(e, unix.ENOENT) {
		return nil, nil
	}
	if e != nil {
		return nil, stopped("TREE_PARENT", e)
	}
	p := &treePlan{action: a, parent: d}
	ok := false
	defer func() {
		if !ok {
			p.close()
		}
	}()
	root, mount, e := l.statTree(d, n)
	if errors.Is(e, unix.ENOENT) {
		ok = true
		p.close()
		return nil, nil
	}
	if e != nil {
		return nil, stopped("TREE_ROOT_LOOKUP", e)
	}
	if !treeRootMatches(root, want) {
		return nil, mismatch(a)
	}
	owner, _, e := lookup(l.sys, "user", a.User)
	if e != nil {
		return nil, stopped("TREE_OWNER_LOOKUP", e)
	}
	if owner == nil || !accountEqual(*owner, *a.Before[0].Account) {
		return nil, namedError("TREE_OWNER_CHANGED", a)
	}
	if e := l.noTreeProcesses(a.UID); e != nil {
		return nil, e
	}
	expected := map[string]bool{}
	for _, name := range a.Sockets {
		expected[name] = true
	}
	var walk func(*os.File, string, string, unix.Stat_t, uint64) error
	walk = func(parent *os.File, name, relative string, st unix.Stat_t, mid uint64) error {
		path := filepath.Join(want.Path, relative)
		if st.Dev != root.Dev || mid != mount {
			return fail(1, "TREE_CROSS_DEVICE_OR_MOUNT "+path)
		}
		if st.Uid != a.UID {
			return fail(1, "TREE_FOREIGN_OWNER "+path)
		}
		if st.Mode&06000 != 0 {
			return fail(1, "TREE_SETID "+path)
		}
		entry := &treeEntry{parent: parent, name: name, relative: relative, stat: st, mount: mid}
		switch st.Mode & unix.S_IFMT {
		case unix.S_IFREG:
			if st.Nlink != 1 {
				return fail(1, "TREE_HARDLINK "+path)
			}
		case unix.S_IFLNK:
			// Ownership is checked on the link. It is unlinked as a link; its target
			// is neither opened, statted nor granted deletion authority.
		case unix.S_IFSOCK:
			if !expected[relative] {
				return fail(1, "TREE_UNEXPECTED_SOCKET "+path)
			}
		case unix.S_IFDIR:
			f, e := at(parent, name, unix.O_RDONLY|unix.O_DIRECTORY, 0)
			if e != nil {
				return stopped("TREE_OPEN_DIRECTORY "+path, e)
			}
			entry.dir = f
			// Add now for failure cleanup; move after children once the walk succeeds.
			p.entries = append(p.entries, entry)
			var opened unix.Stat_t
			if e = unix.Fstat(int(f.Fd()), &opened); e != nil || !stableStat(opened, st) {
				return fail(1, "TREE_CHANGED "+path)
			}
			names, e := treeNames(f)
			if e != nil {
				return stopped("TREE_READ_DIRECTORY "+path, e)
			}
			entry.children = names
			for _, child := range names {
				childStat, childMount, e := l.statTree(f, child)
				if e != nil {
					return stopped("TREE_LOOKUP "+filepath.Join(path, child), e)
				}
				if e := walk(f, child, filepath.Join(relative, child), childStat, childMount); e != nil {
					return e
				}
			}
			// Remove the early cleanup slot and append in postorder.
			for j, v := range p.entries {
				if v == entry {
					p.entries = append(p.entries[:j], p.entries[j+1:]...)
					break
				}
			}
		default:
			return fail(1, "TREE_SPECIAL_FILE "+path)
		}
		p.entries = append(p.entries, entry)
		return nil
	}
	if e := walk(d, n, "", root, mount); e != nil {
		return nil, e
	}
	// Catch additions, removals and edits during phase 1 itself.
	if e := l.recheckTree(p); e != nil {
		return nil, e
	}
	ok = true
	return p, nil
}
func (l *Ledger) checkTreeEntry(p *treePlan, entry *treeEntry) error {
	st, mount, e := l.statTree(entry.parent, entry.name)
	path := filepath.Join(p.action.Paths[0], entry.relative)
	if e != nil {
		return stopped("TREE_RECHECK "+path, e)
	}
	if mount != entry.mount || !stableStat(st, entry.stat) {
		return fail(1, "TREE_CHANGED "+path)
	}
	if entry.dir != nil {
		var opened unix.Stat_t
		if e := unix.Fstat(int(entry.dir.Fd()), &opened); e != nil || !stableStat(opened, st) {
			return fail(1, "TREE_CHANGED "+path)
		}
		names, e := treeNames(entry.dir)
		if e != nil {
			return stopped("TREE_RECHECK_DIRECTORY "+path, e)
		}
		remaining := []string{}
		for _, name := range entry.children {
			removed := false
			for _, child := range p.entries {
				if child.parent == entry.dir && child.name == name {
					removed = child.deleted
					break
				}
			}
			if !removed {
				remaining = append(remaining, name)
			}
		}
		if !slices.Equal(names, remaining) {
			return fail(1, "TREE_CHANGED "+path)
		}
	}
	return nil
}
func (l *Ledger) recheckTree(p *treePlan) error {
	for _, entry := range p.entries {
		if !entry.deleted {
			if e := l.checkTreeEntry(p, entry); e != nil {
				return e
			}
		}
	}
	return nil
}
func (l *Ledger) deleteTree(p *treePlan) error {
	// Recheck the ENTIRE phase-1 list before the first unlink, then recheck each
	// target through its pinned parent immediately before deleting exactly it.
	if e := l.noTreeProcesses(p.action.UID); e != nil {
		return e
	}
	if e := l.recheckTree(p); e != nil {
		return e
	}
	for _, entry := range p.entries {
		if e := l.checkTreeEntry(p, entry); e != nil {
			return e
		}
		flags := 0
		if entry.dir != nil {
			flags = unix.AT_REMOVEDIR
		}
		if e := unix.Unlinkat(int(entry.parent.Fd()), entry.name, flags); e != nil {
			return stopped("TREE_UNLINK", e)
		}
		entry.deleted = true
		if e := l.syncPayload(entry.parent); e != nil {
			return stopped("TREE_UNLINK_SYNC", e)
		}
		// Our unlink changes parent mtime/ctime/nlink. Check its stable ownership,
		// inode and mode, then retain its observed post-unlink stat for the next
		// recheck. Namespace checks still require the exact remaining planned names.
		for _, ancestor := range p.entries {
			if ancestor.dir != entry.parent {
				continue
			}
			var st unix.Stat_t
			if e := unix.Fstat(int(ancestor.dir.Fd()), &st); e != nil {
				return stopped("TREE_PARENT_RECHECK", e)
			}
			old := ancestor.stat
			if st.Dev != old.Dev || st.Ino != old.Ino || st.Mode != old.Mode || st.Uid != old.Uid || st.Gid != old.Gid {
				return fail(1, "TREE_CHANGED_PARENT")
			}
			ancestor.stat = st
		}
	}
	return nil
}

func (l *Ledger) prepareTrees() error {
	l.treePlans = map[string]*treePlan{}
	for _, row := range l.rows {
		if row.Body.Op != "commit" {
			continue
		}
		a := *l.rows[row.Body.Result.Intent].Body.Action
		if a.Kind != "tree" {
			continue
		}
		if effect, _ := retentionPolicy(a.Kind, a.Ret, "rehearsal"); effect != "remove" {
			continue
		}
		plan, e := l.planTree(a, row.Body.Result.Identities[0])
		if e != nil {
			return e
		}
		if plan != nil {
			l.treePlans[a.Paths[0]] = plan
		}
	}
	if l.afterTreeVerify != nil {
		if e := l.afterTreeVerify(); e != nil {
			return stopped("TREE_PHASE_BOUNDARY", e)
		}
	}
	// No deletion anywhere in replay occurs until every plan passes its boundary
	// recheck; a changed older tree cannot sacrifice a newer tree or file.
	for _, plan := range l.treePlans {
		if e := l.noTreeProcesses(plan.action.UID); e != nil {
			return e
		}
		if e := l.recheckTree(plan); e != nil {
			return e
		}
	}
	return nil
}
func (l *Ledger) closeTreePlans() {
	for _, plan := range l.treePlans {
		plan.close()
	}
	l.treePlans = nil
}
func (l *Ledger) ownerTreesGone(name string) error {
	for _, row := range l.rows {
		if row.Body.Op != "commit" {
			continue
		}
		a := l.rows[row.Body.Result.Intent].Body.Action
		if a.Kind != "tree" || a.User != name {
			continue
		}
		got, e := observe(a.Paths[0], "tree")
		if e != nil {
			return stopped("TREE_BEFORE_OWNER_REMOVE", e)
		}
		if got != nil {
			return namedError("TREE_OWNER_STILL_IN_USE", *a)
		}
	}
	return nil
}
