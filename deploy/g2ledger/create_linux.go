package g2ledger

import (
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/relux-works/swarma-chain-lab/deploy/internal/ownerid"
	"golang.org/x/sys/unix"
)

// CreateFS never adopts an existing object. The returned open descriptor, not
// a later pathname lookup, supplies the creator's identity.
func (l *Ledger) CreateFS(path, src, kind, ret string, uid, gid, mode uint32) error {
	a := Action{Kind: kind, Ret: ret, Paths: []string{path}, UID: uid, GID: gid, Mode: mode}
	if kind != "dir" && kind != "file" && kind != "secret" {
		return fail(2, "CREATE_KIND")
	}
	return l.createFS(a, src)
}

func (l *Ledger) createFS(a Action, src string) error {
	path, kind, uid, gid, mode := a.Paths[0], a.Kind, a.UID, a.GID, a.Mode
	if e := validateAction(&a); e != nil {
		return stopped("ACTION", e)
	}
	if e := stationRetentionAllowed(*l.rows[0].Body.Genesis, a); e != nil {
		return e
	}
	var data []byte
	if kind != "dir" && kind != "tree" {
		var e error
		data, e = readFile(src, 64<<20)
		if e != nil {
			return stopped("SOURCE_READ", e)
		}
		defer clear(data)
	}
	d, n, e := parent(path)
	if e != nil {
		return stopped("CREATE_PARENT "+path, e)
	}
	defer d.Close()
	seq, e := l.begin(a)
	if e != nil {
		return e
	}
	var f *os.File
	if kind == "dir" || kind == "tree" {
		e = unix.Mkdirat(int(d.Fd()), n, 0700)
		if e == nil {
			f, e = at(d, n, unix.O_RDONLY|unix.O_DIRECTORY, 0)
		}
	} else {
		f, e = at(d, n, unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY, 0600)
	}
	if errors.Is(e, unix.EEXIST) {
		return l.abort(seq, a)
	}
	if e != nil {
		l.poisoned = true
		return orphan(a)
	}
	defer f.Close()
	if e = setMetadata(f, uid, gid, mode, l.sys); e != nil {
		l.poisoned = true
		return orphan(a)
	}
	if kind != "dir" && kind != "tree" {
		if e = l.write(f, data); e != nil {
			l.poisoned = true
			return orphan(a)
		}
	}
	if e = l.syncPayload(f); e != nil {
		l.poisoned = true
		return orphan(a)
	}
	if e = l.syncPayload(d); e != nil {
		l.poisoned = true
		return orphan(a)
	}
	// Read a non-secret file via a second, inode-checked descriptor because the
	// creating descriptor is write-only. Secret identities read no content.
	identityFile := f
	if kind == "file" {
		identityFile, e = at(d, n, unix.O_RDONLY, 0)
		if e != nil {
			l.poisoned = true
			return orphan(a)
		}
		defer identityFile.Close()
		opened, e1 := f.Stat()
		read, e2 := identityFile.Stat()
		if e1 != nil || e2 != nil || !os.SameFile(opened, read) {
			l.poisoned = true
			return orphan(a)
		}
	}
	fi, e := fsIdentity(identityFile, kind)
	if e != nil {
		l.poisoned = true
		return orphan(a)
	}
	id := Identity{Path: path, FS: fi}
	got, e := observeAt(d, n, path, kind)
	if e != nil || got == nil || !identityEqual(id, *got) {
		l.poisoned = true
		return orphan(a)
	}
	if e = f.Close(); e != nil {
		l.poisoned = true
		return orphan(a)
	}
	return l.commit(seq, a, []Identity{id})
}

func (l *Ledger) CreateAccount(kind, name, ret string, uid, gid uint32, roles ...string) error {
	a := Action{Kind: kind, Name: name, Ret: ret, UID: uid, GID: gid}
	if kind != "user" && kind != "group" {
		return fail(2, "ACCOUNT_KIND")
	}
	if kind == "user" {
		a.Role = "service"
		if len(roles) == 1 {
			a.Role = roles[0]
		}
	}
	if len(roles) > 1 || kind == "group" && len(roles) > 0 {
		return fail(2, "ACCOUNT_ROLE")
	}
	return l.createAccount(a)
}

// CreateUserProfile binds sysusers' home and description to the creating call.
// It creates no home directory and always uses the non-login shell.
func (l *Ledger) CreateUserProfile(name, ret string, uid, gid uint32, home, description string, roles ...string) error {
	if home == "" {
		return fail(2, "USER_HOME_REQUIRED")
	}
	role := "service"
	if len(roles) == 1 {
		role = roles[0]
	}
	if len(roles) > 1 || !validUserRole(role) {
		return fail(2, "USER_ROLE_REQUIRED")
	}
	return l.createAccount(Action{Role: role, Kind: "user", Name: name, Ret: ret, UID: uid, GID: gid, Home: home, Description: description})
}
func (l *Ledger) createAccount(a Action) error {
	kind, name, uid, gid := a.Kind, a.Name, a.UID, a.GID
	if e := validateAction(&a); e != nil {
		return stopped("ACTION", e)
	}
	if e := stationRetentionAllowed(*l.rows[0].Body.Genesis, a); e != nil {
		return e
	}
	old, _, e := lookup(l.sys, kind, name)
	if e != nil {
		return stopped("ACCOUNT_LOOKUP "+name, e)
	}
	if old != nil {
		return namedError("ACCOUNT_EXISTS", a)
	}
	seq, e := l.begin(a)
	if e != nil {
		return e
	}
	command := "/usr/sbin/groupadd"
	args := []string{"-g", strconv.FormatUint(uint64(gid), 10), name}
	if kind == "user" {
		home := a.Home
		if home == "" {
			home = "/nonexistent"
		}
		command = "/usr/sbin/useradd"
		args = []string{"-r", "-M", "-N", "-l", "-u", strconv.FormatUint(uint64(uid), 10), "-g", strconv.FormatUint(uint64(gid), 10), "-s", "/usr/sbin/nologin", "-d", home, "-c", a.Description, "-K", "CREATE_MAIL_SPOOL=no", name}
	}
	_, status, e := l.sys.Run(command, args...)
	// shadow-utils documents 4 (ID in use) and 9 (name in use). No -o/-f
	// option is used: an exists failure never becomes a creation receipt.
	if e == nil && (status == 4 || status == 9) {
		return l.abort(seq, a)
	}
	if e != nil || status != 0 {
		l.poisoned = true
		return orphan(a)
	}
	got, _, e := lookup(l.sys, kind, name)
	if e != nil || got == nil {
		l.poisoned = true
		return orphan(a)
	}
	return l.commit(seq, a, []Identity{{Account: got, Role: a.Role}})
}
func (l *Ledger) AddMember(user, group string) error {
	if !namePattern.MatchString(user) || !namePattern.MatchString(group) {
		return fail(2, "MEMBERSHIP_NAME")
	}
	before, e := membership(l.sys, user, group)
	if e != nil {
		return stopped("MEMBERSHIP_LOOKUP", e)
	}
	if before == nil {
		return fail(1, "MEMBERSHIP_SUBJECT_MISSING "+user+":"+group)
	}
	if before.Membership.Present {
		return fail(1, "MEMBERSHIP_EXISTS "+user+":"+group)
	}
	a := Action{Kind: "membership", Ret: "remove", User: user, Group: group, Before: []Identity{*before}}
	seq, e := l.begin(a)
	if e != nil {
		return e
	}
	// Re-observe before invoking usermod, which otherwise succeeds on an existing
	// membership. Concurrent privileged account edits are outside the root-writer
	// threat model; a detected competing membership leaves a named orphan.
	again, e := membership(l.sys, user, group)
	if e != nil || again == nil || !identityEqual(*again, *before) {
		l.poisoned = true
		return orphan(a)
	}
	if e = commandOK(l.sys, "/usr/sbin/usermod", "-aG", group, user); e != nil {
		l.poisoned = true
		return orphan(a)
	}
	got, e := membership(l.sys, user, group)
	if e != nil || got == nil {
		l.poisoned = true
		return orphan(a)
	}
	return l.commit(seq, a, []Identity{*got})
}
func (l *Ledger) Enable(name string) error {
	if e := installName(name); e != nil {
		return stopped("UNIT_INSTALL "+name, e)
	}
	if !unitPattern.MatchString(name) {
		return fail(2, "UNIT_NAME")
	}
	before, e := unitState(l.sys, name)
	if e != nil {
		return stopped("UNIT_LOOKUP "+name, e)
	}
	if before.Unit.State != "disabled" {
		return fail(1, "UNIT_ALREADY_ENABLED "+name)
	}
	plan, e := expectedUnitInstall(l.sys, name)
	if e != nil {
		return stopped("UNIT_INSTALL "+name, e)
	}
	if len(plan.Missing) == 0 {
		return fail(1, "UNIT_NO_NEW_LINKS "+name)
	}
	a := Action{Kind: "unit", Ret: "state", Name: name, Before: []Identity{*before}}
	seq, e := l.begin(a)
	if e != nil {
		return e
	}
	again, e := unitState(l.sys, name)
	if e != nil || again == nil || !identityEqual(*again, *before) {
		l.poisoned = true
		return orphan(a)
	}
	current, e := expectedUnitInstall(l.sys, name)
	if e != nil || !plan.equal(current) {
		l.poisoned = true
		return orphan(a)
	}
	output, status, e := l.sys.Run("/usr/bin/systemctl", "enable", name)
	if e != nil || status != 0 {
		l.poisoned = true
		return orphan(a)
	}
	links, e := createdUnitLinks(output)
	if e != nil {
		l.poisoned = true
		return orphan(a)
	}
	if !unitReceiptMatches(links, plan.Missing) {
		l.poisoned = true
		return fail(3, "ORPHAN "+name+" UNIT_ENABLE_SET_MISMATCH")
	}
	for _, link := range plan.Existing {
		present, err := unitLinkPresent(link)
		if err != nil || !present {
			l.poisoned = true
			return fail(3, "ORPHAN "+name+" UNIT_EXISTING_LINK_CHANGED")
		}
	}
	for j := range links {
		got, present, err := observeUnitLink(links[j])
		if err != nil || !present {
			l.poisoned = true
			return orphan(a)
		}
		links[j] = got
	}
	got, e := unitState(l.sys, name)
	if e != nil || got == nil {
		l.poisoned = true
		return orphan(a)
	}
	got.Unit.Links = links
	return l.commit(seq, a, []Identity{*got})
}

// A successful arbitrary process is not a creation receipt. Only the current
// deploy-kit executable's audited exclusive creators are admitted. Their actual
// output flag is bound to exactly the declared path before the intent is written.
func creatorCommand(argv, paths []string) error {
	if len(argv) < 4 || len(paths) != 1 || !validPath(argv[0]) {
		return errors.New("EXEC_UNAUDITED_CREATOR")
	}
	self, e := os.Executable()
	if e != nil {
		return e
	}
	a, e := os.Stat(self)
	if e != nil {
		return e
	}
	b, e := os.Stat(argv[0])
	if e != nil || !os.SameFile(a, b) {
		return errors.New("EXEC_NOT_THIS_DEPLOY_KIT")
	}
	output, _, _, _, err := creatorMetadata(argv)
	if err != nil {
		return err
	}
	if output != paths[0] {
		return errors.New("EXEC_OUTPUT_NOT_DECLARED")
	}
	return nil
}

// creatorMetadata accepts only the audited generators' options. Resolve both
// identities before intent/creation; never substitute caller IDs on lookup error.
func creatorMetadata(argv []string) (string, int, int, uint32, error) {
	if len(argv) < 2 {
		return "", 0, 0, 0, errors.New("EXEC_UNAUDITED_SUBCOMMAND")
	}
	f := flag.NewFlagSet("exclusive-creator", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	var owner, group ownerid.Spec
	f.Var(&owner, "owner", "final owner")
	f.Var(&group, "group", "final group")
	output := ""
	mode := "0600"
	switch argv[1] {
	case "g2-keygen":
		f.StringVar(&output, "out", "", "exclusive output")
		f.StringVar(&mode, "mode", "0600", "mode")
	case "g2-rpcauth":
		f.StringVar(&output, "wallet-config-out", "", "exclusive output")
		f.String("params", "", "parameters")
		f.String("wallet-public", "", "public wallet input")
	default:
		return "", 0, 0, 0, errors.New("EXEC_UNAUDITED_SUBCOMMAND")
	}
	// Duplicate flags could redirect a later output or disguise the mode.
	seen := map[string]bool{}
	for j := 2; j < len(argv); j++ {
		field := strings.TrimPrefix(strings.TrimPrefix(argv[j], "-"), "-")
		field, _, inline := strings.Cut(field, "=")
		if field == "" || seen[field] {
			return "", 0, 0, 0, errors.New("EXEC_FLAG_DUPLICATE")
		}
		seen[field] = true
		if !inline {
			j++
			if j >= len(argv) {
				return "", 0, 0, 0, errors.New("EXEC_FLAG_VALUE")
			}
		}
	}
	if f.Parse(argv[2:]) != nil || f.NArg() != 0 || mode != "0600" && mode != "0640" {
		return "", 0, 0, 0, errors.New("EXEC_OUTPUT_NOT_DECLARED")
	}

	uid, gid, err := ownerid.System().Resolve(owner, group)
	if err != nil {
		return "", 0, 0, 0, err
	}
	if argv[1] == "g2-rpcauth" {
		mode = "0640"
	}
	m, err := strconv.ParseUint(mode, 8, 32)
	return output, uid, gid, uint32(m), err
}

// Snapshot only the parents of declared outputs. The admitted tools have no
// other filesystem outputs. Unexpected additions/changes are named orphans.
type parentSnapshot struct {
	dir     *os.File
	path    string
	entries map[string]unix.Stat_t
}

func snapshot(d *os.File) (map[string]unix.Stat_t, error) {
	fd, e := unix.Openat(int(d.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "snapshot")
	defer f.Close()
	names, e := f.Readdirnames(-1)
	if e != nil {
		return nil, e
	}
	out := map[string]unix.Stat_t{}
	for _, n := range names {
		var s unix.Stat_t
		if e := unix.Fstatat(int(d.Fd()), n, &s, unix.AT_SYMLINK_NOFOLLOW); e != nil {
			return nil, e
		}
		out[n] = s
	}
	return out, nil
}
func (l *Ledger) ExecCreate(kind, ret string, paths, argv []string) error {
	if kind != "file" && kind != "secret" {
		return fail(2, "EXEC_KIND")
	}
	if kind != "secret" {
		return fail(1, "EXEC_SECRET_KIND_REQUIRED")
	}
	if e := stationRetentionAllowed(*l.rows[0].Body.Genesis, Action{Kind: kind, Ret: ret, Paths: paths}); e != nil {
		return e
	}
	if e := creatorCommand(argv, paths); e != nil {
		return stopped("EXEC_CONTRACT", e)
	}
	return l.execCreate(kind, ret, paths, argv)
}
func (l *Ledger) execCreate(kind, ret string, paths, argv []string) error {
	a := Action{Kind: kind, Ret: ret, Paths: paths}
	// Record the same resolved ownership and final mode the audited tool uses.
	_, uid, gid, mode, err := creatorMetadata(argv)
	if err != nil {
		return stopped("EXEC_METADATA", err)
	}
	a.UID, a.GID, a.Mode = uint32(os.Geteuid()), uint32(os.Getegid()), mode
	if uid != -1 {
		a.UID = uint32(uid)
	}
	if gid != -1 {
		a.GID = uint32(gid)
	}
	if e := validateAction(&a); e != nil {
		return stopped("ACTION", e)
	}
	if e := stationRetentionAllowed(*l.rows[0].Body.Genesis, a); e != nil {
		return e
	}
	snaps := map[string]parentSnapshot{}
	defer func() {
		for _, s := range snaps {
			s.dir.Close()
		}
	}()
	declared := map[string]bool{}
	for _, p := range paths {
		dir := filepath.Dir(p)
		if _, ok := snaps[dir]; !ok {
			d, e := openDir(dir)
			if e != nil {
				return stopped("EXEC_PARENT "+dir, e)
			}
			entries, e := snapshot(d)
			if e != nil {
				d.Close()
				return stopped("EXEC_INVENTORY "+dir, e)
			}
			snaps[dir] = parentSnapshot{d, dir, entries}
		}
		declared[p] = true
		if _, ok := snaps[dir].entries[filepath.Base(p)]; ok {
			return fail(1, "EXEC_PATH_EXISTS "+p)
		}
	}
	seq, e := l.begin(a)
	if e != nil {
		return e
	}
	output, status, e := l.sys.Run(argv[0], argv[1:]...)
	if e != nil || status != 0 {
		l.poisoned = true
		return orphan(a)
	}
	var journal unix.Stat_t
	if e := unix.Fstat(int(l.dir.Fd()), &journal); e != nil {
		l.poisoned = true
		return orphan(a)
	}
	for dir, s := range snaps {
		after, e := snapshot(s.dir)
		if e != nil {
			l.poisoned = true
			return orphan(a)
		}
		for n, got := range after {
			p := filepath.Join(dir, n)
			if declared[p] {
				continue
			}
			old, ok := s.entries[n]
			// Appending our intent changes the journal directory's child namespace.
			// Exempt only that held inode's mutable directory times/size; replacement
			// or ownership/mode changes still fail. Other siblings keep full checks.
			ownJournal := ok && old.Dev == journal.Dev && old.Ino == journal.Ino &&
				got.Dev == journal.Dev && got.Ino == journal.Ino && old.Mode == got.Mode && old.Uid == got.Uid && old.Gid == got.Gid
			if !ok || !ownJournal && !stableStat(old, got) {
				l.poisoned = true
				return fail(3, "ORPHAN extra or changed path "+p)
			}
		}
		for n := range s.entries {
			if _, ok := after[n]; !ok {
				l.poisoned = true
				return fail(3, "ORPHAN missing prior path "+filepath.Join(dir, n))
			}
		}
	}
	ids := make([]Identity, 0, len(paths))
	for _, p := range paths {
		s := snaps[filepath.Dir(p)]
		got, e := observeAt(s.dir, filepath.Base(p), p, kind)
		if e != nil || got == nil {
			l.poisoned = true
			return fail(3, "ORPHAN missing or unreadable declared path "+p)
		}
		f, e := at(s.dir, filepath.Base(p), unix.O_RDONLY, 0)
		if e != nil {
			l.poisoned = true
			return orphan(a)
		}
		e = f.Sync()
		f.Close()
		if e != nil {
			l.poisoned = true
			return orphan(a)
		}
		if e = s.dir.Sync(); e != nil {
			l.poisoned = true
			return orphan(a)
		}
		ids = append(ids, *got)
	}
	if e = l.commit(seq, a, ids); e != nil {
		return e
	}
	if l.output != nil {
		if e = checkedWrite(l.output, []byte(output)); e != nil {
			return stopped("EXEC_PUBLIC_OUTPUT", e)
		}
	}
	return nil
}

// atomicReplace uses an O_EXCL temp and checks the old identity through the
// same parent descriptor immediately before rename. No symlink is followed.
func (l *Ledger) atomicReplace(path string, want Identity, data []byte, uid, gid, mode uint32) (*Identity, error) {
	d, n, e := parent(path)
	if e != nil {
		return nil, e
	}
	defer d.Close()
	temp := ".g2-ledger-" + randomID()
	f, e := at(d, temp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0600)
	if e != nil {
		return nil, e
	}
	defer unix.Unlinkat(int(d.Fd()), temp, 0)
	if e = setMetadata(f, uid, gid, mode, l.sys); e == nil {
		e = l.write(f, data)
	}
	if e == nil {
		e = f.Sync()
	}
	e = errors.Join(e, f.Close())
	if e != nil {
		return nil, e
	}
	got, e := observeAt(d, n, path, "modify")
	if e != nil {
		return nil, e
	}
	if got == nil || !identityEqual(*got, want) {
		return nil, errors.New("REPLACE_IDENTITY_MISMATCH")
	}
	if e = unix.Renameat(int(d.Fd()), temp, int(d.Fd()), n); e != nil {
		return nil, e
	}
	if e = d.Sync(); e != nil {
		return nil, e
	}
	return observeAt(d, n, path, "modify")
}
func (l *Ledger) ModifyFile(path, backup, newPath string) error {
	original, e := observe(path, "modify")
	if e != nil {
		return stopped("MODIFY_LOOKUP "+path, e)
	}
	if original == nil {
		return fail(1, "MODIFY_MISSING "+path)
	}
	old, e := readFile(backup, 64<<20)
	if e != nil {
		return stopped("BACKUP_READ", e)
	}
	defer clear(old)
	data, e := readFile(newPath, 64<<20)
	if e != nil {
		return stopped("NEW_READ", e)
	}
	defer clear(data)
	if original.FS.SHA256 != digest(old) {
		return fail(1, "BACKUP_MISMATCH "+path)
	}
	if digest(old) == digest(data) {
		return fail(1, "MODIFY_NO_CHANGE "+path)
	}
	a := Action{Kind: "modify", Ret: "state", Paths: []string{path}, Backup: backup, BackupSHA256: digest(old), NewSHA256: digest(data), UID: original.FS.UID, GID: original.FS.GID, Mode: original.FS.Mode, Before: []Identity{*original}}
	seq, e := l.begin(a)
	if e != nil {
		return e
	}
	got, e := l.atomicReplace(path, *original, data, a.UID, a.GID, a.Mode)
	if e != nil || got == nil {
		l.poisoned = true
		return orphan(a)
	}
	return l.commit(seq, a, []Identity{*got})
}
