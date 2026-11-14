package g2ledger

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// Replay validates every row and the terminal HEAD before the first lookup or
// effect. It stops immediately on the first error; effects already completed
// earlier in reverse order are not a transaction and are not undone.
func (l *Ledger) Replay(mode string) error {
	if mode != "station" && mode != "station-remove" && mode != "rehearsal" {
		return fail(2, "REPLAY_MODE")
	}
	if e := l.load(); e != nil {
		return e
	}
	if l.poisoned {
		return fail(1, "LEDGER_POISONED")
	}
	for j := len(l.rows) - 1; j >= 1; j-- {
		r := l.rows[j]
		if r.Body.Op != "commit" {
			continue
		}
		a := *l.rows[r.Body.Result.Intent].Body.Action
		for k := len(r.Body.Result.Identities) - 1; k >= 0; k-- {
			if e := l.undo(a, r.Body.Result.Identities[k], mode); e != nil {
				return e
			}
		}
	}
	return nil
}
func (l *Ledger) undo(a Action, want Identity, mode string) error {
	switch a.Kind {
	case "dir", "file", "secret":
		// d6 is never deleted. state directories remain available for retained data.
		// All identities, including retained objects, are checked before proceeding.
		d, n, e := parent(want.Path)
		if errors.Is(e, unix.ENOENT) {
			return nil
		}
		if e != nil {
			return stopped("LOOKUP "+want.Path, e)
		}
		defer d.Close()
		got, e := observeAt(d, n, want.Path, a.Kind)
		if e != nil {
			return stopped("LOOKUP "+want.Path, e)
		}
		if got == nil {
			return nil
		}
		if !identityEqual(*got, want) {
			return mismatch(a)
		}
		if a.Ret == "d6" || a.Ret == "state" {
			return nil
		}
		flags := 0
		if a.Kind == "dir" {
			flags = unix.AT_REMOVEDIR
		}
		if e = unix.Unlinkat(int(d.Fd()), n, flags); e != nil {
			return stopped("REMOVE "+want.Path, e)
		}
		if e = d.Sync(); e != nil {
			return stopped("REMOVE_DIRECTORY_SYNC "+want.Path, e)
		}
		return nil
	case "user", "group":
		got, _, e := lookup(l.sys, a.Kind, a.Name)
		if e != nil {
			return stopped("LOOKUP "+a.Name, e)
		}
		if got == nil {
			return nil
		}
		if !accountEqual(*got, *want.Account) {
			return mismatch(a)
		}
		if a.Ret == "d6" || a.Ret == "state" {
			return nil
		}
		command := "/usr/sbin/userdel"
		if a.Kind == "group" {
			command = "/usr/sbin/groupdel"
		}
		if e = commandOK(l.sys, command, a.Name); e != nil {
			return stopped("REMOVE_ACCOUNT "+a.Name, e)
		}
		after, _, e := lookup(l.sys, a.Kind, a.Name)
		if e != nil {
			return stopped("REMOVE_ACCOUNT_LOOKUP "+a.Name, e)
		}
		if after != nil {
			return namedError("ACCOUNT_STILL_PRESENT", a)
		}
		return nil
	case "membership":
		got, e := membership(l.sys, a.User, a.Group)
		if e != nil {
			return stopped("MEMBERSHIP_LOOKUP", e)
		}
		if got == nil {
			return nil
		}
		if !accountEqual(got.Membership.User, want.Membership.User) || !accountEqual(got.Membership.Group, want.Membership.Group) {
			return mismatch(a)
		}
		if !got.Membership.Present {
			return nil
		}
		if e = commandOK(l.sys, "/usr/bin/gpasswd", "-d", a.User, a.Group); e != nil {
			return stopped("REMOVE_MEMBER", e)
		}
		after, e := membership(l.sys, a.User, a.Group)
		if e != nil {
			return stopped("MEMBERSHIP_LOOKUP", e)
		}
		if after == nil || after.Membership.Present || !accountEqual(after.Membership.User, want.Membership.User) || !accountEqual(after.Membership.Group, want.Membership.Group) {
			return mismatch(a)
		}
		return nil
	case "unit":
		got, e := unitState(l.sys, a.Name)
		if e != nil {
			return stopped("UNIT_LOOKUP "+a.Name, e)
		}
		if got.Unit.State == "disabled" {
			return nil
		}
		if !identityEqual(*got, want) {
			return mismatch(a)
		}
		if e = commandOK(l.sys, "/usr/bin/systemctl", "disable", a.Name); e != nil {
			return stopped("UNIT_RESTORE "+a.Name, e)
		}
		after, e := unitState(l.sys, a.Name)
		if e != nil {
			return stopped("UNIT_LOOKUP "+a.Name, e)
		}
		if !identityEqual(*after, a.Before[0]) {
			return mismatch(a)
		}
		return nil
	case "modify":
		old, e := readFile(a.Backup, 64<<20)
		if e != nil {
			return stopped("BACKUP_READ "+a.Backup, e)
		}
		defer clear(old)
		if digest(old) != a.BackupSHA256 {
			return namedError("BACKUP_CHANGED", a)
		}
		got, e := observe(want.Path, "modify")
		if e != nil {
			return stopped("MODIFY_LOOKUP "+want.Path, e)
		}
		if got == nil {
			return namedError("MODIFY_MISSING", a)
		}
		// A prior completed restore may be retried, but only exact old content and
		// metadata qualify; an arbitrary hash is never an undo authority.
		if got.FS.SHA256 == a.BackupSHA256 && got.FS.UID == a.UID && got.FS.GID == a.GID && got.FS.Mode == a.Mode {
			return nil
		}
		if !identityEqual(*got, want) || got.FS.SHA256 != a.NewSHA256 {
			return mismatch(a)
		}
		restored, e := l.atomicReplace(want.Path, *got, old, a.UID, a.GID, a.Mode)
		if e != nil {
			return stopped("RESTORE "+want.Path, e)
		}
		if restored == nil || restored.FS.SHA256 != a.BackupSHA256 {
			return namedError("RESTORE_HASH", a)
		}
		return nil
	default:
		return fail(1, fmt.Sprintf("UNKNOWN_KIND %s", a.Kind))
	}
}
