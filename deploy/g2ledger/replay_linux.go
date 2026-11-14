package g2ledger

import (
	"errors"
	"fmt"
	"path/filepath"

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
	g := l.rows[0].Body.Genesis
	if !purposeMatches(g.Purpose, mode) {
		return fail(1, "MODE_PURPOSE_MISMATCH purpose="+g.Purpose+" mode="+mode)
	}
	if mode == "rehearsal" {
		if e := l.preflightRehearsal(); e != nil {
			return e
		}
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
	return l.compareBaseline(mode)
}
func (l *Ledger) undo(a Action, want Identity, mode string) error {
	switch a.Kind {
	case "dir", "file", "secret":
		// Check retained identities too; the shared policy chooses keep or remove.
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
		if effect, _ := retentionPolicy(a.Kind, a.Ret, mode); effect == "keep" {
			return nil
		}
		flags := 0
		if a.Kind == "dir" {
			flags = unix.AT_REMOVEDIR
			target, err := at(d, n, unix.O_RDONLY|unix.O_DIRECTORY, 0)
			if err != nil {
				return stopped("DIRECTORY_LOOKUP "+want.Path, err)
			}
			current, err := fsIdentity(target, "dir")
			if err != nil || !identityEqual(Identity{Path: want.Path, FS: current}, want) {
				target.Close()
				return mismatch(a)
			}
			entries, err := target.ReadDir(-1)
			target.Close()
			if err != nil {
				return stopped("DIRECTORY_LOOKUP "+want.Path, err)
			}
			if len(entries) > 0 {
				return fail(1, "DIRECTORY_NOT_EMPTY "+filepath.Join(want.Path, entries[0].Name()))
			}
		}
		if e = unix.Unlinkat(int(d.Fd()), n, flags); e != nil {
			return stopped("REMOVE "+want.Path, e)
		}
		if e = d.Sync(); e != nil {
			return stopped("REMOVE_DIRECTORY_SYNC "+want.Path, e)
		}
		return nil
	case "user", "group":
		got, members, e := lookup(l.sys, a.Kind, a.Name)
		if e != nil {
			return stopped("LOOKUP "+a.Name, e)
		}
		if got == nil {
			return nil
		}
		if !accountEqual(*got, *want.Account) {
			return mismatch(a)
		}
		if effect, _ := retentionPolicy(a.Kind, a.Ret, mode); effect == "keep" {
			return nil
		}
		command := "/usr/sbin/userdel"
		if a.Kind == "group" {
			if mode == "rehearsal" && len(members) > 0 {
				return fail(1, "GROUP_NOT_EMPTY group:"+a.Name+"/member:"+members[0])
			}
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
		got, e := l.replayUnit(a.Name)
		if e != nil {
			return stopped("UNIT_LOOKUP "+a.Name, e)
		}
		if got == nil || got.Unit.State == "disabled" {
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

// Before rehearsal removes anything, all present identities must still match.
// Reversed absence, disabled units, removed memberships and restored config are
// accepted for retries; they never authorize a mismatched present object.
func (l *Ledger) preflightRehearsal() error {
	for j := len(l.rows) - 1; j >= 1; j-- {
		r := l.rows[j]
		if r.Body.Op != "commit" {
			continue
		}
		a := *l.rows[r.Body.Result.Intent].Body.Action
		effect, _ := retentionPolicy(a.Kind, a.Ret, "rehearsal")
		for _, want := range r.Body.Result.Identities {
			var got *Identity
			var e error
			switch a.Kind {
			case "dir", "file", "secret", "modify":
				got, e = observe(want.Path, a.Kind)
				if e == nil && a.Kind == "modify" && got != nil && restoredIdentity(*got, a) {
					continue
				}
			case "user", "group":
				var account *Account
				var members []string
				account, members, e = lookup(l.sys, a.Kind, a.Name)
				if account != nil {
					got = &Identity{Account: account}
				}
				if e == nil && a.Kind == "group" && account != nil && effect == "remove" {
					allowed := map[string]bool{}
					for _, o := range l.rows[0].Body.Genesis.S0 {
						if o.Kind == "group" && o.Name == a.Name {
							for _, m := range o.Members {
								allowed[m] = true
							}
						}
					}
					for _, row := range l.rows {
						if row.Body.Op == "commit" {
							action := l.rows[row.Body.Result.Intent].Body.Action
							if action.Kind == "membership" && action.Group == a.Name {
								allowed[action.User] = true
							}
						}
					}
					for _, m := range members {
						if !allowed[m] {
							return fail(1, "UNLISTED_DIFFERENCE group:"+a.Name+"/member:"+m)
						}
					}
				}
			case "membership":
				got, e = membership(l.sys, a.User, a.Group)
				if got != nil && !got.Membership.Present {
					copy := *got.Membership
					copy.Present = true
					got = &Identity{Membership: &copy}
				}
			case "unit":
				got, e = l.replayUnit(a.Name)
				if e == nil && got != nil && identityEqual(*got, a.Before[0]) {
					continue
				}
			}
			if e != nil {
				return stopped("PREFLIGHT_LOOKUP "+actionName(a), e)
			}
			if got == nil {
				if a.Kind == "modify" {
					return namedError("MODIFY_MISSING", a)
				}
				continue
			}
			matches := identityEqual(*got, want)
			if got.Account != nil && want.Account != nil {
				matches = accountEqual(*got.Account, *want.Account)
			}
			if !matches {
				return mismatch(a)
			}
		}
	}
	return nil
}

// A unit absent at S0 can already be gone on replay retry after its recorded
// unit file was removed. Existing S0 units retain the strict lookup contract.
func (l *Ledger) replayUnit(name string) (*Identity, error) {
	for _, o := range l.rows[0].Body.Genesis.S0 {
		if o.Kind == "unit" && o.Name == name && o.Identity == nil {
			got, e := snapshotObject(o, l.sys, l.root, l.rows[0].Body.Genesis.Baseline)
			return got.Identity, e
		}
	}
	return unitState(l.sys, name)
}
