package g2ledger

import (
	"errors"
	"fmt"
	"strings"
)

// userGroupPair grants only the two committed creation receipts' joint removal
// authority. Role is validated against the creating action, never inferred from
// passwd. Preflight permits own recorded supplementary additions; the user undo
// requires them to have been reversed before entering this operation.
func (l *Ledger) userGroupPair(a Action, want Identity, mode string, empty bool) (*authority, error) {
	auth := l.authorities()
	groupAuth, recorded := auth[objectKey("group", a.Name)]
	group, members, e := lookup(l.sys, "group", a.Name)
	if e != nil {
		return nil, stopped("USER_GROUP_LOOKUP "+a.Name, e)
	}
	if group == nil {
		if recorded {
			return nil, namedError("PAIRED_GROUP_MISSING", a)
		}
		return nil, nil
	}
	userAuth, userRecorded := auth[objectKey("user", a.Name)]
	userEffect, _ := retentionPolicy(a.Kind, a.Ret, mode)
	groupEffect, _ := retentionPolicy(groupAuth.action.Kind, groupAuth.action.Ret, mode)
	if !recorded || !userRecorded || mode != "rehearsal" || userEffect != "remove" || groupEffect != "remove" ||
		!identityEqual(userAuth.identity, want) || want.Role != a.Role || !validUserRole(want.Role) {
		return nil, namedError("USER_SAME_NAME_GROUP", a)
	}
	if !accountEqual(*group, *groupAuth.identity.Account) {
		return nil, namedError("PAIRED_GROUP_IDENTITY", a)
	}
	if group.GID != want.Account.GID {
		return nil, namedError("PAIRED_GROUP_PRIMARY_GID", a)
	}
	if empty && len(members) != 0 {
		return nil, namedError("PAIRED_GROUP_NOT_EMPTY", a)
	}
	if e := checkPairPrimary(l.sys, group.GID, want.Account); e != nil {
		return nil, stopped("PAIRED_GROUP_PASSWD "+a.Name, e)
	}
	if e := l.recheckPairedGroup(groupAuth, empty); e != nil {
		return nil, e
	}
	return &groupAuth, nil
}

// checkPairPrimary enumerates passwd through the same System seam as lookups.
// A keyed lookup cannot prove the absence of another primary user. Every row
// must parse and the allowed user, when present, must match the full receipt.
func checkPairPrimary(sys System, gid uint32, allowed *Account) error {
	out, status, e := sys.Run("/usr/bin/getent", "passwd")
	if e != nil {
		return e
	}
	if status != 0 {
		return fmt.Errorf("PASSWD_STATUS_%d", status)
	}
	seen := map[string]bool{}
	found := false
	if out != "" {
		for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
			p := strings.Split(line, ":")
			if len(p) != 7 || !namePattern.MatchString(p[0]) || seen[p[0]] || strings.ContainsRune(line, '\r') {
				return errors.New("PASSWD_SCHEMA")
			}
			seen[p[0]] = true
			uid, ue := number(p[2])
			primary, ge := number(p[3])
			if ue != nil || ge != nil || uid == ^uint32(0) || primary == ^uint32(0) || !strings.HasPrefix(p[6], "/") {
				return errors.New("PASSWD_IDENTITY")
			}
			u := Account{Name: p[0], UID: uid, GID: primary, Description: p[4], Home: p[5], Shell: p[6]}
			if allowed != nil && u.Name == allowed.Name {
				if !accountEqual(u, *allowed) {
					return errors.New("PASSWD_USER_CHANGED")
				}
				found = true
			} else if u.GID == gid {
				return errors.New("PAIRED_GROUP_OTHER_PRIMARY_USER")
			}
		}
	}
	if allowed != nil && !found {
		return errors.New("PASSWD_USER_MISSING")
	}
	return nil
}

// checkPairSupplementary enumerates the complete group database, rather than
// the declared scope. No receipt authorizes userdel to consume a remaining
// membership outside the user's same-name group; foreign state is never adopted.
func checkPairSupplementary(sys System, user string) error {
	out, status, e := sys.Run("/usr/bin/getent", "group")
	if e != nil {
		return e
	}
	if status != 0 {
		return fmt.Errorf("GROUP_STATUS_%d", status)
	}
	seen := map[string]bool{}
	if out != "" {
		for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
			p := strings.Split(line, ":")
			if len(p) != 4 || !namePattern.MatchString(p[0]) || seen[p[0]] || strings.ContainsRune(line, '\r') {
				return errors.New("GROUP_SCHEMA")
			}
			seen[p[0]] = true
			gid, e := number(p[2])
			if e != nil || gid == ^uint32(0) {
				return errors.New("GROUP_IDENTITY")
			}
			if p[3] == "" {
				continue
			}
			members := map[string]bool{}
			for _, member := range strings.Split(p[3], ",") {
				if !namePattern.MatchString(member) || members[member] {
					return errors.New("GROUP_MEMBERS")
				}
				members[member] = true
				if member == user && p[0] != user {
					return fmt.Errorf("USER_OTHER_SUPPLEMENTARY_GROUP %s", p[0])
				}
			}
		}
	}
	return nil
}

// shadow-utils userdel(8) and login.defs(5), USERGROUPS_ENAB, document both
// implicit same-name group deletion and survival. Observe the outcome instead
// of reading/changing host policy. The caller records the verified removal so
// the older group receipt cannot remove a subsequently reappearing group.
func (l *Ledger) removePairedAccounts(user Action, group authority) (string, error) {
	// Recorded add-member reversals have already run. userdel also removes
	// supplementary memberships in unrelated, potentially unscoped groups.
	if e := checkPairSupplementary(l.sys, user.Name); e != nil {
		return "", stopped("PAIRED_USER_GROUPS "+user.Name, e)
	}
	if e := l.recheckPairedGroup(group, true); e != nil {
		return "", e
	}
	if e := commandOK(l.sys, "/usr/sbin/userdel", user.Name); e != nil {
		return "", stopped("REMOVE_ACCOUNT "+user.Name, e)
	}
	after, _, e := lookup(l.sys, "user", user.Name)
	if e != nil {
		return "", stopped("REMOVE_ACCOUNT_LOOKUP "+user.Name, e)
	}
	if after != nil {
		return "", namedError("ACCOUNT_STILL_PRESENT", user)
	}
	return l.finishPairedGroup(group)
}

func (l *Ledger) finishPairedGroup(group authority) (string, error) {
	a := group.action
	got, members, e := lookup(l.sys, "group", a.Name)
	if e != nil {
		return "", stopped("PAIRED_GROUP_LOOKUP "+a.Name, e)
	}
	if got == nil {
		return "userdel", nil
	}
	if !accountEqual(*got, *group.identity.Account) {
		return "", namedError("PAIRED_GROUP_IDENTITY", a)
	}
	if len(members) != 0 {
		return "", namedError("PAIRED_GROUP_NOT_EMPTY", a)
	}
	if e := checkPairPrimary(l.sys, got.GID, nil); e != nil {
		return "", stopped("PAIRED_GROUP_PASSWD "+a.Name, e)
	}
	if e := l.recheckPairedGroup(group, true); e != nil {
		return "", e
	}
	if e := commandOK(l.sys, "/usr/sbin/groupdel", a.Name); e != nil {
		return "", stopped("REMOVE_ACCOUNT "+a.Name, e)
	}
	after, _, e := lookup(l.sys, "group", a.Name)
	if e != nil {
		return "", stopped("PAIRED_GROUP_LOOKUP "+a.Name, e)
	}
	if after != nil {
		return "", namedError("PAIRED_GROUP_STILL_PRESENT", a)
	}
	return "groupdel", nil
}

// Recheck after passwd enumeration, immediately before the destructive call.
// Absence here is unexpected: only the post-userdel observation admits it.
func (l *Ledger) recheckPairedGroup(group authority, empty bool) error {
	a := group.action
	got, members, e := lookup(l.sys, "group", a.Name)
	if e != nil {
		return stopped("PAIRED_GROUP_LOOKUP "+a.Name, e)
	}
	if got == nil {
		return namedError("PAIRED_GROUP_MISSING", a)
	}
	if !accountEqual(*got, *group.identity.Account) {
		return namedError("PAIRED_GROUP_IDENTITY", a)
	}
	if empty && len(members) != 0 {
		return namedError("PAIRED_GROUP_NOT_EMPTY", a)
	}
	return nil
}

// A stopped pair may have removed its user while leaving its group. Retrying
// that older group receipt still requires a fresh passwd scan before groupdel.
func (l *Ledger) checkUnfinishedPair(a Action, want Identity) error {
	user, paired := l.authorities()[objectKey("user", a.Name)]
	if !paired || user.identity.Account.GID != want.Account.GID {
		return nil
	}
	if e := checkPairPrimary(l.sys, want.Account.GID, nil); e != nil {
		return stopped("PAIRED_GROUP_PASSWD "+a.Name, e)
	}
	return l.recheckPairedGroup(authority{action: a, identity: want}, true)
}
