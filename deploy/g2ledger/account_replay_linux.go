package g2ledger

import (
	"errors"
	"fmt"
	"sort"
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
	if e := l.checkPairPrimary(group.GID, want.Account); e != nil {
		return nil, stopped("PAIRED_GROUP_PASSWD "+a.Name, e)
	}
	if e := l.recheckPairedGroup(groupAuth, empty); e != nil {
		return nil, e
	}
	return &groupAuth, nil
}

// pairKnownAccounts binds enumeration to known ledger identities that still
// exist. Attempt-created accounts may already be absent on retry; S0 accounts
// must remain. Keyed reads detect contradictions, not arbitrary NSS omissions.
func (l *Ledger) pairKnownAccounts(kind string) (map[string]Account, error) {
	known := map[string]Account{}
	required := map[string]bool{}
	for _, base := range l.rows[0].Body.Genesis.S0 {
		if base.Kind == kind && base.Identity != nil {
			known[base.Name] = *base.Identity.Account
			required[base.Name] = true
		}
	}
	for _, auth := range l.authorities() {
		if auth.action.Kind == kind {
			known[auth.action.Name] = *auth.identity.Account
		}
	}
	names := make([]string, 0, len(known))
	for name := range known {
		names = append(names, name)
	}
	sort.Strings(names)
	prefix := "GROUP"
	if kind == "user" {
		prefix = "PASSWD"
	}
	for _, name := range names {
		got, _, e := lookup(l.sys, kind, name)
		if e != nil {
			return nil, e
		}
		if got == nil && !required[name] {
			delete(known, name)
			continue
		}
		if got == nil || !accountEqual(*got, known[name]) {
			return nil, fmt.Errorf("%s_INCOMPLETE %s", prefix, name)
		}
	}
	return known, nil
}

// checkPairPrimary requires every known-present user in the passwd listing.
// The allowed paired user must match its full receipt; no other primary user
// may use the paired gid, even outside the declared scope.
func (l *Ledger) checkPairPrimary(gid uint32, allowed *Account) error {
	known, e := l.pairKnownAccounts("user")
	if e != nil {
		return e
	}
	out, status, e := l.sys.Run("/usr/bin/getent", "passwd")
	if e != nil {
		return e
	}
	if status != 0 {
		return fmt.Errorf("PASSWD_STATUS_%d", status)
	}
	seen := map[string]Account{}
	found := false
	if out != "" {
		for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
			p := strings.Split(line, ":")
			if len(p) != 7 || !namePattern.MatchString(p[0]) || seen[p[0]].Name != "" || strings.ContainsRune(line, '\r') {
				return errors.New("PASSWD_SCHEMA")
			}
			uid, ue := number(p[2])
			primary, ge := number(p[3])
			if ue != nil || ge != nil || uid == ^uint32(0) || primary == ^uint32(0) || !strings.HasPrefix(p[6], "/") {
				return errors.New("PASSWD_IDENTITY")
			}
			u := Account{Name: p[0], UID: uid, GID: primary, Description: p[4], Home: p[5], Shell: p[6]}
			seen[p[0]] = u
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
	return checkPairEnumeration(known, seen, "PASSWD")
}

// checkPairSupplementary rejects demonstrably incomplete group listings and
// foreign memberships across the database. Preflight allows only exact committed
// additions that reverse before this user; the undo check allows none of them.
func (l *Ledger) checkPairSupplementary(user string, group authority, preflight bool) error {
	known, e := l.pairKnownAccounts("group")
	if e != nil {
		return e
	}
	known[group.action.Name] = *group.identity.Account
	allowed := map[string]Account{}
	if preflight {
		userAuth := l.authorities()[objectKey("user", user)]
		for _, row := range l.rows {
			if row.Body.Op != "commit" || row.Seq <= userAuth.seq {
				continue
			}
			a := l.rows[row.Body.Result.Intent].Body.Action
			if a.Kind != "membership" || a.User != user {
				continue
			}
			for _, id := range row.Body.Result.Identities {
				m := id.Membership
				if accountEqual(m.User, *userAuth.identity.Account) && accountEqual(m.Group, known[m.Group.Name]) {
					allowed[m.Group.Name] = m.Group
				}
			}
		}
	}
	out, status, e := l.sys.Run("/usr/bin/getent", "group")
	if e != nil {
		return e
	}
	if status != 0 {
		return fmt.Errorf("GROUP_STATUS_%d", status)
	}
	seen := map[string]Account{}
	if out != "" {
		for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
			p := strings.Split(line, ":")
			if len(p) != 4 || !namePattern.MatchString(p[0]) || seen[p[0]].Name != "" || strings.ContainsRune(line, '\r') {
				return errors.New("GROUP_SCHEMA")
			}
			gid, e := number(p[2])
			if e != nil || gid == ^uint32(0) {
				return errors.New("GROUP_IDENTITY")
			}
			seen[p[0]] = Account{Name: p[0], GID: gid}
			if p[3] == "" {
				continue
			}
			members := map[string]bool{}
			for _, member := range strings.Split(p[3], ",") {
				if !namePattern.MatchString(member) || members[member] {
					return errors.New("GROUP_MEMBERS")
				}
				members[member] = true
				if member == user && p[0] != user && (allowed[p[0]].Name == "" || allowed[p[0]].GID != gid) {
					return fmt.Errorf("USER_OTHER_SUPPLEMENTARY_GROUP %s", p[0])
				}
			}
		}
	}
	// Successful status alone is insufficient: a known row missing or with a
	// different gid proves this listing cannot authorize paired removal.
	if !accountEqual(seen[group.action.Name], *group.identity.Account) {
		return fmt.Errorf("GROUP_INCOMPLETE %s", group.action.Name)
	}
	return checkPairEnumeration(known, seen, "GROUP")
}

func checkPairEnumeration(known, seen map[string]Account, prefix string) error {
	names := make([]string, 0, len(known))
	for name := range known {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !accountEqual(seen[name], known[name]) {
			return fmt.Errorf("%s_INCOMPLETE %s", prefix, name)
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
	if e := l.checkPairSupplementary(user.Name, group, false); e != nil {
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
	if e := l.checkPairPrimary(got.GID, nil); e != nil {
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
	if e := l.checkPairPrimary(want.Account.GID, nil); e != nil {
		return stopped("PAIRED_GROUP_PASSWD "+a.Name, e)
	}
	return l.recheckPairedGroup(authority{action: a, identity: want}, true)
}
