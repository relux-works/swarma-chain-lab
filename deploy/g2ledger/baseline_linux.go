package g2ledger

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

func objectKey(kind, name string) string {
	if kind == "dir" || kind == "tree" || kind == "file" || kind == "secret" || kind == "modify" {
		return "path:" + name
	}
	return kind + ":" + name
}
func validateScope(s Scope) error {
	seen := map[string]bool{}
	add := func(k string) error {
		if seen[k] {
			return errors.New("DUPLICATE_SCOPE " + k)
		}
		seen[k] = true
		return nil
	}
	for _, p := range s.Paths {
		if !validPath(p.Path) || p.Kind != "dir" && p.Kind != "tree" && p.Kind != "file" && p.Kind != "secret" {
			return errors.New("SCOPE_PATH " + p.Path)
		}
		if e := targetPathPolicy(p.Path); e != nil {
			return e
		}
		if e := add(objectKey(p.Kind, p.Path)); e != nil {
			return e
		}
	}
	for _, tree := range s.Paths {
		if tree.Kind != "tree" {
			continue
		}
		for _, other := range s.Paths {
			if other.Path != tree.Path && (strings.HasPrefix(other.Path, tree.Path+"/") || strings.HasPrefix(tree.Path, other.Path+"/") && other.Kind == "tree") {
				return errors.New("TREE_SCOPE_OVERLAP " + tree.Path)
			}
		}
	}
	for kind, names := range map[string][]string{"user": s.Users, "group": s.Groups, "unit": s.Units} {
		for _, n := range names {
			valid := namePattern.MatchString(n)
			if kind == "unit" {
				valid = unitPattern.MatchString(n)
			}
			if !valid {
				return errors.New("SCOPE_NAME " + kind + ":" + n)
			}
			if e := add(objectKey(kind, n)); e != nil {
				return e
			}
		}
	}
	return nil
}
func scopeObjects(s Scope) ([]BaselineObject, error) {
	objects := map[string]BaselineObject{}
	for _, p := range s.Paths {
		objects[objectKey(p.Kind, p.Path)] = BaselineObject{Kind: p.Kind, Name: p.Path}
	}
	for _, p := range s.Paths {
		name := filepath.Dir(p.Path)
		k := objectKey("dir", name)
		if old, ok := objects[k]; ok && old.Kind != "dir" && old.Kind != "tree" {
			return nil, errors.New("SCOPE_PARENT_NOT_DIRECTORY " + name)
		}
		if _, ok := objects[k]; !ok {
			objects[k] = BaselineObject{Kind: "dir", Name: name}
		}
	}
	for kind, names := range map[string][]string{"user": s.Users, "group": s.Groups, "unit": s.Units} {
		for _, n := range names {
			objects[objectKey(kind, n)] = BaselineObject{Kind: kind, Name: n}
		}
	}
	keys := make([]string, 0, len(objects))
	for k := range objects {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]BaselineObject, 0, len(keys))
	for _, k := range keys {
		out = append(out, objects[k])
	}
	return out, nil
}
func excludedPath(path, ledger, baseline string) bool {
	if path == ledger || path == baseline {
		return true
	}
	err := targetPathPolicy(path)
	return errors.Is(err, errVolatileRuntime)
}
func snapshotObject(o BaselineObject, sys System, ledger, baseline string) (BaselineObject, error) {
	o.Identity = nil
	o.Children = nil
	o.Members = nil
	switch o.Kind {
	case "dir", "tree":
		d, e := openDir(o.Name)
		if errors.Is(e, unix.ENOENT) {
			return o, nil
		}
		if e != nil {
			return o, e
		}
		defer d.Close()
		// Snapshot parent permission bits too, including sticky directories.
		// This observation grants no mutation authority; creation still uses 0777.
		var st unix.Stat_t
		e = unix.Fstat(int(d.Fd()), &st)
		id := &FSIdentity{Dev: uint64(st.Dev), Ino: st.Ino, Type: "dir", Mode: st.Mode & 07777, UID: st.Uid, GID: st.Gid}
		if e != nil {
			return o, e
		}
		o.Identity = &Identity{Path: o.Name, FS: id}
		entries, e := d.ReadDir(-1)
		if e != nil {
			return o, e
		}
		sortEntries(entries)
		for _, entry := range entries {
			if excludedPath(filepath.Join(o.Name, entry.Name()), ledger, baseline) {
				continue
			}
			var st unix.Stat_t
			if e := unix.Fstatat(int(d.Fd()), entry.Name(), &st, unix.AT_SYMLINK_NOFOLLOW); e != nil {
				return o, e
			}
			o.Children = append(o.Children, DirectoryEntry{Name: entry.Name(), Type: st.Mode & unix.S_IFMT})
		}
	case "file", "secret":
		id, e := observe(o.Name, o.Kind)
		if e != nil {
			return o, e
		}
		o.Identity = id
	case "user", "group":
		a, members, e := lookup(sys, o.Kind, o.Name)
		if e != nil {
			return o, e
		}
		if a != nil {
			o.Identity = &Identity{Account: a}
			sort.Strings(members)
			if len(members) > 0 {
				o.Members = members
			}
		}
	case "unit":
		out, status, e := sys.Run("/usr/bin/systemctl", "is-enabled", o.Name)
		if e != nil {
			return o, e
		}
		state := strings.TrimSuffix(out, "\n")
		if state == "not-found" && status == 4 {
			return o, nil
		}
		if !(state == "enabled" && status == 0 || state == "disabled" && status == 1) {
			return o, fmt.Errorf("IS_ENABLED_UNEXPECTED_STATE_STATUS_%d", status)
		}
		o.Identity = &Identity{Unit: &Unit{Name: o.Name, State: state}}
	default:
		return o, errors.New("SCOPE_KIND")
	}
	return o, nil
}
func captureBaseline(s Scope, sys System, ledger, baseline string) ([]BaselineObject, error) {
	objects, e := scopeObjects(s)
	if e != nil {
		return nil, e
	}
	for _, p := range s.Paths {
		for _, protected := range []string{ledger, baseline} {
			if p.Path == protected || strings.HasPrefix(p.Path, protected+"/") || strings.HasPrefix(protected, p.Path+"/") {
				return nil, errors.New("SCOPE_STORAGE_OVERLAP " + p.Path)
			}
		}
	}
	for j, o := range objects {
		objects[j], e = snapshotObject(o, sys, ledger, baseline)
		if e != nil {
			return nil, fmt.Errorf("%s: %w", objectKey(o.Kind, o.Name), e)
		}
	}
	return objects, nil
}
func validateBaseline(g *Genesis) error {
	if e := validateScope(g.Scope); e != nil {
		return e
	}
	objects, e := scopeObjects(g.Scope)
	if e != nil {
		return e
	}
	if len(objects) != len(g.S0) {
		return errors.New("S0_COUNT")
	}
	for j, want := range objects {
		got := g.S0[j]
		if got.Kind != want.Kind || got.Name != want.Name {
			return errors.New("S0_SCOPE")
		}
		if got.Identity == nil {
			if len(got.Children) > 0 || len(got.Members) > 0 {
				return errors.New("S0_ABSENT_FIELDS")
			}
			continue
		}
		id := *got.Identity
		if got.Kind == "user" {
			if id.Account == nil || id.FS != nil || id.Membership != nil || id.Unit != nil || id.Path != "" || !namePattern.MatchString(id.Account.Name) || id.Account.UID == ^uint32(0) || id.Account.GID == ^uint32(0) || !strings.HasPrefix(id.Account.Shell, "/") {
				return errors.New("S0_USER")
			}
		} else if e := validateIdentity(id, got.Kind); e != nil {
			return e
		}
		switch got.Kind {
		case "dir", "tree", "file", "secret":
			if got.Identity.Path != got.Name {
				return errors.New("S0_PATH")
			}
		case "user", "group":
			if got.Identity.Account.Name != got.Name {
				return errors.New("S0_ACCOUNT")
			}
		case "unit":
			if got.Identity.Unit.Name != got.Name {
				return errors.New("S0_UNIT")
			}
		}
		if got.Kind != "dir" && got.Kind != "tree" && len(got.Children) > 0 || got.Kind != "group" && len(got.Members) > 0 {
			return errors.New("S0_EXTRA")
		}
		prev := ""
		for _, child := range got.Children {
			if child.Name <= prev || child.Name == "." || child.Name == ".." || strings.ContainsAny(child.Name, "/\x00") || child.Type == 0 || child.Type & ^uint32(unix.S_IFMT) != 0 {
				return errors.New("S0_CHILD")
			}
			prev = child.Name
		}
		prev = ""
		for _, member := range got.Members {
			if !namePattern.MatchString(member) || member <= prev {
				return errors.New("S0_MEMBER")
			}
			prev = member
		}
	}
	return nil
}
func actionAllowed(g Genesis, a Action) error {
	if e := stationRetentionAllowed(g, a); e != nil {
		return e
	}
	if a.Ret == "rehearsal" && g.Purpose != "rehearsal" {
		return namedError("REHEARSAL_RETENTION_REQUIRES_REHEARSAL_PURPOSE", a)
	}
	allowed := func(kind, name string) bool {
		if kind == "modify" {
			kind = "file"
		}
		for _, p := range g.Scope.Paths {
			if p.Path == name && p.Kind == kind {
				return true
			}
		}
		names := g.Scope.Users
		if kind == "group" {
			names = g.Scope.Groups
		}
		if kind == "unit" {
			names = g.Scope.Units
		}
		if kind == "user" || kind == "group" || kind == "unit" {
			for _, n := range names {
				if n == name {
					return true
				}
			}
		}
		return false
	}
	if a.Kind == "membership" {
		if !allowed("user", a.User) || !allowed("group", a.Group) {
			return namedError("TARGET_OUTSIDE_INIT_SCOPE", a)
		}
		return nil
	}
	if len(a.Paths) > 0 {
		for _, p := range a.Paths {
			if !allowed(a.Kind, p) {
				return namedError("TARGET_OUTSIDE_INIT_SCOPE", a)
			}
		}
		return nil
	}
	if !allowed(a.Kind, a.Name) {
		return namedError("TARGET_OUTSIDE_INIT_SCOPE", a)
	}
	return nil
}
