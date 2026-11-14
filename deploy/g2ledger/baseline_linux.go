package g2ledger

import (
	"errors"
	"fmt"
	"os"
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
	if s.Reused == nil {
		return errors.New("REUSED_SET_REQUIRED")
	}
	reused := map[string]bool{}
	for _, path := range s.Reused {
		if path != "/" && !validPath(path) || reused[path] {
			return errors.New("REUSED_PATH_INVALID_OR_DUPLICATE " + path)
		}
		if e := targetPathPolicy(path); e != nil {
			return e
		}
		reused[path] = true
	}
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
	for _, path := range s.Reused {
		k := objectKey("dir", path)
		if old, ok := objects[k]; ok && old.Kind != "dir" && old.Kind != "tree" {
			return nil, errors.New("REUSED_NOT_DIRECTORY " + path)
		}
		if _, ok := objects[k]; !ok {
			objects[k] = BaselineObject{Kind: "dir", Name: path}
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
	o.Metadata = nil
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
		o.Metadata = baselineMetadata(st)
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
		var after unix.Stat_t
		if e := unix.Fstat(int(d.Fd()), &after); e != nil {
			return o, e
		}
		if !stableStat(st, after) {
			return o, errors.New("BASELINE_DIRECTORY_CHANGED")
		}
	case "file", "secret":
		id, metadata, e := observeBaselineFile(o.Name, o.Kind)
		if e != nil {
			return o, e
		}
		o.Identity = id
		o.Metadata = metadata
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
			for _, path := range s.Reused {
				if path == o.Name {
					return nil, fmt.Errorf("REUSED_DIRECTORY_LOOKUP %s: %w", path, e)
				}
			}
			return nil, fmt.Errorf("%s: %w", objectKey(o.Kind, o.Name), e)
		}
	}
	if e := validateReused(s, objects); e != nil {
		return nil, e
	}
	if e := validateProspectiveReused(s, sys); e != nil {
		return nil, e
	}
	return objects, nil
}

// Declaration use is checked at init, before any effect. File replacement
// temporaries share the declared file's immediate parent; they add no ancestor
// authority. Unit links and absent install directories come from the engine's
// install plan, never from the operations an interrupted attempt reached.
func validateProspectiveReused(s Scope, sys System) error {
	parents := map[string]bool{}
	for _, path := range s.Paths {
		parents[filepath.Dir(path.Path)] = true
	}
	needsUnitPlan := false
	for _, path := range s.Reused {
		needsUnitPlan = needsUnitPlan || !parents[path]
	}
	if needsUnitPlan {
		for _, name := range s.Units {
			plan, err := expectedUnitInstall(sys, name)
			if err != nil {
				return fmt.Errorf("REUSED_PROSPECTIVE_UNIT_PLAN %s: %w", name, err)
			}
			for _, link := range plan.Expected {
				dir := filepath.Dir(link.Path)
				for {
					parents[dir] = true
					st, err := os.Lstat(dir)
					if err == nil {
						if !st.IsDir() {
							return errors.New("UNIT_LINK_PARENT_NOT_DIRECTORY " + dir)
						}
						break
					}
					if !errors.Is(err, os.ErrNotExist) {
						return err
					}
					// Creating this absent directory is itself a prospective entry.
					dir = filepath.Dir(dir)
				}
			}
		}
	}
	for _, path := range s.Reused {
		if !parents[path] {
			return errors.New("REUSED_PARENT_NOT_PROSPECTIVE " + path)
		}
	}
	return nil
}
func baselineMetadata(st unix.Stat_t) *BaselineMetadata {
	return &BaselineMetadata{Size: st.Size, MtimeNS: st.Mtim.Sec*1e9 + st.Mtim.Nsec, CtimeNS: st.Ctim.Sec*1e9 + st.Ctim.Nsec}
}
func validateReused(s Scope, objects []BaselineObject) error {
	for _, path := range s.Reused {
		found := false
		for _, o := range objects {
			if o.Name == path && (o.Kind == "dir" || o.Kind == "tree") && o.Identity != nil && o.Identity.FS != nil && o.Metadata != nil {
				found = true
			}
		}
		if !found {
			return errors.New("REUSED_NOT_BASELINE_DIRECTORY " + path)
		}
	}
	return nil
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
	if e := validateReused(g.Scope, g.S0); e != nil {
		return e
	}
	for j, want := range objects {
		got := g.S0[j]
		if got.Kind != want.Kind || got.Name != want.Name {
			return errors.New("S0_SCOPE")
		}
		if got.Identity == nil {
			if got.Metadata != nil || len(got.Children) > 0 || len(got.Members) > 0 {
				return errors.New("S0_ABSENT_FIELDS")
			}
			continue
		}
		if (got.Identity.FS != nil) != (got.Metadata != nil) || got.Metadata != nil && got.Metadata.Size < 0 {
			return errors.New("S0_METADATA")
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

func observeBaselineFile(path, kind string) (*Identity, *BaselineMetadata, error) {
	d, n, e := parent(path)
	if errors.Is(e, unix.ENOENT) {
		return nil, nil, nil
	}
	if e != nil {
		return nil, nil, e
	}
	defer d.Close()
	f, e := at(d, n, unix.O_RDONLY, 0)
	if errors.Is(e, unix.ENOENT) {
		return nil, nil, nil
	}
	if e != nil {
		return nil, nil, e
	}
	defer f.Close()
	var before, after unix.Stat_t
	if e := unix.Fstat(int(f.Fd()), &before); e != nil {
		return nil, nil, e
	}
	id, e := fsIdentity(f, kind)
	if e != nil {
		return nil, nil, e
	}
	if e := unix.Fstat(int(f.Fd()), &after); e != nil {
		return nil, nil, e
	}
	if !stableStat(before, after) {
		return nil, nil, errors.New("BASELINE_FILE_CHANGED")
	}
	return &Identity{Path: path, FS: id}, baselineMetadata(after), nil
}
