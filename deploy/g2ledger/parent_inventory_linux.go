package g2ledger

import (
	"bytes"
	"path/filepath"
	"sort"
)

// Inventory includes every recorded entry parent, even outside the input scope.
// A first sealed before snapshot can expose an undeclared parent, never authorize it.
func (l *Ledger) parentInventory() map[string]BaselineObject {
	out := map[string]BaselineObject{}
	for _, base := range l.rows[0].Body.Genesis.S0 {
		if base.Kind == "dir" || base.Kind == "tree" {
			out[base.Name] = base
		}
	}
	for _, row := range l.rows {
		if row.Body.Op != "commit" {
			continue
		}
		for _, receipt := range row.Body.Result.Parents {
			if _, ok := out[receipt.Before.Name]; !ok {
				out[receipt.Before.Name] = receipt.Before
			}
		}
		for _, id := range row.Body.Result.Identities {
			if id.Unit != nil {
				for _, dir := range id.Unit.Directories {
					if _, ok := out[dir.Path]; !ok {
						out[dir.Path] = BaselineObject{Kind: "dir", Name: dir.Path}
					}
				}
			}
		}
	}
	// Parents of all ledger entries are checked even if a damaged receipt omitted them.
	for path := range l.touchedParents() {
		if _, ok := out[path]; !ok {
			out[path] = BaselineObject{Kind: "dir", Name: path}
		}
	}
	return out
}
func (l *Ledger) createdDirectories() map[string]Identity {
	out := map[string]Identity{}
	for _, a := range l.authorities() {
		if a.identity.FS != nil && a.identity.FS.Type == "dir" {
			out[a.identity.Path] = a.identity
		}
		if a.identity.Unit != nil {
			for _, dir := range a.identity.Unit.Directories {
				out[dir.Path] = dir
			}
		}
	}
	return out
}
func orderedParents(in map[string]BaselineObject) []BaselineObject {
	names := make([]string, 0, len(in))
	for name := range in {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]BaselineObject, 0, len(names))
	for _, name := range names {
		out = append(out, in[name])
	}
	return out
}
func (l *Ledger) touchedParents() map[string]bool {
	out := map[string]bool{}
	for _, row := range l.rows {
		if row.Body.Op != "commit" {
			continue
		}
		a := l.rows[row.Body.Result.Intent].Body.Action
		for _, path := range a.Paths {
			out[filepath.Dir(path)] = true
		}
		for _, receipt := range row.Body.Result.Parents {
			for _, path := range receipt.Temporary {
				out[filepath.Dir(path)] = true
			}
		}
		for _, id := range row.Body.Result.Identities {
			if id.Unit != nil {
				for _, link := range id.Unit.Links {
					out[filepath.Dir(link.Path)] = true
				}
				for _, dir := range id.Unit.Directories {
					out[filepath.Dir(dir.Path)] = true
				}
			}
		}
	}
	return out
}
func (l *Ledger) checkUnitParent(dir string) error {
	if err := l.checkEntryParent(dir); err != nil {
		return fail(1, "UNIT_LINK_PARENT_NOT_DECLARED "+dir)
	}
	return nil
}
func (l *Ledger) checkEntryParent(dir string) error {
	for _, base := range l.rows[0].Body.Genesis.S0 {
		if base.Name == dir && base.Identity != nil && base.Identity.FS != nil && base.Identity.FS.Type == "dir" {
			for _, reused := range l.rows[0].Body.Genesis.Scope.Reused {
				if reused == dir {
					return nil
				}
			}
		}
	}
	// An attempt-created directory grants authority only for its exact live identity.
	if id, ok := l.createdDirectories()[dir]; ok {
		now, err := observe(dir, "dir")
		if err == nil && now != nil && liveIdentityEqual(*now, id) {
			return nil
		}
	}
	return fail(1, "ENTRY_PARENT_NOT_DECLARED "+dir)
}
func (l *Ledger) parentFinalStable(base, now BaselineObject, mode string) bool {
	if parentStable(base, now) {
		return true
	}
	if mode != "station" || !bytes.Equal(canonical(base.Identity), canonical(now.Identity)) || base.Metadata == nil || now.Metadata == nil {
		return false
	}
	before, after := map[string]uint32{}, map[string]uint32{}
	for _, e := range base.Children {
		before[e.Name] = e.Type
	}
	for _, e := range now.Children {
		after[e.Name] = e.Type
	}
	auth := l.authorities()
	changed := false
	for name, kind := range before {
		if after[name] != kind {
			return false
		}
	}
	for name, kind := range after {
		if before[name] == kind {
			continue
		}
		changed = true
		path := filepath.Join(base.Name, name)
		a, ok := auth[objectKey("file", path)]
		if !ok {
			return false
		}
		effect, _ := retentionPolicy(a.action.Kind, a.action.Ret, mode)
		if effect != "keep" {
			return false
		}
		id, err := observe(path, a.action.Kind)
		if err != nil || id == nil || !liveIdentityEqual(*id, a.identity) {
			return false
		}
	}
	return changed
}
