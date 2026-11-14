package g2ledger

import (
	"path/filepath"
	"strings"
)

func forbiddenTreeID(id uint32) bool {
	return id == 0 || id == 1000 || id == 210001 || id == 210101 || id == 210201 || id == 210301 || id == ^uint32(0)
}
func validTreeRelative(name string) bool {
	return name != "" && name != "." && !filepath.IsAbs(name) && filepath.Clean(name) == name && name != ".." && !strings.HasPrefix(name, "../") && !strings.ContainsAny(name, "\x00\r\n")
}

// treeAuthority is checked both before durable intent and while loading the
// complete chain. A current account lookup or an S0 absence is never authority.
func treeAuthority(a Action, rows []Record) error {
	if a.Kind == "tree" {
		found := false
		for _, row := range rows {
			if row.Body.Op != "commit" {
				continue
			}
			old := rows[row.Body.Result.Intent].Body.Action
			if old.Kind == "user" && old.Name == a.User && accountEqual(*row.Body.Result.Identities[0].Account, *a.Before[0].Account) {
				if old.Role != "tree-owner" {
					return namedError("TREE_OWNER_NOT_DEDICATED", a)
				}
				found = true
			}
			if old.Kind == "membership" && old.User == a.User || len(old.Paths) > 0 && old.Kind != "tree" && old.UID == a.UID {
				return namedError("TREE_OWNER_NOT_DEDICATED", a)
			}
		}
		if !found {
			return namedError("TREE_OWNER_NOT_CREATED", a)
		}
	}
	// The committed role dedicates the account before its first tree.
	// Once dedicated to trees, the account cannot acquire another recorded role
	// or a separately managed directory/file in this attempt.
	for _, row := range rows {
		if row.Body.Op != "commit" {
			continue
		}
		old := rows[row.Body.Result.Intent].Body.Action
		if old.Kind == "user" && old.Role == "tree-owner" && (a.Kind == "membership" && a.User == old.Name || len(a.Paths) > 0 && a.Kind != "tree" && a.UID == old.UID) {
			return namedError("TREE_OWNER_NOT_DEDICATED", a)
		}
		if old.Kind == "tree" && (a.Kind == "membership" && a.User == old.User || len(a.Paths) > 0 && a.Kind != "tree" && a.UID == old.UID) {
			return namedError("TREE_OWNER_NOT_DEDICATED", a)
		}
	}
	return nil
}
