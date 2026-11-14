package g2ledger

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"
)

// CompareRow describes one difference, never secret content. Seq identifies the
// committed result that authorizes retention; its intent carries the policy.
type CompareRow struct {
	Type       string  `json:"type"`
	Object     string  `json:"object"`
	Difference string  `json:"difference"`
	Mode       string  `json:"mode"`
	Seq        *uint64 `json:"seq,omitempty"`
	Retention  string  `json:"retention,omitempty"`
	Rule       string  `json:"rule"`
}
type CompareSummary struct {
	ExcludedVolatile []string `json:"excluded_volatile"`
	Type             string   `json:"type"`
	Mode             string   `json:"mode"`
	Compared         int      `json:"compared"`
	Retained         int      `json:"retained"`
	Unlisted         int      `json:"unlisted"`
}

type authority struct {
	seq      uint64
	action   Action
	identity Identity
}

func (l *Ledger) authorities() map[string]authority {
	out := map[string]authority{}
	for _, r := range l.rows {
		if r.Body.Op != "commit" {
			continue
		}
		a := *l.rows[r.Body.Result.Intent].Body.Action
		for _, id := range r.Body.Result.Identities {
			name := a.Name
			if id.Path != "" {
				name = id.Path
			}
			if a.Kind == "membership" {
				continue
			}
			out[objectKey(a.Kind, name)] = authority{r.Seq, a, id}
		}
	}
	return out
}
func (l *Ledger) compareBaseline(mode string) error {
	g := l.rows[0].Body.Genesis
	auth := l.authorities()
	out := l.output
	if out == nil {
		out = io.Discard
	}
	summary := l.summary
	if summary == nil {
		summary = io.Discard
	}
	enc := json.NewEncoder(out)
	retained, unlisted, compared := 0, 0, 0
	first := ""
	emit := func(object, difference string, allowed *authority, rule string) error {
		row := CompareRow{Type: "unlisted_difference", Object: object, Difference: difference, Mode: mode, Rule: rule}
		if allowed != nil {
			row.Type = "retained"
			seq := allowed.seq
			row.Seq = &seq
			row.Retention = allowed.action.Ret
			retained++
		} else {
			unlisted++
			if first == "" {
				first = object
			}
		}
		if e := enc.Encode(row); e != nil {
			return stopped("COMPARE_OUTPUT", e)
		}
		return nil
	}
	// A keep rule explains presence only with the exact committed identity and
	// an absent S0 object. Existing objects never acquire retention authority.
	explain := func(key string, before, now *Identity) (*authority, string) {
		a, ok := auth[key]
		if !ok || now == nil {
			return nil, "no-retention-authority"
		}
		effect, rule := retentionPolicy(a.action.Kind, a.action.Ret, mode)
		if effect == "keep" && before == nil && identityEqual(*now, a.identity) {
			return &a, rule
		}
		if a.action.Kind == "modify" && before != nil && identityEqual(*before, a.action.Before[0]) && restoredIdentity(*now, a.action) {
			return &a, rule + "-replacement-inode-or-mtime"
		}
		return nil, "no-retention-authority"
	}
	for _, base := range g.S0 {
		key := objectKey(base.Kind, base.Name)
		compared++
		now, e := snapshotObject(base, l.sys, l.root, g.Baseline)
		if e != nil {
			return stopped("COMPARE_LOOKUP "+key, e)
		}
		if !bytes.Equal(canonical(base.Identity), canonical(now.Identity)) {
			a, rule := explain(key, base.Identity, now.Identity)
			if e = emit(key, "identity", a, rule); e != nil {
				return e
			}
		}
		// Parent and recorded-directory inventories are shallow. Each entry delta
		// must independently name an exact, retained child; no subtree wildcard.
		oldEntries := map[string]uint32{}
		newEntries := map[string]uint32{}
		for _, c := range base.Children {
			oldEntries[c.Name] = c.Type
		}
		for _, c := range now.Children {
			newEntries[c.Name] = c.Type
		}
		names := map[string]bool{}
		for n := range oldEntries {
			names[n] = true
		}
		for n := range newEntries {
			names[n] = true
		}
		ordered := make([]string, 0, len(names))
		for n := range names {
			ordered = append(ordered, n)
		}
		sort.Strings(ordered)
		for _, n := range ordered {
			if oldEntries[n] == newEntries[n] {
				continue
			}
			childKey := objectKey("file", filepath.Join(base.Name, n))
			var a *authority
			rule := "unrecorded-directory-entry"
			// Only an added name can represent a retained creation; a removed or
			// type-replaced S0 entry always remains unexplained.
			if oldEntries[n] == 0 {
				if candidate, ok := auth[childKey]; ok {
					id, err := observe(candidate.identity.Path, candidate.action.Kind)
					if err != nil {
						return stopped("COMPARE_LOOKUP "+childKey, err)
					}
					a, rule = explain(childKey, nil, id)
				}
			}
			if oldEntries[n] == 0 && base.Kind == "tree" {
				if owner, ok := auth[key]; ok && now.Identity != nil && identityEqual(*now.Identity, owner.identity) {
					if effect, keepRule := retentionPolicy("tree", owner.action.Ret, mode); effect == "keep" {
						a, rule = &owner, keepRule+"-tree-content"
					}
				}
			}
			if e = emit(childKey, "directory-entry", a, rule); e != nil {
				return e
			}
		}
		oldMembers := map[string]bool{}
		newMembers := map[string]bool{}
		for _, m := range base.Members {
			oldMembers[m] = true
		}
		for _, m := range now.Members {
			newMembers[m] = true
		}
		ms := map[string]bool{}
		for m := range oldMembers {
			ms[m] = true
		}
		for m := range newMembers {
			ms[m] = true
		}
		ordered = ordered[:0]
		for m := range ms {
			ordered = append(ordered, m)
		}
		sort.Strings(ordered)
		for _, m := range ordered {
			if oldMembers[m] != newMembers[m] {
				if e = emit(key+"/member:"+m, "group-member", nil, "unrecorded-group-membership"); e != nil {
					return e
				}
			}
		}
	}
	if e := enc.Encode(CompareSummary{Type: "baseline_summary", Mode: mode, Compared: compared, Retained: retained, Unlisted: unlisted, ExcludedVolatile: []string{"/run"}}); e != nil {
		return stopped("COMPARE_OUTPUT", e)
	}
	if _, e := fmt.Fprintf(summary, "g2-ledger: FINAL_BASELINE_COMPARE mode=%s retained=%d unlisted=%d excluded_volatile=/run\n", mode, retained, unlisted); e != nil {
		return stopped("COMPARE_SUMMARY", e)
	}
	if unlisted > 0 {
		return fail(1, "UNLISTED_DIFFERENCE "+first)
	}
	return nil
}
func restoredIdentity(id Identity, a Action) bool {
	return id.FS != nil && id.FS.SHA256 == a.BackupSHA256 && id.FS.UID == a.UID && id.FS.GID == a.GID && id.FS.Mode == a.Mode && id.FS.Size == a.Before[0].FS.Size
}
