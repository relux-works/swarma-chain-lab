//go:build linux

package g2run

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/relux-works/swarma-chain-lab/deploy/g2ledger"
)

// StagedUnitSpec binds an instance's staged unit; Pin is required for upstream
// units and may be empty for a unit rendered from the verified release.
type StagedUnitSpec struct{ Name, RelativeSource, Pin string }

// ScopeSpec supplies instance paths/accounts from parameters. Paths may contain
// @VERSION@, expanded only by Go using the verified commit's first 12 hex digits.
// CompileInstallScope builds the fixed port shapes; the concrete engine plan
// will supply its layout from decoded instance parameters once E2 lands.
type ScopeSpec struct {
	Purpose, Commit, Stage        string
	UnitDirectory, WantsDirectory string
	Paths                         []g2ledger.ScopePath
	Users, Groups, Reused         []string
	Units                         []StagedUnitSpec
	Node                          *g2ledger.NodeScope
}

func portPurpose(p string) bool { return p == "station" || p == "rehearsal" }
func portUnit(p string) bool {
	return len(p) <= 256 && strings.HasSuffix(p, ".service") && strings.Trim(p, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.@") == ""
}
func portAccount(p string) bool {
	return p != "" && len(p) <= 32 && p[0] != '-' && strings.Trim(p, "abcdefghijklmnopqrstuvwxyz0123456789_-") == ""
}
func installLines(body []byte) []string {
	out := []string{}
	inside := false
	for _, line := range strings.Split(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n") {
		if strings.HasPrefix(line, "[") {
			inside = strings.TrimSpace(line) == "[Install]"
			continue
		}
		if inside {
			for _, key := range []string{"WantedBy=", "RequiredBy=", "UpheldBy=", "Alias=", "Also="} {
				if strings.HasPrefix(line, key) {
					out = append(out, strings.TrimSpace(line))
					break
				}
			}
		}
	}
	return out
}

// BuildScope ports the source generator's parent closure, volatile-path ban,
// future-unit hashing, staged Install checks, purpose split and node declaration.
func BuildScope(fs PortFS, s ScopeSpec) (g2ledger.Scope, error) {
	var out g2ledger.Scope
	fail := func(s string) (g2ledger.Scope, error) { return g2ledger.Scope{}, errors.New("SCOPE_" + s) }
	if !portPurpose(s.Purpose) {
		return fail("PURPOSE")
	}
	if !portHex(s.Commit, 40) {
		return fail("COMMIT")
	}
	if !portAbs(s.UnitDirectory) || !portAbs(s.WantsDirectory) {
		return fail("UNIT_ROOTS")
	}
	if !portAbs(s.Stage) || s.Stage == "/" || !fs.allowed(s.Stage) {
		return fail("STAGE")
	}
	declared, parents := map[string]bool{}, map[string]bool{}
	for _, p := range s.Paths {
		p.Path = strings.ReplaceAll(p.Path, "@VERSION@", s.Commit[:12])
		if !portAbs(p.Path) || p.Path == "/" || strings.Contains(p.Path, "@") {
			return fail("PATH")
		}
		if p.Path == "/run" || strings.HasPrefix(p.Path, "/run/") {
			return fail("VOLATILE_PATH")
		}
		if declared[p.Path] {
			return fail("DUPLICATE_PATH")
		}
		if p.Kind != "dir" && p.Kind != "file" && p.Kind != "secret" {
			return fail("PATH_KIND")
		}
		declared[p.Path] = true
		parents[filepath.Dir(p.Path)] = true
		out.Paths = append(out.Paths, p)
	}
	seen := map[string]bool{}
	for _, u := range s.Units {
		if !portUnit(u.Name) || seen[u.Name] || !validPackagePath(u.RelativeSource) {
			return fail("UNIT")
		}
		seen[u.Name] = true
		source := filepath.Join(s.Stage, u.RelativeSource)
		body, e := fs.read(source)
		if e != nil {
			return fail("STAGED_SOURCE")
		}
		if !utf8.Valid(body) {
			return fail("STAGED_UTF8")
		}
		if bytes.ContainsRune(body, '@') {
			return fail("UNFILLED_TOKEN")
		}
		lines := installLines(body)
		if len(lines) != 1 || lines[0] != "WantedBy=multi-user.target" {
			return fail("INSTALL")
		}
		digest := sha256.Sum256(body)
		sha := hex.EncodeToString(digest[:])
		if u.Pin != "" && (!portHex(u.Pin, 64) || sha != u.Pin) {
			return fail("UNIT_PIN")
		}
		unitPath := s.UnitDirectory + "/" + u.Name
		if !declared[unitPath] {
			return fail("UNIT_UNDECLARED")
		}
		future := g2ledger.FutureUnit{Name: u.Name, Source: source, SHA256: sha, Links: []g2ledger.FutureUnitLink{}}
		if s.Purpose == "station" {
			link := s.WantsDirectory + "/" + u.Name
			parents[filepath.Dir(link)] = true
			future.Links = append(future.Links, g2ledger.FutureUnitLink{Path: link, Target: unitPath})
		}
		out.Units = append(out.Units, u.Name)
		out.FutureUnits = append(out.FutureUnits, future)
	}
	if len(out.Units) == 0 || len(out.Paths) == 0 {
		return fail("EMPTY")
	}
	reused := map[string]bool{}
	for _, r := range s.Reused {
		if !portAbs(r) || reused[r] {
			return fail("REUSED")
		}
		reused[r] = true
		out.Reused = append(out.Reused, r)
	}
	for p := range parents {
		if !declared[p] && !reused[p] {
			return fail("MISSING_REUSED_PARENT")
		}
	}
	for r := range reused {
		if !parents[r] {
			return fail("UNUSED_REUSED_PARENT")
		}
	}
	for i, accounts := range [][]string{s.Users, s.Groups} {
		seen := map[string]bool{}
		dst := []string{}
		for _, a := range accounts {
			if !portAccount(a) || seen[a] {
				return fail("ACCOUNT")
			}
			seen[a] = true
			dst = append(dst, a)
		}
		sort.Strings(dst)
		if i == 0 {
			out.Users = dst
		} else {
			out.Groups = dst
		}
	}
	if s.Purpose == "station" {
		if s.Node == nil || !portUnit(s.Node.Unit) || !portAbs(s.Node.Config) || !portAbs(s.Node.Preimage) || !declared[s.Node.Config] || seen[s.Node.Unit] {
			return fail("NODE")
		}
		n := *s.Node
		out.Node = &n
	} else if s.Node != nil {
		return fail("REHEARSAL_NODE")
	}
	sort.Slice(out.Paths, func(i, j int) bool { return out.Paths[i].Path < out.Paths[j].Path })
	sort.Strings(out.Reused)
	sort.Strings(out.Units)
	sort.Slice(out.FutureUnits, func(i, j int) bool { return out.FutureUnits[i].Name < out.FutureUnits[j].Name })
	return out, nil
}

// WriteScope writes sorted, compact JSON with a newline, privately and exclusively.
func WriteScope(fs PortFS, s ScopeSpec, out string) error {
	scope, e := BuildScope(fs, s)
	if e != nil {
		return e
	}
	raw, e := json.Marshal(scope)
	if e != nil {
		return e
	}
	var sorted any
	if e = json.Unmarshal(raw, &sorted); e != nil {
		return e
	}
	raw, e = json.Marshal(sorted)
	if e != nil {
		return e
	}
	return fs.writeAtomic(out, append(raw, '\n'), 0600)
}
