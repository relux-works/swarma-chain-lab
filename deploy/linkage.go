package deploy

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"slices"
	"strings"
)

// StrictParseCommit is a reviewed release input, never inferred from version order.
const StrictParseCommit = "e70a35a41dec5948d5452f1f898f4d26977372d7"
const internalModulePrefix = "github.com/relux-works/swarma-chain-lab/"
const strictVerdict = "contains " + StrictParseCommit

type ModuleLinkage struct {
	Module  string `json:"module"`
	Version string `json:"version,omitempty"`
	Replace string `json:"replace,omitempty"` // Checkout-relative directory, never an absolute build path.
	Commit  string `json:"commit"`
	Verdict string `json:"verdict"`
}

type BinaryLinkage struct {
	Binary  string          `json:"binary"`
	Modules []ModuleLinkage `json:"modules"`
}

type linkageFunc func(context.Context, string, Artifact, []byte) ([]ModuleLinkage, error)

// Only allow public module/version tokens in refusal diagnostics.
func linkageFailure(binary, module, version string) error {
	safe := func(s string) string {
		if s == "" || strings.ContainsAny(s, "\r\n\t ") || strings.HasPrefix(s, "/") || strings.Contains(s, "..") {
			return "unresolved"
		}
		return s
	}
	return fmt.Errorf("LINKAGE_STRICT_PARSE_MISSING %s %s %s", safe(binary), safe(module), safe(version))
}

// Refuse local history overlays explicitly as well as disabling them in git().
// This diagnoses a tainted build checkout before any ancestry decision.
func linkageOriginalHistory(ctx context.Context, repo string) error {
	refs, e := git(ctx, repo, "for-each-ref", "--format=%(refname)", "refs/replace/")
	if e != nil {
		return fmt.Errorf("LINKAGE_HISTORY_REQUIRED: cannot inspect replacement refs")
	}
	if len(bytes.TrimSpace(refs)) != 0 {
		return fmt.Errorf("LINKAGE_REPLACE_REFS_REFUSED: refs/replace history is not a release input")
	}
	grafts, e := git(ctx, repo, "rev-parse", "--git-common-dir")
	if e != nil {
		return fmt.Errorf("LINKAGE_HISTORY_REQUIRED: cannot inspect grafts")
	}
	path := filepath.Join(strings.TrimSpace(string(grafts)), "info", "grafts")
	if !filepath.IsAbs(path) {
		path = filepath.Join(repo, path)
	}
	if _, e = os.Lstat(path); e == nil {
		return fmt.Errorf("LINKAGE_GRAFTS_REFUSED: graft history is not a release input")
	} else if !os.IsNotExist(e) {
		return fmt.Errorf("LINKAGE_HISTORY_REQUIRED: cannot inspect grafts")
	}
	return nil
}

func linkageHistory(ctx context.Context, repo, commit string) error {
	if e := linkageOriginalHistory(ctx, repo); e != nil {
		return e
	}
	shallow, e := git(ctx, repo, "rev-parse", "--is-shallow-repository")
	if e != nil || strings.TrimSpace(string(shallow)) != "false" {
		return fmt.Errorf("LINKAGE_HISTORY_REQUIRED: full Git history required; clone without --depth or fetch --unshallow before building")
	}
	if _, e = git(ctx, repo, "merge-base", "--is-ancestor", StrictParseCommit, commit); e != nil {
		return linkageFailure("checkout", internalModulePrefix, commit)
	}
	return nil
}

var pseudoCommit = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+-(?:[0-9A-Za-z.-]+\.)?[0-9]{14}-([0-9a-f]{12,40})(?:\+incompatible)?$`)
var releaseVersion = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+incompatible)?$`)

func internalModule(path string) bool {
	return path == strings.TrimSuffix(internalModulePrefix, "/") || strings.HasPrefix(path, internalModulePrefix)
}

func containedDirectory(root, dir string) (string, bool) {
	canonical, e := filepath.EvalSymlinks(dir)
	if e != nil {
		return "", false
	}
	relative, e := filepath.Rel(root, canonical)
	return filepath.ToSlash(relative), e == nil && filepath.IsLocal(relative)
}

func inspectLinkage(ctx context.Context, repo, root, commit string, a Artifact, binary []byte) ([]ModuleLinkage, error) {
	info, e := buildinfo.Read(bytes.NewReader(binary))
	if e != nil {
		return nil, linkageFailure(a.Binary, "build-info", "unavailable")
	}
	if info.Main.Path != internalModulePrefix+a.Module || info.Main.Replace != nil || info.Main.Version != "(devel)" {
		return nil, linkageFailure(a.Binary, "build-info", "unexpected-main-module")
	}
	return selectedLinkage(ctx, repo, root, commit, a, info)
}

func selectedLinkage(ctx context.Context, repo, root, commit string, a Artifact, info *debug.BuildInfo) ([]ModuleLinkage, error) {
	var rows []ModuleLinkage
	modules := append([]*debug.Module{&info.Main}, info.Deps...)
	for i, module := range modules {
		if !internalModule(module.Path) {
			continue
		}
		row := ModuleLinkage{Module: module.Path, Version: module.Version, Verdict: strictVerdict}
		selected := module
		if module.Replace != nil {
			selected = module.Replace
		}
		if i == 0 && module.Version == "(devel)" && module.Replace == nil {
			// The command's main module is compiled from this exact archive at H.
			relative, ok := containedDirectory(root, filepath.Join(root, filepath.FromSlash(a.Module)))
			if !ok || module.Path != internalModulePrefix+a.Module {
				return nil, linkageFailure(a.Binary, module.Path, module.Version)
			}
			row.Replace, row.Commit = relative, commit
		} else if module.Replace != nil && (selected.Version == "" || selected.Version == "(devel)") {
			// Go resolves a directory replacement relative to the command's module.
			dir := selected.Path
			if !filepath.IsAbs(dir) {
				dir = filepath.Join(root, filepath.FromSlash(a.Module), dir)
			}
			relative, ok := containedDirectory(root, dir)
			if !ok {
				return nil, linkageFailure(a.Binary, module.Path, "outside-checkout")
			}
			row.Replace, row.Commit = relative, commit
		} else {
			// Replacing an internal module with an unrelated published module cannot
			// attest to this repository's strict change, even if its version looks new.
			if !internalModule(selected.Path) {
				return nil, linkageFailure(a.Binary, module.Path, selected.Version)
			}
			row.Version = selected.Version
			revision := ""
			if match := pseudoCommit.FindStringSubmatch(selected.Version); match != nil {
				revision = match[1]
			} else if releaseVersion.MatchString(selected.Version) {
				revision = "refs/tags/" + strings.TrimPrefix(selected.Path, internalModulePrefix) + "/" + selected.Version
			}
			if revision == "" {
				return nil, linkageFailure(a.Binary, module.Path, selected.Version)
			}
			resolved, e := git(ctx, repo, "rev-parse", "--verify", revision+"^{commit}")
			if e != nil {
				return nil, linkageFailure(a.Binary, module.Path, selected.Version)
			}
			row.Commit = strings.TrimSpace(string(resolved))
			if _, e = git(ctx, repo, "merge-base", "--is-ancestor", StrictParseCommit, row.Commit); e != nil {
				return nil, linkageFailure(a.Binary, module.Path, selected.Version)
			}
		}
		rows = append(rows, row)
	}
	slices.SortFunc(rows, func(a, b ModuleLinkage) int { return strings.Compare(a.Module, b.Module) })
	if len(rows) == 0 {
		return nil, linkageFailure(a.Binary, "build-info", "no-internal-modules")
	}
	return rows, nil
}

func validLinkage(m Manifest) bool {
	inventory := append([]Artifact(nil), m.Artifacts...)
	for _, tool := range m.Tools {
		inventory = append(inventory, Artifact{Binary: tool.Binary, Module: tool.Module})
	}
	if len(m.Linkage) != len(inventory) {
		return false
	}
	for i, binary := range m.Linkage {
		if binary.Binary != inventory[i].Binary || len(binary.Modules) == 0 {
			return false
		}
		previous, main := "", false
		for _, module := range binary.Modules {
			if !internalModule(module.Module) || module.Module <= previous || !exactHex(module.Commit, 20) || module.Verdict != strictVerdict {
				return false
			}
			if module.Replace != "" {
				if !filepath.IsLocal(module.Replace) || filepath.ToSlash(filepath.Clean(module.Replace)) != module.Replace || module.Commit != m.Commit {
					return false
				}
			} else if module.Version == "" || module.Version == "(devel)" {
				return false
			}
			if module.Module == internalModulePrefix+inventory[i].Module {
				main = true
			}
			previous = module.Module
		}
		if !main {
			return false
		}
	}
	return true
}
