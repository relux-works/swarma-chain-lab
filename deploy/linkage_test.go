package deploy

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime/debug"
	"strings"
	"testing"
)

const oldRentalVersion = "v0.5.1-0.20261114150118-3baa201bafb6"
const strictRentalVersion = "v0.5.1-0.20261114210947-e70a35a41dec"

func linkageRepo(t *testing.T) string {
	t.Helper()
	b, e := git(context.Background(), ".", "rev-parse", "--show-toplevel")
	if e != nil {
		t.Fatal(e)
	}
	return strings.TrimSpace(string(b))
}

// A private clone keeps history plants out of the source checkout.
func linkageHistoryFixture(t *testing.T) (string, string, string) {
	t.Helper()
	repo := filepath.Join(directory(t), "history")
	c := exec.Command("git", "clone", "--quiet", "--no-local", linkageRepo(t), repo)
	if b, e := c.CombinedOutput(); e != nil {
		t.Fatalf("clone: %v %s", e, b)
	}
	old, e := git(context.Background(), repo, "rev-parse", "3baa201bafb6^{commit}")
	if e != nil {
		t.Fatal(e)
	}
	head, e := git(context.Background(), repo, "rev-parse", "HEAD")
	if e != nil {
		t.Fatal(e)
	}
	return repo, strings.TrimSpace(string(old)), strings.TrimSpace(string(head))
}

func linkageHistoryPlant(t *testing.T, repo, old, head, mode string) {
	t.Helper()
	if mode == "replace" {
		if _, e := git(context.Background(), repo, "update-ref", "refs/replace/"+old, head); e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { _, _ = git(context.Background(), repo, "update-ref", "-d", "refs/replace/"+old) })
	} else {
		path := filepath.Join(repo, ".git", "info", "grafts")
		if e := os.WriteFile(path, []byte(old+" "+StrictParseCommit+"\n"), 0600); e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { _ = os.Remove(path) })
	}
	// Establish the plant actually falsifies ancestry with ordinary Git.
	c := exec.Command("git", "merge-base", "--is-ancestor", StrictParseCommit, old)
	c.Dir = repo
	c.Env = []string{"PATH=" + os.Getenv("PATH"), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null"}
	if b, e := c.CombinedOutput(); e != nil {
		t.Fatalf("history plant ineffective: %v %s", e, b)
	}
}

// Claim: every Git query ignores effective replacement/graft plants; the public
// release entry point also names and refuses each plant before compiling or publishing.
func TestLinkageOriginalHistoryRelease(t *testing.T) {
	repo, old, head := linkageHistoryFixture(t)
	if e := linkageHistory(context.Background(), repo, head); e != nil {
		t.Fatalf("valid history control: %v", e)
	}
	for _, mode := range []string{"replace", "graft"} {
		t.Run(mode, func(t *testing.T) {
			linkageHistoryPlant(t, repo, old, head, mode)
			if _, e := git(context.Background(), repo, "merge-base", "--is-ancestor", StrictParseCommit, old); e == nil {
				t.Fatal("original-history query accepted stale commit")
			}
			out := filepath.Join(directory(t), "release")
			_, e := BuildRelease(context.Background(), ReleaseInput{Repo: repo, Commit: head, Out: out})
			witness := "LINKAGE_REPLACE_REFS_REFUSED"
			if mode == "graft" {
				witness = "LINKAGE_GRAFTS_REFUSED"
			}
			if e == nil || !strings.Contains(e.Error(), witness) {
				t.Fatalf("required named history refusal absent: %v", e)
			}
			if _, e := os.Stat(out); !os.IsNotExist(e) {
				t.Fatal("history refusal wrote release layout")
			}
		})
	}
}

// Claim: inherited Git repository/object/config/replacement inputs cannot
// redirect original-history queries; both a valid pin and a stale pin are checked.
func TestLinkageGitEnvironment(t *testing.T) {
	repo, old, head := linkageHistoryFixture(t)
	foreign := directory(t)
	graft := filepath.Join(foreign, "grafts")
	if e := os.WriteFile(graft, []byte(old+" "+StrictParseCommit+"\n"), 0600); e != nil {
		t.Fatal(e)
	}
	for key, value := range map[string]string{
		"GIT_DIR": foreign, "GIT_COMMON_DIR": foreign, "GIT_WORK_TREE": foreign,
		"GIT_OBJECT_DIRECTORY": foreign, "GIT_ALTERNATE_OBJECT_DIRECTORIES": foreign,
		"GIT_REPLACE_REF_BASE": "refs/forged/", "GIT_GRAFT_FILE": graft,
		"GIT_NO_REPLACE_OBJECTS": "0", "GIT_CONFIG_COUNT": "2",
		"GIT_CONFIG_KEY_0": "core.worktree", "GIT_CONFIG_VALUE_0": foreign,
		"GIT_CONFIG_KEY_1": "core.bare", "GIT_CONFIG_VALUE_1": "true",
		"GIT_CONFIG_PARAMETERS": "'core.bare=true'", "GIT_CONFIG": graft,
		"GIT_CONFIG_GLOBAL": graft, "GIT_CONFIG_SYSTEM": graft,
		"HOME": foreign, "XDG_CONFIG_HOME": foreign,
	} {
		t.Setenv(key, value)
	}
	if e := linkageHistory(context.Background(), repo, head); e != nil {
		t.Fatalf("environment redirected valid control: %v", e)
	}
	if e := linkageHistory(context.Background(), repo, old); e == nil || !strings.Contains(e.Error(), "LINKAGE_STRICT_PARSE_MISSING checkout") {
		t.Fatalf("environment accepted stale commit: %v", e)
	}
}

// Claim: real Git ancestry accepts the pin and rejects stale, higher-looking, missing and unrelated replacements, while ignoring external dependencies.
func TestLinkageSelections(t *testing.T) {
	repo := linkageRepo(t)
	module := internalModulePrefix + "experiments/rental"
	a := Artifact{Module: "experiments/agent-wallet", Binary: "bin/agent-wallet"}
	for _, tc := range []struct {
		name, version string
		replacement   *debug.Module
		valid         bool
	}{
		{"contains", strictRentalVersion, nil, true},
		{"pre-strict-3baa201b", oldRentalVersion, nil, false},
		{"higher-version-is-not-ancestry", "v99.0.0-20990101000000-3baa201bafb6", nil, false},
		{"missing-object", "v99.0.0-20990101000000-000000000000", nil, false},
		{"external-replacement", strictRentalVersion, &debug.Module{Path: "example.invalid/other", Version: strictRentalVersion}, false},
		{"in-tree", strictRentalVersion, &debug.Module{Path: "../rental"}, true},
		{"in-tree-devel-buildinfo", strictRentalVersion, &debug.Module{Path: "../rental", Version: "(devel)"}, true},
		{"escape", strictRentalVersion, &debug.Module{Path: "../../../outside"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			info := &debug.BuildInfo{Deps: []*debug.Module{{Path: module, Version: tc.version, Replace: tc.replacement}, {Path: "example.invalid/external", Version: "invalid-ignored"}}}
			rows, e := selectedLinkage(context.Background(), repo, repo, StrictParseCommit, a, info)
			if !tc.valid {
				if e == nil || !strings.Contains(e.Error(), "LINKAGE_STRICT_PARSE_MISSING bin/agent-wallet "+module) {
					t.Fatalf("required named refusal absent: %v", e)
				}
				return
			}
			if e != nil || len(rows) != 1 || rows[0].Verdict != strictVerdict || rows[0].Commit != StrictParseCommit {
				t.Fatalf("wrong linkage: %+v %v", rows, e)
			}
		})
	}
}

// Claim: shallow histories and symlink replacements escaping the extracted checkout fail closed beside full-history and contained controls.
func TestLinkageHistoryAndReplacementBoundary(t *testing.T) {
	repo := linkageRepo(t)
	if e := linkageHistory(context.Background(), repo, StrictParseCommit); e != nil {
		t.Fatal(e)
	}
	clone := filepath.Join(directory(t), "shallow")
	c := exec.Command("git", "clone", "--quiet", "--depth=1", "--no-local", "file://"+repo, clone)
	if b, e := c.CombinedOutput(); e != nil {
		t.Fatalf("clone: %v %s", e, b)
	}
	if e := linkageHistory(context.Background(), clone, StrictParseCommit); e == nil || !strings.Contains(e.Error(), "LINKAGE_HISTORY_REQUIRED") {
		t.Fatalf("shallow accepted: %v", e)
	}
	root := directory(t)
	if e := os.Symlink(repo, filepath.Join(root, "escape")); e != nil {
		t.Fatal(e)
	}
	if _, ok := containedDirectory(root, filepath.Join(root, "escape")); ok {
		t.Fatal("symlink escape accepted")
	}
	if _, ok := containedDirectory(repo, filepath.Join(repo, "experiments/rental")); !ok {
		t.Fatal("contained control refused")
	}
}

// Claim: unreadable executable metadata and missing selected commit objects refuse without creating any release layout (compiler bytes are stand-ins).
func TestLinkageRefusalHasNoLayout(t *testing.T) {
	repo := linkageRepo(t)
	for _, mode := range []string{"invalid-executable", "missing-commit"} {
		t.Run(mode, func(t *testing.T) {
			work, first, second := assembleFixture(t)
			build := func(_ context.Context, _, _, _ string, a Artifact) ([]byte, error) {
				return fixtureBinary(a.Package), nil
			}
			inspect := func(ctx context.Context, root string, a Artifact, b []byte) ([]ModuleLinkage, error) {
				if mode == "missing-commit" {
					info := &debug.BuildInfo{Deps: []*debug.Module{{Path: internalModulePrefix + "experiments/rental", Version: "v99.0.0-20990101000000-000000000000"}}}
					return selectedLinkage(ctx, repo, root, StrictParseCommit, a, info)
				}
				return inspectLinkage(ctx, repo, root, StrictParseCommit, a, b)
			}
			if _, _, e := assembleChecked(context.Background(), work, first, second, StrictParseCommit, build, inspect); e == nil || !strings.Contains(e.Error(), "LINKAGE_STRICT_PARSE_MISSING") {
				t.Fatalf("invalid linkage accepted: %v", e)
			}
			if _, e := os.Stat(filepath.Join(work, "bundle")); !os.IsNotExist(e) {
				t.Fatal("refusal wrote release layout")
			}
		})
	}
}

// Claim: manifest linkage requires every binary's main module, canonical unique module rows, pinned verdicts and checkout-bound replacement commits.
func TestManifestLinkageContract(t *testing.T) {
	work, first, second := assembleFixture(t)
	m, _, e := assemble(context.Background(), work, first, second, fixtureCommit, func(_ context.Context, _, _, _ string, a Artifact) ([]byte, error) {
		return fixtureBinary(a.Package), nil
	})
	if e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*Manifest){
		func(m *Manifest) { m.Linkage = nil },
		func(m *Manifest) { m.Linkage[0].Modules = nil },
		func(m *Manifest) { m.Linkage[0].Modules[0].Verdict = "contains other" },
		func(m *Manifest) { m.Linkage[0].Modules[0].Commit = StrictParseCommit },
		func(m *Manifest) { m.Linkage[0].Modules[0].Replace = "../outside" },
		func(m *Manifest) { m.Linkage[0].Modules = append(m.Linkage[0].Modules, m.Linkage[0].Modules[0]) },
	} {
		b, _ := json.Marshal(m)
		var bad Manifest
		if e := json.Unmarshal(b, &bad); e != nil {
			t.Fatal(e)
		}
		change(&bad)
		b, _ = json.Marshal(bad)
		if _, e := ValidateManifest(b); e != ErrManifest {
			t.Fatalf("bad linkage accepted: %v", e)
		}
	}
}

func linkageGo(t *testing.T, dir string, args ...string) []byte {
	t.Helper()
	c := exec.Command("go", args...)
	c.Dir = dir
	c.Env = append(os.Environ(), "GOWORK=off", "GOENV=off", "GOTOOLCHAIN=local", "GOFLAGS=")
	b, e := c.CombinedOutput()
	if e != nil {
		t.Fatalf("go %v: %v\n%s", args, e, b)
	}
	return b
}

// Claim: an actual wallet executable selecting rental 3baa201b is refused by binary/module/version before any layout is written.
func TestLinkagePublishedStaleWallet(t *testing.T) {
	if os.Getenv("DK1_LINKAGE_TEST") != "1" {
		t.Skip("requires explicit dependency acquisition and real wallet builds")
	}
	repo := linkageRepo(t)
	work := directory(t)
	archive := filepath.Join(work, "source.tar")
	head, e := git(context.Background(), repo, "rev-parse", "HEAD")
	if e != nil {
		t.Fatal(e)
	}
	commit := strings.TrimSpace(string(head))
	if _, e = git(context.Background(), repo, "archive", "--output="+archive, commit); e != nil {
		t.Fatal(e)
	}
	root := filepath.Join(work, "stale")
	if e = extract(archive, root); e != nil {
		t.Fatal(e)
	}
	wallet := filepath.Join(root, "experiments/agent-wallet")
	rental := internalModulePrefix + "experiments/rental"
	linkageGo(t, wallet, "mod", "edit", "-require="+rental+"@"+oldRentalVersion, "-replace="+rental+"="+rental+"@"+oldRentalVersion)
	linkageGo(t, wallet, "mod", "download", "all")
	binary := filepath.Join(work, "agent-wallet")
	linkageGo(t, wallet, "build", "-trimpath", "-buildvcs=false", "-mod=readonly", "-o", binary, "./cmd/agent-wallet")
	raw, e := os.ReadFile(binary)
	if e != nil {
		t.Fatal(e)
	}
	build := func(_ context.Context, _, _, _ string, _ Artifact) ([]byte, error) { return raw, nil }
	inspect := func(ctx context.Context, _ string, a Artifact, b []byte) ([]ModuleLinkage, error) {
		if a.Binary == "bin/agent-wallet" {
			return inspectLinkage(ctx, repo, root, commit, a, b)
		}
		return []ModuleLinkage{{Module: internalModulePrefix + a.Module, Replace: a.Module, Commit: commit, Verdict: strictVerdict}}, nil
	}
	fixture, old, fixtureHead := linkageHistoryFixture(t)
	for _, mode := range []string{"original", "replace", "graft"} {
		t.Run(mode, func(t *testing.T) {
			caseWork, caseFirst, caseSecond := assembleFixture(t)
			if mode != "original" {
				linkageHistoryPlant(t, fixture, old, fixtureHead, mode)
			}
			inspect := func(ctx context.Context, archive string, a Artifact, b []byte) ([]ModuleLinkage, error) {
				if a.Binary == "bin/agent-wallet" {
					return inspectLinkage(ctx, fixture, root, commit, a, b)
				}
				return inspect(ctx, archive, a, b)
			}
			_, _, e := assembleChecked(context.Background(), caseWork, caseFirst, caseSecond, commit, build, inspect)
			witness := "LINKAGE_STRICT_PARSE_MISSING bin/agent-wallet " + rental + " " + oldRentalVersion
			if e == nil || !strings.Contains(e.Error(), witness) {
				t.Fatalf("stale wallet not refused by name: %v", e)
			}
			t.Log(witness)
			if _, e = os.Stat(filepath.Join(caseWork, "bundle")); !os.IsNotExist(e) {
				t.Fatal("stale wallet wrote release layout")
			}
		})
	}
}

// Claim: the real wallet command at H builds through its published graph, records contains for every internal module and refuses s=n before library parsing beside a valid high-S control.
func TestLinkageStationPublishedSignature(t *testing.T) {
	if os.Getenv("DK1_LINKAGE_TEST") != "1" {
		t.Skip("requires explicit published graph acquisition")
	}
	repo := linkageRepo(t)
	work := directory(t)
	archive := filepath.Join(work, "source.tar")
	head, e := git(context.Background(), repo, "rev-parse", "HEAD")
	if e != nil {
		t.Fatal(e)
	}
	commit := strings.TrimSpace(string(head))
	if _, e = git(context.Background(), repo, "archive", "--output="+archive, commit); e != nil {
		t.Fatal(e)
	}
	root := filepath.Join(work, "source")
	if e = extract(archive, root); e != nil {
		t.Fatal(e)
	}
	wallet := filepath.Join(root, "experiments/agent-wallet")
	var mod struct {
		Replace []struct {
			Old struct{ Path, Version string }
		}
	}
	if e = json.Unmarshal(linkageGo(t, wallet, "mod", "edit", "-json"), &mod); e != nil {
		t.Fatal(e)
	}
	for _, r := range mod.Replace {
		linkageGo(t, wallet, "mod", "edit", "-dropreplace="+r.Old.Path)
	}
	linkageGo(t, wallet, "mod", "download", "all")
	binary := filepath.Join(work, "agent-wallet")
	linkageGo(t, wallet, "build", "-trimpath", "-buildvcs=false", "-mod=readonly", "-o", binary, "./cmd/agent-wallet")
	raw, e := os.ReadFile(binary)
	if e != nil {
		t.Fatal(e)
	}
	rows, e := inspectLinkage(context.Background(), repo, root, commit, Artifact{Module: "experiments/agent-wallet", Binary: "bin/agent-wallet"}, raw)
	if e != nil || len(rows) < 2 {
		t.Fatalf("published executable linkage: %+v %v", rows, e)
	}
	for _, r := range rows {
		if r.Verdict != strictVerdict {
			t.Fatal("missing contains verdict")
		}
	}
	linkageGo(t, wallet, "mod", "vendor")
	library := filepath.Join(wallet, "vendor/github.com/btcsuite/btcd/btcec/v2/schnorr/signature.go")
	original, e := os.ReadFile(library)
	if e != nil {
		t.Fatal(e)
	}
	entry := "func ParseSignature(sig []byte) (*Signature, error) {"
	sentinel := entry + `\n if len(sig)==64 && string(sig[32:]) >= "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xba\xae\xdc\xe6\xaf\x48\xa0\x3b\xbf\xd2\x5e\x8c\xd0\x36\x41\x41" { panic("NONCANONICAL_REACHED_LIB_PARSER") }`
	sentinel = strings.Replace(sentinel, `\n`, "\n", 1)
	if strings.Count(string(original), entry) != 1 {
		t.Fatal("parser sentinel was not uniquely applied")
	}
	if e = os.WriteFile(library, []byte(strings.Replace(string(original), entry, sentinel, 1)), 0600); e != nil {
		t.Fatal(e)
	}
	fixture, e := os.ReadFile(filepath.Join(repo, ".scripts/testdata/published_rental_strict_test.go"))
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(wallet, "cmd/agent-wallet/published_rental_strict_test.go"), fixture, 0600); e != nil {
		t.Fatal(e)
	}
	b := linkageGo(t, wallet, "test", "-mod=vendor", "-race", "-count=1", "-v", "-run", "^TestPublished", "./cmd/agent-wallet")
	for _, name := range []string{"TestPublishedRentalValidHighS", "TestPublishedParserSentinelControl", "TestPublishedRentalRejectsBeforeLibraryParse"} {
		if !strings.Contains(string(b), "--- PASS: "+name) {
			t.Fatalf("missing executed control %s: %s", name, b)
		}
	}
	t.Log(string(b))
	// The binary was built before the bounded library instrumentation; its
	// dependency identities are unchanged by running the same-graph controls.
	again, e := os.ReadFile(binary)
	if e != nil || !reflect.DeepEqual(raw, again) {
		t.Fatal("signature controls changed station binary")
	}
}
