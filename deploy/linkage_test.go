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
	work, first, second := assembleFixture(t)
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
	_, _, e = assembleChecked(context.Background(), work, first, second, commit, build, inspect)
	witness := "LINKAGE_STRICT_PARSE_MISSING bin/agent-wallet " + rental + " " + oldRentalVersion
	if e == nil || !strings.Contains(e.Error(), witness) {
		t.Fatalf("stale wallet not refused by name: %v", e)
	}
	t.Log(witness)
	if _, e = os.Stat(filepath.Join(work, "bundle")); !os.IsNotExist(e) {
		t.Fatal("stale wallet wrote release layout")
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
