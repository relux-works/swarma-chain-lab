package deploy

import (
	"archive/tar"
	"bytes"
	"context"
	"debug/elf"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func directory(t *testing.T) string {
	t.Helper()
	p, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	return p
}

// Independent roots, caches and outputs are used even when the first build
// succeeds. A differing or empty second result cannot publish the first result.
func TestBuildPair(t *testing.T) {
	for _, mode := range []string{"equal", "different", "empty", "error-first", "error-second"} {
		t.Run(mode, func(t *testing.T) {
			root := directory(t)
			calls := 0
			var dirs, caches, outputs []string
			build := func(_ context.Context, dir, cache, out string, _ Artifact) ([]byte, error) {
				calls++
				dirs = append(dirs, dir)
				caches = append(caches, cache)
				outputs = append(outputs, out)
				if mode == "error-first" && calls == 1 || mode == "error-second" && calls == 2 {
					return nil, errors.New("sensitive-build-marker")
				}
				if mode == "empty" {
					return nil, nil
				}
				if mode == "different" && calls == 2 {
					return []byte("changed input"), nil
				}
				return []byte("equal binary"), nil
			}
			b, e := buildPair(context.Background(), root, root+"/first", root+"/second", releaseArtifacts[0], build)
			if mode == "equal" {
				if e != nil || string(b) != "equal binary" {
					t.Fatal("reproducible neighbour rejected")
				}
			} else {
				want := ErrDifferent
				if strings.HasPrefix(mode, "error-") {
					want = ErrBuild
				}
				if e != want || b != nil {
					t.Fatalf("bad build not refused: %v", e)
				}
			}
			if mode != "error-first" && (calls != 2 || dirs[0] == dirs[1] || caches[0] == caches[1] || outputs[0] == outputs[1]) {
				t.Fatal("independent build isolation missing")
			}
		})
	}
}

// Dirty tracked/index/untracked files refuse before commit/toolchain/build work;
// no unsigned test commit is created. An empty clean Git fixture is the neighbour.
func TestDirtyCheckout(t *testing.T) {
	for _, stage := range []bool{false, true} {
		t.Run(map[bool]string{false: "untracked", true: "staged"}[stage], func(t *testing.T) {
			repo := directory(t)
			ctx := context.Background()
			c := exec.Command("git", "init", "--quiet", repo)
			if e := c.Run(); e != nil {
				t.Fatal(e)
			}
			if e := clean(ctx, repo); e != nil {
				t.Fatal("clean neighbour refused")
			}
			if e := os.WriteFile(filepath.Join(repo, "dirty.txt"), []byte("preserve this"), 0600); e != nil {
				t.Fatal(e)
			}
			if stage {
				if _, e := git(ctx, repo, "add", "dirty.txt"); e != nil {
					t.Fatal(e)
				}
			}
			out := filepath.Join(directory(t), "release")
			_, e := BuildRelease(ctx, ReleaseInput{Repo: repo, Commit: strings.Repeat("1", 40), Out: out})
			if e != ErrDirty {
				t.Fatalf("dirty checkout not refused before build: %v", e)
			}
			if _, e = os.Stat(out); !os.IsNotExist(e) {
				t.Fatal("dirty release published output")
			}
			b, e := os.ReadFile(filepath.Join(repo, "dirty.txt"))
			if e != nil || string(b) != "preserve this" {
				t.Fatal("dirty input modified")
			}
		})
	}
}

// Archive traversal, symlinks and hardlinks cannot escape into host state;
// regular executable source remains extractable with its content and mode.
func TestArchiveBoundary(t *testing.T) {
	for _, tc := range []struct {
		name  string
		kind  byte
		valid bool
	}{{"cmd/main.go", tar.TypeReg, true}, {"../outside", tar.TypeReg, false}, {"/absolute", tar.TypeReg, false}, {"link", tar.TypeSymlink, false}, {"hardlink", tar.TypeLink, false}} {
		t.Run(tc.name, func(t *testing.T) {
			dir := directory(t)
			archive := filepath.Join(dir, "source.tar")
			f, e := os.Create(archive)
			if e != nil {
				t.Fatal(e)
			}
			w := tar.NewWriter(f)
			h := &tar.Header{Name: tc.name, Mode: 0755, Typeflag: tc.kind, Linkname: "/outside"}
			if tc.kind == tar.TypeReg {
				h.Size = 4
				h.Linkname = ""
			}
			if e = w.WriteHeader(h); e != nil {
				t.Fatal(e)
			}
			if h.Size > 0 {
				_, e = w.Write([]byte("data"))
				if e != nil {
					t.Fatal(e)
				}
			}
			if e = w.Close(); e != nil {
				t.Fatal(e)
			}
			if e = f.Close(); e != nil {
				t.Fatal(e)
			}
			e = extract(archive, filepath.Join(dir, "tree"))
			if tc.valid {
				if e != nil {
					t.Fatal(e)
				}
				b, e := os.ReadFile(filepath.Join(dir, "tree", tc.name))
				if e != nil || string(b) != "data" {
					t.Fatal("regular source lost")
				}
			} else if e == nil {
				t.Fatal("unsafe archive accepted")
			}
		})
	}
}

// SHA256SUMS covers every published file (including policy/templates/manifest)
// in deterministic relative-path order, never a signature or partial listing.
func TestSums(t *testing.T) {
	root := directory(t)
	if e := os.Mkdir(filepath.Join(root, "bin"), 0700); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"manifest.json", "bin/program"} {
		if e := os.WriteFile(filepath.Join(root, name), []byte(name), 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e := writeSums(root); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(filepath.Join(root, "SHA256SUMS"))
	if e != nil {
		t.Fatal(e)
	}
	want := digest([]byte("bin/program")) + "  bin/program\n" + digest([]byte("manifest.json")) + "  manifest.json\n"
	if string(b) != want {
		t.Fatal("checksum coverage or order mismatch")
	}
}

// Opt-in actual release: real Linux ELF builds twice from a clean signed HEAD,
// nine services and the deploy-kit tool. The controls plant unequal source in
// the isolated second tree, once in the first service and once in deploy-kit;
// the actual compiler runs, mismatch must refuse, and no candidate bundle may appear.
func TestReleaseIntegration(t *testing.T) {
	if os.Getenv("DK1_RELEASE_TEST") != "1" {
		t.Skip("requires explicit clean signed-source release run")
	}
	repo := os.Getenv("DK1_RELEASE_REPO")
	out := os.Getenv("DK1_RELEASE_OUT")
	if !canonicalDir(repo) || !canonicalDir(out) {
		t.Fatal("canonical source/output parents required")
	}
	ctx := context.Background()
	head, e := git(ctx, repo, "rev-parse", "HEAD")
	if e != nil {
		t.Fatal(e)
	}
	commit := strings.TrimSpace(string(head))
	in := ReleaseInput{Repo: repo, Commit: commit, Out: filepath.Join(out, "release")}
	m, e := BuildRelease(ctx, in)
	if e != nil {
		t.Fatal(e)
	}
	if len(m.Artifacts) != 9 || len(m.Pending) != 1 || m.Pending[0].Service != "a2ad" || m.Artifacts[0].Status != "configuration-preparation" || m.Artifacts[0].Screening != "off" || m.Artifacts[3].Service != "relay" {
		t.Fatal("manifest service readiness mismatch")
	}
	if len(m.Tools) != 1 || m.Tools[0].Tool != "deploy-kit" || m.Tools[0].Module != "deploy" || m.Tools[0].Package != "./cmd/deploy-kit" || m.Tools[0].Binary != "bin/deploy-kit" {
		t.Fatal("manifest deploy-kit tool row mismatch")
	}
	raw, e := os.ReadFile(filepath.Join(in.Out, "manifest.json"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = ValidateManifest(raw); e != nil {
		t.Fatal("published manifest refused by its validator")
	}
	sums, e := os.ReadFile(filepath.Join(in.Out, "SHA256SUMS"))
	if e != nil || !strings.Contains(string(sums), m.Tools[0].SHA256+"  bin/deploy-kit\n") {
		t.Fatal("SHA256SUMS does not list bin/deploy-kit")
	}
	binaries := append([]Artifact(nil), m.Artifacts...)
	binaries = append(binaries, Artifact{Binary: m.Tools[0].Binary, SHA256: m.Tools[0].SHA256})
	for _, a := range binaries {
		b, e := os.ReadFile(filepath.Join(in.Out, a.Binary))
		if e != nil || digest(b) != a.SHA256 {
			t.Fatal("published binary hash mismatch")
		}
		f, e := elf.NewFile(bytes.NewReader(b))
		if e != nil {
			t.Fatal("artifact is not ELF")
		}
		if f.Machine != elf.EM_X86_64 {
			t.Fatal("wrong target architecture")
		}
		for _, p := range f.Progs {
			if p.Type == elf.PT_INTERP {
				t.Fatal("unexpected dynamic interpreter")
			}
		}
		f.Close()
	}
	if _, e = BuildRelease(ctx, in); e != ErrOutput {
		t.Fatal("existing release was replaceable")
	}
	before, e := os.ReadFile(filepath.Join(in.Out, "manifest.json"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = BuildRelease(ctx, ReleaseInput{Repo: repo, Commit: strings.Repeat("0", 40), Out: filepath.Join(out, "wrong-commit")}); e != ErrSource {
		t.Fatal("wrong commit accepted")
	}
	if _, e = os.Stat(filepath.Join(out, "wrong-commit")); !os.IsNotExist(e) {
		t.Fatal("wrong commit published output")
	}
	mutant := in
	mutant.Out = filepath.Join(out, "must-not-exist")
	build := func(ctx context.Context, root, cache, output string, a Artifact) ([]byte, error) {
		if filepath.Base(root) == "second" {
			p := filepath.Join(root, a.Module, strings.TrimPrefix(a.Package, "./"), "nondeterminism_control.go")
			if e := os.WriteFile(p, []byte("package main\nfunc init(){println(\"nondeterminism-control\")}\n"), 0600); e != nil {
				return nil, e
			}
		}
		return buildGo(ctx, root, cache, output, a)
	}
	_, e = buildRelease(ctx, mutant, build)
	if e != ErrDifferent {
		t.Fatalf("nondeterminism plant missed intended refusal: %v", e)
	}
	if _, e = os.Stat(mutant.Out); !os.IsNotExist(e) {
		t.Fatal("nonreproducible release published partial output")
	}
	// Only deploy-kit reaches the real compiler here; service pairs are equal
	// stand-ins so the refusal can come from the deploy-kit pair alone.
	toolPlant := func(ctx context.Context, root, cache, output string, a Artifact) ([]byte, error) {
		if a.Package != "./cmd/deploy-kit" {
			return []byte("service-control " + a.Package), nil
		}
		return build(ctx, root, cache, output, a)
	}
	toolMutant := in
	toolMutant.Out = filepath.Join(out, "must-not-exist-tool")
	if _, e = buildRelease(ctx, toolMutant, toolPlant); e != ErrDifferent {
		t.Fatalf("deploy-kit nondeterminism plant missed intended refusal: %v", e)
	}
	if _, e = os.Stat(toolMutant.Out); !os.IsNotExist(e) {
		t.Fatal("nonreproducible deploy-kit published partial output")
	}
	after, e := os.ReadFile(filepath.Join(in.Out, "manifest.json"))
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("failed attempt altered previous release")
	}
	if e = clean(ctx, repo); e != nil {
		t.Fatal("release modified source")
	}
	result := struct {
		Commit             string
		Positive, Negative string
	}{commit, "nine service and one deploy-kit tool independent Linux/amd64 ELF pairs match", "real source nondeterminism refused for a service and for deploy-kit; no output; previous release unchanged"}
	b, _ := json.MarshalIndent(result, "", "  ")
	if e = os.WriteFile(filepath.Join(out, "release-control.json"), b, 0600); e != nil {
		t.Fatal(e)
	}
}

// assembleFixture lays out the two extracted source trees assemble reads: the
// deploy templates and the four shipped documents. Binaries come from build.
func assembleFixture(t *testing.T) (work, first, second string) {
	t.Helper()
	work = directory(t)
	first, second = filepath.Join(work, "first"), filepath.Join(work, "second")
	for _, root := range []string{first, second} {
		if e := os.MkdirAll(filepath.Join(root, "deploy", "templates", "systemd"), 0700); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(filepath.Join(root, "deploy", "templates", "systemd", "unit.service.in"), []byte("[Unit]\n"), 0600); e != nil {
			t.Fatal(e)
		}
		for _, name := range []string{"SMOKE.md", "SMOKE-DK2.md", "README.md", "INSTALL-CONFIG.md"} {
			if e := os.WriteFile(filepath.Join(root, "deploy", name), []byte(name), 0600); e != nil {
				t.Fatal(e)
			}
		}
	}
	return work, first, second
}

const fixtureCommit = "0123456789abcdef0123456789abcdef01234567"

// fixtureBinary is the deterministic stand-in a fixture build returns for a package.
func fixtureBinary(pkg string) []byte { return []byte("fixture-binary " + pkg) }

// Claim: a fixture build lists bin/deploy-kit as a tool, not a service, in the
// returned manifest, manifest.json and SHA256SUMS, with the hash of the bytes
// both builds produced; deploy-kit is built exactly twice, once per source
// tree. Valid neighbour: all nine service rows stay as before. Limit: the build
// function is a stand-in; TestReleaseIntegration runs the real compiler.
func TestAssembleShipsDeployKit(t *testing.T) {
	work, first, second := assembleFixture(t)
	var deployKitRoots []string
	build := func(_ context.Context, root, _, _ string, a Artifact) ([]byte, error) {
		if a.Package == "./cmd/deploy-kit" {
			deployKitRoots = append(deployKitRoots, root)
		}
		return fixtureBinary(a.Package), nil
	}
	m, stage, e := assemble(context.Background(), work, first, second, fixtureCommit, build)
	if e != nil {
		t.Fatalf("clean fixture refused: %v", e)
	}
	want := Tool{Tool: "deploy-kit", Module: "deploy", Package: "./cmd/deploy-kit", Binary: "bin/deploy-kit", SHA256: digest(fixtureBinary("./cmd/deploy-kit"))}
	if len(m.Tools) != 1 || m.Tools[0] != want {
		t.Fatalf("deploy-kit tool row missing or wrong: %+v", m.Tools)
	}
	if len(deployKitRoots) != 2 || deployKitRoots[0] != first || deployKitRoots[1] != second {
		t.Fatalf("deploy-kit not built once per source tree: %v", deployKitRoots)
	}
	services := []string{"gateway", "booking", "store", "relay", "issuer", "model", "stations", "payload", "wallet"}
	if len(m.Artifacts) != len(services) {
		t.Fatal("service rows changed")
	}
	for i, a := range m.Artifacts {
		row := releaseArtifacts[i]
		row.SHA256 = digest(fixtureBinary(row.Package))
		if a.Service != services[i] || a != row || a.Binary == want.Binary {
			t.Fatalf("service row %d changed: %+v", i, a)
		}
	}
	raw, e := os.ReadFile(filepath.Join(stage, "manifest.json"))
	if e != nil {
		t.Fatal(e)
	}
	got, e := ValidateManifest(raw)
	if e != nil || len(got.Tools) != 1 || got.Tools[0] != want {
		t.Fatalf("manifest.json lacks the validated deploy-kit row: %v", e)
	}
	var members struct{ Tools []map[string]json.RawMessage }
	if e = json.Unmarshal(raw, &members); e != nil || len(members.Tools) != 1 {
		t.Fatal("manifest.json tools member missing")
	}
	for _, k := range []string{"service", "status", "reason", "screening", "unit"} {
		if _, ok := members.Tools[0][k]; ok {
			t.Fatalf("tool row carries service member %q", k)
		}
	}
	sums, e := os.ReadFile(filepath.Join(stage, "SHA256SUMS"))
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(string(sums), want.SHA256+"  bin/deploy-kit\n") || !strings.Contains(string(sums), digest(fixtureBinary("./cmd/gateway"))+"  bin/gateway\n") {
		t.Fatal("SHA256SUMS does not list bin/deploy-kit and the service binaries")
	}
	bin, e := os.ReadFile(filepath.Join(stage, "bin", "deploy-kit"))
	if e != nil || digest(bin) != want.SHA256 {
		t.Fatal("staged deploy-kit binary does not match its listed hash")
	}
}

// Claim: when the two deploy-kit builds differ or the second one fails, the
// release is refused with the same error a service binary gets, and no
// manifest.json or SHA256SUMS is staged. Neighbours: the same refusal for a
// service mismatch, and acceptance when every pair matches.
func TestAssembleRefusesDeployKitMismatch(t *testing.T) {
	for _, tc := range []struct {
		name, pkg string
		fail      bool
		want      error
	}{
		{"deploy-kit-differs", "./cmd/deploy-kit", false, ErrDifferent},
		{"deploy-kit-second-build-fails", "./cmd/deploy-kit", true, ErrBuild},
		{"service-differs", "./cmd/gateway", false, ErrDifferent},
		{"service-second-build-fails", "./cmd/agent-walletd", true, ErrBuild},
		{"all-pairs-match", "", false, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			work, first, second := assembleFixture(t)
			build := func(_ context.Context, root, _, _ string, a Artifact) ([]byte, error) {
				if root == second && a.Package == tc.pkg {
					if tc.fail {
						return nil, errors.New("second build failed")
					}
					return []byte("second tree differs"), nil
				}
				return fixtureBinary(a.Package), nil
			}
			_, _, e := assemble(context.Background(), work, first, second, fixtureCommit, build)
			if e != tc.want {
				t.Fatalf("got %v, want %v", e, tc.want)
			}
			for _, name := range []string{"manifest.json", "SHA256SUMS"} {
				_, se := os.Stat(filepath.Join(work, "bundle", name))
				if tc.want != nil && !os.IsNotExist(se) || tc.want == nil && se != nil {
					t.Fatalf("%s staged state wrong for %s", name, tc.name)
				}
			}
		})
	}
}

// Claim: ValidateManifest accepts a manifest the kit built, including its
// deploy-kit tool row and any well-formed hash, and refuses each tampered
// variant below with ErrManifest. The tampered rows cover the tool (dropped,
// moved into the service rows, given a service, status or unit member, renamed,
// repointed or given a malformed hash) and, as neighbours, a service row and
// the document framing.
func TestValidateManifest(t *testing.T) {
	work, first, second := assembleFixture(t)
	_, stage, e := assemble(context.Background(), work, first, second, fixtureCommit, func(_ context.Context, _, _, _ string, a Artifact) ([]byte, error) {
		return fixtureBinary(a.Package), nil
	})
	if e != nil {
		t.Fatal(e)
	}
	valid, e := os.ReadFile(filepath.Join(stage, "manifest.json"))
	if e != nil {
		t.Fatal(e)
	}
	if m, e := ValidateManifest(valid); e != nil || len(m.Tools) != 1 || m.Tools[0].Tool != "deploy-kit" {
		t.Fatalf("built manifest lacks a validated deploy-kit tool row: %v", e)
	}
	edit := func(f func(m map[string]any)) []byte {
		var m map[string]any
		if e := json.Unmarshal(valid, &m); e != nil {
			t.Fatal(e)
		}
		f(m)
		b, e := json.Marshal(m)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	tool := func(m map[string]any) map[string]any { return m["tools"].([]any)[0].(map[string]any) }
	service := func(m map[string]any, i int) map[string]any { return m["artifacts"].([]any)[i].(map[string]any) }
	otherHash := strings.Repeat("ab", 32)
	for _, tc := range []struct {
		name string
		raw  []byte
		ok   bool
	}{
		{"built", valid, true},
		{"other-tool-hash", edit(func(m map[string]any) { tool(m)["sha256"] = otherHash }), true},
		{"other-service-hash", edit(func(m map[string]any) { service(m, 8)["sha256"] = otherHash }), true},
		{"tool-dropped", edit(func(m map[string]any) { m["tools"] = []any{} }), false},
		{"tools-member-missing", edit(func(m map[string]any) { delete(m, "tools") }), false},
		{"tools-null", edit(func(m map[string]any) { m["tools"] = nil }), false},
		{"tool-duplicated", edit(func(m map[string]any) { m["tools"] = []any{tool(m), tool(m)} }), false},
		{"tool-moved-to-services", edit(func(m map[string]any) {
			row := map[string]any{"service": "deploy-kit", "module": "deploy", "package": "./cmd/deploy-kit", "binary": "bin/deploy-kit", "sha256": tool(m)["sha256"], "status": "configuration-preparation"}
			m["artifacts"] = append(m["artifacts"].([]any), row)
			m["tools"] = []any{}
		}), false},
		{"tool-with-service", edit(func(m map[string]any) { tool(m)["service"] = "deploy-kit" }), false},
		{"tool-with-status", edit(func(m map[string]any) { tool(m)["status"] = "configuration-preparation" }), false},
		{"tool-with-unit", edit(func(m map[string]any) { tool(m)["unit"] = "swarma-deploy-kit.service" }), false},
		{"tool-renamed", edit(func(m map[string]any) { tool(m)["tool"] = "deploy" }), false},
		{"tool-binary-repointed", edit(func(m map[string]any) { tool(m)["binary"] = "bin/agent-walletd" }), false},
		{"tool-module-repointed", edit(func(m map[string]any) { tool(m)["module"] = "experiments/agent-wallet" }), false},
		{"tool-package-repointed", edit(func(m map[string]any) { tool(m)["package"] = "./cmd/agent-walletd" }), false},
		{"tool-hash-uppercase", edit(func(m map[string]any) { tool(m)["sha256"] = strings.ToUpper(otherHash) }), false},
		{"tool-hash-short", edit(func(m map[string]any) { tool(m)["sha256"] = otherHash[:62] }), false},
		{"tool-hash-empty", edit(func(m map[string]any) { tool(m)["sha256"] = "" }), false},
		{"service-status-activated", edit(func(m map[string]any) { service(m, 8)["status"] = "active" }), false},
		{"service-hash-short", edit(func(m map[string]any) { service(m, 0)["sha256"] = otherHash[:62] }), false},
		{"service-dropped", edit(func(m map[string]any) { m["artifacts"] = m["artifacts"].([]any)[1:] }), false},
		{"pending-dropped", edit(func(m map[string]any) { m["pending"] = []any{} }), false},
		{"commit-short", edit(func(m map[string]any) { m["commit"] = fixtureCommit[:39] }), false},
		{"unknown-member", edit(func(m map[string]any) { m["signed"] = true }), false},
		{"duplicate-tools-key", []byte(strings.Replace(string(valid), `"pending":`, `"tools": [],
  "pending":`, 1)), false},
		{"trailing-value", append(append([]byte(nil), valid...), []byte("{}")...), false},
		{"empty", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, e := ValidateManifest(tc.raw)
			if tc.ok {
				if e != nil || len(m.Tools) != 1 || m.Tools[0].Tool != "deploy-kit" {
					t.Fatalf("valid manifest refused: %v", e)
				}
				return
			}
			if e != ErrManifest || m.Tools != nil || m.Artifacts != nil {
				t.Fatalf("tampered manifest not refused: %v", e)
			}
		})
	}
}
