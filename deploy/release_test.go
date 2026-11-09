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

// Opt-in actual release: real Linux ELF builds twice from a clean signed HEAD.
// The control plants unequal source in the isolated second tree; the actual
// compiler runs, mismatch must refuse, and no candidate bundle may appear.
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
	if len(m.Artifacts) != 8 || len(m.Pending) != 1 || m.Pending[0].Service != "courier" || m.Artifacts[0].Status != "regtest-preparation" || m.Artifacts[0].Screening != "off" || m.Artifacts[3].Service != "relay" {
		t.Fatal("manifest service readiness mismatch")
	}
	for _, a := range m.Artifacts {
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
	}{commit, "eight independent Linux/amd64 ELF pairs match", "real source nondeterminism refused; no output; previous release unchanged"}
	b, _ := json.MarshalIndent(result, "", "  ")
	if e = os.WriteFile(filepath.Join(out, "release-control.json"), b, 0600); e != nil {
		t.Fatal(e)
	}
}
