package wallet

import (
	"context"
	"encoding/json"
	"github.com/relux-works/swarma-chain-lab/deploy/workspace"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type plant struct {
	Name, File, Old, New, Selector, Marker string
	Core                                   bool
}

// Each isolated plant must compile and fail the named assertion. Setup errors,
// crashes, skipped tests and unrelated failures are never successful controls.
func TestGuardPlants(t *testing.T) {
	if os.Getenv("W1_MUTATIONS") != "1" {
		t.Skip("W1_MUTATIONS=1 requires fresh root and pinned dependencies")
	}
	root := os.Getenv("W1_MUTATION_ROOT")
	deps := os.Getenv("W1_DEP_ROOT")
	if !filepath.IsAbs(root) || !filepath.IsAbs(deps) {
		t.Fatal("absolute mutation root/dependencies required")
	}
	if e := os.Mkdir(root, 0700); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile("testdata/mutations.json")
	if e != nil {
		t.Fatal(e)
	}
	var plants []plant
	if json.Unmarshal(raw, &plants) != nil || len(plants) < 20 {
		t.Fatal("plant manifest")
	}
	cwd, e := os.Getwd()
	if e != nil {
		t.Fatal(e)
	}
	copyTree := func(src, dst string) error {
		return filepath.WalkDir(src, func(path string, d fs.DirEntry, e error) error {
			if e != nil {
				return e
			}
			rel, e := filepath.Rel(src, path)
			if e != nil {
				return e
			}
			if d.IsDir() {
				if d.Name() == ".temp" {
					return filepath.SkipDir
				}
				return os.MkdirAll(filepath.Join(dst, rel), 0700)
			}
			if d.Type()&os.ModeSymlink != 0 {
				return fail("source symlink")
			}
			b, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			return os.WriteFile(filepath.Join(dst, rel), b, 0600)
		})
	}
	rows := []map[string]any{}
	// Freeze once: later edits in the development checkout cannot change the
	// baseline halfway through a run.
	frozen := filepath.Join(root, "baseline")
	if e := copyTree(cwd, frozen); e != nil {
		t.Fatal(e)
	}
	for _, p := range plants {
		t.Run(p.Name, func(t *testing.T) {
			dir := filepath.Join(root, p.Name)
			for _, name := range []string{"rental", "single-use", "sealwatch"} {
				if e := copyTree(filepath.Join(deps, name), filepath.Join(dir, name)); e != nil {
					t.Fatal(e)
				}
			}
			module := filepath.Join(dir, "agent-wallet")
			if e := copyTree(frozen, module); e != nil {
				t.Fatal(e)
			}
			file := filepath.Join(module, p.File)
			original, e := os.ReadFile(file)
			if e != nil {
				t.Fatal(e)
			}
			if strings.Count(string(original), p.Old) != 1 {
				t.Fatal("plant guard not uniquely applied")
			}
			mutated := strings.Replace(string(original), p.Old, p.New, 1)
			if e = os.WriteFile(file, []byte(mutated), 0600); e != nil {
				t.Fatal(e)
			}
			fixtureWork, e := workspace.Isolate(cwd, dir)
			if e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			selector := "^" + strings.ReplaceAll(p.Selector, "/", "$/^") + "$"
			cmd := exec.CommandContext(ctx, "go", "test", "-count=1", "-run", selector, ".")
			cmd.Dir = module
			for _, v := range os.Environ() {
				if !strings.HasPrefix(v, "W1_") && !strings.HasPrefix(v, "GOWORK=") {
					cmd.Env = append(cmd.Env, v)
				}
			}
			cmd.Env = append(cmd.Env, "GOWORK="+fixtureWork)
			if p.Core {
				cmd.Env = append(cmd.Env, "W1_REGTEST=1", "W1_RUN_ROOT="+filepath.Join(dir, "core"), "W1_CORE_CLI="+os.Getenv("W1_CORE_CLI"), "W1_CORE_DAEMON="+os.Getenv("W1_CORE_DAEMON"))
			}
			output, err := cmd.CombinedOutput()
			if e = os.WriteFile(filepath.Join(dir, "test.log"), output, 0600); e != nil {
				t.Fatal(e)
			}
			exit := -1
			pid := 0
			if cmd.ProcessState != nil {
				exit = cmd.ProcessState.ExitCode()
				pid = cmd.ProcessState.Pid()
			}
			killed := err != nil && ctx.Err() == nil && strings.Contains(string(output), p.Marker) && strings.Contains(string(output), "--- FAIL:") && !strings.Contains(string(output), "[build failed]") && !strings.Contains(string(output), "[setup failed]") && !strings.Contains(string(output), "panic:")
			rows = append(rows, map[string]any{"name": p.Name, "source_sha256": Hash(original), "mutant_sha256": Hash([]byte(mutated)), "selector": selector, "marker": p.Marker, "exit": exit, "killed": killed, "core": p.Core, "test_pid": pid})
			if !killed {
				t.Fatalf("intended control not detected: %s", filepath.Join(dir, "test.log"))
			}
		})
	}
	if e = os.WriteFile(filepath.Join(root, "results.json"), canonical(rows), 0600); e != nil {
		t.Fatal(e)
	}
}
