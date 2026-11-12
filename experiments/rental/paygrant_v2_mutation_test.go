package rental

// Owner S4. Guard-removal controls for the pay-grant helper. The agent-wallet
// runner (mutation_test.go there) mutates only agent-wallet files, so S4's
// manifest lives in this module: testdata/px1-mutations-s4.json, same plant
// shape and same W1_MUTATIONS gate.

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type payGrantPlant struct {
	Name, File, Old, New, Selector, Marker string
	Core                                   bool
}

// Claim: each S4 plant compiles in an isolated copy and fails its named
// assertion (the marker), never a build, setup, panic or timeout. A plant
// that does not apply exactly once is a runner failure, not a detection.
func TestPayGrantV2GuardPlants(t *testing.T) {
	if os.Getenv("W1_MUTATIONS") != "1" {
		t.Skip("W1_MUTATIONS=1 requires a fresh absolute W1_MUTATION_ROOT")
	}
	root := os.Getenv("W1_MUTATION_ROOT")
	if !filepath.IsAbs(root) {
		t.Fatal("absolute mutation root required")
	}
	if e := os.Mkdir(root, 0700); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile("testdata/px1-mutations-s4.json")
	if e != nil {
		t.Fatal(e)
	}
	var plants []payGrantPlant
	if json.Unmarshal(raw, &plants) != nil || len(plants) < 1 {
		t.Fatal("S4 plant manifest")
	}
	cwd, e := os.Getwd()
	if e != nil {
		t.Fatal(e)
	}
	source := filepath.Dir(cwd)
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
				return nil
			}
			b, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			return os.WriteFile(filepath.Join(dst, rel), b, 0600)
		})
	}
	// Freeze the baseline once, so later checkout edits cannot leak into a run.
	baseline := filepath.Join(root, "baseline")
	for _, m := range []string{"rental", "single-use", "sealwatch", "payment-chain", "rental-booking"} {
		if e := copyTree(filepath.Join(source, m), filepath.Join(baseline, m)); e != nil {
			t.Fatal(e)
		}
	}
	rows := []map[string]any{}
	for _, p := range plants {
		t.Run(p.Name, func(t *testing.T) {
			dir := filepath.Join(root, p.Name)
			if e := copyTree(baseline, dir); e != nil {
				t.Fatal(e)
			}
			file := filepath.Join(dir, "rental", p.File)
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
			ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
			defer cancel()
			selector := "^" + strings.ReplaceAll(p.Selector, "/", "$/^") + "$"
			pkg := "."
			if strings.HasPrefix(p.File, "cmd/") {
				pkg = "./" + filepath.Dir(p.File)
			}
			cmd := exec.CommandContext(ctx, "go", "test", "-count=1", "-run", selector, pkg)
			cmd.Dir = filepath.Join(dir, "rental")
			for _, v := range os.Environ() {
				if !strings.HasPrefix(v, "W1_") && !strings.HasPrefix(v, "M1_") && !strings.HasPrefix(v, "GOWORK=") {
					cmd.Env = append(cmd.Env, v)
				}
			}
			cmd.Env = append(cmd.Env, "GOWORK=off")
			if p.Core {
				cmd.Env = append(cmd.Env, "M1_REGTEST=1", "M1_RUN_ROOT="+filepath.Join(dir, "core"), "M1_CORE_CLI="+os.Getenv("M1_CORE_CLI"), "M1_CORE_DAEMON="+os.Getenv("M1_CORE_DAEMON"))
			}
			output, err := cmd.CombinedOutput()
			if e = os.WriteFile(filepath.Join(dir, "test.log"), output, 0600); e != nil {
				t.Fatal(e)
			}
			exit := -1
			if cmd.ProcessState != nil {
				exit = cmd.ProcessState.ExitCode()
			}
			out := string(output)
			killed := err != nil && ctx.Err() == nil && strings.Contains(out, p.Marker) && strings.Contains(out, "--- FAIL:") && !strings.Contains(out, "[build failed]") && !strings.Contains(out, "[setup failed]") && !strings.Contains(out, "panic:")
			rows = append(rows, map[string]any{"name": p.Name, "file": p.File, "source_sha256": Hash(original), "mutant_sha256": Hash([]byte(mutated)), "selector": selector, "marker": p.Marker, "exit": exit, "killed": killed, "core": p.Core})
			if !killed {
				t.Fatalf("intended control not detected: %s", filepath.Join(dir, "test.log"))
			}
		})
	}
	b, _ := json.MarshalIndent(rows, "", "  ")
	if e = os.WriteFile(filepath.Join(root, "results.json"), append(b, '\n'), 0600); e != nil {
		t.Fatal(e)
	}
}
