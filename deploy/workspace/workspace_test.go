package workspace

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func put(t *testing.T, root, name, content string) {
	t.Helper()
	p := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

// A copied dependency and nested module must be compiled from the fixture,
// even when the caller points GOWORK at the original tree. A deliberate wrong
// value must fail the actual assertion, not workspace or compilation setup.
func TestCopiedModules(t *testing.T) {
	source, scratch := t.TempDir(), t.TempDir()
	put(t, source, "go.work", "go 1.26.0\nuse (\n ./deploy\n ./experiments/a\n ./experiments/a/nested\n)\n")
	put(t, source, "deploy/go.mod", "module example.com/fixture/deploy\ngo 1.26.0\n")
	put(t, source, "experiments/a/go.mod", "module example.com/fixture/a\ngo 1.26.0\n")
	put(t, source, "experiments/a/a.go", "package a\nconst Value = 1\n")
	put(t, source, "experiments/a/nested/go.mod", "module example.com/fixture/a/nested\ngo 1.26.0\n")
	put(t, source, "experiments/a/nested/n.go", "package nested\nconst Value = 1\n")
	put(t, scratch, "a/go.mod", "module example.com/fixture/a\ngo 1.26.0\n")
	put(t, scratch, "a/a.go", "package a\nconst Value = 2\n")
	put(t, scratch, "a/nested/go.mod", "module example.com/fixture/a/nested\ngo 1.26.0\n")
	put(t, scratch, "a/nested/n.go", "package nested\nconst Value = 2\n")
	put(t, scratch, "deploy/go.mod", "module example.com/fixture/deploy\ngo 1.26.0\n")
	put(t, scratch, "deploy/check_test.go", "package deploy\nimport (\"testing\"; \"example.com/fixture/a\"; \"example.com/fixture/a/nested\")\nfunc TestCopied(t *testing.T) { if a.Value != 2 || nested.Value != 2 { t.Fatal(\"copied module not selected\") } }\n")
	t.Setenv("GOWORK", filepath.Join(source, "go.work"))
	work, err := Isolate(filepath.Join(source, "experiments/a"), scratch)
	if err != nil {
		t.Fatal(err)
	}
	run := func() ([]byte, error) {
		cmd := exec.Command("go", "test", "-count=1", "./...")
		cmd.Dir = filepath.Join(scratch, "deploy")
		cmd.Env = append(os.Environ(), "GOWORK="+work, "GOPROXY=off", "GOTOOLCHAIN=local")
		return cmd.CombinedOutput()
	}
	if out, err := run(); err != nil {
		t.Fatalf("positive control: %v %s", err, out)
	}
	put(t, scratch, "a/nested/n.go", "package nested\nconst Value = 3\n")
	out, err := run()
	exit, ok := err.(*exec.ExitError)
	if !ok || exit.ExitCode() != 1 || !strings.Contains(string(out), "copied module not selected") || strings.Contains(string(out), "build failed") {
		t.Fatalf("mutation did not reach assertion: %v %s", err, out)
	}
	before, _ := os.ReadFile(work)
	if _, err = Isolate(source, scratch); err == nil {
		t.Fatal("existing fixture overwritten")
	}
	after, _ := os.ReadFile(work)
	if string(before) != string(after) {
		t.Fatal("failed recreation changed workspace")
	}
}

// Missing modules, nonlocal paths and replaces fail before a workspace appears.
func TestInvalidWorkspace(t *testing.T) {
	for _, text := range []string{"go 1.26.0\nuse ./missing\n", "go 1.26.0\nuse ../foreign\n", "go 1.26.0\nuse ./deploy\nreplace example.com/a => ../a\n"} {
		source, scratch := t.TempDir(), t.TempDir()
		put(t, source, "go.work", text)
		if _, err := Isolate(source, scratch); err == nil {
			t.Fatal("invalid source accepted")
		}
		if _, err := os.Stat(filepath.Join(scratch, "go.work")); !os.IsNotExist(err) {
			t.Fatal("invalid source wrote workspace")
		}
	}
}
