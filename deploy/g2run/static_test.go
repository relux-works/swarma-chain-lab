package g2run

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// execSites lists, per file, every way a Go file could start a process: an os/exec import, os.StartProcess, and the
// syscall or x/sys exec and fork entry points.
func execSites(t *testing.T, files []string) map[string][]string {
	t.Helper()
	sites := map[string][]string{}
	fs := token.NewFileSet()
	for _, f := range files {
		af, e := parser.ParseFile(fs, f, nil, parser.ImportsOnly|parser.ParseComments)
		if e != nil {
			t.Fatal(e)
		}
		for _, im := range af.Imports {
			if strings.Trim(im.Path.Value, `"`) == "os/exec" {
				sites[filepath.Base(f)] = append(sites[filepath.Base(f)], "import os/exec")
			}
		}
		full, e := parser.ParseFile(fs, f, nil, 0)
		if e != nil {
			t.Fatal(e)
		}
		ast.Inspect(full, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			switch pkg.Name + "." + sel.Sel.Name {
			case "os.StartProcess", "syscall.Exec", "syscall.ForkExec", "syscall.StartProcess", "unix.Exec",
				"syscall.RawSyscall", "unix.RawSyscall", "syscall.Syscall", "unix.Syscall":
				sites[filepath.Base(f)] = append(sites[filepath.Base(f)], pkg.Name+"."+sel.Sel.Name)
			}
			return true
		})
	}
	return sites
}

func packageSources(t *testing.T, dir string) []string {
	t.Helper()
	var files []string
	ents, e := os.ReadDir(dir)
	if e != nil {
		t.Fatal(e)
	}
	for _, en := range ents {
		n := en.Name()
		if strings.HasSuffix(n, ".go") && !strings.HasSuffix(n, "_test.go") {
			files = append(files, filepath.Join(dir, n))
		}
	}
	return files
}

// Claim: in this package's non-test sources, the ONLY way to start a process is ExecFixed in execfixed_linux.go.
// Control: the same checker flags a planted source file that imports os/exec, so a clean result is not vacuous.
func TestOnlyExecFixedStartsProcesses(t *testing.T) {
	sites := execSites(t, packageSources(t, "."))
	for f, s := range sites {
		if f != "execfixed_linux.go" {
			t.Errorf("%s starts processes outside ExecFixed: %v", f, s)
		}
	}
	if len(sites["execfixed_linux.go"]) == 0 {
		t.Error("execfixed_linux.go has no exec site: the checker is not seeing it")
	}
	plant := filepath.Join(t.TempDir(), "plant.go")
	os.WriteFile(plant, []byte("package g2run\nimport \"os/exec\"\nfunc f() { exec.Command(\"sh\", \"-c\", \"x\").Run() }\n"), 0600)
	if s := execSites(t, []string{plant}); len(s["plant.go"]) == 0 {
		t.Fatal("CONTROL: the checker missed a planted os/exec import")
	}
	plant2 := filepath.Join(t.TempDir(), "plant2.go")
	os.WriteFile(plant2, []byte("package g2run\nimport \"syscall\"\nfunc g() { syscall.Exec(\"/bin/sh\", nil, nil) }\n"), 0600)
	if s := execSites(t, []string{plant2}); len(s["plant2.go"]) == 0 {
		t.Fatal("CONTROL: the checker missed a planted syscall.Exec")
	}
}
