package g2run

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// watched lists, per import path, the members that start a process or carry an exec's attributes ("*" = every
// member). They may be used only inside the one designated function, (*Executor).Run in execfixed_linux.go.
var watched = map[string]map[string]bool{
	"os/exec": {"*": true},
	"os":      {"StartProcess": true, "ProcAttr": true},
	"syscall": {"Exec": true, "ForkExec": true, "StartProcess": true, "Syscall": true, "Syscall6": true,
		"RawSyscall": true, "RawSyscall6": true, "SysProcAttr": true, "Credential": true, "WaitStatus": true},
	"golang.org/x/sys/unix": {"Exec": true, "Syscall": true, "Syscall6": true, "RawSyscall": true, "RawSyscall6": true,
		"SyscallNoError": true, "RawSyscallNoError": true},
}

// forbiddenImports may not be imported at all: they reach the kernel or foreign code around the checker.
var forbiddenImports = map[string]bool{"unsafe": true, "C": true, "plugin": true}

func isDesignated(file string, fd *ast.FuncDecl) bool {
	if filepath.Base(file) != "execfixed_linux.go" || fd.Name.Name != "Run" || fd.Recv == nil || len(fd.Recv.List) != 1 {
		return false
	}
	st, ok := fd.Recv.List[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	id, ok := st.X.(*ast.Ident)
	return ok && id.Name == "Executor"
}

// execViolations resolves each file's import names (aliases included) and reports every use of a watched member
// outside the designated function, every dot or blank import of a watched package, every forbidden import, and every
// go:linkname directive.
func execViolations(t *testing.T, files []string) []string {
	t.Helper()
	var out []string
	fs := token.NewFileSet()
	for _, f := range files {
		af, e := parser.ParseFile(fs, f, nil, parser.ParseComments)
		if e != nil {
			t.Fatal(e)
		}
		base := filepath.Base(f)
		for _, cg := range af.Comments {
			for _, c := range cg.List {
				if strings.Contains(c.Text, "go:linkname") {
					out = append(out, base+": go:linkname")
				}
			}
		}
		names := map[string]string{} // local name -> watched import path
		for _, im := range af.Imports {
			path, _ := strconv.Unquote(im.Path.Value)
			if forbiddenImports[path] {
				out = append(out, base+": import "+path)
				continue
			}
			if watched[path] == nil {
				continue
			}
			local := path[strings.LastIndex(path, "/")+1:]
			if im.Name != nil {
				local = im.Name.Name
			}
			if local == "." || local == "_" {
				out = append(out, base+": "+local+" import of "+path)
				continue
			}
			names[local] = path
		}
		check := func(n ast.Node, allowed bool, where string) {
			ast.Inspect(n, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				id, ok := sel.X.(*ast.Ident)
				if !ok {
					return true
				}
				path, ok := names[id.Name]
				if !ok {
					return true
				}
				if (watched[path]["*"] || watched[path][sel.Sel.Name]) && !allowed {
					out = append(out, base+": "+where+" uses "+path+"."+sel.Sel.Name)
				}
				return true
			})
		}
		for _, d := range af.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok {
				check(fd, isDesignated(f, fd), "func "+fd.Name.Name)
			} else {
				check(d, false, "package level")
			}
		}
	}
	return out
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

// Claim: in this package's non-test sources, nothing but (*Executor).Run in execfixed_linux.go starts a process or
// builds an exec's attributes, under any import alias; and no file reaches the kernel around the checker (unsafe,
// cgo, plugin, go:linkname). Controls: each planted alternate path the review of record executed (an aliased os
// import, a second exec function inside execfixed_linux.go, syscall.Exec, a dot import, go:linkname, unsafe) is
// flagged, and the designated function itself is not, so a clean result is not vacuous.
func TestOnlyExecFixedStartsProcesses(t *testing.T) {
	if v := execViolations(t, packageSources(t, ".")); len(v) != 0 {
		t.Errorf("exec paths outside (*Executor).Run: %v", v)
	}
	plants := map[string]string{
		"alias.go":    "package g2run\nimport process \"os\"\nfunc a() { process.StartProcess(\"/bin/sh\", nil, nil) }\n",
		"syscall.go":  "package g2run\nimport \"syscall\"\nfunc b() { syscall.Exec(\"/bin/sh\", nil, nil) }\n",
		"dot.go":      "package g2run\nimport . \"os/exec\"\nfunc c() { Command(\"sh\").Run() }\n",
		"link.go":     "package g2run\nimport _ \"unsafe\"\n//go:linkname d syscall.forkExec\nfunc d()\n",
		"pkglevel.go": "package g2run\nimport \"os/exec\"\nvar e = exec.Command\n",
		// A file with the designated name: Run is allowed, a second function using exec is not.
		"execfixed_linux.go": "package g2run\nimport \"os/exec\"\ntype Executor struct{}\nfunc (x *Executor) Run() { exec.Command(\"/usr/bin/true\").Run() }\nfunc other() { exec.Command(\"/bin/sh\").Run() }\n",
	}
	for name, src := range plants {
		dir := t.TempDir()
		p := filepath.Join(dir, name)
		if e := os.WriteFile(p, []byte(src), 0600); e != nil {
			t.Fatal(e)
		}
		v := execViolations(t, []string{p})
		if len(v) == 0 {
			t.Errorf("CONTROL %s: the checker missed the planted exec path", name)
		}
		if name == "execfixed_linux.go" {
			for _, x := range v {
				if strings.Contains(x, "func Run") {
					t.Errorf("CONTROL %s: the designated function itself was flagged: %v", name, v)
				}
			}
		}
	}
}
