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

// kernelMembers is the CLOSED set of members of the kernel-facing packages that code OUTSIDE the designated function
// may use: types, constants and file operations. Everything else in syscall and golang.org/x/sys/unix (raw syscalls,
// AllThreadsSyscall, ptrace, clone, exec, ...) is refused outside (*Executor).Run, whether or not it is listed above.
var kernelMembers = map[string]map[string]bool{
	"syscall": {"Stat_t": true},
	"golang.org/x/sys/unix": {
		"AT_SYMLINK_NOFOLLOW": true, "CLOSE_RANGE_CLOEXEC": true, "Close": true, "CloseRange": true, "EBADF": true,
		"FD_CLOEXEC": true, "F_GETFD": true, "F_SETFD": true, "F_SETFL": true, "Fchmod": true, "FcntlInt": true, "Flock": true,
		"Fstat": true, "Fstatat": true, "Fsync": true, "Ftruncate": true, "LOCK_EX": true, "LOCK_NB": true, "Mkdir": true,
		"O_CLOEXEC": true, "O_CREAT": true, "O_DIRECTORY": true, "O_NOFOLLOW": true, "O_NONBLOCK": true, "O_PATH": true,
		"O_RDONLY": true, "O_WRONLY": true, "Open": true, "OpenHow": true, "Openat2": true, "RESOLVE_BENEATH": true,
		"RESOLVE_NO_MAGICLINKS": true, "RESOLVE_NO_SYMLINKS": true, "Rmdir": true, "S_IFMT": true, "S_IFREG": true,
		"Stat_t": true, "Umask": true,
	},
}

// forbiddenImports may not be imported at all: they reach the kernel or foreign code around the checker.
var forbiddenImports = map[string]bool{"unsafe": true, "C": true, "plugin": true}

// allowedImports is the CLOSED set of imports a non-test source of this package may use. The watched packages are
// confined member by member (above); every other entry was reviewed not to start a process. Any import outside this
// set is a violation, standard library or not: a package that launches processes indirectly (net/http/cgi's Handler,
// go/build's go-command calls, a module wrapping exec) can enter only by a reviewed change to this list.
var allowedImports = map[string]string{
	"io/fs":    "file modes and path errors",
	"net/http": "RouteCode: one loopback RPC status probe; the client starts no process (net/http/cgi stays out)",
	"sort":     "ordering",
	"strconv":  "numeric parsing",
	// The one indirect launcher admitted on purpose: the attempt ledger runs in-process, and its exec-create starts the
	// reviewed key and rpcauth tools under g2ledger's own review and tests, never a program named by a plan.
	"github.com/relux-works/swarma-chain-lab/deploy/g2ledger": "the attempt ledger, in-process (exec-create: g2-keygen, g2-rpcauth)",
	"archive/tar":           "reads the package archive",
	"bufio":                 "buffered reads",
	"bytes":                 "byte buffers",
	"compress/gzip":         "reads the package archive",
	"crypto/sha256":         "package and record digests",
	"encoding/hex":          "digest text",
	"encoding/json":         "strict parameter decoding",
	"errors":                "error values",
	"fmt":                   "formatting",
	"io":                    "readers and writers",
	"os":                    "files; StartProcess and ProcAttr are watched",
	"os/exec":               "watched: every member, only in (*Executor).Run",
	"path":                  "slash paths",
	"path/filepath":         "file paths",
	"regexp":                "name patterns",
	"strings":               "text",
	"syscall":               "watched members only in (*Executor).Run",
	"time":                  "timestamps and timeouts",
	"golang.org/x/sys/unix": "openat2, fstat, flock, fsync; Exec and Syscall* are watched",
}

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
			if _, ok := allowedImports[path]; !ok {
				out = append(out, base+": import "+path+" is not in the reviewed allow-list")
				continue
			}
			if watched[path] == nil && kernelMembers[path] == nil {
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
				} else if kernelMembers[path] != nil && !kernelMembers[path][sel.Sel.Name] && !allowed {
					out = append(out, base+": "+where+" uses "+path+"."+sel.Sel.Name+" (not in the kernel member allow-list)")
				}
				return true
			})
		}
		for _, d := range af.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok {
				// A bodyless declaration is implemented elsewhere (assembly, linkname): refused in this package.
				if fd.Body == nil {
					out = append(out, base+": bodyless func "+fd.Name.Name)
				}
				check(fd, isDesignated(f, fd), "func "+fd.Name.Name)
			} else {
				check(d, false, "package level")
			}
		}
	}
	return out
}

// foreignSources lists every entry of the package directory that is not a Go source file: assembly (.s, .S), C, C++,
// Objective-C, Fortran, SWIG and .syso objects would all join the build beside the Go files and bypass the checker, so
// the package holds Go files only.
func foreignSources(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	ents, e := os.ReadDir(dir)
	if e != nil {
		t.Fatal(e)
	}
	for _, en := range ents {
		if en.IsDir() || !strings.HasSuffix(en.Name(), ".go") {
			out = append(out, en.Name())
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
// builds an exec's attributes, under any import alias; no file reaches the kernel around the checker (unsafe, cgo,
// plugin, go:linkname); and no file imports anything outside the closed, reviewed allow-list. Controls: each planted
// alternate path the reviews of record executed (an aliased os import, a second exec function inside
// execfixed_linux.go, syscall.Exec, a dot import, go:linkname, unsafe, net/http/cgi's Handler, go/build,
// syscall.AllThreadsSyscall, unix.PtraceAttach, a bodyless assembly-backed declaration) is flagged; the package
// directory holds Go files only (.s, .c, .syso and subdirectories are reported, with a control); the members of
// syscall and golang.org/x/sys/unix used outside (*Executor).Run come from a closed allow-list;
// and the designated function itself is not, so a clean result is not vacuous. Limit: the allow-list's
// "starts no process" review covers the listed packages as they are in the pinned Go toolchain, and g2ledger is
// the one admitted exception: its exec-create starts the kit's own key and rpcauth tools under that package's review.
func TestOnlyExecFixedStartsProcesses(t *testing.T) {
	if v := execViolations(t, packageSources(t, ".")); len(v) != 0 {
		t.Errorf("exec paths outside (*Executor).Run: %v", v)
	}
	if f := foreignSources(t, "."); len(f) != 0 {
		t.Errorf("non-Go entries in the package directory: %v", f)
	}
	// Control: assembly, C and object files and a subdirectory are each reported.
	fdir := t.TempDir()
	for _, n := range []string{"ok.go", "x_amd64.s", "y.c", "z.syso"} {
		os.WriteFile(filepath.Join(fdir, n), []byte("package g2run\n"), 0600)
	}
	os.Mkdir(filepath.Join(fdir, "sub"), 0700)
	if got := foreignSources(t, fdir); len(got) != 4 {
		t.Errorf("CONTROL foreign sources: got %v, want x_amd64.s, y.c, z.syso and sub", got)
	}
	plants := map[string]string{
		"alias.go":    "package g2run\nimport process \"os\"\nfunc a() { process.StartProcess(\"/bin/sh\", nil, nil) }\n",
		"syscall.go":  "package g2run\nimport \"syscall\"\nfunc b() { syscall.Exec(\"/bin/sh\", nil, nil) }\n",
		"dot.go":      "package g2run\nimport . \"os/exec\"\nfunc c() { Command(\"sh\").Run() }\n",
		"link.go":     "package g2run\nimport _ \"unsafe\"\n//go:linkname d syscall.forkExec\nfunc d()\n",
		"pkglevel.go": "package g2run\nimport \"os/exec\"\nvar e = exec.Command\n",
		// rev366 delta: an indirect launcher from the standard library, outside every watched package.
		"cgi.go":     "package g2run\nimport (\n\"net/http\"\n\"net/http/cgi\"\n)\nfunc f(w http.ResponseWriter, r *http.Request) { (&cgi.Handler{Path: \"/usr/bin/printf\"}).ServeHTTP(w, r) }\n",
		"gobuild.go": "package g2run\nimport \"go/build\"\nfunc g() { build.Default.Import(\"x\", \".\", 0) }\n",
		// rev366 second delta: raw syscalls outside the enumerated denylist, and an assembly stub.
		"allthreads.go": "package g2run\nimport \"syscall\"\nfunc h() { syscall.AllThreadsSyscall(59, 0, 0, 0) }\n",
		"unixptrace.go": "package g2run\nimport \"golang.org/x/sys/unix\"\nfunc i() { unix.PtraceAttach(1) }\n",
		"bodyless.go":   "package g2run\nfunc rawExec(path, argv, envv uintptr) uintptr\n",
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

// argsViolations reports every Cmd.Args element that is not a constant: Args must be a []string literal whose
// elements are string literals or flagValue("-flag", typedValue) with a literal flag (the owner's E2 condition: a
// typed value never enters Args except through flagValue, which validates it as an operand).
func argsViolations(t *testing.T, files []string) []string {
	t.Helper()
	var out []string
	fs := token.NewFileSet()
	okElem := func(e ast.Expr) bool {
		switch x := e.(type) {
		case *ast.BasicLit:
			return x.Kind == token.STRING
		case *ast.CallExpr:
			id, ok := x.Fun.(*ast.Ident)
			if !ok || id.Name != "flagValue" || len(x.Args) != 2 {
				return false
			}
			lit, ok := x.Args[0].(*ast.BasicLit)
			return ok && lit.Kind == token.STRING
		}
		return false
	}
	checkValue := func(base string, v ast.Expr) {
		lit, ok := v.(*ast.CompositeLit)
		if !ok {
			out = append(out, base+": Args is not a literal")
			return
		}
		for _, el := range lit.Elts {
			if !okElem(el) {
				out = append(out, base+": a non-constant Args element")
			}
		}
	}
	for _, f := range files {
		af, e := parser.ParseFile(fs, f, nil, 0)
		if e != nil {
			t.Fatal(e)
		}
		base := filepath.Base(f)
		ast.Inspect(af, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CompositeLit:
				if id, ok := x.Type.(*ast.Ident); ok && id.Name == "Cmd" {
					for _, el := range x.Elts {
						if kvx, ok := el.(*ast.KeyValueExpr); ok {
							if k, ok := kvx.Key.(*ast.Ident); ok && k.Name == "Args" {
								checkValue(base, kvx.Value)
							}
						}
					}
				}
			case *ast.AssignStmt:
				for i, l := range x.Lhs {
					if sel, ok := l.(*ast.SelectorExpr); ok && sel.Sel.Name == "Args" && i < len(x.Rhs) {
						checkValue(base, x.Rhs[i])
					}
				}
			}
			return true
		})
	}
	return out
}

// Claim: in every non-test source, Cmd.Args holds only constants or flagValue(literal flag, typed value); controls:
// a concatenated value, a variable, an append, and a computed flag name are each flagged, and a valid literal with
// flagValue is not.
func TestArgsHoldOnlyConstants(t *testing.T) {
	if v := argsViolations(t, packageSources(t, ".")); len(v) != 0 {
		t.Errorf("non-constant Args: %v", v)
	}
	plants := map[string]bool{
		"package g2run\nfunc a(v string) Cmd { return Cmd{Program: \"x\", Args: []string{\"--file=\" + v}} }\n":               true,
		"package g2run\nfunc b(args []string) Cmd { return Cmd{Program: \"x\", Args: args} }\n":                               true,
		"package g2run\nfunc c(x *Cmd, v string) { x.Args = append(x.Args, v) }\n":                                            true,
		"package g2run\nfunc d(f, v string) Cmd { return Cmd{Program: \"x\", Args: []string{flagValue(f, v)}} }\n":            true,
		"package g2run\nfunc e(v string) Cmd { return Cmd{Program: \"x\", Args: []string{\"-p\", flagValue(\"--x\", v)}} }\n": false,
	}
	for src, bad := range plants {
		p := filepath.Join(t.TempDir(), "plant.go")
		os.WriteFile(p, []byte(src), 0600)
		if got := len(argsViolations(t, []string{p})) != 0; got != bad {
			t.Errorf("CONTROL %q: flagged=%v want %v", src, got, bad)
		}
	}
}
