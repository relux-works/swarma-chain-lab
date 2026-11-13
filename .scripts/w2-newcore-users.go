// W2 Core test inventory from the Go syntax tree (stdlib only).
//
// Lists the top-level declarations of one package directory's *_test.go files
// that reference the identifier newCore (the W2 grant fixture) in any form: a
// call, a parenthesised call such as (newCore)(t), a function value assigned
// to a variable or passed as an argument, or any other use of the name.
// Comments and string literals are not references. A Test function (the go
// test naming rule, no receiver, not TestMain) that references newCore is a
// test; every other function, method or package-level var/const/type spec that
// references it is a helper (an indirect user a manifest could miss).
//
// The rule is syntactic: an identifier newCore that is a shadowing local, a
// field or a method name also counts. That over-counts and never under-counts.
//
// Run at the repository root (stdlib only, no module needed):
//
//	go run .scripts/w2-newcore-users.go -dir experiments/agent-wallet
//
// Output (stdout): {"tests": [...], "helpers": [...]}, each sorted. Exit 1 if
// the directory has no *_test.go file, a file does not parse, or the files do
// not declare exactly one top-level func newCore.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

const fixture = "newCore"

// references reports whether the subtree contains the identifier newCore.
func references(node ast.Node) bool {
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && id.Name == fixture {
			found = true
		}
		return !found
	})
	return found
}

// isTest applies the go test rule: TestXxx where Xxx does not start with a
// lower-case letter, a plain function, and not TestMain.
func isTest(d *ast.FuncDecl) bool {
	name := d.Name.Name
	if d.Recv != nil || !strings.HasPrefix(name, "Test") || name == "TestMain" {
		return false
	}
	if len(name) == len("Test") {
		return true
	}
	r, _ := utf8.DecodeRuneInString(name[len("Test"):])
	return !unicode.IsLower(r)
}

func inventory(dir string) (tests, helpers []string, err error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*_test.go"))
	if err != nil {
		return nil, nil, err
	}
	if len(paths) == 0 {
		return nil, nil, fmt.Errorf("no *_test.go file in %s", dir)
	}
	sort.Strings(paths)
	fset := token.NewFileSet()
	t, h := map[string]bool{}, map[string]bool{}
	fixtures := 0
	for _, path := range paths {
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, nil, err
		}
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil && d.Name.Name == fixture {
					fixtures++
					continue
				}
				if d.Body == nil || !references(d.Body) {
					continue
				}
				if isTest(d) {
					t[d.Name.Name] = true
				} else {
					h[d.Name.Name] = true
				}
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch s := spec.(type) {
					case *ast.ValueSpec:
						hit := s.Type != nil && references(s.Type)
						for _, v := range s.Values {
							hit = hit || references(v)
						}
						if hit {
							for _, n := range s.Names {
								h[n.Name] = true
							}
						}
					case *ast.TypeSpec:
						if references(s.Type) {
							h[s.Name.Name] = true
						}
					}
				}
			}
		}
	}
	if fixtures != 1 {
		return nil, nil, fmt.Errorf("%d top-level func %s declarations in %s, want 1", fixtures, fixture, dir)
	}
	return keys(t), keys(h), nil
}

func keys(m map[string]bool) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func main() {
	dir := flag.String("dir", "", "package directory whose *_test.go files are read")
	flag.Parse()
	if *dir == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: go run .scripts/w2-newcore-users.go -dir DIR")
		os.Exit(2)
	}
	tests, helpers, err := inventory(*dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "W2_NEWCORE_USERS_ERROR", err)
		os.Exit(1)
	}
	out, err := json.Marshal(map[string][]string{"tests": tests, "helpers": helpers})
	if err != nil {
		fmt.Fprintln(os.Stderr, "W2_NEWCORE_USERS_ERROR", err)
		os.Exit(1)
	}
	fmt.Println(string(out))
}
