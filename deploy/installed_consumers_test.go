package deploy

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

var installedBindings = map[string]string{
	"experiments/agent-wallet/installed.go":                          "ReadService:wallet",
	"experiments/agent-wallet/cmd/agent-walletd/main.go":             "CheckMain:wallet",
	"experiments/grant-store/cmd/grant-store/installed.go":           "ReadService:store",
	"experiments/grant-store/cmd/grant-store/main.go":                "CheckMain:store",
	"experiments/model-proxy/installed.go":                           "ReadService:model",
	"experiments/model-proxy/cmd/model-proxy/main.go":                "CheckMain:model",
	"experiments/relay/cmd/swarma-relay/installed.go":                "ReadService:relay",
	"experiments/relay/cmd/swarma-relay/main.go":                     "CheckMain:relay",
	"experiments/rental-booking/cmd/rental-booking/installed.go":     "ReadService:booking",
	"experiments/rental-booking/cmd/rental-booking/main.go":          "CheckMain:booking",
	"experiments/rental-gateway/cmd/gateway/installed.go":            "ReadService:gateway",
	"experiments/rental-gateway/cmd/gateway/main.go":                 "CheckMain:gateway",
	"experiments/rental/installed_key.go":                            "ReadService:issuer",
	"experiments/signer-service/installed.go":                        "ReadService:issuer",
	"experiments/signer-service/cmd/swarma-signer/main.go":           "CheckMain:issuer",
	"experiments/station-lifecycle/cmd/station-manager/installed.go": "ReadService:stations",
	"experiments/station-lifecycle/cmd/station-manager/main.go":      "CheckMain:stations",
	"experiments/station-payload/cmd/station-payload/installed.go":   "ReadService:payload",
}

func checkInstalledConsumer(raw []byte, want string) error {
	f, e := parser.ParseFile(token.NewFileSet(), "consumer.go", raw, 0)
	if e != nil {
		return e
	}
	aliases := map[string]bool{}
	constants := map[string]string{}
	for _, imp := range f.Imports {
		path, _ := strconv.Unquote(imp.Path.Value)
		if path != "github.com/relux-works/swarma-chain-lab/experiments/single-use/configguard" {
			continue
		}
		name := "configguard"
		if imp.Name != nil {
			name = imp.Name.Name
		}
		if name == "." {
			return fmt.Errorf("unsigned surface: dot import")
		}
		aliases[name] = true
	}
	ast.Inspect(f, func(n ast.Node) bool {
		d, ok := n.(*ast.GenDecl)
		if !ok || d.Tok != token.CONST {
			return true
		}
		for _, spec := range d.Specs {
			v := spec.(*ast.ValueSpec)
			for i, name := range v.Names {
				if i < len(v.Values) {
					if l, ok := v.Values[i].(*ast.BasicLit); ok && l.Kind == token.STRING {
						constants[name.Name], _ = strconv.Unquote(l.Value)
					}
				}
			}
		}
		return true
	})
	found := 0
	var failure error
	ast.Inspect(f, func(n ast.Node) bool {
		if s, ok := n.(*ast.SelectorExpr); ok {
			if alias, ok := s.X.(*ast.Ident); ok && aliases[alias.Name] {
				switch s.Sel.Name {
				case "Read", "Native", "Reader", "OpenSignedSet":
					failure = fmt.Errorf("unsigned surface: %s", s.Sel.Name)
				}
			}
		}
		c, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		s, ok := c.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		a, ok := s.X.(*ast.Ident)
		if !ok || !aliases[a.Name] || (s.Sel.Name != "ReadService" && s.Sel.Name != "CheckMain") {
			return true
		}
		found++
		value := ""
		if len(c.Args) > 0 {
			switch v := c.Args[0].(type) {
			case *ast.BasicLit:
				if v.Kind == token.STRING {
					value, _ = strconv.Unquote(v.Value)
				}
			case *ast.Ident:
				value = constants[v.Name]
			}
		}
		if want == "" || s.Sel.Name+":"+value != want {
			failure = fmt.Errorf("service binding: %s:%s expected %s", s.Sel.Name, value, want)
		}
		return true
	})
	if failure != nil {
		return failure
	}
	if (want != "" && found != 1) || (want == "" && found != 0) {
		return fmt.Errorf("service binding inventory")
	}
	return nil
}

// Every non-test consumer stays on the signed boundary, with the service fixed
// independently by the unit inventory. Source scanning cannot prove NSS/ACLs.
func TestInstalledConsumerBoundary(t *testing.T) {
	root, e := filepath.Abs("..")
	if e != nil {
		t.Fatal(e)
	}
	seen := map[string]bool{}
	e = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, e := filepath.Rel(root, path)
		if e != nil {
			return e
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == ".temp" || rel == "experiments/single-use/configguard" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		raw, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		want := installedBindings[filepath.ToSlash(rel)]
		if want == "" && !strings.Contains(string(raw), "/single-use/configguard") {
			return nil
		}
		if e = checkInstalledConsumer(raw, want); e != nil {
			t.Errorf("%s: %v", rel, e)
		}
		if want != "" {
			seen[filepath.ToSlash(rel)] = true
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	for p := range installedBindings {
		if !seen[p] {
			t.Errorf("missing installed consumer: %s", p)
		}
	}
}

// Known wrong-service and unsigned-reader source plants calibrate the scanner;
// renamed imports are checked too, beside the valid signed consumer.
func TestInstalledConsumerScannerControls(t *testing.T) {
	valid := []byte("package p\nimport cg \"github.com/relux-works/swarma-chain-lab/experiments/single-use/configguard\"\nconst installedService=\"issuer\"\nvar r=func(p string,n int64)([]byte,error){return cg.ReadService(installedService,p,n)}")
	if e := checkInstalledConsumer(valid, "ReadService:issuer"); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{strings.Replace(string(valid), "issuer", "gateway", 1), string(valid) + "\nvar unsigned=cg.Native", string(valid) + "\nvar unsigned=cg.Reader{}", string(valid) + "\nvar unsigned=cg.Read", string(valid) + "\nvar unsigned=cg.OpenSignedSet"} {
		if e := checkInstalledConsumer([]byte(bad), "ReadService:issuer"); e == nil {
			t.Fatal("consumer scanner missed violation")
		}
	}
}
