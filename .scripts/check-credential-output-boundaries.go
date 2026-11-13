// Command check-credential-output-boundaries checks the reviewed N1b storage and
// explicit-reveal inventory. This is a source-change guard, not a taint analyzer.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
)

func rendered(n ast.Node) string {
	var b bytes.Buffer
	_ = format.Node(&b, token.NewFileSet(), n)
	return b.String()
}

var fields = map[string]string{
	"experiments/model-proxy/types.go:Config.APIKey":                                "UpstreamKey",
	"experiments/rental-gateway/station/station.go:Station.TrackBToken":             "TrackBToken",
	"experiments/rental-gateway/station/trackbadmin.go:trackBMintReply.Token":       "TrackBToken",
	"experiments/rental-gateway/station/trackbadmin.go:decodeTrackBMintReply.Token": "string",
	"experiments/rental-executor/http.go:trackBClaimRequest.Token":                  "TrackBToken",
	"experiments/rental-executor/http.go:decodeTrackBClaim.Token":                   "string",
	"experiments/m5-rehearsal/fixtures/registrar.go.txt:rehearsalRegistrar.APIKey":  "proxy.UpstreamKey",
	"experiments/rental-gateway/station/linuxuser.go:FakeExec.Inputs":               "[]codec.Secret[[]byte]",
}
var reveals = map[string]int{
	"experiments/model-proxy/registry.go:New:r.Bearer.Reveal()":                                   4,
	"experiments/model-proxy/registry.go:New:c.APIKey.Reveal()":                                   3,
	"experiments/model-proxy/messages.go:Messages.Headers:key.Reveal()":                           1,
	"experiments/model-proxy/responses.go:Responses.Headers:key.Reveal()":                         1,
	"experiments/rental-gateway/station/localtest.go:LocalTestDriver.Create:token.Reveal()":       1,
	"experiments/rental-gateway/station/linuxuser.go:LinuxUserDriver.Create:token.Reveal()":       1,
	"experiments/rental-gateway/station/trackbadmin.go:TrackBAdminClient.Mint:out.Token.Reveal()": 1,
	"experiments/rental-gateway/gateway/gateway.go:Gateway.startStation:st.TrackBToken.Reveal()":  1,
	"experiments/rental-executor/trackb.go:TrackB.Mint:token.Reveal()":                            1,
	"experiments/rental-executor/trackb.go:TrackB.Claim:token.Reveal()":                           2,
	"experiments/rental-executor/http.go:writeTrackBMintReply:token.Reveal()":                     1,
}

func receiver(f *ast.FuncDecl) string {
	if f.Recv == nil {
		return f.Name.Name
	}
	n := f.Recv.List[0].Type
	if p, ok := n.(*ast.StarExpr); ok {
		n = p.X
	}
	return rendered(n) + "." + f.Name.Name
}
func inventory(path string, raw []byte, gotFields map[string]string, gotReveals map[string]int) {
	f, e := parser.ParseFile(token.NewFileSet(), path, raw, 0)
	if e != nil {
		panic("source parse refused")
	}
	var scan func(ast.Node, string)
	scan = func(n ast.Node, owner string) {
		ast.Inspect(n, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.StructType:
				for _, field := range v.Fields.List {
					for _, name := range field.Names {
						if name.Name == "APIKey" || name.Name == "TrackBToken" || name.Name == "Token" || (owner == "FakeExec" && name.Name == "Inputs") {
							gotFields[path+":"+owner+"."+name.Name] = rendered(field.Type)
						}
					}
				}
			case *ast.CallExpr:
				selector, ok := v.Fun.(*ast.SelectorExpr)
				if !ok || selector.Sel.Name != "Reveal" {
					break
				}
				expression := rendered(v)
				scope := path + ":" + owner + ":"
				targetScope := false
				for expected := range reveals {
					if strings.HasPrefix(expected, scope) {
						targetScope = true
						break
					}
				}
				if targetScope || strings.Contains(expression, "APIKey") || strings.Contains(expression, "TrackBToken") || strings.Contains(expression, ".Token.") {
					gotReveals[scope+expression]++
				}
			}
			return true
		})
	}
	for _, decl := range f.Decls {
		switch v := decl.(type) {
		case *ast.FuncDecl:
			scan(v, receiver(v))
		case *ast.GenDecl:
			for _, s := range v.Specs {
				if typ, ok := s.(*ast.TypeSpec); ok {
					scan(typ.Type, typ.Name.Name)
				}
			}
		}
	}
}
func main() {
	// The checker must reject an extra carrier, a raw retained field and a new
	// reveal site. These isolated controls print no credential-bearing source.
	controlFields, controlReveals := map[string]string{}, map[string]int{}
	inventory("control.go", []byte(`package control;type Carrier struct{TrackBToken string};func expose(c Carrier){_=c.TrackBToken.Reveal()}`), controlFields, controlReveals)
	if len(controlFields) != 1 || len(controlReveals) != 1 || reflect.DeepEqual(controlFields, fields) || reflect.DeepEqual(controlReveals, reveals) {
		panic("inventory detector control failed")
	}
	changed := map[string]string{}
	for k, v := range fields {
		changed[k] = v
	}
	changed["experiments/model-proxy/types.go:Config.APIKey"] = "Secret"
	if reflect.DeepEqual(changed, fields) {
		panic("raw carrier detector control failed")
	}
	gotFields, gotReveals := map[string]string{}, map[string]int{}
	var paths []string
	e := filepath.WalkDir(".", func(path string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			if path != "." && (strings.HasPrefix(d.Name(), ".") || d.Name() == "vendor") {
				return filepath.SkipDir
			}
			return nil
		}
		if (strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go")) || strings.HasSuffix(path, ".go.txt") {
			paths = append(paths, path)
		}
		return nil
	})
	if e != nil {
		panic("source walk refused")
	}
	sort.Strings(paths)
	for _, path := range paths {
		raw, e := os.ReadFile(path)
		if e != nil {
			panic("source read refused")
		}
		inventory(path, raw, gotFields, gotReveals)
	}
	if !reflect.DeepEqual(fields, gotFields) || !reflect.DeepEqual(reveals, gotReveals) {
		fmt.Fprintln(os.Stderr, "credential storage/reveal inventory changed; re-audit required")
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"fields": gotFields, "reveals": gotReveals})
		os.Exit(1)
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"carrier_fields": gotFields, "explicit_reveals": gotReveals, "controls": 3, "note": "Reviewed source inventory; not an arbitrary-code taint proof"})
}
