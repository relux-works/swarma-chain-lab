package payloadbootstrap

import (
	"errors"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

var errPureImport = errors.New("pure API import boundary violated")

func checkPureImports(roots ...string) error {
	allowed := map[string]bool{"bytes": true, "crypto/sha256": true, "encoding/base64": true, "encoding/hex": true, "encoding/json": true, "errors": true, "io": true, "net/url": true, "strings": true, "unicode/utf8": true, "github.com/relux-works/swarma-chain-lab/experiments/single-use/payloadbootstrap/codec": true}
	for _, root := range roots {
		entries, e := os.ReadDir(root)
		if e != nil {
			return e
		}
		for _, f := range entries {
			if !strings.HasSuffix(f.Name(), ".go") || strings.HasSuffix(f.Name(), "_test.go") {
				continue
			}
			node, e := parser.ParseFile(token.NewFileSet(), filepath.Join(root, f.Name()), nil, parser.ImportsOnly)
			if e != nil {
				return e
			}
			for _, im := range node.Imports {
				path, e := strconv.Unquote(im.Path.Value)
				if e != nil || !allowed[path] {
					return errPureImport
				}
			}
		}
	}
	return nil
}

// Pure consumer code has only the declared parser/crypto imports, with no direct
// filesystem/environment/clock/network-client or gateway/lifecycle/proxy import.
// This is not a claim about all standard-library transitive imports.
func TestPureImports(t *testing.T) {
	if e := checkPureImports(".", "codec", "../modelprofile"); e != nil {
		t.Fatal(e)
	}
}

// A real isolated source-file plant proves the import scanner rejects an os
// dependency; the nearby allowed encoding/json import passes the same scanner.
func TestPureImportControl(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "plant.go")
	for _, c := range []struct {
		source string
		want   error
	}{{`package plant; import _ "encoding/json"`, nil}, {`package plant; import _ "os"`, errPureImport}} {
		if e := os.WriteFile(p, []byte(c.source), 0600); e != nil {
			t.Fatal(e)
		}
		if e := checkPureImports(dir); e != c.want {
			t.Fatalf("import control: got %v want %v", e, c.want)
		}
	}
}
