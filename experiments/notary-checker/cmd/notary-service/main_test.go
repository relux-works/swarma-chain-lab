package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Keygen prints exactly one x-only public key, never secret material, and
// refuses overwrite. Serve has no offline-fixture/import/export command path.
func TestCLIKeyOutputAndNoFixtureFlag(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	var out bytes.Buffer
	if run(context.Background(), []string{"keygen", "-out", path}, &out) != 0 {
		t.Fatal("generation")
	}
	printed := strings.TrimSuffix(out.String(), "\n")
	if len(printed) != 64 {
		t.Fatal("public output")
	}
	if _, e := hex.DecodeString(printed); e != nil {
		t.Fatal("public encoding")
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(out.String(), hex.EncodeToString(raw[len(raw)-32:])) {
		t.Fatal("secret output")
	}
	for _, args := range [][]string{{"keygen", "-out", path}, {"serve", "-config", "missing", "-offline-name-fixture", "x"}, {"import", "x"}, {"export", "x"}} {
		out.Reset()
		if run(context.Background(), args, &out) == 0 {
			t.Fatal("forbidden path")
		}
		if strings.Contains(out.String(), path) || strings.Contains(out.String(), hex.EncodeToString(raw[len(raw)-32:])) {
			t.Fatal("diagnostic leak")
		}
	}
}
