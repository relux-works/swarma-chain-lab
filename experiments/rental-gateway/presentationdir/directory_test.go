package presentationdir

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Direct callers get the same root/control-byte refusals as the gateway CLI.
// CR/LF fixtures are real readable directories, so rejection cannot be explained
// by a missing path. A valid neighbour reads the exact bytes without mutation.
func TestOpenPathBoundary(t *testing.T) {
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(root, 0755); e != nil {
		t.Fatal(e)
	}
	id := strings.Repeat("a", 64)
	proof := []byte("public fixture")
	path := filepath.Join(root, id+".json")
	if e = os.WriteFile(path, proof, 0644); e != nil {
		t.Fatal(e)
	}
	d, e := Open(root)
	if e != nil {
		t.Fatal("valid directory refused", e)
	}
	got, e := d.Presentation(context.Background(), id)
	_ = d.Close()
	if e != nil || string(got) != string(proof) {
		t.Fatal("valid proof changed", e)
	}
	cases := []struct{ name, path string }{{"root", string(filepath.Separator)}, {"nul", root + "\x00"}, {"cr", filepath.Join(root, "with\rcontrol")}, {"lf", filepath.Join(root, "with\ncontrol")}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "cr" || tc.name == "lf" {
				if e := os.Mkdir(tc.path, 0755); e != nil {
					t.Fatal(e)
				}
			}
			d, e := Open(tc.path)
			if d != nil {
				_ = d.Close()
			}
			if e != ErrSource || d != nil {
				t.Fatal("forbidden source path accepted")
			}
			if tc.name == "cr" || tc.name == "lf" {
				entries, e := os.ReadDir(tc.path)
				if e != nil || len(entries) != 0 {
					t.Fatal("refusal changed directory")
				}
			}
		})
	}
	after, e := os.ReadFile(path)
	if e != nil || string(after) != string(proof) {
		t.Fatal("source mutated")
	}
}
