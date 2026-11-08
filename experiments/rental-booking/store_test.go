package booking

import (
	"os"
	"path/filepath"
	"testing"
)

func privateDir(t *testing.T) string {
	t.Helper()
	p := t.TempDir()
	if e := os.Chmod(p, 0700); e != nil {
		t.Fatal(e)
	}
	p, e := filepath.EvalSymlinks(p)
	if e != nil {
		t.Fatal(e)
	}
	return p
}

// This test proves exclusive writer ownership and durable reopen/idempotent
// outbox behavior; conflicting outbox writes leave the original bytes intact.
func TestStoreLockAndOutbox(t *testing.T) {
	root := privateDir(t)
	s, e := openStore(root)
	if e != nil {
		t.Fatal(e)
	}
	defer s.close()
	if other, e := openStore(root); e == nil {
		other.close()
		t.Fatal("parallel writer accepted")
	} else if e.Error() != "STATE_BUSY" {
		t.Fatal(e)
	}
	if e = s.write("state.json", []byte(`{"v":1}`), false); e != nil {
		t.Fatal(e)
	}
	s.close()
	s, e = openStore(root)
	if e != nil {
		t.Fatal(e)
	}
	defer s.close()
	b, e := s.read("state.json", 100)
	if e != nil || string(b) != `{"v":1}` {
		t.Fatalf("reopen: %q %v", b, e)
	}
	for i := 0; i < 2; i++ {
		if e = s.write("issue.json", []byte("first"), true); e != nil {
			t.Fatal(e)
		}
	}
	if e = s.write("issue.json", []byte("second"), true); e == nil || e.Error() != "OUTBOX_CONFLICT" {
		t.Fatalf("conflict: %v", e)
	}
	b, e = s.read("issue.json", 100)
	if e != nil || string(b) != "first" {
		t.Fatalf("outbox changed: %q %v", b, e)
	}
}

// Unsafe roots, state symlinks and hard links are refused without overwriting
// their target; normal private state in a separate directory remains writable.
func TestStoreUnsafePaths(t *testing.T) {
	root := privateDir(t)
	target := filepath.Join(root, "target")
	if e := os.WriteFile(target, []byte("sentinel"), 0600); e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"symlink", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			dir := privateDir(t)
			s, e := openStore(dir)
			if e != nil {
				t.Fatal(e)
			}
			defer s.close()
			p := filepath.Join(dir, "state.json")
			if kind == "symlink" {
				e = os.Symlink(target, p)
			} else {
				e = os.Link(target, p)
			}
			if e != nil {
				t.Fatal(e)
			}
			defer os.Remove(p)
			if e = s.write("state.json", []byte("bad"), false); e == nil {
				t.Fatal("unsafe state accepted")
			}
			b, _ := os.ReadFile(target)
			if string(b) != "sentinel" {
				t.Fatal("target altered")
			}
			if e = s.write("safe.json", []byte("safe"), false); e != nil {
				t.Fatal(e)
			}
		})
	}
	alias := filepath.Join(root, "alias")
	if e := os.Symlink(root, alias); e != nil {
		t.Fatal(e)
	}
	if s, e := openStore(alias); e == nil {
		s.close()
		t.Fatal("symlink root accepted")
	}
	if e := os.Chmod(root, 0755); e != nil {
		t.Fatal(e)
	}
	if s, e := openStore(root); e == nil {
		s.close()
		t.Fatal("public root accepted")
	}
}
