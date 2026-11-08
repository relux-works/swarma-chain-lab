package rental

import (
	"os"
	"path/filepath"
	"testing"
)

// The binary scalar loader accepts a private owner file and rejects alternate
// encodings, zero/overflow scalars, links, broad mode and a mismatched key pin.
// These local fixtures do not establish hardware/OS secret isolation.
func TestGrantKeyBoundary(t *testing.T) {
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(root, "key")
	k, pub := testKey(1)
	valid := k.Serialize()
	for _, mode := range []string{"valid", "short", "zero", "overflow", "mode", "symlink", "hardlink", "pin"} {
		t.Run(mode, func(t *testing.T) {
			if e := os.WriteFile(path, valid, 0600); e != nil {
				t.Fatal(e)
			}
			if e := os.Chmod(path, 0600); e != nil {
				t.Fatal(e)
			}
			input, pin, want := path, pub, ""
			switch mode {
			case "short":
				if e := os.WriteFile(path, valid[:31], 0600); e != nil {
					t.Fatal(e)
				}
				want = "KEY_FILE"
			case "zero":
				if e := os.WriteFile(path, make([]byte, 32), 0600); e != nil {
					t.Fatal(e)
				}
				want = "KEY_SCALAR"
			case "overflow":
				b := make([]byte, 32)
				for i := range b {
					b[i] = 255
				}
				if e := os.WriteFile(path, b, 0600); e != nil {
					t.Fatal(e)
				}
				want = "KEY_SCALAR"
			case "mode":
				if e := os.Chmod(path, 0644); e != nil {
					t.Fatal(e)
				}
				want = "KEY_FILE"
			case "symlink":
				input = filepath.Join(root, "symlink")
				if e := os.Symlink(path, input); e != nil {
					t.Fatal(e)
				}
				want = "KEY_PATH"
			case "hardlink":
				link := filepath.Join(root, "hardlink")
				if e := os.Link(path, link); e != nil {
					t.Fatal(e)
				}
				defer os.Remove(link)
				want = "KEY_FILE"
			case "pin":
				_, pin = testKey(2)
				want = "KEY_PIN"
			}
			key, e := readGrantKey(input, pin)
			if want == "" {
				if e != nil {
					t.Fatal(e)
				}
				key.Zero()
			} else if e == nil || e.Error() != want {
				if key != nil {
					key.Zero()
				}
				t.Fatal("key boundary", want, e)
			}
		})
	}
	if e := os.WriteFile(path, valid, 0600); e != nil {
		t.Fatal(e)
	}
	key, e := readGrantKey(path, pub)
	if e != nil {
		t.Fatal("valid neighbor", e)
	}
	key.Zero()
}
