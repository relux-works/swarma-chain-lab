package configguard

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"os/exec"
	"testing"

	"golang.org/x/sys/unix"
)

// Separate children cover the fixture-mode class in both restrictive (0077)
// and permissive (0002) directions. Signed and composed neighbors must pass;
// public inputs still refuse. Ownership/NSS/traversal are synthetic, modes real.
func TestFixtureUmask(t *testing.T) {
	mask := os.Getenv("DK5_UMASK_CHILD")
	if mask == "" {
		for _, mask := range []string{"0077", "0002"} {
			t.Run(mask, func(t *testing.T) {
				cmd := exec.Command(os.Args[0], "-test.run=^TestFixtureUmask$", "-test.v")
				cmd.Env = append(os.Environ(), "DK5_UMASK_CHILD="+mask)
				out, e := cmd.CombinedOutput()
				if e != nil {
					t.Fatalf("fixture umask child: %v\n%s", e, out)
				}
				if !bytes.Contains(out, []byte("--- PASS: TestFixtureUmask (")) {
					t.Fatalf("fixture umask child did not run: %s", out)
				}
			})
		}
		return
	}
	var mode int
	switch mask {
	case "0077":
		mode = 0077
	case "0002":
		mode = 0002
	default:
		t.Fatalf("unknown fixture umask %q", mask)
	}
	old := unix.Umask(mode)
	t.Cleanup(func() { unix.Umask(old) })
	t.Run("signed", func(t *testing.T) {
		_, key, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		r, p, anchor, _ := signedFixture(t, key, "ed25519")
		s, e := OpenSignedSet(anchor, "model", r)
		if e != nil {
			t.Fatalf("umask signed neighbor: %v", e)
		}
		if b, e := s.Read(p, 32); e != nil || string(b) != "{}" {
			t.Fatalf("umask signed bytes: %v", e)
		}
		writeMode(t, p, []byte("{}"), 0644)
		if b, e := s.Read(p, 32); e == nil || e.Error() != "DK5_FILE_MODE" || b != nil {
			t.Fatalf("umask public input refusal: %v", e)
		}
	})
	for _, service := range []string{"model", "wallet"} {
		t.Run(service, func(t *testing.T) {
			_, p := composedFixture(t, service)
			if b, e := ReadService(service, p, 32); e != nil || string(b) != "{}" {
				t.Fatalf("umask composed neighbor: %v", e)
			}
			writeMode(t, p, []byte("{}"), 0644)
			if b, e := ReadService(service, p, 32); e == nil || e.Error() != "DK5_FILE_MODE" || b != nil {
				t.Fatalf("umask composed public refusal: %v", e)
			}
		})
	}
}
