package configguard

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"os/exec"
	"testing"

	"golang.org/x/sys/unix"
)

// A child confines the process-global umask. Signed and composed neighbors must
// remain valid under 0077; an explicitly public input must still refuse. Only
// ownership/NSS/traversal are synthetic; the tested mode bits remain real.
func TestFixtureUmask(t *testing.T) {
	if os.Getenv("DK5_UMASK_CHILD") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestFixtureUmask$", "-test.v")
		cmd.Env = append(os.Environ(), "DK5_UMASK_CHILD=1")
		if out, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("fixture umask child: %v\n%s", e, out)
		}
		return
	}
	old := unix.Umask(0077)
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
