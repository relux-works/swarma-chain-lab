package main

import (
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/configguard"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"testing"
)

// Existing loader/unit tests use a labelled synthetic root-ownership seam.
// The fixture boundary is the file parent; ancestor cases are exercised inside
// configguard fixtures. No host ancestry or mode bits are synthesized here.
// Real modes, kinds, descriptor reads and parsers remain exercised. Signed
// anchor/manifest checks are tested in configguard; this is not host qualification.
func init() {
	r := configguard.Reader{EUID: os.Geteuid(), GID: os.Getegid(), Metadata: func(_ string, s *unix.Stat_t) { s.Uid = 0 }}
	installedRead = func(path string, limit int64) ([]byte, error) {
		fixture := r
		fixture.FixtureRoot = filepath.Dir(path)
		return fixture.Read(path, limit)
	}
}
func writeInstalled(t *testing.T, path string, b []byte) {
	t.Helper()
	if e := os.Chmod(filepath.Dir(path), 0750); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(path, b, 0640); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(path, 0640); e != nil {
		t.Fatal(e)
	}
}

// A static reader rejects public/writable bytes before returning content, with
// an adjacent positive input. Mutable-state readers are not substituted here.
func TestDK5InstalledMode(t *testing.T) {
	p := filepath.Join(t.TempDir(), "input")
	writeInstalled(t, p, []byte("fixture"))
	if b, e := installedRead(p, 32); e != nil || string(b) != "fixture" {
		t.Fatalf("DK5 valid neighbor: %v", e)
	}
	for _, mode := range []os.FileMode{0644, 0660, 0666} {
		if e := os.Chmod(p, mode); e != nil {
			t.Fatal(e)
		}
		b, e := installedRead(p, 32)
		if e == nil || e.Error() != "DK5_FILE_MODE" || b != nil {
			t.Fatalf("DK5 mode refused before bytes: %v", e)
		}
	}
}

// The compiled consumer identity is pinned to its independently specified unit.
func TestDK5ServiceBinding(t *testing.T) {
	if installedService != "relay" {
		t.Fatal("service binding differs from unit")
	}
}
