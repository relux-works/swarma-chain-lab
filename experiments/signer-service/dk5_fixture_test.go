package signerservice

import (
	"bytes"
	"context"
	"fmt"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/configguard"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Existing loader/unit tests use a labelled synthetic root-ownership seam.
// Real modes, kinds, descriptor reads and parsers remain exercised. Signed
// anchor/manifest checks are tested in configguard; this is not host qualification.
func init() {
	r := configguard.Reader{EUID: os.Geteuid(), GID: os.Getegid(), Metadata: func(_ string, s *unix.Stat_t) { s.Uid = 0 }}
	installedRead = r.Read
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

// Real RunFile rejects installed config metadata before parsing or opening its
// service state. A valid-mode neighbor reaches the actual config decoder; full
// daemon/chain startup is not asserted by this non-root ownership fixture.
func TestDK5RunFileNoEffects(t *testing.T) {
	for _, mode := range []os.FileMode{0644, 0660, 0666} {
		t.Run(fmt.Sprintf("%04o", mode), func(t *testing.T) {
			c := config(t)
			p := filepath.Join(t.TempDir(), "service.json")
			writeInstalled(t, p, encode(FileConfig{Config: c, IntervalSeconds: 1}))
			var decoded FileConfig
			if e := readJSON(p, &decoded); e != nil || decoded.Config.StateDir != c.StateDir {
				t.Fatal("config decoder neighbor", e)
			}
			before := snapshotTree(t, c.StateDir)
			if e := os.Chmod(p, mode); e != nil {
				t.Fatal(e)
			}
			reports := 0
			e := RunFile(context.Background(), p, true, func(Result) { reports++ })
			if e == nil || e.Error() != "DK5_FILE_MODE" {
				t.Fatal("DK5 startup guard", e)
			}
			if reports != 0 || !bytes.Equal(before, snapshotTree(t, c.StateDir)) {
				t.Fatal("DK5 config refusal changed state")
			}
		})
	}
}

// A malformed funding key's installed metadata refuses before a signer lock,
// ledger reservation or loop starts, even when the grant key/routes are valid.
func TestDK5FundingBeforeState(t *testing.T) {
	c := config(t)
	root := t.TempDir()
	readPath, sendPath := filepath.Join(root, "read.json"), filepath.Join(root, "send.json")
	route := su.Route{Host: "127.0.0.1", Port: 18443, Username: "w3-observer", Password: strings.Repeat("x", 32)}
	writeInstalled(t, readPath, encode(route))
	route.Username = "sg1-broadcaster"
	writeInstalled(t, sendPath, encode(route))
	p := filepath.Join(root, "service.json")
	writeInstalled(t, p, encode(FileConfig{Config: c, ReadRouteFile: readPath, BroadcastRouteFile: sendPath, IntervalSeconds: 1}))
	key, e := loadKey(c.FundingKeyPath, c.Policy.Policy.FundingScript)
	if e != nil {
		t.Fatal("funding positive", e)
	}
	key.Zero()
	if e = os.Chmod(c.FundingKeyPath, 0644); e != nil {
		t.Fatal(e)
	}
	before := snapshotTree(t, c.StateDir)
	e = RunFile(context.Background(), p, true, func(Result) { t.Fatal("unexpected report") })
	if e == nil || e.Error() != "DK5_FILE_MODE" {
		t.Fatal("DK5 funding startup guard", e)
	}
	if !bytes.Equal(before, snapshotTree(t, c.StateDir)) {
		t.Fatal("funding refusal opened state")
	}
}
