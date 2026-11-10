package configguard

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

const fixturePrivateGID = 2002
const fixturePeerGID = 2001

// Only identity, NSS and the filesystem root are synthetic. The production
// ServiceSet/ReadService composition consumes real signed bytes and real modes.
func bindComposedFixture(t *testing.T, root, service string) {
	t.Helper()
	old := installedSource
	t.Cleanup(func() { installedSource = old })
	installedSource.reader = func() Reader {
		return Reader{EUID: 1001, GID: fixturePeerGID, FixtureRoot: root, Metadata: func(p string, s *unix.Stat_t) {
			s.Uid = 0
			s.Gid = fixturePrivateGID
			if p == filepath.Join(root, "units") || strings.HasPrefix(p, filepath.Join(root, "units")+"/") {
				s.Gid = 0
			}
		}}
	}
	installedSource.group = func(name string) (*user.Group, error) {
		if name != "swarma-"+service {
			return nil, fmt.Errorf("unexpected group")
		}
		return &user.Group{Name: name, Gid: strconv.Itoa(fixturePrivateGID)}, nil
	}
	installedSource.units = filepath.Join(root, "units")
	installedSource.payload = filepath.Join(root, "payload-anchors")
}
func composedFixture(t *testing.T, service string) (string, string) {
	t.Helper()
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	r, p, ap, a := signedFixture(t, key, "ed25519")
	m := goodManifest(r, p)
	m.Service = service
	m.GID = fixturePrivateGID
	raw, e := json.Marshal(m)
	if e != nil {
		t.Fatal(e)
	}
	writeMode(t, a.Manifest, raw, 0644)
	writeMode(t, a.Signature, signFixture(t, raw, "ed25519", key), 0644)
	a.Digest = digest(raw)
	body, e := RenderDropIn(a)
	if e != nil {
		t.Fatal(e)
	}
	ap = filepath.Join(r.FixtureRoot, "units", "swarma-"+service+".service.d", "10-install.conf")
	mkdirMode(t, filepath.Dir(filepath.Dir(ap)), 0755)
	mkdirMode(t, filepath.Dir(ap), 0755)
	writeMode(t, ap, body, 0644)
	bindComposedFixture(t, r.FixtureRoot, service)
	return r.FixtureRoot, p
}

// The private group wins over the peer effective group in the actual composed
// entry points. Peer-readable content refuses and returns no usable set/bytes.
func TestComposedPrivateGroup(t *testing.T) {
	for _, service := range []string{"model", "wallet"} {
		t.Run(service, func(t *testing.T) {
			_, p := composedFixture(t, service)
			_, r, e := serviceBinding(service)
			if e != nil || r.GID != fixturePrivateGID {
				t.Fatalf("private group binding: %v gid=%d", e, r.GID)
			}
			if s, e := ServiceSet(service); e != nil || s == nil {
				t.Fatalf("composed signed neighbor: %v", e)
			}
			if b, e := ReadService(service, p, 32); e != nil || string(b) != "{}" {
				t.Fatalf("composed bytes: %v", e)
			}
			original := installedSource.reader
			installedSource.reader = func() Reader {
				r := original()
				base := r.Metadata
				r.Metadata = func(path string, s *unix.Stat_t) {
					base(path, s)
					if path == p {
						s.Gid = fixturePeerGID
					}
				}
				return r
			}
			s, e := ServiceSet(service)
			code(t, e, "DK5_FILE_GROUP")
			if s != nil {
				t.Fatal("peer group acquired authority")
			}
			b, e := ReadService(service, p, 32)
			code(t, e, "DK5_FILE_GROUP")
			if b != nil {
				t.Fatal("peer group read bytes")
			}
		})
	}
}

// Missing/malformed NSS, root identity, unknown service and unlisted paths all
// refuse through the public composition after a valid signed private-group read.
func TestComposedRefusals(t *testing.T) {
	for _, name := range []string{"nss_missing", "nss_invalid", "root", "unknown", "unlisted"} {
		t.Run(name, func(t *testing.T) {
			_, p := composedFixture(t, "model")
			if b, e := ReadService("model", p, 32); e != nil || string(b) != "{}" {
				t.Fatalf("composed neighbor: %v", e)
			}
			service := "model"
			want := "DK5_SERVICE_GROUP"
			switch name {
			case "nss_missing":
				installedSource.group = func(string) (*user.Group, error) { return nil, fmt.Errorf("missing") }
			case "nss_invalid":
				installedSource.group = func(string) (*user.Group, error) { return &user.Group{Gid: "invalid"}, nil }
			case "root":
				original := installedSource.reader
				installedSource.reader = func() Reader { r := original(); r.EUID = 0; return r }
				want = "DK5_SERVICE_IDENTITY"
			case "unknown":
				service = "unknown"
				want = "DK5_SERVICE_IDENTITY"
			case "unlisted":
				p += "-unlisted"
				want = "DK5_UNLISTED_PATH"
			}
			b, e := ReadService(service, p, 32)
			code(t, e, want)
			if b != nil {
				t.Fatal("composed refusal returned bytes")
			}
		})
	}
}

// This child executes the real os.Exit path. It neither launches a daemon nor
// bypasses signature verification; fixture location/ownership/NSS are labelled.
func TestComposedCheckMainChild(t *testing.T) {
	root := os.Getenv("DK5_CHECKMAIN_FIXTURE")
	if root == "" {
		t.Skip("subprocess only")
	}
	bindComposedFixture(t, root, "model")
	os.Args = []string{"fixture-service", "--check-installed"}
	CheckMain("model")
	t.Fatal("preflight returned to service constructor")
}

// A valid set exits0; removed-anchor refusal exits1 and emits its exact reason.
// A return or success on refusal would cross the constructor boundary and fails.
func TestComposedCheckMain(t *testing.T) {
	root, _ := composedFixture(t, "model")
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	run := func() (int, string) {
		cmd := exec.Command(exe, "-test.run=^TestComposedCheckMainChild$", "-test.v")
		cmd.Env = append(os.Environ(), "DK5_CHECKMAIN_FIXTURE="+root)
		b, e := cmd.CombinedOutput()
		if e == nil {
			return 0, string(b)
		}
		if x, ok := e.(*exec.ExitError); ok {
			return x.ExitCode(), string(b)
		}
		t.Fatal(e)
		return -1, ""
	}
	if rc, b := run(); rc != 0 {
		t.Fatalf("preflight positive exit %d: %s", rc, b)
	}
	if e = os.Remove(filepath.Join(root, "units", "swarma-model.service.d", "10-install.conf")); e != nil {
		t.Fatal(e)
	}
	if rc, b := run(); rc != 1 || !strings.Contains(b, "DK5_ANCHOR_FILE") || strings.Contains(b, "preflight returned") {
		t.Fatalf("preflight refusal exit %d: %s", rc, b)
	}
}
