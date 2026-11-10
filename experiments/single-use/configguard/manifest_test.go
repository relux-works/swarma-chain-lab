package configguard

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func seal(t *testing.T, r Reader, p string, m Manifest) (string, string) {
	t.Helper()
	b, e := json.Marshal(m)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(filepath.Dir(p), "installed.json")
	if e = os.WriteFile(path, b, 0640); e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(path, 0640); e != nil {
		t.Fatal(e)
	}
	return path, hash(b)
}
func goodManifest(r Reader, p string) Manifest {
	return Manifest{Version: 1, ReleaseSHA256: strings.Repeat("a", 64), Service: "model", GID: r.GID, Files: []Entry{{Path: p, SHA256: hash([]byte("{}"))}}}
}

// The anchor is a synthetic pre-supplied value, never learned from installed
// files at verification time. Missing/malformed/unlisted/tampered sets return no
// usable set or bytes. This does not certify an external unit's anchor custody.
func TestManifestRefusals(t *testing.T) {
	for _, name := range []string{"missing", "malformed", "duplicate", "unsafe", "wrong_service", "wrong_group", "release", "hash_change", "anchor", "unlisted", "late_change"} {
		t.Run(name, func(t *testing.T) {
			r, p := fixture(t)
			m := goodManifest(r, p)
			mp, anchor := seal(t, r, p, m)
			set, e := openSet(mp, anchor, m.ReleaseSHA256, "model", r)
			if e != nil {
				t.Fatalf("valid manifest: %v", e)
			}
			if b, e := set.Read(p, 32); e != nil || string(b) != "{}" {
				t.Fatalf("valid manifest neighbor %s %v", b, e)
			}
			want := ""
			switch name {
			case "missing":
				os.Remove(mp)
				want = "DK5_MANIFEST_READ"
			case "malformed":
				b := []byte("{")
				os.WriteFile(mp, b, 0640)
				anchor = hash(b)
				want = "DK5_MANIFEST_SCHEMA"
			case "duplicate":
				m.Files = append(m.Files, m.Files[0])
				mp, anchor = seal(t, r, p, m)
				want = "DK5_MANIFEST_PATH"
			case "unsafe":
				m.Files[0].Path = filepath.Dir(p) + "/../service.json"
				mp, anchor = seal(t, r, p, m)
				want = "DK5_MANIFEST_PATH"
			case "wrong_service":
				m.Service = "issuer"
				mp, anchor = seal(t, r, p, m)
				want = "DK5_MANIFEST_BINDING"
			case "wrong_group":
				m.GID++
				mp, anchor = seal(t, r, p, m)
				want = "DK5_MANIFEST_BINDING"
			case "release":
				m.ReleaseSHA256 = strings.Repeat("b", 64)
				mp, anchor = seal(t, r, p, m)
				want = "DK5_MANIFEST_BINDING"
			case "hash_change":
				os.WriteFile(p, []byte("[]"), 0640)
				want = "DK5_CONTENT_HASH"
			case "anchor":
				anchor = strings.Repeat("b", 64)
				want = "DK5_MANIFEST_HASH"
			case "unlisted":
				b, e := set.Read(p+".other", 32)
				code(t, e, "DK5_UNLISTED_PATH")
				if b != nil {
					t.Fatal("unlisted bytes")
				}
				return
			case "late_change":
				os.WriteFile(p, []byte("[]"), 0640)
				b, e := set.Read(p, 32)
				code(t, e, "DK5_CONTENT_HASH")
				if b != nil {
					t.Fatal("changed bytes")
				}
				return
			}
			got, e := openSet(mp, anchor, strings.Repeat("a", 64), "model", r)
			code(t, e, want)
			if got != nil {
				t.Fatal("partial manifest authority")
			}
		})
	}
}

// Test-only unsigned anchor isolates manifest schema/hash controls; production
// entry points require OpenSignedSet and real signatures.
// openSet authenticates a pre-supplied anchor before interpreting the manifest.
// It never computes the expected anchor from current files, seals an install,
// or returns partial authority. All listed files are checked before success.
func openSet(path, anchor, release, service string, r Reader) (*Set, error) {
	if !digestOK(anchor) || !digestOK(release) || service == "" {
		return nil, fail("DK5_MANIFEST_ANCHOR")
	}
	raw, e := r.Read(path, 1<<20)
	if e != nil {
		return nil, fail("DK5_MANIFEST_READ")
	}
	defer clear(raw)
	if digest(raw) != anchor {
		return nil, fail("DK5_MANIFEST_HASH")
	}
	return openManifest(raw, path, release, service, r)
}
