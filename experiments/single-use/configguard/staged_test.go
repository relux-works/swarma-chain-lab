package configguard

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type stagedFixture struct {
	input  StagedSet
	policy StagedPolicy
	key    crypto.Signer
}

func newStagedFixture(t *testing.T, key crypto.Signer, algorithm string) stagedFixture {
	t.Helper()
	f := stagedFixture{key: key}
	f.policy = StagedPolicy{ManifestPath: "/uninstalled/payload/static/manifest.json", SignaturePath: "/uninstalled/payload/static/manifest.sig", ReleaseSHA256: strings.Repeat("a", 64), Service: "payload", GID: 200017, Paths: []string{"/uninstalled/payload/inputs/ca.pem", "/uninstalled/payload/inputs/model.json"}}
	f.input.Files = map[string][]byte{f.policy.Paths[0]: []byte("public fixture certificate"), f.policy.Paths[1]: []byte("{}")}
	m := Manifest{Version: 1, ReleaseSHA256: f.policy.ReleaseSHA256, Service: f.policy.Service, GID: f.policy.GID}
	for _, p := range f.policy.Paths {
		m.Files = append(m.Files, Entry{p, digest(f.input.Files[p])})
	}
	raw, e := json.Marshal(m)
	if e != nil {
		t.Fatal(e)
	}
	der, e := x509.MarshalPKIXPublicKey(key.Public())
	if e != nil {
		t.Fatal(e)
	}
	a := Anchor{f.policy.ManifestPath, f.policy.SignaturePath, digest(raw), f.policy.ReleaseSHA256, algorithm, base64.StdEncoding.EncodeToString(der)}
	f.input.Anchor, e = RenderDropIn(a)
	if e != nil {
		t.Fatal(e)
	}
	f.input.Manifest = raw
	f.input.Signature = signFixture(t, raw, algorithm, key)
	return f
}
func (f *stagedFixture) rewriteAnchor(t *testing.T, edit func(*Anchor)) {
	t.Helper()
	a, e := parseAnchor(f.input.Anchor)
	if e != nil {
		t.Fatal(e)
	}
	edit(&a)
	f.input.Anchor, e = RenderDropIn(a)
	if e != nil {
		t.Fatal(e)
	}
}
func (f *stagedFixture) signManifest(t *testing.T, raw []byte) {
	t.Helper()
	a, e := parseAnchor(f.input.Anchor)
	if e != nil {
		t.Fatal(e)
	}
	f.input.Manifest = raw
	f.input.Signature = signFixture(t, raw, a.Algorithm, f.key)
	f.rewriteAnchor(t, func(a *Anchor) { a.Digest = digest(raw) })
}
func (f *stagedFixture) editManifest(t *testing.T, edit func(*Manifest)) {
	t.Helper()
	var m Manifest
	if e := json.Unmarshal(f.input.Manifest, &m); e != nil {
		t.Fatal(e)
	}
	edit(&m)
	raw, e := json.Marshal(m)
	if e != nil {
		t.Fatal(e)
	}
	f.signManifest(t, raw)
}
func stagedSnapshot(t *testing.T, f stagedFixture) []byte {
	t.Helper()
	b, e := json.Marshal(struct {
		Input  StagedSet
		Policy StagedPolicy
	}{f.input, f.policy})
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func assertStaged(t *testing.T, f stagedFixture, want string) {
	t.Helper()
	before := stagedSnapshot(t, f)
	e := ValidateStagedSet(f.input, f.policy)
	if want == "" {
		if e != nil {
			t.Fatalf("staged valid neighbor: %v", e)
		}
	} else if e == nil || e.Error() != want {
		t.Fatalf("staged refusal: got %v want %s", e, want)
	}
	if !bytes.Equal(before, stagedSnapshot(t, f)) {
		t.Fatal("staged validator mutated caller bytes or policy")
	}
}

// Real signatures over the actual bytes are accepted without final paths existing;
// both algorithms reject a signature over other bytes. No ownership seam is used.
func TestStagedAlgorithms(t *testing.T) {
	_, ed, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	rsaKey, e := rsa.GenerateKey(rand.Reader, 3072)
	if e != nil {
		t.Fatal(e)
	}
	for alg, key := range map[string]crypto.Signer{"ed25519": ed, "rsa-pss-sha256": rsaKey} {
		t.Run(alg, func(t *testing.T) {
			f := newStagedFixture(t, key, alg)
			root := t.TempDir()
			p := filepath.Join(root, "not-installed", "manifest.json")
			f.policy.ManifestPath = p
			f.policy.SignaturePath = p + ".sig"
			f.rewriteAnchor(t, func(a *Anchor) { a.Manifest = p; a.Signature = p + ".sig" })
			assertStaged(t, f, "")
			if _, e := os.Lstat(filepath.Dir(p)); !os.IsNotExist(e) {
				t.Fatalf("validator created final state: %v", e)
			}
			f.input.Signature = signFixture(t, []byte("different manifest"), alg, key)
			assertStaged(t, f, "DK5_SIGNATURE_INVALID")
		})
	}
}

// Every row starts with a signed valid neighbor, then checks the exact named
// refusal and unchanged inputs. Hash/schema cases are re-signed deliberately to
// reach their intended guard; signature cases keep the trusted public pin.
func TestStagedRefusals(t *testing.T) {
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	type testCase struct {
		name, want string
		change     func(*stagedFixture)
	}
	cases := []testCase{
		{"policy_service", "DK5_SERVICE_IDENTITY", func(f *stagedFixture) { f.policy.Service = "" }},
		{"policy_gid", "DK5_SERVICE_IDENTITY", func(f *stagedFixture) { f.policy.GID = 0 }},
		{"policy_release", "DK5_MANIFEST_ANCHOR", func(f *stagedFixture) { f.policy.ReleaseSHA256 = "bad" }},
		{"policy_manifest_path", "DK5_PATH", func(f *stagedFixture) { f.policy.ManifestPath = "relative" }},
		{"policy_signature_path", "DK5_PATH", func(f *stagedFixture) { f.policy.SignaturePath = f.policy.ManifestPath }},
		{"policy_paths_absent", "DK5_MANIFEST_PATH", func(f *stagedFixture) { f.policy.Paths = nil }},
		{"policy_paths_many", "DK5_MANIFEST_PATH", func(f *stagedFixture) { f.policy.Paths = make([]string, 257) }},
		{"policy_path_relative", "DK5_MANIFEST_PATH", func(f *stagedFixture) { f.policy.Paths[0] = "relative" }},
		{"policy_path_duplicate", "DK5_MANIFEST_PATH", func(f *stagedFixture) { f.policy.Paths[1] = f.policy.Paths[0] }},
		{"policy_path_manifest", "DK5_MANIFEST_PATH", func(f *stagedFixture) { f.policy.Paths = []string{f.policy.ManifestPath} }},
		{"policy_path_signature", "DK5_MANIFEST_PATH", func(f *stagedFixture) { f.policy.Paths = []string{f.policy.SignaturePath} }},
		{"anchor_absent", "DK5_ANCHOR_FILE", func(f *stagedFixture) { f.input.Anchor = nil }},
		{"anchor_empty", "DK5_ANCHOR_FILE", func(f *stagedFixture) { f.input.Anchor = []byte{} }},
		{"anchor_large", "DK5_ANCHOR_FILE", func(f *stagedFixture) { f.input.Anchor = bytes.Repeat([]byte("x"), 32769) }},
		{"anchor_schema", "DK5_ANCHOR_SCHEMA", func(f *stagedFixture) { f.input.Anchor = []byte("[Service]\n") }},
		{"anchor_manifest_path", "DK5_MANIFEST_BINDING", func(f *stagedFixture) { f.rewriteAnchor(t, func(a *Anchor) { a.Manifest += ".other" }) }},
		{"anchor_signature_path", "DK5_MANIFEST_BINDING", func(f *stagedFixture) { f.rewriteAnchor(t, func(a *Anchor) { a.Signature += ".other" }) }},
		{"anchor_release", "DK5_MANIFEST_BINDING", func(f *stagedFixture) { f.rewriteAnchor(t, func(a *Anchor) { a.Release = strings.Repeat("b", 64) }) }},
		{"manifest_absent", "DK5_MANIFEST_READ", func(f *stagedFixture) { f.input.Manifest = nil }},
		{"manifest_empty", "DK5_MANIFEST_READ", func(f *stagedFixture) { f.input.Manifest = []byte{} }},
		{"manifest_large", "DK5_MANIFEST_READ", func(f *stagedFixture) { f.input.Manifest = make([]byte, (1<<20)+1) }},
		{"manifest_hash", "DK5_MANIFEST_HASH", func(f *stagedFixture) { f.rewriteAnchor(t, func(a *Anchor) { a.Digest = strings.Repeat("b", 64) }) }},
		{"signature_absent", "DK5_SIGNATURE_FILE", func(f *stagedFixture) { f.input.Signature = nil }},
		{"signature_empty", "DK5_SIGNATURE_FILE", func(f *stagedFixture) { f.input.Signature = []byte{} }},
		{"signature_large", "DK5_SIGNATURE_FILE", func(f *stagedFixture) { f.input.Signature = make([]byte, 32769) }},
		{"signature_schema", "DK5_SIGNATURE_SCHEMA", func(f *stagedFixture) { f.input.Signature = []byte("{}") }},
		{"signature_algorithm", "DK5_SIGNATURE_SCHEMA", func(f *stagedFixture) {
			f.input.Signature = bytes.Replace(f.input.Signature, []byte("ed25519"), []byte("rsa-pss-sha256"), 1)
		}},
		{"signature_invalid", "DK5_SIGNATURE_INVALID", func(f *stagedFixture) { f.input.Signature = signFixture(t, []byte("other bytes"), "ed25519", f.key) }},
		{"public_key", "DK5_SIGNATURE_KEY", func(f *stagedFixture) {
			a, _ := parseAnchor(f.input.Anchor)
			f.input.Anchor = bytes.Replace(f.input.Anchor, []byte(a.PublicKey), []byte("invalid"), 1)
		}},
		{"manifest_schema", "DK5_MANIFEST_SCHEMA", func(f *stagedFixture) { f.signManifest(t, []byte("{")) }},
		{"manifest_duplicate_key", "DK5_MANIFEST_SCHEMA", func(f *stagedFixture) {
			f.signManifest(t, bytes.Replace(f.input.Manifest, []byte("\"v\":1"), []byte("\"v\":1,\"v\":1"), 1))
		}},
		{"manifest_unknown", "DK5_MANIFEST_SCHEMA", func(f *stagedFixture) {
			f.signManifest(t, bytes.Replace(f.input.Manifest, []byte("\"v\":1"), []byte("\"extra\":1,\"v\":1"), 1))
		}},
		{"manifest_version", "DK5_MANIFEST_SCHEMA", func(f *stagedFixture) { f.editManifest(t, func(m *Manifest) { m.Version = 2 }) }},
		{"manifest_empty_files", "DK5_MANIFEST_SCHEMA", func(f *stagedFixture) { f.editManifest(t, func(m *Manifest) { m.Files = nil }) }},
		{"manifest_service", "DK5_MANIFEST_BINDING", func(f *stagedFixture) { f.editManifest(t, func(m *Manifest) { m.Service = "relay" }) }},
		{"manifest_gid", "DK5_MANIFEST_BINDING", func(f *stagedFixture) { f.editManifest(t, func(m *Manifest) { m.GID++ }) }},
		{"manifest_release", "DK5_MANIFEST_BINDING", func(f *stagedFixture) {
			f.editManifest(t, func(m *Manifest) { m.ReleaseSHA256 = strings.Repeat("b", 64) })
		}},
		{"manifest_relative", "DK5_MANIFEST_PATH", func(f *stagedFixture) { f.editManifest(t, func(m *Manifest) { m.Files[0].Path = "relative" }) }},
		{"manifest_duplicate_path", "DK5_MANIFEST_PATH", func(f *stagedFixture) { f.editManifest(t, func(m *Manifest) { m.Files[1] = m.Files[0] }) }},
		{"manifest_bad_digest", "DK5_MANIFEST_PATH", func(f *stagedFixture) { f.editManifest(t, func(m *Manifest) { m.Files[0].SHA256 = "bad" }) }},
		{"expected_membership", "DK5_MANIFEST_BINDING", func(f *stagedFixture) { f.policy.Paths[1] += ".other" }},
		{"expected_count", "DK5_MANIFEST_BINDING", func(f *stagedFixture) { f.policy.Paths = f.policy.Paths[:1] }},
		{"unlisted_bytes", "DK5_UNLISTED_PATH", func(f *stagedFixture) { f.input.Files["/unlisted"] = []byte("{}") }},
		{"missing_bytes", "DK5_FILE_OPEN", func(f *stagedFixture) { delete(f.input.Files, f.policy.Paths[0]) }},
		{"empty_bytes", "DK5_FILE_SIZE", func(f *stagedFixture) { f.input.Files[f.policy.Paths[0]] = []byte{} }},
		{"nil_bytes", "DK5_FILE_SIZE", func(f *stagedFixture) { f.input.Files[f.policy.Paths[0]] = nil }},
		{"oversize_bytes", "DK5_FILE_SIZE", func(f *stagedFixture) { f.input.Files[f.policy.Paths[0]] = make([]byte, (16<<20)+1) }},
		{"changed_bytes", "DK5_CONTENT_HASH", func(f *stagedFixture) { f.input.Files[f.policy.Paths[0]] = []byte("changed") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newStagedFixture(t, key, "ed25519")
			assertStaged(t, f, "")
			tc.change(&f)
			assertStaged(t, f, tc.want)
		})
	}
}

// Independently expected final names reject a completely re-signed, internally
// consistent relocation; release/service/GID rejection is not merely hash failure.
func TestStagedSignedRelocation(t *testing.T) {
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	f := newStagedFixture(t, key, "ed25519")
	assertStaged(t, f, "")
	old := f.policy.Paths[1]
	newPath := old + ".relocated"
	f.input.Files[newPath] = f.input.Files[old]
	delete(f.input.Files, old)
	f.editManifest(t, func(m *Manifest) { m.Files[1].Path = newPath })
	assertStaged(t, f, "DK5_MANIFEST_BINDING")
	f.policy.Paths[1] = newPath
	assertStaged(t, f, "")
}

// Installed and staged contracts share signature/schema/binding/content verdicts;
// staged additionally requires independently expected paths. Installed metadata
// is synthetic in this comparison only; this does not qualify real root custody.
func TestStagedInstalledParity(t *testing.T) {
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"valid", "content", "signature", "schema", "binding"} {
		t.Run(kind, func(t *testing.T) {
			r, p, ap, a := signedFixture(t, key, "ed25519")
			read := func(path string) []byte {
				b, e := os.ReadFile(path)
				if e != nil {
					t.Fatal(e)
				}
				return b
			}
			s := StagedSet{Anchor: read(ap), Manifest: read(a.Manifest), Signature: read(a.Signature), Files: map[string][]byte{p: read(p)}}
			policy := StagedPolicy{ManifestPath: a.Manifest, SignaturePath: a.Signature, ReleaseSHA256: a.Release, Service: "model", GID: r.GID, Paths: []string{p}}
			assertStaged(t, stagedFixture{input: s, policy: policy}, "")
			want := ""
			switch kind {
			case "content":
				s.Files[p] = []byte("changed")
				writeMode(t, p, s.Files[p], 0640)
				want = "DK5_CONTENT_HASH"
			case "signature":
				s.Signature = signFixture(t, []byte("other"), "ed25519", key)
				writeMode(t, a.Signature, s.Signature, 0644)
				want = "DK5_SIGNATURE_INVALID"
			case "schema", "binding":
				if kind == "schema" {
					s.Manifest = []byte("{")
					want = "DK5_MANIFEST_SCHEMA"
				} else {
					var m Manifest
					json.Unmarshal(s.Manifest, &m)
					m.GID++
					s.Manifest, _ = json.Marshal(m)
					want = "DK5_MANIFEST_BINDING"
				}
				a.Digest = digest(s.Manifest)
				s.Anchor, _ = RenderDropIn(a)
				s.Signature = signFixture(t, s.Manifest, "ed25519", key)
				writeMode(t, ap, s.Anchor, 0644)
				writeMode(t, a.Manifest, s.Manifest, 0644)
				writeMode(t, a.Signature, s.Signature, 0644)
			}
			assertStaged(t, stagedFixture{input: s, policy: policy}, want)
			set, err := OpenSignedSet(ap, "model", r)
			if want == "" {
				if err != nil || set == nil {
					t.Fatal("installed valid neighbor", err)
				}
			} else {
				code(t, err, want)
				if set != nil {
					t.Fatal("installed partial authority")
				}
			}
		})
	}
}
