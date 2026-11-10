package configguard

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func signFixture(t *testing.T, raw []byte, algorithm string, key crypto.Signer) []byte {
	t.Helper()
	message := append([]byte(SignatureDomain), raw...)
	var value []byte
	var e error
	switch algorithm {
	case "ed25519":
		value, e = key.Sign(rand.Reader, message, crypto.Hash(0))
	case "rsa-pss-sha256":
		h := sha256.Sum256(message)
		value, e = key.Sign(rand.Reader, h[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	}
	if e != nil {
		t.Fatal(e)
	}
	out, e := json.Marshal(Signature{1, algorithm, base64.StdEncoding.EncodeToString(value)})
	if e != nil {
		t.Fatal(e)
	}
	return out
}
func writeMode(t *testing.T, path string, b []byte, mode os.FileMode) {
	t.Helper()
	if e := os.WriteFile(path, b, mode); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(path, mode); e != nil {
		t.Fatal(e)
	}
}
func signedFixture(t *testing.T, key crypto.Signer, algorithm string) (Reader, string, string, Anchor) {
	t.Helper()
	r, p := fixture(t)
	m := goodManifest(r, p)
	raw, _ := json.Marshal(m)
	manifest := filepath.Join(filepath.Dir(p), "install-manifest.json")
	sig := manifest + ".sig"
	writeMode(t, manifest, raw, 0644)
	writeMode(t, sig, signFixture(t, raw, algorithm, key), 0644)
	der, e := x509.MarshalPKIXPublicKey(key.Public())
	if e != nil {
		t.Fatal(e)
	}
	a := Anchor{manifest, sig, digest(raw), m.ReleaseSHA256, algorithm, base64.StdEncoding.EncodeToString(der)}
	root := filepath.Join(r.FixtureRoot, "anchor")
	mkdirMode(t, root, 0755)
	anchorPath := filepath.Join(root, "10-install.conf")
	body, e := RenderDropIn(a)
	if e != nil {
		t.Fatal(e)
	}
	writeMode(t, anchorPath, body, 0644)
	r.Metadata = func(path string, s *unix.Stat_t) {
		s.Uid = 0
		if path == root || path == anchorPath {
			s.Gid = 0
		}
	}
	return r, p, anchorPath, a
}

// Both algorithms verify real scratch-generated signatures. Synthetic ownership
// is labelled; contents, paths, modes, hashes and crypto are the production path.
func TestSignedAlgorithms(t *testing.T) {
	_, ed, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	rsaKey, e := rsa.GenerateKey(rand.Reader, 3072)
	if e != nil {
		t.Fatal(e)
	}
	for algorithm, key := range map[string]crypto.Signer{"ed25519": ed, "rsa-pss-sha256": rsaKey} {
		t.Run(algorithm, func(t *testing.T) {
			r, p, a, pins := signedFixture(t, key, algorithm)
			s, e := OpenSignedSet(a, "model", r)
			if e != nil {
				t.Fatal("signed positive", e)
			}
			if b, e := s.Read(p, 32); e != nil || string(b) != "{}" {
				t.Fatal("signed bytes", e)
			}
			// A signature for different bytes must fail under each supported algorithm.
			writeMode(t, pins.Signature, signFixture(t, []byte("different manifest"), algorithm, key), 0644)
			rejected, err := OpenSignedSet(a, "model", r)
			code(t, err, "DK5_SIGNATURE_INVALID")
			if rejected != nil {
				t.Fatal("invalid signature returned authority")
			}
		})
	}
}

// Each refusal has a signed positive neighbor and returns no usable set/bytes.
// No test starts a service or writes application state; files are isolated inputs.
func TestSignedRefusals(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	for _, name := range []string{"absent_signature", "bad_signature", "wrong_key", "wrong_algorithm", "other_release", "manifest_hash", "missing_manifest", "malformed_manifest", "missing_file", "changed_file", "unlisted", "anchor_mode", "anchor_owner", "anchor_group", "dir_mode", "file_mode", "signature_link", "anchor_link", "environment"} {
		t.Run(name, func(t *testing.T) {
			r, p, ap, a := signedFixture(t, key, "ed25519")
			good, e := OpenSignedSet(ap, "model", r)
			if e != nil {
				t.Fatal("valid signed neighbor", e)
			}
			want := ""
			rewrite := func() {
				b, e := RenderDropIn(a)
				if e != nil {
					t.Fatal(e)
				}
				writeMode(t, ap, b, 0644)
			}
			switch name {
			case "absent_signature":
				os.Remove(a.Signature)
				want = "DK5_SIGNATURE_FILE"
			case "bad_signature":
				writeMode(t, a.Signature, signFixture(t, []byte("other bytes"), "ed25519", key), 0644)
				want = "DK5_SIGNATURE_INVALID"
			case "wrong_key":
				pub, _, _ := ed25519.GenerateKey(rand.Reader)
				der, _ := x509.MarshalPKIXPublicKey(pub)
				a.PublicKey = base64.StdEncoding.EncodeToString(der)
				rewrite()
				want = "DK5_SIGNATURE_INVALID"
			case "wrong_algorithm":
				// Keep the valid Ed25519 bytes/key; only the self-declared
				// signature label changes, so dropping its check admits it.
				raw, err := os.ReadFile(a.Signature)
				if err != nil {
					t.Fatal(err)
				}
				var sig Signature
				if err = json.Unmarshal(raw, &sig); err != nil {
					t.Fatal(err)
				}
				sig.Algorithm = "rsa-pss-sha256"
				raw, err = json.Marshal(sig)
				if err != nil {
					t.Fatal(err)
				}
				writeMode(t, a.Signature, raw, 0644)
				want = "DK5_SIGNATURE_SCHEMA"
			case "other_release":
				a.Release = strings.Repeat("b", 64)
				rewrite()
				want = "DK5_MANIFEST_BINDING"
			case "manifest_hash":
				a.Digest = strings.Repeat("b", 64)
				rewrite()
				want = "DK5_MANIFEST_HASH"
			case "missing_manifest":
				os.Remove(a.Manifest)
				want = "DK5_MANIFEST_READ"
			case "malformed_manifest":
				raw := []byte("{")
				writeMode(t, a.Manifest, raw, 0644)
				writeMode(t, a.Signature, signFixture(t, raw, "ed25519", key), 0644)
				a.Digest = digest(raw)
				rewrite()
				want = "DK5_MANIFEST_SCHEMA"
			case "missing_file":
				os.Remove(p)
				want = "DK5_FILE_OPEN"
			case "changed_file":
				writeMode(t, p, []byte("[]"), 0640)
				want = "DK5_CONTENT_HASH"
			case "unlisted":
				b, e := good.Read(p+"-unlisted", 32)
				code(t, e, "DK5_UNLISTED_PATH")
				if b != nil {
					t.Fatal("unlisted bytes")
				}
				return
			case "anchor_mode":
				os.Chmod(ap, 0664)
				want = "DK5_ANCHOR_FILE"
			case "anchor_owner":
				base := r.Metadata
				r.Metadata = func(path string, s *unix.Stat_t) {
					base(path, s)
					if path == ap {
						s.Uid = 42
					}
				}
				want = "DK5_ANCHOR_FILE"
			case "anchor_group":
				base := r.Metadata
				r.Metadata = func(path string, s *unix.Stat_t) {
					base(path, s)
					if path == ap {
						s.Gid = 42
					}
				}
				want = "DK5_ANCHOR_FILE"
			case "dir_mode":
				os.Chmod(filepath.Dir(p), 0755)
				want = "DK5_MANIFEST_READ"
			case "file_mode":
				os.Chmod(p, 0644)
				want = "DK5_FILE_MODE"
			case "signature_link":
				os.Rename(a.Signature, a.Signature+"-real")
				os.Symlink(a.Signature+"-real", a.Signature)
				want = "DK5_SIGNATURE_FILE"
			case "anchor_link":
				os.Rename(ap, ap+"-real")
				os.Symlink(ap+"-real", ap)
				want = "DK5_ANCHOR_FILE"
			case "environment":
				t.Setenv("SWARMA_INSTALL_SHA256", strings.Repeat("b", 64))
				s, e := OpenSignedSet(ap, "model", r)
				if e != nil || s == nil {
					t.Fatal("environment changed trusted anchor", e)
				}
				return
			}
			got, e := OpenSignedSet(ap, "model", r)
			code(t, e, want)
			if got != nil {
				t.Fatal("partial signed authority")
			}
		})
	}
}

// Key decoding rejects unknown algorithms, malformed/algorithm-mismatched keys
// and private-key DER, beside a valid pinned Ed25519 public key.
func TestSignatureKeyPins(t *testing.T) {
	pub, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	der, e := x509.MarshalPKIXPublicKey(pub)
	if e != nil {
		t.Fatal(e)
	}
	encoded := base64.StdEncoding.EncodeToString(der)
	if _, e = parsePublicKey("ed25519", encoded); e != nil {
		t.Fatal(e)
	}
	secretDER, e := x509.MarshalPKCS8PrivateKey(private)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(secretDER)
	defer clear(private)
	for _, tc := range []struct{ name, alg, key, reason string }{
		{"unknown", "unknown", encoded, "DK5_SIGNATURE_ALGORITHM"},
		{"mismatch", "rsa-pss-sha256", encoded, "DK5_SIGNATURE_KEY"},
		{"malformed", "ed25519", "not-base64", "DK5_SIGNATURE_KEY"},
		{"private", "ed25519", base64.StdEncoding.EncodeToString(secretDER), "DK5_SIGNATURE_KEY"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, e := parsePublicKey(tc.alg, tc.key)
			code(t, e, tc.reason)
			if got != nil {
				t.Fatal("invalid public pin accepted")
			}
		})
	}
}

// Public-key policy rejects undersized/oversized moduli and a wrong exponent,
// beside a real 3072-bit positive. Synthetic modulus tests claim policy only.
func TestRSAKeyPolicy(t *testing.T) {
	key, e := rsa.GenerateKey(rand.Reader, 3072)
	if e != nil {
		t.Fatal(e)
	}
	encode := func(p *rsa.PublicKey) string {
		b, e := x509.MarshalPKIXPublicKey(p)
		if e != nil {
			t.Fatal(e)
		}
		return base64.StdEncoding.EncodeToString(b)
	}
	if _, e = parsePublicKey("rsa-pss-sha256", encode(&key.PublicKey)); e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		name           string
		bits, exponent int
	}{{"2048", 2048, 65537}, {"8193", 8193, 65537}, {"exponent", 3072, 3}} {
		t.Run(tc.name, func(t *testing.T) {
			p := &rsa.PublicKey{N: new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), uint(tc.bits-1)), big.NewInt(1)), E: tc.exponent}
			got, e := parsePublicKey("rsa-pss-sha256", encode(p))
			code(t, e, "DK5_SIGNATURE_KEY")
			if got != nil {
				t.Fatal("RSA policy returned key")
			}
		})
	}
}
