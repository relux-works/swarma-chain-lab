package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/single-use/configguard"
	"golang.org/x/sys/unix"
)

func installSignWrite(t *testing.T, path string, raw []byte, mode os.FileMode) {
	t.Helper()
	if e := os.WriteFile(path, raw, mode); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(path, mode); e != nil {
		t.Fatal(e)
	}
}
func installSignRead(t *testing.T, path string) []byte {
	t.Helper()
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func installSignArgs(t *testing.T) (args []string, sig, pub string) {
	t.Helper()
	dir := t.TempDir()
	manifest := filepath.Join(dir, "manifest.json")
	installSignWrite(t, manifest, []byte(`{"approved":"fixture"}`), 0600)
	sig, pub = filepath.Join(dir, "signature.json"), filepath.Join(dir, "public.key")
	return []string{"-manifest", manifest, "-sig-out", sig, "-pub-out", pub}, sig, pub
}
func installSignAbsent(t *testing.T, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if _, e := os.Lstat(p); !errors.Is(e, os.ErrNotExist) {
			t.Fatal("unexpected output or lookup failure")
		}
	}
}
func installSignHash(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }

type installSignEntropy struct {
	calls int
	seed  []byte
}

func (r *installSignEntropy) Read(p []byte) (int, error) {
	r.calls++
	r.seed = p
	for i := range p {
		p[i] = byte(i + 17)
	}
	return len(p), nil
}

// Existing files, directories and dangling/live symlinks refuse before entropy or writes; clean neighbors succeed.
func TestG2InstallSignExistingOutputs(t *testing.T) {
	for _, which := range []int{3, 5} {
		for _, kind := range []string{"file", "directory", "symlink", "dangling"} {
			t.Run(kind+string(rune('0'+which)), func(t *testing.T) {
				args, sig, pub := installSignArgs(t)
				target := filepath.Join(filepath.Dir(sig), "foreign")
				installSignWrite(t, target, []byte("foreign sentinel"), 0600)
				p := args[which]
				switch kind {
				case "file":
					installSignWrite(t, p, []byte("foreign sentinel"), 0600)
				case "directory":
					if e := os.Mkdir(p, 0700); e != nil {
						t.Fatal(e)
					}
				default:
					dest := target
					if kind == "dangling" {
						dest += ".absent"
					}
					if e := os.Symlink(dest, p); e != nil {
						t.Fatal(e)
					}
				}
				before, e := os.Lstat(p)
				if e != nil {
					t.Fatal(e)
				}
				r := &installSignEntropy{}
				e = g2InstallSignWith(args, installSignIO{r, func(*os.File, []byte) (int, error) { t.Fatal("write on refusal"); return 0, nil }})
				if e == nil || r.calls != 0 {
					t.Fatal("existing output did not refuse before entropy")
				}
				after, e := os.Lstat(p)
				if e != nil || !os.SameFile(before, after) {
					t.Fatal("existing output changed")
				}
				if !bytes.Equal(installSignRead(t, target), []byte("foreign sentinel")) {
					t.Fatal("symlink target changed")
				}
				if kind == "file" && !bytes.Equal(installSignRead(t, p), []byte("foreign sentinel")) {
					t.Fatal("existing file changed")
				}
				other := pub
				if p == pub {
					other = sig
				}
				installSignAbsent(t, other)
			})
		}
	}
	args, sig, pub := installSignArgs(t)
	if e := g2InstallSign(args); e != nil {
		t.Fatal(e)
	}
	for _, p := range []string{sig, pub} {
		st, e := os.Stat(p)
		if e != nil || st.Mode().Perm() != 0644 {
			t.Fatal("output mode")
		}
	}
}

// A short write at either publication fails and removes only this invocation's created outputs.
func TestG2InstallSignShortWrite(t *testing.T) {
	for _, failAt := range []int{1, 2} {
		t.Run(string(rune('0'+failAt)), func(t *testing.T) {
			args, sig, pub := installSignArgs(t)
			count := 0
			e := g2InstallSignWith(args, installSignIO{rand.Reader, func(f *os.File, b []byte) (int, error) {
				count++
				if count == failAt {
					return f.Write(b[:len(b)-1])
				}
				return f.Write(b)
			}})
			if !errors.Is(e, errInstallSign) || count != failAt {
				t.Fatal("short write not refused")
			}
			installSignAbsent(t, sig, pub)
		})
	}
}

// Replacement of the first output before second-write failure survives rollback; the owned second output is removed.
func TestG2InstallSignRollbackIdentity(t *testing.T) {
	args, sig, pub := installSignArgs(t)
	count := 0
	e := g2InstallSignWith(args, installSignIO{rand.Reader, func(f *os.File, b []byte) (int, error) {
		count++
		if count == 2 {
			if e := os.Rename(sig, sig+".original"); e != nil {
				t.Fatal(e)
			}
			installSignWrite(t, sig, []byte("foreign replacement"), 0644)
			return 0, io.ErrShortWrite
		}
		return f.Write(b)
	}})
	if !errors.Is(e, errInstallSignCleanup) {
		t.Fatal("replacement cleanup did not refuse")
	}
	if !bytes.Equal(installSignRead(t, sig), []byte("foreign replacement")) {
		t.Fatal("foreign replacement removed or changed")
	}
	installSignAbsent(t, pub)
}

// A file or symlink raced into the second output after preflight stays untouched; exclusive creation rolls back the first.
func TestG2InstallSignExclusiveRace(t *testing.T) {
	for _, symlink := range []bool{false, true} {
		t.Run(map[bool]string{false: "file", true: "symlink"}[symlink], func(t *testing.T) {
			args, sig, pub := installSignArgs(t)
			target := pub + ".target"
			installSignWrite(t, target, []byte("foreign sentinel"), 0600)
			calls := 0
			e := g2InstallSignWith(args, installSignIO{rand.Reader, func(f *os.File, b []byte) (int, error) {
				calls++
				if calls == 1 {
					if symlink {
						if e := os.Symlink(target, pub); e != nil {
							t.Fatal(e)
						}
					} else {
						installSignWrite(t, pub, []byte("foreign sentinel"), 0600)
					}
				}
				return f.Write(b)
			}})
			if e == nil || calls != 1 {
				t.Fatal("exclusive publication failed to refuse raced output")
			}
			if !bytes.Equal(installSignRead(t, pub), []byte("foreign sentinel")) || !bytes.Equal(installSignRead(t, target), []byte("foreign sentinel")) {
				t.Fatal("foreign output overwritten")
			}
			installSignAbsent(t, sig)
		})
	}
}

// Only signature/public-key formats leave the signer; seed/private encodings are absent and owned seed bytes are cleared.
func TestG2InstallSignNoPrivateMaterial(t *testing.T) {
	args, sig, pub := installSignArgs(t)
	r := &installSignEntropy{}
	if e := g2InstallSignWith(args, installSignIO{r, (*os.File).Write}); e != nil {
		t.Fatal(e)
	}
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 17)
	}
	private := ed25519.NewKeyFromSeed(seed)
	defer clear(private)
	defer clear(seed)
	der, e := x509.MarshalPKCS8PrivateKey(private)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(der)
	var sigJSON configguard.Signature
	sigBytes, pubBytes := installSignRead(t, sig), installSignRead(t, pub)
	if json.Unmarshal(sigBytes, &sigJSON) != nil || sigJSON.Version != 1 || sigJSON.Algorithm != "ed25519" {
		t.Fatal("signature format")
	}
	for _, secret := range [][]byte{seed, private, der} {
		for _, form := range [][]byte{secret, []byte(hex.EncodeToString(secret)), []byte(base64.StdEncoding.EncodeToString(secret))} {
			if bytes.Contains(sigBytes, form) || bytes.Contains(pubBytes, form) {
				t.Fatal("private material in output")
			}
		}
	}
	publicDER, e := base64.StdEncoding.Strict().DecodeString(string(pubBytes))
	if e != nil {
		t.Fatal("public encoding")
	}
	public, e := x509.ParsePKIXPublicKey(publicDER)
	if e != nil {
		t.Fatal("public PKIX format")
	}
	if _, ok := public.(ed25519.PublicKey); !ok {
		t.Fatal("not Ed25519 public key")
	}
	if r.calls != 1 || !bytes.Equal(r.seed, make([]byte, ed25519.SeedSize)) {
		t.Fatal("owned seed buffer was not cleared")
	}
}

// Both CLI input modes feed the renderer and real installed configguard path; changed bytes and another key's signature refuse.
func TestG2InstallSignConfigguardCompatibility(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "config")
	units := filepath.Join(root, "unit")
	if e := os.Mkdir(dir, 0750); e != nil {
		t.Fatal(e)
	}
	if e := os.Mkdir(units, 0755); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(dir, 0750); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(units, 0755); e != nil {
		t.Fatal(e)
	}
	config := filepath.Join(dir, "service.json")
	installSignWrite(t, config, []byte("{}"), 0640)
	manifest := filepath.Join(dir, "manifest.json")
	sig, pub := filepath.Join(dir, "signature.json"), filepath.Join(dir, "public.key")
	release := strings.Repeat("a", 64)
	raw, e := json.Marshal(configguard.Manifest{Version: 1, ReleaseSHA256: release, Service: "model", GID: 1234, Files: []configguard.Entry{{Path: config, SHA256: installSignHash([]byte("{}"))}}})
	if e != nil {
		t.Fatal(e)
	}
	installSignWrite(t, manifest, raw, 0644)
	args := []string{"-manifest", manifest, "-sig-out", sig, "-pub-out", pub}
	if e := run(append([]string{"g2-install-sign"}, args...)); e != nil {
		t.Fatal(e)
	}
	var anchor bytes.Buffer
	render := func(digest string) {
		t.Helper()
		anchor.Reset()
		if e := renderInstallAnchor([]string{"-manifest", manifest, "-signature", sig, "-manifest-sha256", digest, "-release-sha256", release, "-algorithm", "ed25519", "-public-key", string(installSignRead(t, pub))}, &anchor); e != nil {
			t.Fatal(e)
		}
		installSignWrite(t, filepath.Join(units, "10-install.conf"), anchor.Bytes(), 0644)
	}
	render(installSignHash(raw))
	reader := configguard.Reader{EUID: 4321, GID: 1234, FixtureRoot: root, Metadata: func(path string, st *unix.Stat_t) {
		st.Uid = 0
		st.Gid = 0
		if path == dir || path == manifest || path == sig || path == config {
			st.Gid = 1234
		}
	}}
	verify := func(want string) {
		t.Helper()
		set, e := configguard.OpenSignedSet(filepath.Join(units, "10-install.conf"), "model", reader)
		if want != "" {
			if e == nil || e.Error() != want {
				t.Fatalf("got %v want %s", e, want)
			}
			return
		}
		if e != nil {
			t.Fatal(e)
		}
		b, e := set.Read(config, 1024)
		if e != nil || !bytes.Equal(b, []byte("{}")) {
			t.Fatal("installed config refused")
		}
	}
	verify("")
	// Move the digest pin with one changed manifest byte to prove signature refusal, beyond hash refusal.
	changed := bytes.Clone(raw)
	i := bytes.Index(changed, []byte(`"model"`))
	if i < 0 {
		t.Fatal("fixture")
	}
	changed[i+1] = 'n'
	installSignWrite(t, manifest, changed, 0644)
	render(installSignHash(changed))
	verify("DK5_SIGNATURE_INVALID")
	installSignWrite(t, manifest, raw, 0644)
	render(installSignHash(raw))
	verify("")
	input := filepath.Join(dir, "signed-input")
	installSignWrite(t, input, append([]byte(configguard.SignatureDomain), raw...), 0600)
	otherSig, otherPub := sig+".other", pub+".other"
	if e := run([]string{"g2-install-sign", "-input", input, "-sig-out", otherSig, "-pub-out", otherPub}); e != nil {
		t.Fatal(e)
	}
	if bytes.Equal(installSignRead(t, pub), installSignRead(t, otherPub)) {
		t.Fatal("fresh runs reused a key")
	}
	original := installSignRead(t, sig)
	installSignWrite(t, sig, installSignRead(t, otherSig), 0644)
	verify("DK5_SIGNATURE_INVALID")
	installSignWrite(t, sig, original, 0644)
	verify("")
	// The -input signature is accepted when its own public key is pinned.
	installSignWrite(t, sig, installSignRead(t, otherSig), 0644)
	installSignWrite(t, pub, installSignRead(t, otherPub), 0644)
	render(installSignHash(raw))
	verify("")
}

// Malformed input/framing/arguments and failed entropy leave no artifacts; valid neighbors are exercised above.
func TestG2InstallSignInvalidInput(t *testing.T) {
	for _, kind := range []string{"empty", "oversize", "unframed", "domain-only", "both", "neither", "same-output", "entropy"} {
		t.Run(kind, func(t *testing.T) {
			args, sig, pub := installSignArgs(t)
			random := io.Reader(rand.Reader)
			switch kind {
			case "empty":
				installSignWrite(t, args[1], nil, 0600)
			case "oversize":
				installSignWrite(t, args[1], make([]byte, (1<<20)+1), 0600)
			case "unframed":
				args[0] = "-input"
			case "domain-only":
				args[0] = "-input"
				installSignWrite(t, args[1], []byte(configguard.SignatureDomain), 0600)
			case "both":
				args = append(args, "-input", args[1])
			case "neither":
				args = args[2:]
			case "same-output":
				args[5] = sig
			case "entropy":
				random = bytes.NewReader(nil)
			}
			if e := g2InstallSignWith(args, installSignIO{random, (*os.File).Write}); e == nil {
				t.Fatal("invalid input accepted")
			}
			installSignAbsent(t, sig, pub)
		})
	}
}

// The actual CLI emits no success output, uses exit 1 for collisions, and prints only a generic refusal on stderr.
func TestG2InstallSignProcess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	binary := filepath.Join(t.TempDir(), "deploy-kit")
	if out, e := exec.CommandContext(ctx, "go", "build", "-o", binary, ".").CombinedOutput(); e != nil {
		t.Fatalf("build: %v %s", e, out)
	}
	args, sig, pub := installSignArgs(t)
	invoke := func(args []string, want int) {
		t.Helper()
		cmd := exec.CommandContext(ctx, binary, append([]string{"g2-install-sign"}, args...)...)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		e := cmd.Run()
		code := 0
		if e != nil {
			var exit *exec.ExitError
			if !errors.As(e, &exit) {
				t.Fatal(e)
			}
			code = exit.ExitCode()
		}
		if code != want || stdout.Len() != 0 {
			t.Fatal("CLI exit/stdout contract")
		}
		if want == 0 && stderr.Len() != 0 {
			t.Fatal("success stderr")
		}
		if want == 1 && stderr.String() != errInstallSign.Error()+"\n" {
			t.Fatal("non-generic refusal stderr")
		}
	}
	invoke(args, 0)
	beforeSig, beforePub := installSignRead(t, sig), installSignRead(t, pub)
	invoke(args, 1)
	if !bytes.Equal(beforeSig, installSignRead(t, sig)) || !bytes.Equal(beforePub, installSignRead(t, pub)) {
		t.Fatal("CLI overwrote existing outputs")
	}
}
