package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/relux-works/swarma-chain-lab/deploy"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/configguard"
	"golang.org/x/sys/unix"
)

var errInstallSign = errors.New("deploy-kit: install signing refused")
var errInstallSignCleanup = errors.New("deploy-kit: install signing cleanup refused; output identity changed or unavailable")

type installSignIO struct {
	random io.Reader
	write  func(*os.File, []byte) (int, error)
}

func g2InstallSign(args []string) error {
	return g2InstallSignWith(args, installSignIO{rand.Reader, (*os.File).Write})
}

// Only public artifacts leave this function. Clearing owned seed/private-key
// buffers is best effort: Go and the crypto implementation may retain copies.
func installSignBytes(message []byte, random io.Reader) ([]byte, []byte, error) {
	var seed [ed25519.SeedSize]byte
	defer clear(seed[:])
	if _, e := io.ReadFull(random, seed[:]); e != nil {
		return nil, nil, errInstallSign
	}
	private := ed25519.NewKeyFromSeed(seed[:])
	clear(seed[:])
	defer clear(private)
	signature := ed25519.Sign(private, message)
	der, e := x509.MarshalPKIXPublicKey(private.Public())
	if e != nil {
		return nil, nil, errInstallSign
	}
	encoded, e := json.Marshal(configguard.Signature{Version: 1, Algorithm: "ed25519", Value: base64.StdEncoding.EncodeToString(signature)})
	if e != nil {
		return nil, nil, errInstallSign
	}
	return append(encoded, '\n'), []byte(base64.StdEncoding.EncodeToString(der)), nil
}

// Parent descriptors are pinned through a no-symlink walk, so publication and
// rollback use the same directories even if an ancestor is renamed.
type installSignOutput struct {
	dir      *os.File
	name     string
	file     *os.File
	identity unix.Stat_t
	created  bool
}

func installSignTarget(path string) (*installSignOutput, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, deploy.ErrInput
	}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, errInstallSign
	}
	for _, part := range strings.Split(strings.TrimPrefix(filepath.Dir(path), "/"), "/") {
		if part == "" {
			continue
		}
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if err != nil {
			return nil, errInstallSign
		}
		fd = next
	}
	out := &installSignOutput{dir: os.NewFile(uintptr(fd), "install-sign-parent"), name: filepath.Base(path)}
	var st unix.Stat_t
	if e := unix.Fstatat(fd, out.name, &st, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(e, unix.ENOENT) {
		out.dir.Close()
		return nil, errInstallSign
	}
	return out, nil
}

func (o *installSignOutput) create(data []byte, write func(*os.File, []byte) (int, error)) error {
	fd, e := unix.Openat(int(o.dir.Fd()), o.name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0644)
	if e != nil {
		return errInstallSign
	}
	o.file = os.NewFile(uintptr(fd), "install-sign-output")
	// Record the creating descriptor's dev+ino, never a later path lookup.
	if unix.Fstat(fd, &o.identity) != nil {
		return errInstallSignCleanup
	}
	o.created = true
	if o.file.Chmod(0644) != nil {
		return errInstallSign
	}
	n, e := write(o.file, data)
	if e != nil || n != len(data) {
		return errInstallSign
	}
	if o.file.Sync() != nil || o.dir.Sync() != nil {
		return errInstallSign
	}
	return nil
}

func (o *installSignOutput) rollback() error {
	if !o.created {
		return nil
	}
	var current unix.Stat_t
	e := unix.Fstatat(int(o.dir.Fd()), o.name, &current, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(e, unix.ENOENT) {
		return nil
	}
	if e != nil || current.Dev != o.identity.Dev || current.Ino != o.identity.Ino {
		return errInstallSignCleanup
	}
	if unix.Unlinkat(int(o.dir.Fd()), o.name, 0) != nil || o.dir.Sync() != nil {
		return errInstallSignCleanup
	}
	return nil
}

func g2InstallSignWith(args []string, ops installSignIO) (result error) {
	f := flag.NewFlagSet("g2-install-sign", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	manifest := f.String("manifest", "", "approved manifest bytes (recommended)")
	input := f.String("input", "", "domain-prefixed manifest bytes")
	sigPath := f.String("sig-out", "", "new absolute detached signature JSON file")
	pubPath := f.String("pub-out", "", "new absolute base64 PKIX public key file")
	if f.Parse(args) != nil || f.NArg() != 0 || (*manifest == "") == (*input == "") || *sigPath == *pubPath {
		return deploy.ErrInput
	}
	// Both outputs must be absent before reading input or drawing any entropy.
	sig, e := installSignTarget(*sigPath)
	if e != nil {
		return e
	}
	defer sig.dir.Close()
	pub, e := installSignTarget(*pubPath)
	if e != nil {
		return e
	}
	defer pub.dir.Close()
	defer func() {
		if result != nil {
			result = errors.Join(result, pub.rollback(), sig.rollback())
		}
		if sig.file != nil {
			sig.file.Close()
		}
		if pub.file != nil {
			pub.file.Close()
		}
	}()
	path := *manifest
	limit := int64(1 << 20)
	if *input != "" {
		path = *input
		limit += int64(len(configguard.SignatureDomain))
	}
	file, e := os.Open(path)
	if e != nil {
		return errInstallSign
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	closeErr := file.Close()
	defer clear(raw)
	if readErr != nil || closeErr != nil || len(raw) == 0 || int64(len(raw)) > limit {
		return errInstallSign
	}
	var message []byte
	if *manifest != "" {
		message = append([]byte(configguard.SignatureDomain), raw...)
	} else {
		if !bytes.HasPrefix(raw, []byte(configguard.SignatureDomain)) || len(raw) == len(configguard.SignatureDomain) {
			return deploy.ErrInput
		}
		message = raw
	}
	defer clear(message)
	signature, public, e := installSignBytes(message, ops.random)
	if e != nil {
		return e
	}
	if e := sig.create(signature, ops.write); e != nil {
		return e
	}
	if e := pub.create(public, ops.write); e != nil {
		return e
	}
	// Keep recorded identities for rollback even if a close reports failure.
	sigErr, pubErr := sig.file.Close(), pub.file.Close()
	sig.file, pub.file = nil, nil
	if sigErr != nil || pubErr != nil {
		return errInstallSign
	}
	return nil
}
