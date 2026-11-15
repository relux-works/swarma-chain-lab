//go:build linux

package g2run

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// PortFS restricts ports to declared absolute roots. Every component, including
// the roots themselves, is opened without symlinks. A root is not authority to
// create ledger targets: activation delegates those writes to E2 Ledger.
type PortFS struct{ Roots []string }

func portAbs(p string) bool {
	return filepath.IsAbs(p) && filepath.Clean(p) == p && !strings.ContainsAny(p, "\x00\r\n\t")
}
func (fs PortFS) Validate() error {
	if len(fs.Roots) == 0 {
		return errors.New("PORT_ROOTS_REQUIRED")
	}
	seen := map[string]bool{}
	for _, r := range fs.Roots {
		if !portAbs(r) || r == "/" || seen[r] {
			return errors.New("PORT_ROOT")
		}
		seen[r] = true
	}
	return nil
}
func (fs PortFS) allowed(p string) bool {
	if fs.Validate() != nil || !portAbs(p) {
		return false
	}
	for _, r := range fs.Roots {
		if p == r || strings.HasPrefix(p, r+"/") {
			return true
		}
	}
	return false
}
func portOpenAbsolute(p string, flags int) (*os.File, error) {
	if !portAbs(p) {
		return nil, errors.New("PORT_PATH")
	}
	root, e := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	defer unix.Close(root)
	rel := strings.TrimPrefix(p, "/")
	if rel == "" {
		rel = "."
	}
	flags |= unix.O_CLOEXEC | unix.O_NOFOLLOW
	if flags&unix.O_PATH == 0 {
		flags |= unix.O_NONBLOCK
	}
	fd, e := unix.Openat2(root, rel, &unix.OpenHow{Flags: uint64(flags), Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if e != nil {
		return nil, e
	}
	return os.NewFile(uintptr(fd), p), nil
}
func (fs PortFS) open(p string, flags int, dir bool) (*os.File, error) {
	if !fs.allowed(p) {
		return nil, errors.New("PORT_PATH_OUTSIDE_ROOTS")
	}
	if dir {
		flags |= unix.O_DIRECTORY
	}
	f, e := portOpenAbsolute(p, flags)
	if e != nil {
		return nil, e
	}
	st, e := f.Stat()
	if e != nil || (!dir && !st.Mode().IsRegular()) {
		f.Close()
		return nil, errors.New("PORT_NOT_REGULAR")
	}
	return f, nil
}
func (fs PortFS) read(p string) ([]byte, error) {
	f, e := fs.open(p, unix.O_RDONLY, false)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, (16<<20)+1))
	if len(b) > 16<<20 {
		return nil, errors.New("PORT_FILE_TOO_LARGE")
	}
	return b, e
}
func (fs PortFS) hash(p string) (string, error) {
	f, e := fs.open(p, unix.O_RDONLY, false)
	if e != nil {
		return "", e
	}
	defer f.Close()
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		return "", e
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func (fs PortFS) parent(p string) (*os.File, string, error) {
	if !fs.allowed(p) || !fs.allowed(filepath.Dir(p)) {
		return nil, "", errors.New("PORT_PARENT_OUTSIDE_ROOTS")
	}
	f, e := fs.open(filepath.Dir(p), unix.O_RDONLY, true)
	return f, filepath.Base(p), e
}

// writeAtomic creates a private workspace file durably. It never follows or
// replaces an existing destination, including a symlink. Final mode is explicit.
func (fs PortFS) writeAtomic(p string, b []byte, mode uint32) error {
	if mode > 0777 {
		return errors.New("MODE_OCTAL_RANGE")
	}
	parent, name, e := fs.parent(p)
	if e != nil {
		return e
	}
	defer parent.Close()
	var token [12]byte
	if _, e = rand.Read(token[:]); e != nil {
		return e
	}
	tmp := ".g2-" + hex.EncodeToString(token[:])
	fd, e := unix.Openat(int(parent.Fd()), tmp, unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if e != nil {
		return e
	}
	defer unix.Unlinkat(int(parent.Fd()), tmp, 0)
	f := os.NewFile(uintptr(fd), tmp)
	if e = f.Chmod(os.FileMode(mode)); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	if e = unix.Renameat2(int(parent.Fd()), tmp, int(parent.Fd()), name, unix.RENAME_NOREPLACE); e != nil {
		return e
	}
	return parent.Sync()
}
func (fs PortFS) samePath(p string, st *unix.Stat_t) error {
	parent, name, e := fs.parent(p)
	if e != nil {
		return e
	}
	defer parent.Close()
	var got unix.Stat_t
	if e = unix.Fstatat(int(parent.Fd()), name, &got, unix.AT_SYMLINK_NOFOLLOW); e != nil {
		return e
	}
	if got.Dev != st.Dev || got.Ino != st.Ino || got.Mode&unix.S_IFMT != unix.S_IFREG {
		return errors.New("PORT_PATH_IDENTITY")
	}
	return nil
}
func (fs PortFS) removeSame(p string, st *unix.Stat_t) error {
	parent, name, e := fs.parent(p)
	if e != nil {
		return e
	}
	defer parent.Close()
	var got unix.Stat_t
	if e = unix.Fstatat(int(parent.Fd()), name, &got, unix.AT_SYMLINK_NOFOLLOW); e != nil {
		return e
	}
	if got.Dev != st.Dev || got.Ino != st.Ino {
		return errors.New("PORT_PATH_IDENTITY")
	}
	if e = unix.Unlinkat(int(parent.Fd()), name, 0); e != nil {
		return e
	}
	return parent.Sync()
}
