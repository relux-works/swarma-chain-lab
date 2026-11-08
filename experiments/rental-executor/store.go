//go:build darwin || linux

package executor

// Adapted from single-use/journal.go at 2a4410e: flock lifetime ownership,
// private regular files, fsync temporary file then rename then fsync directory.
import (
	"io"
	"os"
	"path/filepath"
	"syscall"
)

type store struct {
	root   string
	lock   *os.File
	poison bool
}

func private(i os.FileInfo) bool {
	s, ok := i.Sys().(*syscall.Stat_t)
	return ok && i.Mode().IsRegular() && i.Mode().Perm() == 0600 && int(s.Uid) == os.Getuid() && s.Nlink == 1
}
func openStore(root string) (*store, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, fail("STATE_ROOT")
	}
	real, e := filepath.EvalSymlinks(root)
	if e != nil || real != root {
		return nil, fail("STATE_ROOT")
	}
	i, e := os.Lstat(root)
	if e != nil || !i.IsDir() || i.Mode().Perm() != 0700 {
		return nil, fail("STATE_ROOT")
	}
	st, ok := i.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Getuid() {
		return nil, fail("STATE_OWNER")
	}
	path := filepath.Join(root, "executor.lock")
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if os.IsExist(e) {
		f, e = os.OpenFile(path, os.O_RDWR|syscall.O_NOFOLLOW, 0)
	}
	if e != nil {
		return nil, fail("STATE_LOCK")
	}
	i, e = f.Stat()
	if e != nil || !private(i) {
		f.Close()
		return nil, fail("STATE_LOCK")
	}
	if syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		f.Close()
		return nil, fail("STATE_BUSY")
	}
	return &store{root: root, lock: f}, nil
}
func (s *store) close() {
	s.poison = true
	if s.lock != nil {
		_ = syscall.Flock(int(s.lock.Fd()), syscall.LOCK_UN)
		_ = s.lock.Close()
		s.lock = nil
	}
}
func (s *store) read(name string) ([]byte, error) {
	if s.poison || filepath.Base(name) != name {
		return nil, fail("STATE_UNAVAILABLE")
	}
	f, e := os.OpenFile(filepath.Join(s.root, name), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if os.IsNotExist(e) {
		return nil, nil
	}
	if e != nil {
		return nil, fail("STATE_READ")
	}
	defer f.Close()
	i, e := f.Stat()
	if e != nil || !private(i) {
		return nil, fail("STATE_FILE")
	}
	b, e := io.ReadAll(io.LimitReader(f, 16<<20+1))
	if e != nil || len(b) > 16<<20 {
		return nil, fail("STATE_READ")
	}
	return b, nil
}
func syncDir(root string) error {
	f, e := os.Open(root)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func (s *store) write(name string, b []byte) error {
	if s.poison || filepath.Base(name) != name || len(b) > 16<<20 {
		return fail("STATE_UNAVAILABLE")
	}
	if _, e := s.read(name); e != nil {
		return e
	}
	f, e := os.CreateTemp(s.root, ".executor-")
	if e != nil {
		return fail("STATE_WRITE")
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil || ce != nil {
		s.poison = true
		return fail("STATE_FSYNC")
	}
	if os.Rename(tmp, filepath.Join(s.root, name)) != nil || syncDir(s.root) != nil {
		s.poison = true
		return fail("STATE_COMMIT")
	}
	return nil
}

func owned(i os.FileInfo) bool {
	s, ok := i.Sys().(*syscall.Stat_t)
	return ok && int(s.Uid) == os.Getuid()
}
