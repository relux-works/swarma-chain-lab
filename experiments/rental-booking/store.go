//go:build darwin || linux

package booking

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// fileStore holds an exclusive process lock for its lifetime. A failed fsync
// poisons the handle: a successful rename may already be durable, so callers
// must reopen and reconcile rather than retry from stale in-memory state.
type fileStore struct {
	root     string
	lock     *os.File
	poisoned bool
}

func privateFile(i os.FileInfo) bool {
	s, ok := i.Sys().(*syscall.Stat_t)
	return ok && i.Mode().IsRegular() && i.Mode().Perm() == 0600 && int(s.Uid) == os.Getuid() && s.Nlink == 1
}
func openStore(root string) (*fileStore, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, refuse("STATE_ROOT")
	}
	real, e := filepath.EvalSymlinks(root)
	if e != nil || real != root {
		return nil, refuse("STATE_ROOT")
	}
	i, e := os.Lstat(root)
	if e != nil || !i.IsDir() || i.Mode().Perm() != 0700 {
		return nil, refuse("STATE_ROOT")
	}
	st, ok := i.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Getuid() {
		return nil, refuse("STATE_OWNER")
	}
	f, e := os.OpenFile(filepath.Join(root, "booking.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, refuse("STATE_LOCK")
	}
	i, e = f.Stat()
	if e != nil || !privateFile(i) {
		f.Close()
		return nil, refuse("STATE_LOCK")
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		f.Close()
		return nil, refuse("STATE_BUSY")
	}
	return &fileStore{root: root, lock: f}, nil
}
func (s *fileStore) close() {
	if s.lock != nil {
		_ = syscall.Flock(int(s.lock.Fd()), syscall.LOCK_UN)
		_ = s.lock.Close()
		s.lock = nil
	}
	s.poisoned = true
}
func (s *fileStore) read(name string, limit int64) ([]byte, error) {
	if filepath.Base(name) != name || s.poisoned {
		return nil, refuse("STATE_UNAVAILABLE")
	}
	f, e := os.OpenFile(filepath.Join(s.root, name), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if os.IsNotExist(e) {
		return nil, nil
	}
	if e != nil {
		return nil, refuse("STATE_READ")
	}
	defer f.Close()
	i, e := f.Stat()
	if e != nil || !privateFile(i) {
		return nil, refuse("STATE_FILE")
	}
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || int64(len(b)) > limit {
		return nil, refuse("STATE_READ")
	}
	return b, nil
}
func syncDirectory(root string) error {
	f, e := os.Open(root)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func (s *fileStore) write(name string, b []byte, once bool) error {
	if filepath.Base(name) != name || s.poisoned || len(b) > 32<<20 {
		return refuse("STATE_UNAVAILABLE")
	}
	old, e := s.read(name, 32<<20)
	if e != nil {
		return e
	}
	if once && old != nil {
		if !bytes.Equal(old, b) {
			return refuse("OUTBOX_CONFLICT")
		}
		return nil
	}
	f, e := os.CreateTemp(s.root, ".booking-")
	if e != nil {
		return refuse("STATE_WRITE")
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil || ce != nil {
		s.poisoned = true
		return refuse("STATE_FSYNC")
	}
	path := filepath.Join(s.root, name)
	e = os.Rename(tmp, path)
	if e != nil {
		s.poisoned = true
		return refuse("STATE_COMMIT")
	}
	if e = syncDirectory(s.root); e != nil {
		s.poisoned = true
		return refuse("STATE_FSYNC")
	}
	return nil
}
