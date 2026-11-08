//go:build darwin || linux

// Package durable provides the shared journal storage primitives. It does not
// interpret records or decide whether an observation authorizes a state change.
package durable

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

func PrivateRegular(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode().IsRegular() && info.Mode().Perm() == 0600 && int(stat.Uid) == os.Getuid() && stat.Nlink == 1
}

type Store struct {
	root          string
	lock          *os.File
	syncFile      func(*os.File) error
	syncDirectory func(string) error
}

// Open requires an existing private owner-controlled root and obtains a
// nonblocking exclusive lock. All users of one state root must share lockName.
func Open(root, lockName string) (*Store, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || !component(lockName) {
		return nil, errors.New("PRIVATE_STATE_ROOT")
	}
	info, e := os.Lstat(root)
	if e != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return nil, errors.New("PRIVATE_STATE_ROOT")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || int(stat.Uid) != os.Getuid() {
		return nil, errors.New("STATE_OWNER")
	}
	path := filepath.Join(root, lockName)
	// Exclusive creation avoids Darwin's concurrent O_CREAT/no-O_EXCL race.
	// Existing names are opened without creation; never replace the lock inode.
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if errors.Is(e, os.ErrExist) {
		f, e = os.OpenFile(path, os.O_RDWR|syscall.O_NOFOLLOW, 0)
	}
	if e != nil {
		return nil, errors.New("STATE_LOCK")
	}
	s, e := f.Stat()
	if e != nil || !PrivateRegular(s) {
		f.Close()
		return nil, errors.New("STATE_LOCK_FILE")
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		f.Close()
		return nil, errors.New("STATE_BUSY")
	}
	return &Store{root: root, lock: f, syncFile: (*os.File).Sync, syncDirectory: SyncDir}, nil
}
func component(name string) bool {
	return name != "" && name != "." && name != ".." && filepath.Base(name) == name
}
func (s *Store) Close() { _ = syscall.Flock(int(s.lock.Fd()), syscall.LOCK_UN); _ = s.lock.Close() }
func SyncDir(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}

// Read treats absence separately from corruption. Symlinks, hardlinks, broad
// permissions and replacement between lstat/open are rejected.
func (s *Store) Read(name string, limit int64) ([]byte, error) {
	if !component(name) || limit < 1 {
		return nil, errors.New("JOURNAL_READ")
	}
	path := filepath.Join(s.root, name)
	info, e := os.Lstat(path)
	if os.IsNotExist(e) {
		return nil, nil
	}
	if e != nil {
		return nil, errors.New("JOURNAL_READ")
	}
	if !PrivateRegular(info) || info.Size() < 1 || info.Size() > limit {
		return nil, errors.New("JOURNAL_FILE")
	}
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return nil, errors.New("JOURNAL_READ")
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(info, opened) || !PrivateRegular(opened) {
		return nil, errors.New("JOURNAL_FILE")
	}
	b := make([]byte, info.Size())
	n, e := f.ReadAt(b, 0)
	if e != nil || n != len(b) {
		return nil, errors.New("JOURNAL_READ")
	}
	after, e := f.Stat()
	if e != nil || after.Size() != info.Size() {
		return nil, errors.New("JOURNAL_READ")
	}
	return b, nil
}

// Write completes file and directory fsync before success. Callers must retain
// the lock across read/validate/write; failure never authorizes an effect.
func (s *Store) Write(name string, b []byte) error {
	if !component(name) || len(b) == 0 || len(b) > 65536 {
		return errors.New("JOURNAL_ENCODING")
	}
	path := filepath.Join(s.root, name)
	if info, e := os.Lstat(path); e == nil {
		if !PrivateRegular(info) {
			return errors.New("JOURNAL_FILE")
		}
	} else if !os.IsNotExist(e) {
		return errors.New("JOURNAL_READ")
	}
	tmp, e := os.CreateTemp(s.root, ".journal-")
	if e != nil {
		return errors.New("JOURNAL_WRITE")
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, e = tmp.Write(b); e == nil {
		e = s.syncFile(tmp)
	}
	ce := tmp.Close()
	if e != nil || ce != nil {
		return errors.New("JOURNAL_FSYNC")
	}
	if os.Rename(tmpName, path) != nil || s.syncDirectory(s.root) != nil {
		return errors.New("JOURNAL_COMMIT")
	}
	return nil
}
