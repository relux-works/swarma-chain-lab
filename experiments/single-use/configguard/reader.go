// Package configguard checks root-owned installed inputs independently from
// mutable service state. It neither provisions files nor chooses a trust anchor.
package configguard

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

type Reason string

func (r Reason) Error() string { return string(r) }
func fail(s string) error      { return Reason(s) }

// Reader's identity comes from the trusted process/unit, never from file values.
// Metadata is an explicit synthetic ownership seam for isolated tests. Production
// callers use Native; no environment, CLI or config switch selects this seam.
type Reader struct {
	EUID     int
	GID      int
	Metadata func(path string, stat *unix.Stat_t)
}

func Native() Reader                                { return Reader{EUID: os.Geteuid(), GID: os.Getegid()} }
func Read(path string, limit int64) ([]byte, error) { return Native().Read(path, limit) }
func (r Reader) stat(f *os.File, path string) (unix.Stat_t, error) {
	var s unix.Stat_t
	if unix.Fstat(int(f.Fd()), &s) != nil {
		return s, fail("DK5_FILE_STAT")
	}
	if r.Metadata != nil {
		r.Metadata(path, &s)
	}
	return s, nil
}
func validPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/" && !strings.ContainsAny(path, "\x00\r\n")
}
func (r Reader) directory(s unix.Stat_t, immediate bool, parentMode uint32, parentGID uint32) error {
	if s.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fail("DK5_DIRECTORY_KIND")
	}
	if s.Uid != 0 {
		return fail("DK5_DIRECTORY_OWNER")
	}
	if immediate {
		if s.Gid != parentGID {
			return fail("DK5_DIRECTORY_GROUP")
		}
		if uint32(s.Mode)&07777 != parentMode {
			return fail("DK5_DIRECTORY_MODE")
		}
	} else if s.Mode&0022 != 0 || s.Mode&07000 != 0 {
		return fail("DK5_ANCESTOR_MODE")
	}
	return nil
}
func (r Reader) regular(s unix.Stat_t, limit int64, mode uint32, gid uint32) error {
	if s.Mode&unix.S_IFMT != unix.S_IFREG {
		return fail("DK5_FILE_KIND")
	}
	if s.Uid != 0 {
		return fail("DK5_FILE_OWNER")
	}
	if s.Gid != gid {
		return fail("DK5_FILE_GROUP")
	}
	if uint32(s.Mode)&07777 != mode {
		return fail("DK5_FILE_MODE")
	}
	if s.Nlink != 1 {
		return fail("DK5_FILE_LINKS")
	}
	if s.Size < 1 || s.Size > limit {
		return fail("DK5_FILE_SIZE")
	}
	return nil
}

// Read opens each component relative to its pinned parent descriptor with
// O_NOFOLLOW. Every metadata check precedes any content read, including FIFO
// refusal; NONBLOCK prevents a hostile special file from stalling admission.
func (r Reader) Read(path string, limit int64) ([]byte, error) {
	return r.read(path, limit, 0640, 0750, uint32(r.GID))
}

func (r Reader) read(path string, limit int64, mode, parentMode, gid uint32) ([]byte, error) {
	if r.EUID <= 0 || r.GID <= 0 {
		return nil, fail("DK5_SERVICE_IDENTITY")
	}
	if !validPath(path) || limit < 1 || limit > 16<<20 {
		return nil, fail("DK5_PATH")
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, fail("DK5_DIRECTORY_OPEN")
	}
	parent := os.NewFile(uintptr(fd), "/")
	defer func() { parent.Close() }()
	current := "/"
	st, e := r.stat(parent, current)
	if e != nil {
		return nil, e
	}
	if e = r.directory(st, len(parts) == 1, parentMode, gid); e != nil {
		return nil, e
	}
	for _, component := range parts[:len(parts)-1] {
		fd, e = unix.Openat(int(parent.Fd()), component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if e != nil {
			return nil, fail("DK5_DIRECTORY_OPEN")
		}
		next := os.NewFile(uintptr(fd), component)
		parent.Close()
		parent = next
		current = filepath.Join(current, component)
		st, e = r.stat(parent, current)
		if e != nil {
			return nil, e
		}
		if e = r.directory(st, current == filepath.Dir(path), parentMode, gid); e != nil {
			return nil, e
		}
	}
	fd, e = unix.Openat(int(parent.Fd()), parts[len(parts)-1], unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, fail("DK5_FILE_OPEN")
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	before, e := r.stat(f, path)
	if e != nil {
		return nil, e
	}
	if e = r.regular(before, limit, mode, gid); e != nil {
		return nil, e
	}
	info, e := f.Stat()
	if e != nil {
		return nil, fail("DK5_FILE_STAT")
	}
	raw, e := io.ReadAll(io.LimitReader(f, limit+1))
	after, se := r.stat(f, path)
	last, le := f.Stat()
	if e != nil || se != nil || le != nil || r.regular(after, limit, mode, gid) != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Mode != after.Mode || before.Uid != after.Uid || before.Gid != after.Gid || before.Nlink != after.Nlink || before.Size != after.Size || !info.ModTime().Equal(last.ModTime()) || int64(len(raw)) != before.Size {
		clear(raw)
		return nil, fail("DK5_FILE_CHANGED")
	}
	return raw, nil
}
