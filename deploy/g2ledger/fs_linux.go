package g2ledger

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// Walk all parent components by descriptor. A symlink in any component is
// refused, including a symlink introduced at the final component.
func openDir(path string) (*os.File, error) {
	if path != "/" && !validPath(path) {
		return nil, errors.New("PATH_NOT_ABSOLUTE_CLEAN")
	}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "/")
	if path == "/" {
		return f, nil
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		next, e := unix.Openat(int(f.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		f.Close()
		if e != nil {
			return nil, e
		}
		f = os.NewFile(uintptr(next), part)
	}
	return f, nil
}
func parent(path string) (*os.File, string, error) {
	if !validPath(path) {
		return nil, "", errors.New("PATH_NOT_ABSOLUTE_CLEAN")
	}
	f, e := openDir(filepath.Dir(path))
	return f, filepath.Base(path), e
}
func at(dir *os.File, name string, flags int, mode uint32) (*os.File, error) {
	fd, e := unix.Openat(int(dir.Fd()), name, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, mode)
	if e != nil {
		return nil, e
	}
	return os.NewFile(uintptr(fd), name), nil
}
func checkedWrite(w io.Writer, b []byte) error {
	n, e := w.Write(b)
	if e != nil {
		return e
	}
	if n != len(b) {
		return io.ErrShortWrite
	}
	return nil
}
func fsIdentity(f *os.File, kind string) (*FSIdentity, error) {
	var s unix.Stat_t
	if e := unix.Fstat(int(f.Fd()), &s); e != nil {
		return nil, e
	}
	typ := "file"
	if kind == "dir" || kind == "tree" {
		typ = "dir"
	}
	if s.Mode&unix.S_IFMT != unix.S_IFREG && typ == "file" || s.Mode&unix.S_IFMT != unix.S_IFDIR && typ == "dir" {
		return nil, errors.New("UNEXPECTED_FILE_TYPE")
	}
	if s.Mode&07000 != 0 || typ == "file" && s.Nlink != 1 {
		return nil, errors.New("UNEXPECTED_FILE_METADATA")
	}
	i := &FSIdentity{Dev: uint64(s.Dev), Ino: s.Ino, Type: typ, Mode: s.Mode & 0777, UID: s.Uid, GID: s.Gid}
	if typ == "file" {
		i.Size = s.Size
		i.MtimeNS = s.Mtim.Sec*1e9 + s.Mtim.Nsec
		if kind != "secret" {
			if _, e := f.Seek(0, io.SeekStart); e != nil {
				return nil, e
			}
			// Stream public files; secret contents are never read for an identity.
			h := newDigest()
			if _, e := io.Copy(h, f); e != nil {
				return nil, e
			}
			i.SHA256 = fmt.Sprintf("%x", h.Sum(nil))
		}
		var after unix.Stat_t
		if e := unix.Fstat(int(f.Fd()), &after); e != nil {
			return nil, e
		}
		if !stableStat(after, s) {
			return nil, errors.New("FILE_CHANGED_DURING_READ")
		}
	}
	return i, nil
}
func observeAt(d *os.File, name, path, kind string) (*Identity, error) {
	flags := unix.O_RDONLY
	if kind == "dir" || kind == "tree" {
		flags |= unix.O_DIRECTORY
	}
	f, e := at(d, name, flags, 0)
	if errors.Is(e, unix.ENOENT) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	defer f.Close()
	i, e := fsIdentity(f, kind)
	if e != nil {
		return nil, e
	}
	return &Identity{Path: path, FS: i}, nil
}
func observe(path, kind string) (*Identity, error) {
	d, n, e := parent(path)
	if errors.Is(e, unix.ENOENT) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	defer d.Close()
	return observeAt(d, n, path, kind)
}
func readFile(path string, limit int64) ([]byte, error) {
	d, n, e := parent(path)
	if e != nil {
		return nil, e
	}
	defer d.Close()
	f, e := at(d, n, unix.O_RDONLY, 0)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	if _, e = fsIdentity(f, "file"); e != nil {
		return nil, e
	}
	if _, e = f.Seek(0, io.SeekStart); e != nil {
		return nil, e
	}
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || int64(len(b)) > limit {
		return nil, errors.New("FILE_READ_LIMIT")
	}
	return b, nil
}
func setMetadata(f *os.File, uid, gid, mode uint32, sys System) error {
	if e := sys.Chown(f, uid, gid); e != nil {
		return e
	}
	return f.Chmod(os.FileMode(mode))
}
func private(f *os.File, dir bool) error {
	var s unix.Stat_t
	if e := unix.Fstat(int(f.Fd()), &s); e != nil {
		return e
	}
	mode, typ := uint32(0600), uint32(unix.S_IFREG)
	if dir {
		mode = 0700
		typ = unix.S_IFDIR
	}
	if s.Mode&unix.S_IFMT != typ || s.Mode&07777 != mode || s.Uid != uint32(os.Geteuid()) || !dir && s.Nlink != 1 {
		return errors.New("PRIVATE_STATE_METADATA")
	}
	return nil
}
func syncClose(f *os.File) error { e := f.Sync(); return errors.Join(e, f.Close()) }

func baselineDigest(path string) (string, error) {
	d, e := openDir(path)
	if e != nil {
		return "", e
	}
	defer d.Close()
	h := newDigest()
	var walk func(*os.File, string) error
	walk = func(dir *os.File, prefix string) error {
		entries, e := dir.ReadDir(-1)
		if e != nil {
			return e
		}
		sortEntries(entries)
		for _, entry := range entries {
			name := entry.Name()
			var s unix.Stat_t
			if e := unix.Fstatat(int(dir.Fd()), name, &s, unix.AT_SYMLINK_NOFOLLOW); e != nil {
				return e
			}
			switch s.Mode & unix.S_IFMT {
			case unix.S_IFDIR:
				f, e := at(dir, name, unix.O_RDONLY|unix.O_DIRECTORY, 0)
				if e != nil {
					return e
				}
				fmt.Fprintf(h, "d %q %o %d %d\n", prefix+name, s.Mode&07777, s.Uid, s.Gid)
				e = walk(f, prefix+name+"/")
				f.Close()
				if e != nil {
					return e
				}
			case unix.S_IFREG:
				f, e := at(dir, name, unix.O_RDONLY, 0)
				if e != nil {
					return e
				}
				id, e := fsIdentity(f, "file")
				f.Close()
				if e != nil {
					return e
				}
				fmt.Fprintf(h, "f %q %o %d %d %s\n", prefix+name, id.Mode, id.UID, id.GID, id.SHA256)
			default:
				return errors.New("BASELINE_NONREGULAR")
			}
		}
		return nil
	}
	if e := walk(d, ""); e != nil {
		return "", e
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
func fsOwnership(f *os.File) ([2]uint32, error) {
	var s unix.Stat_t
	e := unix.Fstat(int(f.Fd()), &s)
	return [2]uint32{s.Uid, s.Gid}, e
}

func stableStat(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Nlink == b.Nlink && a.Uid == b.Uid && a.Gid == b.Gid && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim && a.Rdev == b.Rdev
}
