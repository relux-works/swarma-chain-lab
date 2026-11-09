// Package presentationdir is the gateway's read-only issued-grant source.
package presentationdir

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

var ErrSource = errors.New("PRESENTATION_SOURCE")

type Directory struct{ root *os.File }

func Open(path string) (*Directory, error) {
	if path == string(filepath.Separator) || strings.ContainsAny(path, "\x00\r\n") {
		return nil, ErrSource
	}
	actual, e := filepath.EvalSymlinks(path)
	if e != nil || (!filepath.IsAbs(path) || filepath.Clean(path) != path) || actual != path {
		return nil, ErrSource
	}
	st, e := os.Stat(path)
	if e != nil || !st.IsDir() || st.Mode().Perm()&0022 != 0 {
		return nil, ErrSource
	}
	root, e := os.OpenFile(path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return nil, ErrSource
	}
	return &Directory{root}, nil
}
func (p *Directory) Close() error { return p.root.Close() }
func (p *Directory) Presentation(ctx context.Context, id string) ([]byte, error) {
	if ctx.Err() != nil || !digest(id) {
		return nil, ErrSource
	}
	// Open relative to the held directory descriptor. os.Root.OpenFile follows
	// in-root symlinks even with platform O_NOFOLLOW; openat preserves the
	// required leaf refusal without resolving mutable parent paths again.
	fd, e := unix.Openat(int(p.root.Fd()), id+".json", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if errors.Is(e, os.ErrNotExist) {
		return nil, nil
	}
	if e != nil {
		return nil, ErrSource
	}
	f := os.NewFile(uintptr(fd), id+".json")
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0022 != 0 || st.Size() < 1 || st.Size() > 16384 {
		return nil, ErrSource
	}
	b, e := io.ReadAll(io.LimitReader(f, 16385))
	if e != nil || len(b) > 16384 || ctx.Err() != nil {
		return nil, ErrSource
	}
	return b, nil // bookingbind.Grants owns canonical/signature/binding checks.
}

func digest(id string) bool {
	raw, e := hex.DecodeString(id)
	return e == nil && len(raw) == 32 && hex.EncodeToString(raw) == id
}
