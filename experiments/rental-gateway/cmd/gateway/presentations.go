package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

var errPresentation = errors.New("PRESENTATION_SOURCE")

type presentationDirectory struct{ root *os.File }

func openPresentations(path string) (*presentationDirectory, error) {
	actual, e := filepath.EvalSymlinks(path)
	if e != nil || !absPath(path) || actual != path {
		return nil, errPresentation
	}
	st, e := os.Stat(path)
	if e != nil || !st.IsDir() || st.Mode().Perm()&0022 != 0 {
		return nil, errPresentation
	}
	root, e := os.OpenFile(path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return nil, errPresentation
	}
	return &presentationDirectory{root}, nil
}
func (p *presentationDirectory) Close() error { return p.root.Close() }
func (p *presentationDirectory) Presentation(ctx context.Context, id string) ([]byte, error) {
	if ctx.Err() != nil || !digest(id) {
		return nil, errPresentation
	}
	// Open relative to the held directory descriptor. os.Root.OpenFile follows
	// in-root symlinks even with platform O_NOFOLLOW; openat preserves the
	// required leaf refusal without resolving mutable parent paths again.
	fd, e := unix.Openat(int(p.root.Fd()), id+".json", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if errors.Is(e, os.ErrNotExist) {
		return nil, nil
	}
	if e != nil {
		return nil, errPresentation
	}
	f := os.NewFile(uintptr(fd), id+".json")
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0022 != 0 || st.Size() < 1 || st.Size() > 16384 {
		return nil, errPresentation
	}
	b, e := io.ReadAll(io.LimitReader(f, 16385))
	if e != nil || len(b) > 16384 || ctx.Err() != nil {
		return nil, errPresentation
	}
	return b, nil // bookingbind.Grants owns canonical/signature/binding checks.
}
