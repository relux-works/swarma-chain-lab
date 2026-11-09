//go:build linux

package signerservice

import "golang.org/x/sys/unix"

func renamePresentation(fd int, from, to string) error {
	return unix.Renameat2(fd, from, fd, to, unix.RENAME_NOREPLACE)
}
