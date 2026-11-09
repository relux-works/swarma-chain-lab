//go:build darwin

package signerservice

import "golang.org/x/sys/unix"

func renamePresentation(fd int, from, to string) error {
	return unix.RenameatxNp(fd, from, fd, to, unix.RENAME_EXCL)
}
