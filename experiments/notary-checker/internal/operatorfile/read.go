// Package operatorfile reads bounded regular operator inputs without following
// symlinks or waiting for a FIFO writer.
package operatorfile

import (
	"errors"
	"io"
	"os"
	"syscall"
)

// Read checks the opened descriptor before restoring blocking reads. Callers
// map this local error to their existing public refusal code.
func Read(path string, max int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("FILE_READ")
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return nil, errors.New("FILE_READ")
	}
	if err = syscall.SetNonblock(int(f.Fd()), false); err != nil {
		return nil, errors.New("FILE_READ")
	}
	raw, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(raw)) > max {
		return nil, errors.New("FILE_READ")
	}
	return raw, nil
}
