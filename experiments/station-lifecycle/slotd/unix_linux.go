//go:build linux

package slotd

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// NewUnixClient verifies the configured root-owned socket and its parent, then
// the connected root peer. SO_PEERCRED on the helper independently gates caller.
func NewUnixClient(path string) (*Client, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, failure("SLOTD_SOCKET")
	}
	return &Client{timeout: 2 * time.Second, dial: func(ctx context.Context) (net.Conn, error) {
		for _, name := range []string{filepath.Dir(path), path} {
			st, e := os.Lstat(name)
			if e != nil {
				return nil, failure("SLOTD_SOCKET")
			}
			stat, ok := st.Sys().(*syscall.Stat_t)
			if !ok || stat.Uid != 0 || st.Mode()&os.ModeSymlink != 0 {
				return nil, failure("SLOTD_SOCKET")
			}
			if name == path {
				if st.Mode()&os.ModeSocket == 0 || st.Mode().Perm() != 0660 {
					return nil, failure("SLOTD_SOCKET")
				}
			} else if !st.IsDir() || st.Mode().Perm() != 0750 {
				return nil, failure("SLOTD_SOCKET")
			}
		}
		conn, e := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", path)
		if e != nil {
			return nil, failure("SLOTD_SOCKET")
		}
		u, ok := conn.(*net.UnixConn)
		if !ok {
			conn.Close()
			return nil, failure("SLOTD_PEER")
		}
		raw, e := u.SyscallConn()
		if e != nil {
			conn.Close()
			return nil, failure("SLOTD_PEER")
		}
		valid := false
		e = raw.Control(func(fd uintptr) {
			cred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
			valid = err == nil && cred.Uid == 0
		})
		if e != nil || !valid {
			conn.Close()
			return nil, failure("SLOTD_PEER")
		}
		return conn, nil
	}}, nil
}
