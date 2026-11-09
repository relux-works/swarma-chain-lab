//go:build linux

package modelproxy

import (
	"golang.org/x/sys/unix"
	"net"
	"os"
	"syscall"
)

func supportsPeers() bool { return true }
func fileUID(i os.FileInfo) int {
	s, ok := i.Sys().(*syscall.Stat_t)
	if !ok {
		return -1
	}
	return int(s.Uid)
}
func peerUID(c net.Conn) (uint32, error) {
	u, ok := c.(*net.UnixConn)
	if !ok {
		return 0, fail("PEER")
	}
	raw, e := u.SyscallConn()
	if e != nil {
		return 0, fail("PEER")
	}
	var creds *unix.Ucred
	var inner error
	e = raw.Control(func(fd uintptr) { creds, inner = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
	if e != nil || inner != nil || creds == nil {
		return 0, fail("PEER")
	}
	return creds.Uid, nil
}
