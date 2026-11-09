//go:build linux

package wallet

import (
	"golang.org/x/sys/unix"
	"net"
)

func socketPeer(c *net.UnixConn) (PeerIdentity, error) {
	raw, e := c.SyscallConn()
	if e != nil {
		return PeerIdentity{}, fail("SERVICE_PEER")
	}
	var cred *unix.Ucred
	var inner error
	e = raw.Control(func(fd uintptr) { cred, inner = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
	if e != nil || inner != nil || cred == nil {
		return PeerIdentity{}, fail("SERVICE_PEER")
	}
	return PeerIdentity{cred.Uid, cred.Gid}, nil
}
