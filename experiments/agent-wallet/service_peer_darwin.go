//go:build darwin

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
	var cred *unix.Xucred
	var inner error
	e = raw.Control(func(fd uintptr) { cred, inner = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED) })
	if e != nil || inner != nil || cred == nil || cred.Version != 0 || cred.Ngroups < 1 {
		return PeerIdentity{}, fail("SERVICE_PEER")
	}
	return PeerIdentity{cred.Uid, cred.Groups[0]}, nil
}
