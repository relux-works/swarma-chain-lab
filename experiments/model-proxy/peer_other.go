//go:build !linux

package modelproxy

import (
	"net"
	"os"
	"syscall"
)

func supportsPeers() bool { return false }
func fileUID(i os.FileInfo) int {
	s, ok := i.Sys().(*syscall.Stat_t)
	if !ok {
		return -1
	}
	return int(s.Uid)
}
func peerUID(net.Conn) (uint32, error) { return 0, fail("LINUX_ONLY") }
