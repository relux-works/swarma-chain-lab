package chaingateway

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"strings"
	"syscall"
	"time"
)

type socketEvidence struct {
	family, state         byte
	local, remote         net.IP
	localPort, remotePort uint16
	uid                   uint32
	cookie                [8]byte
}

// Kernel evidence is requested in this network namespace. A translated user
// namespace cannot authenticate host service UIDs and is refused.
func socketTable(family byte) ([]socketEvidence, error) {
	mapping, e := os.ReadFile("/proc/self/uid_map")
	if e != nil || strings.Join(strings.Fields(string(mapping)), " ") != "0 0 4294967295" {
		return nil, bad("user namespace")
	}
	fd, e := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, 4)
	if e != nil {
		return nil, e
	}
	defer syscall.Close(fd)
	if e = syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); e != nil {
		return nil, e
	}
	if e = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 1}); e != nil {
		return nil, e
	}
	// nlmsghdr + inet_diag_req_v2; native-endian scalar fields and network ports.
	req := make([]byte, 72)
	binary.NativeEndian.PutUint32(req[0:4], uint32(len(req)))
	binary.NativeEndian.PutUint16(req[4:6], 20) // SOCK_DIAG_BY_FAMILY
	binary.NativeEndian.PutUint16(req[6:8], syscall.NLM_F_REQUEST|syscall.NLM_F_DUMP)
	binary.NativeEndian.PutUint32(req[8:12], 1)
	req[16], req[17] = family, syscall.IPPROTO_TCP
	binary.NativeEndian.PutUint32(req[20:24], (1<<1)|(1<<10)) // ESTABLISHED, LISTEN
	for i := 64; i < 72; i++ {
		req[i] = 255
	}
	if e = syscall.Sendto(fd, req, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); e != nil {
		return nil, e
	}
	var rows []socketEvidence
	deadline := time.Now().Add(time.Second)
	for batches := 0; batches < 4096; batches++ {
		if time.Now().After(deadline) {
			return nil, bad("evidence timeout")
		}
		buf := make([]byte, 65536)
		n, _, flags, from, e := syscall.Recvmsg(fd, buf, nil, 0)
		kernel, ok := from.(*syscall.SockaddrNetlink)
		if e != nil || !ok || kernel.Pid != 0 || flags&syscall.MSG_TRUNC != 0 {
			return nil, bad("socket evidence")
		}
		msgs, e := syscall.ParseNetlinkMessage(buf[:n])
		if e != nil {
			return nil, e
		}
		for _, m := range msgs {
			if m.Header.Seq != 1 || m.Header.Flags&0x10 != 0 {
				return nil, bad("interrupted evidence")
			}
			if m.Header.Type == syscall.NLMSG_DONE {
				return rows, nil
			}
			if m.Header.Type != 20 || len(m.Data) < 72 {
				return nil, bad("kernel refusal")
			}
			b := m.Data
			if b[0] != family {
				return nil, bad("socket family")
			}
			width := 16
			if family == syscall.AF_INET {
				width = 4
			}
			row := socketEvidence{family: b[0], state: b[1], local: append(net.IP(nil), b[8:8+width]...), remote: append(net.IP(nil), b[24:24+width]...), localPort: binary.BigEndian.Uint16(b[4:6]), remotePort: binary.BigEndian.Uint16(b[6:8]), uid: binary.NativeEndian.Uint32(b[64:68])}
			copy(row.cookie[:], b[44:52])
			rows = append(rows, row)
		}
	}
	return nil, bad("evidence capacity")
}

func authenticateConnection(conn net.Conn, uid uint32) error {
	server, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return bad("tcp peer")
	}
	client, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok {
		return bad("tcp local")
	}
	family := byte(syscall.AF_INET6)
	if server.IP.To4() != nil {
		family = syscall.AF_INET
	}
	rows, e := socketTable(family)
	if e != nil {
		return e
	}
	return verifySocketRows(rows, server, client, uid)
}

func verifySocketRows(rows []socketEvidence, server, client *net.TCPAddr, uid uint32) error {
	listeners, peers := 0, 0
	for _, r := range rows {
		if int(r.localPort) != server.Port {
			continue
		}
		if r.state == 10 && (r.local.Equal(server.IP) || r.local.IsUnspecified()) {
			if r.uid != uid {
				return bad("listener uid")
			}
			listeners++
		}
		if r.state == 1 && r.local.Equal(server.IP) && r.remote.Equal(client.IP) && int(r.remotePort) == client.Port {
			if r.uid != uid || r.cookie == [8]byte{} || r.cookie == [8]byte{255, 255, 255, 255, 255, 255, 255, 255} {
				return bad("peer uid or cookie")
			}
			peers++
		}
	}
	if listeners != 1 || peers != 1 {
		return bad("missing or ambiguous endpoint")
	}
	return nil
}
func authenticatedDial(ctx context.Context, network, address string, uid uint32) (net.Conn, error) {
	conn, e := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, address)
	if e != nil {
		return nil, e
	}
	if e = authenticateConnection(conn, uid); e != nil {
		conn.Close()
		return nil, e
	}
	return conn, nil
}

func hardenDumps() error {
	if _, _, e := syscall.Syscall6(syscall.SYS_PRCTL, 4, 0, 0, 0, 0, 0); e != 0 {
		return e
	} // PR_SET_DUMPABLE
	if e := syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0}); e != nil {
		return e
	}
	v, _, e := syscall.Syscall6(syscall.SYS_PRCTL, 3, 0, 0, 0, 0, 0) // PR_GET_DUMPABLE
	var limit syscall.Rlimit
	if e != 0 || v != 0 || syscall.Getrlimit(syscall.RLIMIT_CORE, &limit) != nil || limit.Cur != 0 || limit.Max != 0 {
		return bad("dump hardening")
	}
	return nil
}
