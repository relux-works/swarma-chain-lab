package wallet

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"syscall"
	"time"
)

func readActionFrame(r io.Reader) ([]byte, error) {
	var prefix [4]byte
	if _, e := io.ReadFull(r, prefix[:]); e != nil {
		return nil, fail("ACTION_FRAME")
	}
	n := binary.BigEndian.Uint32(prefix[:])
	if n == 0 || n > MaxActionFrame {
		return nil, fail("ACTION_FRAME_SIZE")
	}
	b := make([]byte, int(n))
	if _, e := io.ReadFull(r, b); e != nil {
		return nil, fail("ACTION_FRAME")
	}
	return b, nil
}
func writeActionFrame(w io.Writer, b []byte) error {
	if len(b) == 0 || len(b) > MaxActionFrame {
		return fail("ACTION_FRAME_SIZE")
	}
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(b)))
	frame := append(prefix[:], b...)
	for len(frame) > 0 {
		n, e := w.Write(frame)
		if e != nil || n == 0 {
			return fail("ACTION_FRAME")
		}
		frame = frame[n:]
	}
	return nil
}

// Serve uses one bounded request per accepted connection. A stale socket refuses
// startup; it never unlinks a path that another service might currently own.
func (s *ActionService) Serve(ctx context.Context) error {
	if _, e := os.Lstat(s.config.Socket); !os.IsNotExist(e) {
		return fail("SERVICE_SOCKET_EXISTS")
	}
	l, e := net.ListenUnix("unix", &net.UnixAddr{Name: s.config.Socket, Net: "unix"})
	if e != nil {
		return fail("SERVICE_SOCKET_BIND")
	}
	defer l.Close()
	if os.Chown(s.config.Socket, os.Getuid(), int(s.config.SocketGID)) != nil || os.Chmod(s.config.Socket, 0660) != nil {
		return fail("SERVICE_SOCKET_MODE")
	}
	return s.serveListener(ctx, l)
}
func (s *ActionService) serveListener(ctx context.Context, l *net.UnixListener) error {
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			l.Close()
		case <-done:
		}
	}()
	for {
		c, e := l.AcceptUnix()
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fail("SERVICE_ACCEPT")
		}
		s.serveConnection(ctx, c)
		c.Close()
	}
}
func (s *ActionService) serveConnection(ctx context.Context, c *net.UnixConn) {
	deadline := time.Now().Add(time.Duration(s.config.TimeoutSeconds) * time.Second)
	c.SetDeadline(deadline)
	callCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	stop := context.AfterFunc(callCtx, func() { c.Close() })
	defer stop()
	peer, e := socketPeer(c)
	if e != nil || peer.UID != s.config.PeerUID {
		return
	}
	raw, e := readActionFrame(c)
	if e != nil {
		return
	}
	response := s.handle(callCtx, raw, peer)
	_ = writeActionFrame(c, response)
}

// ExchangeAction checks both the kernel-supplied service UID and its pinned
// receipt key. The client opens no wallet configuration or effect credential.
func ExchangeAction(ctx context.Context, socket string, serviceUID uint32, receiptKey string, raw []byte) ([]byte, error) {
	v, e := ParseAction(raw, WalletServiceID)
	if e != nil {
		return nil, e
	}
	i, e := os.Lstat(socket)
	if e != nil || i.Mode()&os.ModeSocket == 0 || i.Mode().Perm() != 0660 {
		return nil, fail("SERVICE_SOCKET_MODE")
	}
	st, ok := i.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != serviceUID {
		return nil, fail("SERVICE_SOCKET_OWNER")
	}
	d := net.Dialer{}
	conn, e := d.DialContext(ctx, "unix", socket)
	if e != nil {
		return nil, fail("SERVICE_CONNECT")
	}
	defer conn.Close()
	c, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, fail("SERVICE_PEER")
	}
	peer, e := socketPeer(c)
	if e != nil || peer.UID != serviceUID {
		return nil, fail("SERVICE_PEER")
	}
	deadline := time.Now().Add(60 * time.Second)
	if t, ok := ctx.Deadline(); ok && t.Before(deadline) {
		deadline = t
	}
	c.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	if e = writeActionFrame(c, raw); e != nil {
		return nil, e
	}
	reply, e := readActionFrame(c)
	if e != nil {
		return nil, e
	}
	if _, e = ParseActionReceipt(reply, receiptKey, v.Hash, v.Envelope.Request.Grantee); e != nil {
		return nil, e
	}
	return reply, nil
}
