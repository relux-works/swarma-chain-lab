package wallet

// PX1 stream S3 status socket listener (owner S3). The operator status socket
// is read-only: it serves only {"v":1,"action":"status"} and answers with the
// canonical StatusProjectionV1, which makes no node call and no journal write.

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"time"
)

// PX1StatusSocketPath is the deployed operator status socket.
const PX1StatusSocketPath = "/run/swarma-wallet/status.sock"

const (
	px1StatusTimeout  = 5 * time.Second
	px1StartupTimeout = 120 * time.Second // the startup pass reads the whole wallet history
)

// px1ListenStatus binds the status socket: an existing path refuses (it is
// never unlinked), the socket is chowned to (service UID, operator GID) and
// set to 0660. The operator GID must differ from the agent socket group, so
// the agent peer can never read the status socket through group access.
func px1ListenStatus(path string, gid, agentGID uint32) (*net.UnixListener, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || gid == 0 || gid == agentGID {
		return nil, fail("STATUS_SOCKET_CONFIG")
	}
	if _, e := os.Lstat(path); !os.IsNotExist(e) {
		return nil, fail("STATUS_SOCKET_EXISTS")
	}
	l, e := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if e != nil {
		return nil, fail("STATUS_SOCKET_BIND")
	}
	if os.Chown(path, os.Getuid(), int(gid)) != nil || os.Chmod(path, 0660) != nil {
		l.Close()
		return nil, fail("STATUS_SOCKET_MODE")
	}
	return l, nil
}

// px1ServeStatusListener accepts connections one at a time until ctx ends.
// Each connection gets a short deadline and exactly one ServeStatus exchange.
func px1ServeStatusListener(ctx context.Context, l *net.UnixListener, source func() (StatusProjectionV1, error)) error {
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
			return fail("STATUS_ACCEPT")
		}
		c.SetDeadline(time.Now().Add(px1StatusTimeout))
		callCtx, cancel := context.WithTimeout(ctx, px1StatusTimeout)
		_ = ServeStatus(callCtx, c, source)
		cancel()
	}
}

// ReadPX1Status dials the status socket and returns the decoded projection.
func ReadPX1Status(ctx context.Context, path string) (StatusProjectionV1, error) {
	i, e := os.Lstat(path)
	if e != nil || i.Mode()&os.ModeSocket == 0 || i.Mode().Perm() != 0660 {
		return StatusProjectionV1{}, fail("STATUS_SOCKET_MODE")
	}
	d := net.Dialer{Timeout: px1StatusTimeout}
	c, e := d.DialContext(ctx, "unix", path)
	if e != nil {
		return StatusProjectionV1{}, fail("STATUS_CONNECT")
	}
	c.SetDeadline(time.Now().Add(px1StatusTimeout))
	return ExchangeStatus(ctx, c)
}

// RunPX1Observers runs the G2 observation side of agent-walletd: one startup
// pass that must succeed before the caller serves requests (canary, startup
// reconciliation), then the tick loop and, when path is set, the status
// socket. It returns after the startup pass; the loops stop with ctx.
func (s *ActionService) RunPX1Observers(ctx context.Context, path string, operatorGID uint32, every time.Duration, report func(code string)) (<-chan error, error) {
	if s.PX1Profile() == nil {
		return nil, fail("SERVICE_PROFILE")
	}
	if every < time.Second {
		return nil, fail("SERVICE_ARGUMENTS")
	}
	startCtx, cancel := context.WithTimeout(ctx, px1StartupTimeout)
	e := s.PX1Tick(startCtx)
	cancel()
	if e != nil {
		return nil, e
	}
	errs := make(chan error, 1)
	var l *net.UnixListener
	if path != "" {
		var e error
		if l, e = px1ListenStatus(path, operatorGID, s.config.SocketGID); e != nil {
			return nil, e
		}
		go func() { errs <- px1ServeStatusListener(ctx, l, s.PX1Status); l.Close() }()
	}
	go px1TickLoop(ctx, every, s.PX1Tick, report)
	return errs, nil
}
