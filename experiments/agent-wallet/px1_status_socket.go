package wallet

// PX1 stream S3 status socket listener (owner S3). The operator status socket
// is read-only: it serves only {"v":1,"action":"status"} and answers with the
// canonical StatusProjectionV1, which makes no node call and no journal write.

import (
	"context"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"time"
)

// PX1StatusSocketPath is the deployed operator status socket.
const PX1StatusSocketPath = "/run/swarma-wallet/status.sock"

const (
	px1oStatusTimeout  = 5 * time.Second
	px1oStartupTimeout = 120 * time.Second // the startup pass reads the whole wallet history
)

// px1oStatusAccess is the access contract of the operator status socket
// (decision on S5 request R3, option (a)). The socket stays in the W2 runtime
// directory /run/swarma-wallet (0750, group socket_gid); operator users join
// socket_gid to traverse it, and wallet.sock keeps refusing every UID except
// peer_uid (SERVICE_PEER). The socket itself is (service UID, operator GID,
// 0660). The agent (peer_uid) must never reach it (T19): the agent account
// must not be a member of the operator group, and a connection whose
// SO_PEERCRED UID is peer_uid is closed without a reply.
type px1oStatusAccess struct {
	operatorGID uint32 // status socket group
	agentGID    uint32 // socket_gid: the agent socket group
	agentUID    uint32 // peer_uid: the agent
}

// px1oAgentGroups lists the group IDs of the agent account (primary and
// supplementary). A variable so that a test can name the account database.
var px1oAgentGroups = func(uid uint32) ([]string, error) {
	u, e := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if e != nil {
		return nil, e
	}
	return u.GroupIds()
}

// px1oListenStatus binds the status socket: an existing path refuses (it is
// never unlinked), the socket is chowned to (service UID, operator GID) and
// set to 0660. The operator GID must differ from the agent socket group, and
// the agent account must not be a member of the operator group; an agent
// account whose groups cannot be read also refuses (STATUS_SOCKET_AGENT).
func px1oListenStatus(path string, a px1oStatusAccess) (*net.UnixListener, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || a.operatorGID == 0 || a.operatorGID == a.agentGID || a.agentUID == 0 {
		return nil, fail("STATUS_SOCKET_CONFIG")
	}
	groups, e := px1oAgentGroups(a.agentUID)
	if e != nil {
		return nil, fail("STATUS_SOCKET_AGENT")
	}
	for _, g := range groups {
		if g == strconv.FormatUint(uint64(a.operatorGID), 10) {
			return nil, fail("STATUS_SOCKET_AGENT")
		}
	}
	if _, e := os.Lstat(path); !os.IsNotExist(e) {
		return nil, fail("STATUS_SOCKET_EXISTS")
	}
	l, e := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if e != nil {
		return nil, fail("STATUS_SOCKET_BIND")
	}
	if os.Chown(path, os.Getuid(), int(a.operatorGID)) != nil || os.Chmod(path, 0660) != nil {
		l.Close()
		return nil, fail("STATUS_SOCKET_MODE")
	}
	return l, nil
}

// px1oServeStatusListener accepts connections one at a time until ctx ends.
// A connection from the agent UID, or one whose peer credentials cannot be
// read, is closed without a reply. Every other connection gets a short
// deadline and exactly one ServeStatus exchange.
func px1oServeStatusListener(ctx context.Context, l *net.UnixListener, agentUID uint32, source func() (StatusProjectionV1, error)) error {
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
		if peer, e := socketPeer(c); e != nil || peer.UID == agentUID {
			c.Close()
			continue
		}
		c.SetDeadline(time.Now().Add(px1oStatusTimeout))
		callCtx, cancel := context.WithTimeout(ctx, px1oStatusTimeout)
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
	d := net.Dialer{Timeout: px1oStatusTimeout}
	c, e := d.DialContext(ctx, "unix", path)
	if e != nil {
		return StatusProjectionV1{}, fail("STATUS_CONNECT")
	}
	c.SetDeadline(time.Now().Add(px1oStatusTimeout))
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
	startCtx, cancel := context.WithTimeout(ctx, px1oStartupTimeout)
	e := s.PX1Tick(startCtx)
	cancel()
	if e != nil {
		return nil, e
	}
	errs := make(chan error, 1)
	var l *net.UnixListener
	if path != "" {
		var e error
		if l, e = px1oListenStatus(path, px1oStatusAccess{operatorGID: operatorGID, agentGID: s.config.SocketGID, agentUID: s.config.PeerUID}); e != nil {
			return nil, e
		}
		go func() { errs <- px1oServeStatusListener(ctx, l, s.config.PeerUID, s.PX1Status); l.Close() }()
	}
	go px1oTickLoop(ctx, every, s.PX1Tick, report)
	return errs, nil
}
