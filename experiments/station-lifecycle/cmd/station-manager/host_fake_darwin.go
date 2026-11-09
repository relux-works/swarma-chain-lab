//go:build darwin && slotdfake

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	lifecycle "github.com/relux-works/swarma-chain-lab/experiments/station-lifecycle"
	"github.com/relux-works/swarma-chain-lab/experiments/station-lifecycle/slotd"
)

// The fixture explicitly owns its clock: SOCKET.clock holds a canonical
// CreateFence and must be advanced by the harness. There is no implicit
// production wall-clock fallback or command-line/environment bypass.
func newHost(c config) (*slotd.Host, error) {
	clock := func() (lifecycle.CreateFence, error) {
		var f lifecycle.CreateFence
		raw, e := readPrivate(c.Socket + ".clock")
		if e != nil {
			return f, fail("SLOTD_FAKE_CLOCK")
		}
		if json.Unmarshal(raw, &f) != nil {
			return f, fail("SLOTD_FAKE_CLOCK")
		}
		encoded, _ := json.Marshal(f)
		if !bytes.Equal(raw, encoded) || !f.Valid() {
			return f, fail("SLOTD_FAKE_CLOCK")
		}
		return f, nil
	}
	if _, e := clock(); e != nil {
		return nil, e
	}
	helper, e := slotd.NewFakeClient(func(ctx context.Context) (net.Conn, error) {
		for _, path := range []string{filepath.Dir(c.Socket), c.Socket} {
			resolved, e := filepath.EvalSymlinks(path)
			st, se := os.Lstat(path)
			if e != nil || se != nil || resolved != path {
				return nil, fail("SLOTD_FAKE_SOCKET")
			}
			owner, ok := st.Sys().(*syscall.Stat_t)
			if !ok || owner.Uid != uint32(os.Geteuid()) {
				return nil, fail("SLOTD_FAKE_SOCKET")
			}
			if path == c.Socket {
				if st.Mode()&os.ModeSocket == 0 || st.Mode().Perm() != 0600 {
					return nil, fail("SLOTD_FAKE_SOCKET")
				}
			} else if !st.IsDir() || st.Mode().Perm() != 0700 {
				return nil, fail("SLOTD_FAKE_SOCKET")
			}
		}
		return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", c.Socket)
	})
	if e != nil {
		return nil, e
	}
	return &slotd.Host{Client: helper, Now: time.Now, BootClock: clock}, nil
}
