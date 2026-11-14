//go:build darwin && slotdfake

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	lifecycle "github.com/relux-works/swarma-chain-lab/experiments/station-lifecycle"
	"github.com/relux-works/swarma-chain-lab/experiments/station-lifecycle/slotd"
)

func fakeClockFixture(t *testing.T) (config, lifecycle.CreateFence) {
	t.Helper()
	// Short names keep real Unix sockets inside Darwin's path-length bound.
	tmp, e := os.MkdirTemp("", "fake-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(tmp) })
	root, e := filepath.EvalSymlinks(tmp)
	if e != nil {
		t.Fatal(e)
	}
	clockDir, socketDir := filepath.Join(root, "c"), filepath.Join(root, "s")
	for _, dir := range []string{clockDir, socketDir} {
		if e := os.Mkdir(dir, 0700); e != nil {
			t.Fatal(e)
		}
	}
	c := config{Socket: filepath.Join(socketDir, "s"), FakeClock: filepath.Join(clockDir, "clock")}
	f := lifecycle.CreateFence{BootID: "0f8e1c3a-6b2d-4e7f-9a1b-2c3d4e5f6a7b", IssuedBoottimeNS: "10000000000"}
	raw, e := json.Marshal(f)
	if e != nil {
		t.Fatal(e)
	}
	writeInstalled(t, c.FakeClock, raw)
	return c, f
}

func assertFakeClock(t *testing.T, c config, want lifecycle.CreateFence) {
	t.Helper()
	h, e := newHost(c)
	if e != nil {
		t.Fatal("valid clock", e)
	}
	if got, e := h.BootClock(); e != nil || got != want {
		t.Fatal("clock fence", got, e)
	}
}

// Omitting fake_clock reads exactly SOCKET.clock on construction and refresh; a missing default never falls back.
func TestFakeClockDefaultPath(t *testing.T) {
	c, fence := fakeClockFixture(t)
	raw, e := json.Marshal(c)
	if e != nil {
		t.Fatal(e)
	}
	var fields map[string]json.RawMessage
	if e := json.Unmarshal(raw, &fields); e != nil {
		t.Fatal(e)
	}
	delete(fields, "fake_clock")
	raw, e = json.Marshal(fields)
	if e != nil {
		t.Fatal(e)
	}
	var unset config
	if e := json.Unmarshal(raw, &unset); e != nil || unset.FakeClock != "" {
		t.Fatal("unset fake_clock", e)
	}
	defaultPath := c.Socket + ".clock"
	clock, e := os.ReadFile(c.FakeClock)
	if e != nil {
		t.Fatal(e)
	}
	writeInstalled(t, defaultPath, clock)
	read := installedRead
	var paths []string
	installedRead = func(path string, limit int64) ([]byte, error) {
		paths = append(paths, path)
		return read(path, limit)
	}
	t.Cleanup(func() { installedRead = read })
	assertFakeClock(t, unset, fence)
	if len(paths) != 2 || paths[0] != defaultPath || paths[1] != defaultPath {
		t.Fatal("default clock read different path", paths)
	}
	if e := os.Remove(defaultPath); e != nil {
		t.Fatal(e)
	}
	if h, e := newHost(unset); h != nil || e == nil || e.Error() != "SLOTD_FAKE_CLOCK" {
		t.Fatal("missing default clock accepted", e)
	}
}

// A configured clock in its own installed directory loads and overrides an invalid SOCKET.clock.
func TestFakeConfigClockPath(t *testing.T) {
	c, path := checkConfigFixture(t)
	fixture, fence := fakeClockFixture(t)
	c.Socket, c.FakeClock = fixture.Socket, fixture.FakeClock
	// A bad default witnesses that the explicit input is selected, rather than ignored.
	writeInstalled(t, c.Socket+".clock", []byte(`{}`))
	raw, e := json.Marshal(c)
	if e != nil {
		t.Fatal(e)
	}
	writeInstalled(t, path, raw)
	loaded, client, e := load(path)
	if e != nil {
		t.Fatal("fake config rejected", e)
	}
	defer client.Close()
	if loaded.FakeClock != c.FakeClock {
		t.Fatal("fake clock path lost")
	}
	assertFakeClock(t, loaded, fence)
}

// A 0750 clock parent is accepted; neighboring wrong modes fail without constructing a host.
func TestFakeClockParentMode(t *testing.T) {
	for _, mode := range []os.FileMode{0700, 0755, 0770} {
		t.Run(fmt.Sprintf("%04o", mode), func(t *testing.T) {
			c, fence := fakeClockFixture(t)
			assertFakeClock(t, c, fence)
			if e := os.Chmod(filepath.Dir(c.FakeClock), mode); e != nil {
				t.Fatal(e)
			}
			if h, e := newHost(c); h != nil || e == nil || e.Error() != "SLOTD_FAKE_CLOCK" {
				t.Fatal("wrong clock parent accepted", e)
			}
			if e := os.Chmod(filepath.Dir(c.FakeClock), 0750); e != nil {
				t.Fatal(e)
			}
			assertFakeClock(t, c, fence)
		})
	}
}

// Direct clock paths load; symlinks at either the file or immediate parent fail without a host.
func TestFakeClockSymlink(t *testing.T) {
	for _, parent := range []bool{false, true} {
		t.Run(fmt.Sprintf("parent=%t", parent), func(t *testing.T) {
			c, fence := fakeClockFixture(t)
			assertFakeClock(t, c, fence)
			target, alias := c.FakeClock, c.FakeClock+".link"
			if parent {
				target, alias = filepath.Dir(c.FakeClock), filepath.Dir(c.FakeClock)+".link"
			}
			if e := os.Symlink(target, alias); e != nil {
				t.Fatal(e)
			}
			c.FakeClock = alias
			if parent {
				c.FakeClock = filepath.Join(alias, "clock")
			}
			if h, e := newHost(c); h != nil || e == nil || e.Error() != "SLOTD_FAKE_CLOCK" {
				t.Fatal("symlink clock accepted", e)
			}
		})
	}
}

func fakeSocketListener(t *testing.T, c config) *net.UnixListener {
	t.Helper()
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: c.Socket, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { listener.Close() })
	if e := os.Chmod(c.Socket, 0600); e != nil {
		t.Fatal(e)
	}
	return listener
}

func assertFakeSocket(t *testing.T, c config, listener *net.UnixListener) {
	t.Helper()
	h, e := newHost(c)
	if e != nil {
		t.Fatal(e)
	}
	if e := listener.SetDeadline(time.Now().Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() {
		conn, e := listener.Accept()
		if e != nil {
			done <- e
			return
		}
		defer conn.Close()
		if e := conn.SetDeadline(time.Now().Add(time.Second)); e != nil {
			done <- e
			return
		}
		raw, e := bufio.NewReader(conn).ReadBytes('\n')
		var q slotd.Request
		if e != nil || json.Unmarshal(raw, &q) != nil || !slotd.ValidRequest(q) || q.Op != "status" || q.Slot != "1" {
			done <- fmt.Errorf("unexpected fake request: %v", e)
			return
		}
		_, e = conn.Write([]byte("{\"v\":1,\"ok\":true,\"slot\":\"1\",\"state\":\"absent\"}\n"))
		done <- e
	}()
	_, callErr := h.Client.Call(context.Background(), slotd.Request{V: 1, Op: "status", Slot: "1"})
	if e := <-done; e != nil || callErr != nil {
		t.Fatal("valid fake socket", callErr, e)
	}
}

// A 0700 socket parent exchanges a real status request; other modes refuse before any socket connection.
func TestFakeSocketParentMode(t *testing.T) {
	for _, mode := range []os.FileMode{0750, 0755, 0770} {
		t.Run(fmt.Sprintf("%04o", mode), func(t *testing.T) {
			c, _ := fakeClockFixture(t)
			listener := fakeSocketListener(t, c)
			assertFakeSocket(t, c, listener)
			if e := os.Chmod(filepath.Dir(c.Socket), mode); e != nil {
				t.Fatal(e)
			}
			h, e := newHost(c)
			if e != nil {
				t.Fatal(e)
			}
			out, e := h.Client.Call(context.Background(), slotd.Request{V: 1, Op: "status", Slot: "1"})
			if e == nil || e.Error() != "SLOTD_UNAVAILABLE" || out != (slotd.Response{}) {
				t.Fatal("wrong socket parent accepted", e)
			}
			if e := listener.SetDeadline(time.Now().Add(25 * time.Millisecond)); e != nil {
				t.Fatal(e)
			}
			conn, e := listener.Accept()
			if conn != nil {
				conn.Close()
				t.Fatal("forbidden socket connection")
			}
			if timeout, ok := e.(net.Error); !ok || !timeout.Timeout() {
				t.Fatal("expected no socket connection", e)
			}
			if e := os.Chmod(filepath.Dir(c.Socket), 0700); e != nil {
				t.Fatal(e)
			}
			assertFakeSocket(t, c, listener)
		})
	}
}
