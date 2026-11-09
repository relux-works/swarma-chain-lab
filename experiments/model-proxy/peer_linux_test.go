//go:build linux

package modelproxy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// On Linux this exercises the real Unix socket and SO_PEERCRED policy: the
// current UID can Prepare/Activate/Revoke only when it is the pinned caller.
// A different pinned caller refuses before creating a record. It does not
// provision users or prove separation between compromised same-UID processes.
func TestUnixPeerRoundTrip(t *testing.T) {
	for _, allowed := range []bool{true, false} {
		t.Run(map[bool]string{true: "allowed", false: "wrong-caller"}[allowed], func(t *testing.T) {
			h := fixture(t)
			root, e := filepath.EvalSymlinks(t.TempDir())
			if e != nil {
				t.Fatal(e)
			}
			if e = os.Chmod(root, 0750); e != nil {
				t.Fatal(e)
			}
			path := filepath.Join(root, "admin.sock")
			uid := uint32(os.Getuid())
			caller := uid
			if !allowed {
				caller++
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- h.s.ServeAdmin(ctx, path, caller) }()
			t.Cleanup(func() {
				cancel()
				select {
				case e := <-done:
					if e != nil {
						t.Error(e)
					}
				case <-time.After(3 * time.Second):
					t.Error("admin listener did not stop")
				}
			})
			deadline := time.Now().Add(2 * time.Second)
			for {
				st, e := os.Lstat(path)
				if e == nil && st.Mode().Perm() == 0660 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("admin socket not ready")
				}
				time.Sleep(time.Millisecond)
			}
			b := h.b
			b.SlotID = strings.Repeat("f", 64)
			client := Client{SocketPath: path, ServerUID: uid}
			call, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			cred, e := client.Prepare(call, b)
			if !allowed {
				if e == nil {
					t.Fatal("wrong Unix peer accepted")
				}
				if _, e = h.s.Status(b.SlotID); e == nil {
					t.Fatal("wrong Unix peer wrote registry")
				}
				return
			}
			if e != nil || !cred.Valid() {
				t.Fatal("Unix prepare refused", e)
			}
			again, e := client.Prepare(call, b)
			if e != nil || again != cred {
				t.Fatal("Unix retry reminted credential")
			}
			if e = client.Activate(call, b); e != nil {
				t.Fatal(e)
			}
			if h.sendAs(request(false), b.SlotID, cred.Bearer).Code != 200 {
				t.Fatal("Unix activation not usable")
			}
			if e = client.Revoke(call, b); e != nil {
				t.Fatal(e)
			}
			if h.sendAs(request(false), b.SlotID, cred.Bearer).Code != 401 {
				t.Fatal("Unix revoke not effective")
			}
		})
	}
}
