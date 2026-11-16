package chaingateway

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"testing"
	"time"
)

// The maximal fake endpoint must supply authenticatable kernel evidence before
// credentials on every connection. Failure diagnostics contain only fixed local
// kernel-authentication errors, never HTTP bodies, headers or credentials.
func TestKernelEndpointUnderCollectionLoad(t *testing.T) {
	x := makeFixture(t, "cookie")
	x.rpc.flexible = true
	x.c.Names = nil
	x.c.Seals = nil
	for i := 0; i < 16; i++ {
		x.c.Names = append(x.c.Names, fmt.Sprintf("id/example-%02d", i))
	}
	for i := 0; i < 256; i++ {
		x.c.Seals = append(x.c.Seals, Outpoint{x.c.Genesis, uint32(i)})
	}
	// The fake fixture uses one fixed txid; retain that same binding.
	for i := range x.c.Seals {
		x.c.Seals[i].Txid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	}
	r, e := newRPC(x.c, x.p)
	if e != nil {
		t.Fatal("kernel startup evidence:", e)
	}
	defer r.client.CloseIdleConnections()
	transport := r.client.Transport.(*http.Transport)
	dial := transport.DialContext
	failures := make(chan error, 64)
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, e := dial(ctx, network, address)
		if e != nil {
			select {
			case failures <- e:
			default:
			}
		}
		return conn, e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	at, e := r.tip(ctx, x.c.Network)
	if e != nil {
		t.Fatal("kernel tip evidence:", e)
	}
	for attempt := 0; attempt < 3; attempt++ {
		if _, _, e = r.collect(ctx, x.c, at); e != nil {
			for len(failures) > 0 {
				t.Log("kernel dial evidence:", <-failures)
			}
			t.Fatal("kernel collection evidence:", e)
		}
	}
}

// Unaccepted connections are incomplete evidence even when the kernel reports
// UID zero and the configured node UID is zero. Only a real accepted inode can
// authenticate that account; wrong attached owners remain immediate refusals.
func TestUnacceptedPeerIsNotRootOwnership(t *testing.T) {
	server := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}
	client := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4321}
	rows := []socketEvidence{{state: 10, local: server.IP, localPort: 1234, uid: 0}, {state: 1, local: server.IP, remote: client.IP, localPort: 1234, remotePort: 4321, uid: 0, cookie: [8]byte{1}}}
	if e := verifySocketRows(rows, server, client, 0); e != errPeerNotAccepted {
		t.Fatalf("unaccepted UID zero authenticated: %v", e)
	}
	rows[1].inode = 1
	if e := verifySocketRows(rows, server, client, 0); e != nil {
		t.Fatalf("accepted root control: %v", e)
	}
	rows[1].uid = 1
	if e := verifySocketRows(rows, server, client, 0); e == nil || e == errPeerNotAccepted {
		t.Fatalf("attached wrong UID was not immediately refused: %v", e)
	}
}

// Authentication waits for a delayed accept within its original deadline and
// sends zero application bytes. A listener that never accepts times out closed.
func TestAuthenticateWaitsForAcceptedInode(t *testing.T) {
	for _, accept := range []bool{true, false} {
		t.Run(fmt.Sprint(accept), func(t *testing.T) {
			listener, e := net.Listen("tcp4", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			defer listener.Close()
			received := make(chan int, 1)
			if accept {
				go func() {
					time.Sleep(75 * time.Millisecond)
					conn, e := listener.Accept()
					if e != nil {
						received <- -1
						return
					}
					defer conn.Close()
					conn.SetReadDeadline(time.Now().Add(time.Second))
					data, _ := io.ReadAll(conn)
					received <- len(data)
				}()
			}
			ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
			defer cancel()
			start := time.Now()
			conn, e := authenticatedDial(ctx, "tcp4", listener.Addr().String(), uint32(os.Getuid()))
			if accept {
				if e != nil {
					t.Fatal("accepted owner unavailable:", e)
				}
				conn.Close()
				if elapsed := time.Since(start); elapsed < 75*time.Millisecond {
					t.Fatalf("authenticated before accept: %s", elapsed)
				}
				if n := <-received; n != 0 {
					t.Fatalf("pre-auth application bytes: %d", n)
				}
			} else {
				if conn != nil || e == nil {
					if conn != nil {
						conn.Close()
					}
					t.Fatal("unaccepted endpoint authenticated")
				}
				if elapsed := time.Since(start); elapsed < 250*time.Millisecond || elapsed > time.Second {
					t.Fatalf("accept deadline %s", elapsed)
				}
			}
		})
	}
}
