package chaingateway

import (
	"context"
	"fmt"
	"net"
	"net/http"
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
