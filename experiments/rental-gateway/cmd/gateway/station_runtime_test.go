package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/gateway"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/journal"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernel"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/screen"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/stationlink"
	lifecycle "github.com/relux-works/swarma-chain-lab/experiments/station-lifecycle"
	"github.com/relux-works/swarma-chain-lab/experiments/station-lifecycle/gatewaybind"
)

func vacantAddress(t *testing.T) string {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	s := l.Addr().String()
	l.Close()
	return s
}

func remoteFixture(t *testing.T) (serveConfig, *journal.Store, *tls.Config, *tls.Config, tls.Certificate, *x509.CertPool, *testCA) {
	t.Helper()
	c := remoteConfig(t)
	m := c.Station.Manager
	m.Listen = vacantAddress(t)
	for {
		m.PayloadListen = vacantAddress(t)
		if m.PayloadListen != m.Listen {
			break
		}
	}
	ca := newTestCA(t)
	server, cert, key := ca.leaf(t, 2, false, false)
	manager, _, _ := ca.leaf(t, 3, true, false)
	for _, f := range []struct {
		path string
		raw  []byte
		mode os.FileMode
	}{{m.TLS.CertFile, cert, 0644}, {m.TLS.KeyFile, key, 0400}, {m.TLS.ManagerCAFile, ca.pem, 0644}} {
		if e := os.WriteFile(f.path, f.raw, 0640); e != nil {
			t.Fatal(e)
		}
	}
	m.TLS.CertSHA256 = certPin(server)
	m.TLS.ManagerCertSHA256 = certPin(manager)
	mtls, ptls, e := gatewayTLS(m.TLS)
	if e != nil {
		t.Fatal(e)
	}
	if e = privateDir(m.StateDir); e != nil {
		t.Fatal(e)
	}
	j, e := journal.Open(c.JournalDir)
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca.pem)
	return c, j, mtls, ptls, manager, roots, ca
}

type remotePublisher struct{}

func (remotePublisher) Publish(context.Context, *nostr.Event) error { return nil }

// Remote TLS input refusal precedes agent-key reads, state creation and network
// effects; the valid TLS/remote constructor neighbour is exercised below.
func TestRemoteTLSBeforeEffects(t *testing.T) {
	c := remoteConfig(t)
	if e := serve(context.Background(), c); e == nil || e.Error() != "DK5_FILE_OPEN" {
		t.Fatal("remote TLS preflight missing", e)
	}
	entries, e := os.ReadDir(strings.TrimSuffix(c.AgentKeyFile, "/agent.key"))
	if e != nil || len(entries) != 0 {
		t.Fatal("TLS refusal caused state effects")
	}
}

// The actual serve constructor composes manager mTLS, the real durable broker
// and payload TLS/HMAC. The authenticated manager's reports are simulated here;
// a stub kernel limits this to wiring, not real grants or Linux helper execution.
func TestRemoteStationTransport(t *testing.T) {
	c, j, mtls, ptls, manager, roots, ca := remoteFixture(t)
	r, e := newStationRuntime(c, j, mtls, ptls)
	if e != nil {
		t.Fatal(e)
	}
	if _, ok := r.driver.(*gatewaybind.Driver); !ok {
		t.Fatal("remote driver not constructed")
	}
	defer r.close()
	key, _ := nostr.GeneratePrivKey()
	renter, _ := nostr.GeneratePrivKey()
	g, e := gateway.New(gateway.Config{AgentKey: key, Kernel: &kernel.Stub{Verdict: kernel.Live}, Screener: screen.Off{}, Publisher: remotePublisher{}, Journal: j, Driver: r.driver, Endpoint: r.endpoint, PullTimeout: 50 * time.Millisecond})
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 2)
	go func() { done <- r.manager.Serve(r.managerListener) }()
	go func() { done <- g.ServeStations(r.payload) }()
	defer func() {
		r.closeTransports()
		for i := 0; i < 2; i++ {
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("listener did not stop")
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	endpoint := "https://" + c.Station.Manager.Listen + lifecycle.PollPath
	client, e := lifecycle.NewPollClient(endpoint, manager, roots, c.Station.Manager.TLS.CertSHA256)
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	if p, e := client.Poll(ctx, nil); e != nil || len(p.Commands) != 0 {
		t.Fatal("valid manager poll refused", e)
	}
	sibling, _, _ := ca.leaf(t, 4, true, false)
	wrong, e := lifecycle.NewPollClient(endpoint, sibling, roots, c.Station.Manager.TLS.CertSHA256)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = wrong.Poll(ctx, nil); e == nil {
		t.Fatal("wrong manager pin accepted")
	}
	wrong.Close()
	if conn, e := lifecycle.DialPayload(ctx, r.endpoint, strings.Repeat("0", 64), roots); e == nil {
		conn.Close()
		t.Fatal("wrong payload server pin accepted")
	}
	id := strings.Repeat("b", 64)
	now := time.Now().Unix()
	raw := []byte(`{"signed_grant":{"grant":{"version":3},"signature":"` + strings.Repeat("0", 128) + `"},"issuance":{"txid":"` + strings.Repeat("0", 64) + `"}}`)
	if e = g.RegisterSlot(gateway.SlotSpec{ID: id, BookingID: id, StationName: "id/remote-fixture", RenterPubKey: renter.PubKeyHex(), Certificate: raw, ContractSHA256: strings.Repeat("d", 64), NotBefore: now - 1, NotAfter: now + 180}); e != nil {
		t.Fatal(e)
	}
	started := make(chan error, 1)
	go func() { started <- g.StartSlot(ctx, id) }()
	var command lifecycle.Command
	for command.Op == "" {
		p, e := client.Poll(ctx, nil)
		if e != nil {
			t.Fatal(e)
		}
		if len(p.Commands) > 0 {
			command = p.Commands[0]
			break
		}
		select {
		case e := <-started:
			t.Fatal("start did not wait for manager", e)
		case <-time.After(5 * time.Millisecond):
		}
	}
	b, e := gatewaybind.DecodeBootstrap(command.Slot.Bootstrap)
	if e != nil || b.BookingID != id {
		t.Fatal("invalid private bootstrap")
	}
	if _, e = client.Poll(ctx, []lifecycle.Status{{SlotID: command.Slot.ID, Binding: command.Binding, Phase: "running", NotAfter: command.Slot.NotAfter}}); e != nil {
		t.Fatal(e)
	}
	if e = <-started; e != nil {
		t.Fatal("manager running did not start gateway", e)
	}
	connect := func(secret []byte) *stationlink.Frame {
		t.Helper()
		conn, e := lifecycle.DialPayload(ctx, r.endpoint, c.Station.Manager.TLS.CertSHA256, roots)
		if e != nil {
			t.Fatal(e)
		}
		cl := stationlink.NewClient(conn)
		defer cl.Close()
		f, e := cl.Hello(b.BookingID, b.StationName, secret)
		if e != nil {
			t.Fatal(e)
		}
		return f
	}
	if f := connect(make([]byte, 32)); f.Type != stationlink.TypeError {
		t.Fatal("payload wrong credential accepted")
	}
	if f := connect(b.ChannelSecret); f.Type != stationlink.TypeSystem || f.SlotID != id {
		t.Fatal("real payload TLS/HMAC refused")
	}
	// Keep a raw connection idle to exercise shutdown of an incomplete TLS peer.
	idle, e := net.Dial("tcp", r.endpoint)
	if e != nil {
		t.Fatal(e)
	}
	defer idle.Close()
	r.closeTransports()
	_ = idle.SetReadDeadline(time.Now().Add(time.Second))
	var buf [1]byte
	if _, e = idle.Read(buf[:]); e == nil {
		t.Fatal("idle connection survived shutdown")
	} else {
		var timeout net.Error
		if errors.As(e, &timeout) && timeout.Timeout() {
			t.Fatal("shutdown left idle connection open")
		}
	}
}

// A busy second listener closes the first and releases the broker lock; a
// later valid start with the same config/state succeeds without manual cleanup.
func TestRemoteStartupRollback(t *testing.T) {
	c, j, mtls, ptls, _, _, _ := remoteFixture(t)
	busy, e := net.Listen("tcp", c.Station.Manager.Listen)
	if e != nil {
		t.Fatal(e)
	}
	if r, e := newStationRuntime(c, j, mtls, ptls); e == nil {
		r.close()
		busy.Close()
		t.Fatal("busy manager listener accepted")
	}
	probe, e := net.Listen("tcp", c.Station.Manager.PayloadListen)
	if e != nil {
		busy.Close()
		t.Fatal("partial payload listener leaked")
	}
	probe.Close()
	busy.Close()
	r, e := newStationRuntime(c, j, mtls, ptls)
	if e != nil {
		t.Fatal("broker lock or listener leaked", e)
	}
	r.close()
}

// Admission caps hold beside a valid connection; idle reads expire, excess
// peers are closed, and shutdown does not leave an accepting goroutine behind.
func TestRemoteConnectionBounds(t *testing.T) {
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	l := &trackedListener{Listener: ln, conns: map[net.Conn]bool{}, limit: 1, timeout: 100 * time.Millisecond}
	defer l.closeAll()
	a, e := net.Dial("tcp", ln.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	s, e := l.Accept()
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	accepted := make(chan net.Conn, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		conn, e := l.Accept()
		if e == nil {
			accepted <- conn
		}
	}()
	b, e := net.Dial("tcp", ln.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	_ = b.SetReadDeadline(time.Now().Add(time.Second))
	var buf [1]byte
	if _, e = b.Read(buf[:]); e == nil {
		t.Fatal("excess connection admitted")
	} else {
		var timeout net.Error
		if errors.As(e, &timeout) && timeout.Timeout() {
			t.Fatal("excess connection not refused")
		}
	}
	_ = s.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	before := time.Now()
	if _, e = s.Read(buf[:]); e == nil {
		t.Fatal("idle read lacked deadline")
	} else {
		var timeout net.Error
		if !errors.As(e, &timeout) || !timeout.Timeout() {
			t.Fatal("unexpected idle read failure")
		}
	}
	if time.Since(before) > 400*time.Millisecond {
		t.Fatal("idle deadline not enforced")
	}
	s.Close()
	d, e := net.Dial("tcp", ln.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	select {
	case conn := <-accepted:
		conn.Close()
	case <-time.After(time.Second):
		t.Fatal("valid peer after refusal not admitted")
	}
	l.closeAll()
	<-finished
}
