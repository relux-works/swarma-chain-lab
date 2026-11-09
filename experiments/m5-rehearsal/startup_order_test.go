package rehearsal

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"os"
	"strings"
	"testing"
	"time"

	"relux.works/swarma-chain-lab/experiments/rental-gateway/gateway"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/journal"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/kernel"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/nostr"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/screen"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/station"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/stationlink"
	lifecycle "relux.works/swarma-chain-lab/experiments/station-lifecycle"
	"relux.works/swarma-chain-lab/experiments/station-lifecycle/gatewaybind"
	payload "relux.works/swarma-chain-lab/experiments/station-payload"
)

type orderingDriver struct {
	secret []byte
	start  func() error
}

func (d *orderingDriver) Create(_ context.Context, s station.SlotSpec) (*station.Station, error) {
	return &station.Station{SlotID: s.SlotID, StationName: s.StationName, ChannelSecret: append([]byte(nil), d.secret...)}, nil
}
func (d *orderingDriver) StartSession(context.Context, *station.Station, station.SessionInfo) error {
	return d.start()
}
func (d *orderingDriver) End(context.Context, *station.Station, string) error { return nil }
func (d *orderingDriver) Destroy(context.Context, *station.Station) (station.DestroyReport, error) {
	return station.DestroyReport{}, nil
}

type orderingPublisher struct{}

func (orderingPublisher) Publish(context.Context, *nostr.Event) error { return nil }

// This is an expected-defect ordering witness, not a passing full rehearsal.
// While StartSession is still running, real gateway TLS/HMAC admission rejects
// Hello as "session not started" and real PL1 Run terminates with ErrChannel.
// After StartSession returns, the same credential gets a System handshake.
// Kernel/driver/publisher are explicit stubs; this does not prove Core admission.
func TestStartupOrderingWitness(t *testing.T) {
	root := t.TempDir()
	l := &lab{t: t, private: root}
	p := l.tlsFiles()
	pair, e := tls.LoadX509KeyPair(p.server, p.key)
	checked(t, e, "ordering TLS")
	ca, e := os.ReadFile(p.ca)
	checked(t, e, "ordering roots")
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("ordering roots")
	}
	listener, e := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13})
	checked(t, e, "ordering listener")
	defer listener.Close()
	agent, e := nostr.GeneratePrivKey()
	checked(t, e, "ordering agent")
	renter, e := nostr.GeneratePrivKey()
	checked(t, e, "ordering renter")
	store, e := journal.Open(l.dir("journal"))
	checked(t, e, "ordering journal")
	id := strings.Repeat("b", 64)
	name := "id/ordering-station"
	secret := []byte(strings.Repeat("x", 32))
	driver := &orderingDriver{secret: secret}
	g, e := gateway.New(gateway.Config{AgentKey: agent, Kernel: &kernel.Stub{Verdict: kernel.Live}, Screener: &screen.Stub{}, Journal: store, Publisher: orderingPublisher{}, Driver: driver, Now: func() time.Time { return time.Unix(1000, 0) }})
	checked(t, e, "ordering gateway")
	checked(t, g.RegisterSlot(gateway.SlotSpec{ID: id, StationName: name, RenterPubKey: renter.PubKeyHex(), Certificate: []byte("explicit kernel stub fixture"), ContractSHA256: strings.Repeat("c", 64), BookingID: id, NotBefore: 900, NotAfter: 1200}), "ordering slot")
	serverDone := make(chan error, 1)
	go func() { serverDone <- g.ServeStations(listener) }()
	defer func() {
		listener.Close()
		select {
		case <-serverDone:
		case <-time.After(time.Second):
			t.Error("ordering server did not stop")
		}
	}()
	hello := func() *stationlink.Frame {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		conn, e := lifecycle.DialPayload(ctx, listener.Addr().String(), p.serverPin, roots)
		checked(t, e, "ordering payload dial")
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		frame, e := stationlink.NewClient(conn).Hello(id, name, secret)
		checked(t, e, "ordering Hello")
		return frame
	}
	driver.start = func() error {
		s, ok := store.Get(id)
		if !ok || s.Started || s.ChannelSecretHex == "" {
			t.Fatal("ordering precondition")
		}
		frame := hello()
		if frame.Type != stationlink.TypeError || frame.Reason != "session not started" {
			t.Fatal("pre-start Hello was not refused at the exact gate")
		}
		bootstrap, e := gatewaybind.EncodeBootstrap(gatewaybind.PayloadBootstrap{V: 1, BookingID: id, StationName: name, ChannelSecret: lifecycle.Secret(secret)})
		checked(t, e, "ordering bootstrap")
		client, e := payload.New(bootstrap, payload.Options{})
		checked(t, e, "ordering payload")
		defer client.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if e = client.Run(ctx, listener.Addr().String(), p.serverPin, roots); e != payload.ErrChannel {
			t.Fatal("pre-start PL1 Run did not terminate with PAYLOAD_CHANNEL")
		}
		return nil
	}
	checked(t, g.StartSlot(context.Background(), id), "ordering native start")
	if frame := hello(); frame.Type != stationlink.TypeSystem {
		t.Fatal("post-start Hello positive control refused")
	}
	t.Log("witness: pre-return Hello=session not started and PL1 Run=PAYLOAD_CHANNEL; identical post-return credential authenticates")
}
