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

// During an active durable Starting attempt, real TLS/HMAC admission accepts
// the correct credential and refuses a wrong one; admission also works Started.
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
	hello := func(credential []byte) *stationlink.Frame {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		conn, e := lifecycle.DialPayload(ctx, listener.Addr().String(), p.serverPin, roots)
		checked(t, e, "ordering payload dial")
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		frame, e := stationlink.NewClient(conn).Hello(id, name, credential)
		checked(t, e, "ordering Hello")
		return frame
	}
	driver.start = func() error {
		s, ok := store.Get(id)
		if !ok || s.Started || !s.Starting || s.ChannelSecretHex == "" {
			t.Fatal("ordering precondition")
		}
		if frame := hello(secret); frame.Type != stationlink.TypeSystem {
			t.Fatal("active Starting Hello was not admitted")
		}
		if frame := hello([]byte(strings.Repeat("y", 32))); frame.Type != stationlink.TypeError || frame.Reason != "authentication failed" {
			t.Fatal("active Starting accepted wrong credential")
		}
		return nil
	}
	checked(t, g.StartSlot(context.Background(), id), "ordering native start")
	if frame := hello(secret); frame.Type != stationlink.TypeSystem {
		t.Fatal("post-start Hello positive control refused")
	}
	t.Log("witness: active Starting admits correct TLS/HMAC credential, refuses wrong credential, and identical credential authenticates after start")
}
