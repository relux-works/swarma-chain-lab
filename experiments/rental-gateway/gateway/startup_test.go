package gateway_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"net/http/httptest"
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
)

type startupDriver struct {
	secret    []byte
	start     func() error
	destroyed int
	destroy   func() error
}

func (d *startupDriver) Create(_ context.Context, s station.SlotSpec) (*station.Station, error) {
	return &station.Station{SlotID: s.SlotID, StationName: s.StationName, ChannelSecret: d.secret}, nil
}
func (d *startupDriver) StartSession(context.Context, *station.Station, station.SessionInfo) error {
	return d.start()
}
func (d *startupDriver) End(context.Context, *station.Station, string) error { return nil }
func (d *startupDriver) Destroy(context.Context, *station.Station) (station.DestroyReport, error) {
	d.destroyed++
	if d.destroy != nil {
		return station.DestroyReport{}, d.destroy()
	}
	return station.DestroyReport{}, nil
}
func (d *startupDriver) Reattach(ctx context.Context, s station.SlotSpec) (*station.Station, error) {
	return d.Create(ctx, s)
}

type startupFixture struct {
	g      *gateway.Gateway
	store  *journal.Store
	dir    string
	d      *startupDriver
	pub    *collectPublisher
	renter *nostr.PrivKey
	config gateway.Config
	dial   func() net.Conn
}

func newStartupFixture(t *testing.T) *startupFixture {
	t.Helper()
	f := &startupFixture{dir: t.TempDir(), d: &startupDriver{secret: randomSecret(t)}, pub: &collectPublisher{}}
	var err error
	f.store, err = journal.Open(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	agent, _ := nostr.GeneratePrivKey()
	renter, _ := nostr.GeneratePrivKey()
	f.renter = renter
	f.config = gateway.Config{AgentKey: agent, Kernel: &kernel.Stub{Verdict: kernel.Live}, Screener: &screen.Stub{}, Journal: f.store, Publisher: f.pub, Driver: f.d, Now: func() time.Time { return time.Unix(nowMid, 0) }}
	f.g, err = gateway.New(f.config)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.g.RegisterSlot(gateway.SlotSpec{ID: "startup", StationName: "id/startup", RenterPubKey: renter.PubKeyHex(), Certificate: []byte("explicit kernel stub"), ContractSHA256: strings.Repeat("c", 64), NotBefore: slotNotBefore, NotAfter: slotNotAfter}); err != nil {
		t.Fatal(err)
	}
	// Reuse a standard-library test certificate, then serve stationlink over TLS.
	certServer := httptest.NewTLSServer(nil)
	serverTLS := certServer.TLS.Clone()
	roots := x509.NewCertPool()
	roots.AddCert(certServer.Certificate())
	certServer.Close()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); _ = f.g.ServeStations(ln) }()
	t.Cleanup(func() { ln.Close(); <-done })
	f.dial = func() net.Conn {
		t.Helper()
		c, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", ln.Addr().String(), &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13})
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		t.Cleanup(func() { c.Close() })
		return c
	}
	return f
}

// Ports the rehearsal ordering witness: actual TLS/HMAC Hello completes while
// StartSession is on the stack. Explicit kernel/driver stubs isolate scheduling;
// this is not a Core, process-launch, or model-call integration claim.
func TestStartupOrdering(t *testing.T) {
	f := newStartupFixture(t)
	var conn net.Conn
	f.d.start = func() error {
		s, _ := f.store.Get("startup")
		if s.Started || s.ChannelSecretHex == "" {
			t.Fatal("ordering precondition")
		}
		reopened, err := journal.Open(f.dir)
		if err != nil {
			t.Fatal(err)
		}
		durable, _ := reopened.Get("startup")
		if !durable.Starting || durable.Started {
			t.Fatal("launch intent not durable before driver")
		}
		conn = f.dial()
		if got := manualHello(t, conn, "startup", "id/startup", f.d.secret); got.Type != stationlink.TypeSystem {
			t.Fatalf("early Hello refused: %+v", got)
		}
		assertStartupRequestGated(t, conn)
		if f.pub.count() != 0 {
			t.Fatal("application effect before promotion")
		}
		return nil
	}
	if err := f.g.StartSlot(context.Background(), "startup"); err != nil {
		t.Fatal(err)
	}
	s, _ := f.store.Get("startup")
	if got, err := stationlink.ReadFrame(conn); err != nil || got.Type != stationlink.TypeAck {
		t.Fatalf("first request after promotion: %+v %v", got, err)
	}
	if !s.Started || s.Starting || s.Ended || f.d.destroyed != 0 || f.pub.count() != 2 {
		t.Fatal("successful start not promoted")
	}
}

// A bounded read deadline establishes absence of an application response while
// the driver is deliberately held on its stack. This is not a launch delay or
// reconnect: the same connection/request must resume after durable promotion.
func assertStartupRequestGated(t *testing.T, c net.Conn) {
	t.Helper()
	if err := stationlink.WriteFrame(c, &stationlink.Frame{Type: stationlink.TypeReply, SlotID: "foreign", Content: "early application request"}); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	got, err := stationlink.ReadFrame(c)
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("application escaped starting barrier: %+v %v", got, err)
	}
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
}

// Failed launches must close an already authenticated channel, suppress its
// pending application request, and destroy even with a cancelled caller or an
// unwritable journal. The publisher is the upstream effect boundary here; no
// model implementation is involved, so model integration is tested separately.
func TestStartupFailure(t *testing.T) {
	for _, mode := range []string{"driver", "promotion", "cancelled", "all_writes", "destroy_pending"} {
		t.Run(mode, func(t *testing.T) {
			f := newStartupFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var conn net.Conn
			failure := errors.New("injected start failure")
			f.d.start = func() error {
				conn = f.dial()
				if got := manualHello(t, conn, "startup", "id/startup", f.d.secret); got.Type != stationlink.TypeSystem {
					t.Fatal("early handshake failed")
				}
				assertStartupRequestGated(t, conn)
				if mode == "promotion" || mode == "all_writes" {
					if err := os.Chmod(f.dir, 0500); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = os.Chmod(f.dir, 0700) })
					if mode == "promotion" {
						f.d.destroy = func() error { return os.Chmod(f.dir, 0700) }
					}
					return nil
				}
				if mode == "cancelled" {
					cancel()
				}
				if mode == "destroy_pending" {
					f.d.destroy = func() error { return station.ErrCleanupPending }
				}
				return failure
			}
			err := f.g.StartSlot(ctx, "startup")
			if err == nil {
				t.Fatal("failed start reported success")
			}
			if mode == "destroy_pending" && !errors.Is(err, station.ErrCleanupPending) {
				t.Fatal("cleanup uncertainty lost")
			}
			assertStartupClosed(t, conn, "failed start channel not closed")
			s, _ := f.store.Get("startup")
			if s.Started || f.d.destroyed != 1 || f.pub.count() != 0 || len(s.SeenRumorIDs) != 0 {
				t.Fatal("failed start escaped cleanup/effect boundary")
			}
			if mode != "all_writes" && (!s.Ended || s.ChannelSecretHex != "") {
				t.Fatal("failed start retained admission")
			}
			if mode != "all_writes" && mode != "destroy_pending" && (!s.Destroyed || s.Starting) {
				t.Fatal("successful destruction not recorded")
			}
			if got := manualHello(t, f.dial(), "startup", "id/startup", f.d.secret); got.Type == stationlink.TypeSystem || got.Type == stationlink.TypeChallenge {
				t.Fatal("failed launch readmitted")
			}
		})
	}
}

// Starting does not relax identity/HMAC/credential/single-binding checks; a
// valid neighbor authenticates after each nonterminal rejection. Terminal
// cases retain their exact Error/End response and never promote afterwards.
func TestStartupAdmissionGuards(t *testing.T) {
	for _, mode := range []string{"unknown", "wrong_name", "wrong_secret", "no_credential", "second_bind", "ended", "destroyed"} {
		t.Run(mode, func(t *testing.T) {
			f := newStartupFixture(t)
			f.d.start = func() error {
				id, name, secret := "startup", "id/startup", f.d.secret
				wantType, wantReason := stationlink.TypeError, ""
				switch mode {
				case "unknown":
					id = "unknown"
					wantReason = "unknown slot"
				case "wrong_name":
					name = "id/foreign"
					wantReason = "station name mismatch"
				case "wrong_secret":
					secret = randomSecret(t)
					wantReason = "authentication failed"
				case "no_credential":
					if err := f.store.SetChannelSecret(id, "", ""); err != nil {
						t.Fatal(err)
					}
					wantReason = "no channel credential registered"
				case "second_bind":
					if got := manualHello(t, f.dial(), id, name, secret); got.Type != stationlink.TypeSystem {
						t.Fatal("valid neighbor failed")
					}
					wantReason = "slot already bound"
				case "ended":
					if err := f.store.MarkEnded(id, "closed"); err != nil {
						t.Fatal(err)
					}
					wantType = stationlink.TypeEnd
					wantReason = "closed"
				case "destroyed":
					if err := f.store.MarkDestroyed(id); err != nil {
						t.Fatal(err)
					}
					wantReason = "station destroyed"
				}
				got := manualHello(t, f.dial(), id, name, secret)
				if got.Type != wantType || got.Reason != wantReason {
					t.Fatalf("startup admission guard %s: %+v", mode, got)
				}
				if mode == "no_credential" {
					if err := f.store.SetChannelSecret("startup", hex.EncodeToString(f.d.secret), ""); err != nil {
						t.Fatal(err)
					}
				}
				if mode != "ended" && mode != "destroyed" && mode != "second_bind" {
					if got := manualHello(t, f.dial(), "startup", "id/startup", f.d.secret); got.Type != stationlink.TypeSystem {
						t.Fatal("valid neighbor failed")
					}
				}
				return nil
			}
			err := f.g.StartSlot(context.Background(), "startup")
			if (mode == "ended" || mode == "destroyed") != (err != nil) {
				t.Fatalf("terminal promotion guard: %v", err)
			}
		})
	}
}

func directStartupConn(t *testing.T, g *gateway.Gateway) net.Conn {
	t.Helper()
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() { defer close(done); g.HandleStationConn(server) }()
	t.Cleanup(func() { client.Close(); <-done })
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	return client
}

// A durable orphan cannot authenticate or be relaunched by StartSlot. Recovery
// reattaches and destroys exactly once; uncertain cleanup stays denied and the
// recorded operation resumes on the next recovery call without starting payload.
func TestStartupRecovery(t *testing.T) {
	f := newStartupFixture(t)
	if err := f.store.SetChannelSecret("startup", hex.EncodeToString(f.d.secret), ""); err != nil {
		t.Fatal(err)
	}
	if err := f.store.MarkStarting("startup"); err != nil {
		t.Fatal(err)
	}
	reopened, err := journal.Open(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := f.config
	cfg.Journal = reopened
	g, err := gateway.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got := manualHello(t, directStartupConn(t, g), "startup", "id/startup", f.d.secret); got.Type != stationlink.TypeError || got.Reason != "session not started" {
		t.Fatal("orphan start admitted")
	}
	if err := g.StartSlot(context.Background(), "startup"); err == nil {
		t.Fatal("orphan start replayed")
	}
	if _, _, err := reopened.BeginOperation("startup", journal.OpDestroy, "closer-owned", "destroyed", nowMid); err != nil {
		t.Fatal(err)
	}
	f.d.destroy = func() error { return station.ErrCleanupPending }
	if err := g.RecoverStarting(context.Background()); !errors.Is(err, gateway.ErrOperationUncertain) {
		t.Fatalf("recovery uncertainty: %v", err)
	}
	s, _ := reopened.Get("startup")
	if !s.Starting || !s.Ended || s.Destroyed || s.ChannelSecretHex != "" {
		t.Fatal("uncertain recovery lost intent/admission denial")
	}
	f.d.destroy = nil
	if err := g.RecoverStarting(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := g.RecoverStarting(context.Background()); err != nil {
		t.Fatal(err)
	}
	s, _ = reopened.Get("startup")
	if s.Starting || s.Started || !s.Destroyed || f.d.destroyed != 2 {
		t.Fatal("recovery did not destroy exactly once after uncertainty")
	}
	if got := manualHello(t, directStartupConn(t, g), "startup", "id/startup", f.d.secret); got.Type != stationlink.TypeError || got.Reason != "station destroyed" {
		t.Fatal("recovered start admitted")
	}
}

// A challenge cannot outlive its failed attempt, including when no journal
// invalidation can be written. Auth must recheck the live attempt, not just HMAC.
func TestStartupStaleChallenge(t *testing.T) {
	f := newStartupFixture(t)
	var conn net.Conn
	var challenge *stationlink.Frame
	f.d.start = func() error {
		conn = f.dial()
		if err := stationlink.WriteFrame(conn, &stationlink.Frame{Type: stationlink.TypeHello, SlotID: "startup", StationName: "id/startup"}); err != nil {
			t.Fatal(err)
		}
		var err error
		challenge, err = stationlink.ReadFrame(conn)
		if err != nil || challenge.Type != stationlink.TypeChallenge {
			t.Fatal("challenge failed")
		}
		if err = os.Chmod(f.dir, 0500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(f.dir, 0700) })
		return errors.New("injected failure")
	}
	if err := f.g.StartSlot(context.Background(), "startup"); err == nil {
		t.Fatal("failed start succeeded")
	}
	response, err := stationlink.ComputeResponse(f.d.secret, challenge.Nonce, "startup", "id/startup")
	if err != nil {
		t.Fatal(err)
	}
	if err = stationlink.WriteFrame(conn, &stationlink.Frame{Type: stationlink.TypeAuth, SlotID: "startup", StationName: "id/startup", Response: response}); err != nil {
		t.Fatal(err)
	}
	got, err := stationlink.ReadFrame(conn)
	if err != nil || got.Type != stationlink.TypeError || got.Reason != "authentication failed" {
		t.Fatalf("stale challenge admitted: %+v %v", got, err)
	}
}

// Before a live kernel verdict the credential alone cannot start or admit a
// station. The valid live neighbor is exercised by TestStartupOrdering.
func TestStartupPreGrant(t *testing.T) {
	f := newStartupFixture(t)
	if err := f.store.SetChannelSecret("startup", hex.EncodeToString(f.d.secret), ""); err != nil {
		t.Fatal(err)
	}
	if got := manualHello(t, f.dial(), "startup", "id/startup", f.d.secret); got.Type != stationlink.TypeError || got.Reason != "session not started" {
		t.Fatal("never-started slot admitted")
	}
	f.config.Kernel.(*kernel.Stub).Verdict = kernel.Pending
	f.d.start = func() error { t.Fatal("pending grant launched"); return nil }
	if err := f.g.StartSlot(context.Background(), "startup"); err == nil {
		t.Fatal("pending grant admitted")
	}
	if got := manualHello(t, f.dial(), "startup", "id/startup", f.d.secret); got.Type != stationlink.TypeError || got.Reason != "session not started" {
		t.Fatal("pre-grant slot admitted")
	}
}

// Two challenges may be issued before either binds. Auth must still claim the
// slot atomically: only the first valid response receives System.
func TestStartupPendingBindings(t *testing.T) {
	f := newStartupFixture(t)
	f.d.start = func() error {
		connections := []net.Conn{f.dial(), f.dial()}
		responses := make([]string, 2)
		for i, c := range connections {
			if err := stationlink.WriteFrame(c, &stationlink.Frame{Type: stationlink.TypeHello, SlotID: "startup", StationName: "id/startup"}); err != nil {
				t.Fatal(err)
			}
			ch, err := stationlink.ReadFrame(c)
			if err != nil || ch.Type != stationlink.TypeChallenge {
				t.Fatal("parallel challenge failed")
			}
			responses[i], err = stationlink.ComputeResponse(f.d.secret, ch.Nonce, "startup", "id/startup")
			if err != nil {
				t.Fatal(err)
			}
		}
		for i, c := range connections {
			if err := stationlink.WriteFrame(c, &stationlink.Frame{Type: stationlink.TypeAuth, SlotID: "startup", StationName: "id/startup", Response: responses[i]}); err != nil {
				t.Fatal(err)
			}
			got, err := stationlink.ReadFrame(c)
			if err != nil {
				t.Fatal(err)
			}
			if i == 0 && got.Type != stationlink.TypeSystem {
				t.Fatal("first binding refused")
			}
			if i == 1 && (got.Type != stationlink.TypeError || got.Reason != "slot already bound") {
				t.Fatal("second pending binding admitted")
			}
		}
		return nil
	}
	if err := f.g.StartSlot(context.Background(), "startup"); err != nil {
		t.Fatal(err)
	}
}

// A queued message for another started slot cannot escape through an early
// Pull with a forged SlotID. Failure closes that Pull without a delivery/model
// trigger; success releases only the authenticated slot's later message. Both
// use the actual gateway queues; no model API is called in this transport test.
func TestStartupPullIsolation(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "promoted", true: "failed"}[fail], func(t *testing.T) {
			f := newStartupFixture(t)
			other, _ := nostr.GeneratePrivKey()
			if err := f.g.RegisterSlot(gateway.SlotSpec{ID: "other", StationName: "id/other", RenterPubKey: other.PubKeyHex(), Certificate: []byte("stub"), NotBefore: slotNotBefore, NotAfter: slotNotAfter}); err != nil {
				t.Fatal(err)
			}
			f.d.start = func() error { return nil }
			if err := f.g.StartSlot(context.Background(), "other"); err != nil {
				t.Fatal(err)
			}
			wrap, _, err := nostr.WrapDM(other, f.config.AgentKey.PubKeyHex(), "other-slot message", nil, nowMid)
			if err != nil {
				t.Fatal(err)
			}
			if res := f.g.HandleGiftWrap(context.Background(), wrap); !res.Delivered {
				t.Fatal(res)
			}
			var conn net.Conn
			f.d.start = func() error {
				conn = f.dial()
				if got := manualHello(t, conn, "startup", "id/startup", f.d.secret); got.Type != stationlink.TypeSystem {
					t.Fatal("early Hello failed")
				}
				if err := stationlink.WriteFrame(conn, &stationlink.Frame{Type: stationlink.TypePull, SlotID: "other"}); err != nil {
					t.Fatal(err)
				}
				_ = conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
				got, err := stationlink.ReadFrame(conn)
				var timeout net.Error
				if !errors.As(err, &timeout) || !timeout.Timeout() {
					t.Fatalf("starting Pull leaked delivery: %+v %v", got, err)
				}
				_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
				if fail {
					return errors.New("injected failure")
				}
				return nil
			}
			wrap, _, err = nostr.WrapDM(f.renter, f.config.AgentKey.PubKeyHex(), "own-slot message", nil, nowMid)
			if err != nil {
				t.Fatal(err)
			}
			res := f.g.HandleGiftWrap(context.Background(), wrap)
			if fail {
				if !res.Refused || res.Reason != "station_start_failed" || res.Delivered {
					t.Fatalf("failed launch delivered inbound: %+v", res)
				}
				assertStartupClosed(t, conn, "failed Pull not closed without model trigger")
				s, _ := f.store.Get("startup")
				if len(s.SeenRumorIDs) != 0 || f.config.Screener.(*screen.Stub).Calls != 1 || f.pub.count() != 1 {
					t.Fatal("failed launch called screening/upstream or recorded rumor")
				}
			} else {
				if !res.Delivered {
					t.Fatal(res)
				}
				got, err := stationlink.ReadFrame(conn)
				if err != nil || got.Type != stationlink.TypeDeliver || got.SlotID != "startup" || got.Content != "own-slot message" {
					t.Fatalf("promoted Pull crossed slots: %+v %v", got, err)
				}
			}
			otherConn := f.dial()
			if got := manualHello(t, otherConn, "other", "id/other", f.d.secret); got.Type != stationlink.TypeSystem {
				t.Fatal("other-slot binding damaged")
			}
			if err := stationlink.WriteFrame(otherConn, &stationlink.Frame{Type: stationlink.TypePull}); err != nil {
				t.Fatal(err)
			}
			got, err := stationlink.ReadFrame(otherConn)
			if err != nil || got.Content != "other-slot message" || got.SlotID != "other" {
				t.Fatal("other-slot queue consumed by starting peer")
			}
		})
	}
}

// Abort may race a fixed Error/End response already being written. Neither is
// an application effect; after at most that one rejection the transport closes.
func assertStartupClosed(t *testing.T, c net.Conn, witness string) {
	t.Helper()
	got, err := stationlink.ReadFrame(c)
	if err == nil && (got.Type == stationlink.TypeError || got.Type == stationlink.TypeEnd) {
		got, err = stationlink.ReadFrame(c)
	}
	var timeout net.Error
	if err == nil || (errors.As(err, &timeout) && timeout.Timeout()) {
		t.Fatalf("%s: %+v %v", witness, got, err)
	}
}
