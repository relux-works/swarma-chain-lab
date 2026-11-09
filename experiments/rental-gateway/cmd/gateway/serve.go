package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	booking "github.com/relux-works/swarma-chain-lab/experiments/rental-booking"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/exchange"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/gateway"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/journal"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernel"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernelbind"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernelbind/bookingbind"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/screen"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/station"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

func configArgs(args []string, validate bool) (string, bool, error) {
	fs := flag.NewFlagSet("gateway", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	path := fs.String("config", "", "public configuration JSON")
	var allow *bool
	if validate {
		allow = fs.Bool("allow-test", false, "validate an explicit test-mode config")
	}
	if fs.Parse(args) != nil || fs.NArg() != 0 || *path == "" {
		return "", false, errConfig
	}
	return *path, allow != nil && *allow, nil
}
func runValidate(args []string) error {
	path, allow, e := configArgs(args, true)
	if e != nil {
		return e
	}
	if _, e = loadConfig(path, allow); e != nil {
		return e
	}
	fmt.Println("valid-public-config")
	return nil
}
func runServe(args []string) error {
	path, _, e := configArgs(args, false)
	if e != nil {
		return e
	}
	c, e := loadConfig(path, true)
	if e != nil {
		return e
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return serve(ctx, c)
}

func serve(parent context.Context, c serveConfig) error {
	// Validate before any file containing secrets, state, socket or network effect.
	if e := c.validate(true); e != nil {
		return e
	}
	var managerTLS, payloadTLS *tls.Config
	if c.Station.Driver == "manager" {
		var e error
		managerTLS, payloadTLS, e = gatewayTLS(c.Station.Manager.TLS)
		if e != nil {
			return e
		}
	}
	keyBytes, e := readFile(c.AgentKeyFile, 65, 0600)
	if e != nil {
		return errConfig
	}
	key, e := nostr.PrivKeyFromHex(strings.TrimSpace(string(keyBytes)))
	clear(keyBytes)
	if e != nil || key.PubKeyHex() != c.AgentPubkey {
		return errConfig
	}
	raw, e := readFile(c.Kernel.RPCRouteFile, 4096, 0400)
	if e != nil {
		return errConfig
	}
	var route su.Route
	if booking.Strict(raw, &route) != nil {
		clear(raw)
		return errConfig
	}
	clear(raw)
	if route.Host != c.Kernel.RPCHost || route.Port != c.Kernel.RPCPort {
		return errConfig
	}
	node, e := su.NewRPC(route)
	route.Password = ""
	if e != nil {
		return errConfig
	}
	adapter, e := kernelbind.New(node, c.Kernel.StateDir, c.Kernel.AgentName, c.Kernel.LandlordName, c.Kernel.IssuerPubkey)
	if e != nil {
		return errConfig
	}
	var checker kernel.Checker = adapter
	var presenter kernel.Presenter = adapter
	if c.Kernel.Kind == "stub" {
		checker = &kernel.Stub{Verdict: c.Kernel.StubVerdict}
		presenter = nil
	}
	var screener screen.Screener = screen.Off{}
	if c.Screening == "stub" {
		screener = &screen.Stub{}
	}
	presentations, e := openPresentations(c.Exchange.PresentationsDir)
	if e != nil {
		return e
	}
	defer presentations.Close()
	client := newBookingClient(c.Exchange.BookingURL, c.Exchange.PrivacySHA256, c.Exchange.TemplateSHA256, c.Exchange.ProfileSHA256, time.Duration(c.Exchange.CallMilliseconds)*time.Millisecond)
	defer client.close()
	// Check public booking pins at startup, before creating gateway state.
	var backend exchange.Backend
	if c.Exchange.BookingVersion == 1 {
		if _, e = client.Catalogue(time.Now().Unix()+86400, 16); e != nil {
			return errBooking
		}
		backend = &bookingbind.Adapter{Service: client, AgentName: c.Kernel.AgentName, LandlordName: c.Kernel.LandlordName, AgentPubkey: c.AgentPubkey, Now: time.Now}
	} else {
		v2 := &bookingV2Client{client}
		if _, e = v2.Catalogue(time.Now().Unix()+86400, 16); e != nil {
			return errBooking
		}
		backend = &bookingbind.AdapterV2{ServiceV2: v2, AgentName: c.Kernel.AgentName, LandlordName: c.Kernel.LandlordName, AgentPubkey: c.AgentPubkey, Now: time.Now, PaymentCoins: c.Exchange.PaymentCoins}
	}
	for _, dir := range []string{c.JournalDir, c.Kernel.StateDir, c.Exchange.StateDir, c.stationStateDir()} {
		if e = privateDir(dir); e != nil {
			return e
		}
	}
	eng, e := exchange.New(c.exchangeConfig(backend, bookingbind.Grants{Source: presentations}))
	if e != nil {
		return errors.New("EXCHANGE_STATE")
	}
	defer eng.Close()
	store, e := journal.Open(c.JournalDir)
	if e != nil {
		return errors.New("JOURNAL_STATE")
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	relay := &gateway.RelayClient{URL: c.RelayURL, Auth: c.RelayAuth, AgentKey: key, ReplayLimit: c.RelayReplayLimit, OnStatus: func(s gateway.RelayStatus) { _ = json.NewEncoder(os.Stderr).Encode(s) }}
	defer relay.Close()
	runtime, e := newStationRuntime(c, store, managerTLS, payloadTLS)
	if e != nil {
		return e
	}
	defer runtime.close()
	gw, e := gateway.New(gateway.Config{AgentKey: key, AgentName: c.Kernel.AgentName, Kernel: checker, Presenter: presenter, Screener: screener, Journal: store, Publisher: relay, Driver: runtime.driver, Endpoint: runtime.endpoint, Exchange: eng, PullTimeout: time.Second})
	if e != nil {
		return errors.New("GATEWAY_CONSTRUCTION")
	}
	var workers sync.WaitGroup
	errs := make(chan error, 3)
	defer func() { cancel(); relay.Close(); runtime.closeTransports(); workers.Wait() }()
	if runtime.manager != nil {
		workers.Add(1)
		go func() { defer workers.Done(); errs <- runtime.manager.Serve(runtime.managerListener) }()
	}
	// Remote Destroy needs manager RPC; payload/renter traffic starts only after
	// interrupted launches have been reconciled, without replaying execution.
	recoveryCtx, recoveryCancel := context.WithTimeout(ctx, 30*time.Second)
	e = gw.RecoverStarting(recoveryCtx)
	recoveryCancel()
	if e != nil {
		return errors.New("GATEWAY_START_RECOVERY")
	}
	workers.Add(3)
	go func() { defer workers.Done(); errs <- gw.ServeStations(runtime.payload) }()
	go func() {
		defer workers.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				gw.Tick(ctx)
			}
		}
	}()
	inbound := newInbound(ctx, c.Exchange.QueueSize, func(ctx context.Context, ev *nostr.Event) {
		r := gw.HandleGiftWrap(ctx, ev)
		fmt.Fprintf(os.Stderr, "gateway: inbound delivered=%t refused=%t exchange=%t\n", r.Delivered, r.Refused, r.ExchangeQueued)
	})
	defer inbound.close()
	workers.Go(func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		inbound.reportStatus(os.Stderr, ticker.C)
	})
	fmt.Fprintf(os.Stderr, "gateway: screening=%s mode=%s kernel=%s station=%s pid=%d\n", c.Screening, c.Mode, c.Kernel.Kind, c.Station.Driver, os.Getpid())
	go func() {
		defer workers.Done()
		errs <- relay.RunGiftWraps(ctx, gw.AgentPubKey(), func(ctx context.Context, ev *nostr.Event) {
			inbound.offer(ev)
		})
	}()
	select {
	case <-ctx.Done():
		return nil
	case <-errs:
		if ctx.Err() != nil {
			return nil
		}
		return errors.New("GATEWAY_TRANSPORT")
	}
}
func privateDir(path string) error {
	if !absPath(path) {
		return errConfig
	}
	// Resolve the existing ancestor before creating anything. A symlinked
	// ancestor must not redirect even a rejected directory creation.
	ancestor := path
	for {
		_, e := os.Lstat(ancestor)
		if e == nil {
			break
		}
		if !errors.Is(e, os.ErrNotExist) {
			return errConfig
		}
		ancestor = filepath.Dir(ancestor)
	}
	resolved, e := filepath.EvalSymlinks(ancestor)
	if e != nil || resolved != ancestor {
		return errConfig
	}
	if e := os.MkdirAll(path, 0700); e != nil {
		return errConfig
	}
	st, e := os.Lstat(path)
	if e != nil || !st.IsDir() || st.Mode().Perm() != 0700 {
		return errConfig
	}
	return nil
}

// This test-only wrapper stops only its recorded children on shutdown.
type testDriver struct {
	*station.LocalTestDriver
	mu      sync.Mutex
	started []*station.Station
}

func (d *testDriver) StartSession(ctx context.Context, s *station.Station, i station.SessionInfo) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if e := d.LocalTestDriver.StartSession(ctx, s, i); e != nil {
		return e
	}
	d.started = append(d.started, s)
	if s.PID != 0 {
		fmt.Fprintf(os.Stderr, "gateway: test station pid=%d\n", s.PID)
	}
	return nil
}
func (d *testDriver) End(ctx context.Context, s *station.Station, reason string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.LocalTestDriver.End(ctx, s, reason)
}
func (d *testDriver) Destroy(ctx context.Context, s *station.Station) (station.DestroyReport, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.LocalTestDriver.Destroy(ctx, s)
}
func (d *testDriver) close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, s := range d.started {
		_ = d.LocalTestDriver.End(context.Background(), s, "test gateway shutdown")
	}
}

type trackedListener struct {
	net.Listener
	mu      sync.Mutex
	conns   map[net.Conn]bool
	closed  bool
	limit   int
	timeout time.Duration
}
type trackedConn struct {
	net.Conn
	owner *trackedListener
	once  sync.Once
}

func (c *trackedConn) Read(p []byte) (int, error) {
	if c.owner.timeout > 0 {
		_ = c.Conn.SetReadDeadline(time.Now().Add(c.owner.timeout))
	}
	return c.Conn.Read(p)
}
func (c *trackedConn) Write(p []byte) (int, error) {
	if c.owner.timeout > 0 {
		_ = c.Conn.SetWriteDeadline(time.Now().Add(c.owner.timeout))
	}
	return c.Conn.Write(p)
}

func (c *trackedConn) Close() error {
	e := c.Conn.Close()
	c.once.Do(func() { c.owner.mu.Lock(); delete(c.owner.conns, c); c.owner.mu.Unlock() })
	return e
}
func (l *trackedListener) Accept() (net.Conn, error) {
	for {
		c, e := l.Listener.Accept()
		if e != nil {
			return nil, e
		}
		l.mu.Lock()
		if l.closed {
			l.mu.Unlock()
			c.Close()
			return nil, net.ErrClosed
		}
		if l.limit > 0 && len(l.conns) >= l.limit {
			l.mu.Unlock()
			c.Close()
			continue
		}
		w := &trackedConn{Conn: c, owner: l}
		l.conns[w] = true
		l.mu.Unlock()
		return w, nil
	}
}
func (l *trackedListener) closeAll() {
	_ = l.Listener.Close()
	l.mu.Lock()
	l.closed = true
	var conns []net.Conn
	for c := range l.conns {
		conns = append(conns, c)
	}
	l.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}
