package main

import (
	"context"
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

	booking "relux.works/swarma-chain-lab/experiments/rental-booking"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/exchange"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/gateway"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/journal"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/kernel"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/kernelbind"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/kernelbind/bookingbind"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/nostr"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/screen"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/station"
	su "relux.works/swarma-chain-lab/experiments/single-use"
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
	client := newBookingClient(c.Exchange.BookingURL, c.Exchange.PrivacySHA256, c.Exchange.TemplateSHA256, c.Exchange.ProfileSHA256)
	defer client.close()
	// Check public booking pins at startup, before creating gateway state.
	if _, e = client.Catalogue(time.Now().Unix()+86400, 16); e != nil {
		return errBooking
	}
	backend := &bookingbind.Adapter{Service: client, AgentName: c.Kernel.AgentName, LandlordName: c.Kernel.LandlordName, AgentPubkey: c.AgentPubkey, Now: time.Now}
	for _, dir := range []string{c.JournalDir, c.Kernel.StateDir, c.Exchange.StateDir, c.Station.Root} {
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
	relay := &gateway.RelayClient{URL: c.RelayURL}
	if e = relay.Dial(ctx); e != nil {
		return errors.New("RELAY_UNAVAILABLE")
	}
	defer relay.Close()
	driver := &testDriver{LocalTestDriver: &station.LocalTestDriver{Root: c.Station.Root}}
	if c.Station.StubAgent {
		self, e := os.Executable()
		if e != nil {
			return errConfig
		}
		driver.StubCommand = []string{self, "station-stub"}
	}
	defer driver.close()
	gw, e := gateway.New(gateway.Config{AgentKey: key, AgentName: c.Kernel.AgentName, Kernel: checker, Presenter: presenter, Screener: screener, Journal: store, Publisher: relay, Driver: driver, Endpoint: c.StationSocket, Exchange: eng, PullTimeout: time.Second})
	if e != nil {
		return errors.New("GATEWAY_CONSTRUCTION")
	}
	// Never unlink an existing endpoint; an operator must establish ownership.
	if e = privateDir(filepath.Dir(c.StationSocket)); e != nil {
		return e
	}
	ln, e := net.Listen("unix", c.StationSocket)
	if e != nil {
		return errors.New("STATION_LISTEN")
	}
	connections := &trackedListener{Listener: ln, conns: map[net.Conn]bool{}}
	defer connections.closeAll()
	var workers sync.WaitGroup
	workers.Add(3)
	errs := make(chan error, 2)
	go func() { defer workers.Done(); errs <- gw.ServeStations(connections) }()
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
	defer func() { cancel(); relay.Close(); connections.closeAll(); workers.Wait() }()
	inbound := newInbound(ctx, c.Exchange.QueueSize, func(ctx context.Context, ev *nostr.Event) {
		r := gw.HandleGiftWrap(ctx, ev)
		fmt.Fprintf(os.Stderr, "gateway: inbound delivered=%t refused=%t exchange=%t\n", r.Delivered, r.Refused, r.ExchangeQueued)
	})
	defer inbound.close()
	fmt.Fprintf(os.Stderr, "gateway: screening=%s mode=%s kernel=%s station=%s pid=%d\n", c.Screening, c.Mode, c.Kernel.Kind, c.Station.Driver, os.Getpid())
	go func() {
		defer workers.Done()
		errs <- relay.SubscribeGiftWraps(ctx, gw.AgentPubKey(), func(ctx context.Context, ev *nostr.Event) {
			if !inbound.offer(ev) {
				fmt.Fprintln(os.Stderr, "gateway: inbound queue unavailable")
			}
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
	mu     sync.Mutex
	conns  map[net.Conn]bool
	closed bool
}
type trackedConn struct {
	net.Conn
	owner *trackedListener
	once  sync.Once
}

func (c *trackedConn) Close() error {
	e := c.Conn.Close()
	c.once.Do(func() { c.owner.mu.Lock(); delete(c.owner.conns, c); c.owner.mu.Unlock() })
	return e
}
func (l *trackedListener) Accept() (net.Conn, error) {
	c, e := l.Listener.Accept()
	if e != nil {
		return nil, e
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		c.Close()
		return nil, net.ErrClosed
	}
	w := &trackedConn{Conn: c, owner: l}
	l.conns[w] = true
	return w, nil
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
