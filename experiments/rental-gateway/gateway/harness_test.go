package gateway_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"relux.works/swarma-chain-lab/experiments/rental-gateway/exchange"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/gateway"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/journal"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/kernel"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/nostr"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/screen"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/station"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/stationlink"
)

const (
	slotNotBefore = 1000
	slotNotAfter  = 2000
	nowMid        = 1500
)

type testClock struct {
	mu sync.Mutex
	t  int64
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Unix(c.t, 0)
}

func (c *testClock) Set(t int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

type collectPublisher struct {
	mu  sync.Mutex
	evs []*nostr.Event
}

func (p *collectPublisher) Publish(ctx context.Context, ev *nostr.Event) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.evs = append(p.evs, ev)
	return nil
}

// dmsTo unwraps every published DM readable by priv, returning contents.
func (p *collectPublisher) dmsTo(priv *nostr.PrivKey) []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []string
	for _, ev := range p.evs {
		if u, err := nostr.UnwrapDM(ev, priv); err == nil {
			out = append(out, u.Rumor.Content)
		}
	}
	return out
}

func (p *collectPublisher) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.evs)
}

func (p *collectPublisher) evsSnapshot() []*nostr.Event {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]*nostr.Event(nil), p.evs...)
}

// dialStation dials without hello (for refused-hello assertions).
func dialStation(h *harness) (*stationlink.Client, error) {
	conn, err := net.Dial("unix", h.sockPath)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	return stationlink.NewClient(conn), nil
}

type harness struct {
	t          *testing.T
	gw         *gateway.Gateway
	store      *journal.Store
	journalDir string
	clock      *testClock
	agent      *nostr.PrivKey
	renter     *nostr.PrivKey
	kern       *kernel.Stub
	scr        *screen.Stub
	pub        *collectPublisher
	driver     *station.LocalTestDriver
	stationDir string
	sockPath   string
	listener   net.Listener
	screenTO   time.Duration
	presenter  bool
	agentName  string
	exchange   *exchange.Engine
}

type harnessOpts struct {
	skipRegister bool
	skipStart    bool
	screenTO     time.Duration
	stationName  string
	stubCmd      []string
	presenter    bool   // wire the stub kernel also as kernel.Presenter
	noCert       bool   // register the slot without stored certificate bytes
	agentName    string // gateway AgentName pin (empty = slot station name)
	exchange     *exchange.Engine
}

func newHarness(t *testing.T, opts harnessOpts) *harness {
	t.Helper()
	h := &harness{t: t, clock: &testClock{t: nowMid}, screenTO: opts.screenTO,
		presenter: opts.presenter, agentName: opts.agentName, exchange: opts.exchange}
	if h.screenTO <= 0 {
		h.screenTO = 2 * time.Second
	}
	var err error
	h.agent, _ = nostr.GeneratePrivKey()
	h.renter, _ = nostr.GeneratePrivKey()
	h.journalDir = filepath.Join(t.TempDir(), "journal")
	h.stationDir = filepath.Join(t.TempDir(), "stations")
	h.store, err = journal.Open(h.journalDir)
	if err != nil {
		t.Fatal(err)
	}
	h.kern = &kernel.Stub{Verdict: kernel.Live}
	h.scr = &screen.Stub{}
	h.pub = &collectPublisher{}
	h.driver = &station.LocalTestDriver{Root: h.stationDir, StubCommand: opts.stubCmd}

	sockDir, err := os.MkdirTemp("", "gw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	h.sockPath = filepath.Join(sockDir, "s.sock")

	h.gw = h.buildGateway()
	h.listener, err = net.Listen("unix", h.sockPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.listener.Close() })
	gw := h.gw
	go func() { _ = gw.ServeStations(h.listener) }()

	if !opts.skipRegister {
		stationName := opts.stationName
		if stationName == "" {
			stationName = "id/swarma-station-1"
		}
		cert := []byte("test-certificate-envelope")
		if opts.noCert {
			cert = nil
		}
		err = h.gw.RegisterSlot(gateway.SlotSpec{
			ID: "slot-1", StationName: stationName,
			RenterPubKey:   h.renter.PubKeyHex(),
			Certificate:    cert,
			ContractSHA256: strings.Repeat("a", 64),
			NotBefore:      slotNotBefore, NotAfter: slotNotAfter,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if !opts.skipStart && !opts.skipRegister {
		if err := h.gw.StartSlot(context.Background(), "slot-1"); err != nil {
			t.Fatalf("StartSlot: %v", err)
		}
	}
	return h
}

func (h *harness) buildGateway() *gateway.Gateway {
	var presenter kernel.Presenter
	if h.presenter {
		presenter = h.kern
	}
	gw, err := gateway.New(gateway.Config{
		AgentKey: h.agent, Kernel: h.kern, Screener: h.scr,
		Presenter: presenter, AgentName: h.agentName,
		Exchange: h.exchange,
		Journal:  h.store, Publisher: h.pub, Driver: h.driver,
		Endpoint: h.sockPath, ScreenTimeout: h.screenTO,
		PullTimeout: 150 * time.Millisecond, Now: h.clock.Now,
	})
	if err != nil {
		h.t.Fatal(err)
	}
	return gw
}

// rebuild simulates a gateway restart over the same journal dir.
func (h *harness) rebuild() {
	h.t.Helper()
	store, err := journal.Open(h.journalDir)
	if err != nil {
		h.t.Fatal(err)
	}
	h.store = store
	h.gw = h.buildGateway()
	// The original ServeStations loop keeps accepting on the same
	// listener for the old gateway; restart tests here drive
	// HandleGiftWrap directly and need no second station loop.
}

func (h *harness) renterDM(content string, at int64) *nostr.Event {
	h.t.Helper()
	wrap, _, err := nostr.WrapDM(h.renter, h.agent.PubKeyHex(), content, nil, at)
	if err != nil {
		h.t.Fatal(err)
	}
	return wrap
}

func (h *harness) handle(wrap *nostr.Event) gateway.Result {
	return h.gw.HandleGiftWrap(context.Background(), wrap)
}

// slotSecret reads the registered channel secret for a slot.
func (h *harness) slotSecret(slotID string) []byte {
	h.t.Helper()
	slot, ok := h.store.Get(slotID)
	if !ok || slot.ChannelSecretHex == "" {
		h.t.Fatalf("no channel secret for %s", slotID)
	}
	b, err := hex.DecodeString(slot.ChannelSecretHex)
	if err != nil {
		h.t.Fatal(err)
	}
	return b
}

// stationClient dials the gateway as the station and hellos.
func (h *harness) stationClient() (*stationlink.Client, net.Conn) {
	h.t.Helper()
	conn, err := net.Dial("unix", h.sockPath)
	if err != nil {
		h.t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	c := stationlink.NewClient(conn)
	sys, err := c.Hello("slot-1", "id/swarma-station-1", h.slotSecret("slot-1"))
	if err != nil {
		h.t.Fatal(err)
	}
	if sys.Type != stationlink.TypeSystem {
		h.t.Fatalf("hello = %s %s, want system", sys.Type, sys.Reason)
	}
	if sys.RenterPubKey != h.renter.PubKeyHex() || sys.NotAfter != slotNotAfter ||
		sys.ContractSHA256 != strings.Repeat("a", 64) {
		h.t.Fatalf("system frame mismatch: %+v", sys)
	}
	return c, conn
}

func pull(t *testing.T, c *stationlink.Client) *stationlink.Frame {
	t.Helper()
	f, err := c.Pull()
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	return f
}

// deliverValid is the valid neighbour used beside negative controls:
// a well-formed renter DM must reach the station queue.
func (h *harness) deliverValid(c *stationlink.Client, content string) {
	h.t.Helper()
	res := h.handle(h.renterDM(content, nowMid))
	if !res.Delivered {
		h.t.Fatalf("valid neighbour refused: %+v", res)
	}
	f := pull(h.t, c)
	if f.Type != stationlink.TypeDeliver || f.Content != content {
		h.t.Fatalf("station got %+v, want deliver %q", f, content)
	}
}

// craftWrap builds adversarial wraps with full control over rumor,
// seal signer and wrap signer.
func craftWrap(t *testing.T, rumor *nostr.Event, sealSigner, wrapSigner *nostr.PrivKey,
	recipient string, mutateSeal func(*nostr.Event), tamperWrap bool) *nostr.Event {
	t.Helper()
	r := *rumor
	r.Sig = ""
	if r.ID == "" {
		r.ID = r.ComputeID()
	}
	rumorJSON, _ := json.Marshal(&r)
	ckSeal, err := nostr.ConversationKey(sealSigner, recipient)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := nostr.EncryptNIP44(string(rumorJSON), ckSeal, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	seal := &nostr.Event{CreatedAt: nowMid, Kind: nostr.KindSeal, Tags: [][]string{}, Content: enc}
	if err := sealSigner.SignEvent(seal); err != nil {
		t.Fatal(err)
	}
	if mutateSeal != nil {
		mutateSeal(seal)
	}
	sealJSON, _ := json.Marshal(seal)
	ckWrap, err := nostr.ConversationKey(wrapSigner, recipient)
	if err != nil {
		t.Fatal(err)
	}
	enc2, err := nostr.EncryptNIP44(string(sealJSON), ckWrap, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	if tamperWrap {
		b := []byte(enc2)
		i := len(b) / 2
		if b[i] == 'A' {
			b[i] = 'B'
		} else {
			b[i] = 'A'
		}
		enc2 = string(b)
	}
	wrap := &nostr.Event{CreatedAt: nowMid, Kind: nostr.KindGiftWrap,
		Tags: [][]string{{"p", recipient}}, Content: enc2}
	if err := wrapSigner.SignEvent(wrap); err != nil {
		t.Fatal(err)
	}
	return wrap
}

func rumorFrom(sender *nostr.PrivKey, recipient, content string, at int64) *nostr.Event {
	r := &nostr.Event{
		PubKey: sender.PubKeyHex(), CreatedAt: at, Kind: nostr.KindRumor,
		Tags: [][]string{{"p", recipient}}, Content: content,
	}
	r.ID = r.ComputeID()
	return r
}
