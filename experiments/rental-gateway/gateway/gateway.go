// Package gateway routes NIP-17 direct messages between renters and
// stations under one stable agent identity. It holds the agent's
// Nostr private key (stations never see it), authenticates every
// inbound gift wrap by its inner seal key, asks the grant kernel
// whether the renter's slot is live, screens content (the model can
// only refuse), and delivers to the slot's station. The gateway does
// not judge action scope: that is the executor's job (R3).
package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"relux.works/swarma-chain-lab/experiments/rental-gateway/journal"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/kernel"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/nostr"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/screen"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/station"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/stationlink"
)

// Publisher sends one signed event to the relay set. It is the
// renter-channel transport boundary: outbound traffic leaves only
// through it, inbound enters only through HandleGiftWrap, so the
// Nostr relay transport (RelayClient) can later be replaced by an
// a2a transport without touching gateway policy (owner decision,
// 2026-11-08; no a2a work in this milestone).
type Publisher interface {
	Publish(ctx context.Context, ev *nostr.Event) error
}

// Transport is the renter-channel transport (see Publisher).
type Transport = Publisher

// Config wires the gateway. Now defaults to time.Now.
type Config struct {
	AgentKey      *nostr.PrivKey
	Kernel        kernel.Checker
	Screener      screen.Screener
	Journal       *journal.Store
	Publisher     Publisher
	Driver        station.Driver
	Endpoint      string // station-facing endpoint advertised in StartSession
	ScreenTimeout time.Duration
	PullTimeout   time.Duration
	Now           func() time.Time
}

// SlotSpec registers one rental slot with the gateway.
type SlotSpec struct {
	ID             string
	StationName    string
	RenterPubKey   string // grantee key, 64 lower hex
	Certificate    []byte // signed rental certificate envelope bytes
	ContractSHA256 string
	BookingID      string // M3 booking id, 64 lower hex (Track B key); may be empty locally
	NotBefore      int64
	NotAfter       int64 // half-open end
}

// Result describes the outcome of handling one inbound gift wrap.
type Result struct {
	Delivered   bool
	Refused     bool
	Reason      string // precise refusal reason when Refused
	SlotID      string
	SenderHex   string
	WarningSent bool
	SlotEnded   bool
}

// Gateway is the message router and station manager front-end.
type Gateway struct {
	cfg Config

	mu       sync.Mutex
	stations map[string]*station.Station
	queues   map[string]chan *stationlink.Frame
	bound    map[string]*connState // slot id -> live authenticated station binding
}

// New validates config and builds a Gateway.
func New(cfg Config) (*Gateway, error) {
	if cfg.AgentKey == nil || cfg.Kernel == nil || cfg.Screener == nil ||
		cfg.Journal == nil || cfg.Publisher == nil || cfg.Driver == nil {
		return nil, fmt.Errorf("gateway: AgentKey, Kernel, Screener, Journal, Publisher and Driver are required")
	}
	if cfg.ScreenTimeout <= 0 {
		cfg.ScreenTimeout = 5 * time.Second
	}
	if cfg.PullTimeout <= 0 {
		cfg.PullTimeout = 30 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Gateway{cfg: cfg, stations: map[string]*station.Station{},
		queues: map[string]chan *stationlink.Frame{},
		bound:  map[string]*connState{}}, nil
}

// AgentPubKey returns the stable agent public identity (hex).
func (g *Gateway) AgentPubKey() string { return g.cfg.AgentKey.PubKeyHex() }

func (g *Gateway) queueFor(slotID string) chan *stationlink.Frame {
	g.mu.Lock()
	defer g.mu.Unlock()
	q, ok := g.queues[slotID]
	if !ok {
		q = make(chan *stationlink.Frame, 64)
		g.queues[slotID] = q
	}
	return q
}

// RegisterSlot durably registers a slot (one active slot per renter).
func (g *Gateway) RegisterSlot(spec SlotSpec) error {
	if spec.NotAfter <= spec.NotBefore {
		return fmt.Errorf("gateway: empty slot window")
	}
	return g.cfg.Journal.Put(&journal.Slot{
		ID:             spec.ID,
		StationName:    spec.StationName,
		RenterPubKey:   spec.RenterPubKey,
		CertificateB64: base64.StdEncoding.EncodeToString(spec.Certificate),
		ContractSHA256: spec.ContractSHA256,
		BookingID:      spec.BookingID,
		NotBefore:      spec.NotBefore,
		NotAfter:       spec.NotAfter,
	})
}

// StartSlot starts the station session when the kernel says the grant
// is live and now >= not_before, then DMs the renter "ready" from the
// agent key. Pending kernel verdicts (including unconfirmed anchors
// on 0-conf-payment slots) never start a session: start-now changes
// payment eligibility only, per the M1 decisions.
func (g *Gateway) StartSlot(ctx context.Context, slotID string) error {
	slot, ok := g.cfg.Journal.Get(slotID)
	if !ok {
		return fmt.Errorf("gateway: no slot %s", slotID)
	}
	if slot.Ended || slot.Destroyed {
		return fmt.Errorf("gateway: slot %s ended", slotID)
	}
	if slot.Started {
		return fmt.Errorf("gateway: slot %s already started", slotID)
	}
	now := g.cfg.Now().Unix()
	if now < slot.NotBefore {
		return fmt.Errorf("gateway: slot %s pending: before not_before", slotID)
	}
	if now >= slot.NotAfter {
		return fmt.Errorf("gateway: slot %s refused: window over", slotID)
	}
	receipt, err := g.kernelCheck(ctx, slot, now)
	if err != nil {
		return fmt.Errorf("gateway: slot %s refused: kernel error: %w", slotID, err)
	}
	if receipt.Closed {
		g.endSlot(ctx, slotID, "kernel_closed", "")
		return fmt.Errorf("gateway: slot %s closed: %s", slotID, receipt.Reason)
	}
	if !receipt.Admits() {
		return fmt.Errorf("gateway: slot %s %s: %s", slotID, receipt.Verdict, receipt.Reason)
	}
	st, err := g.cfg.Driver.Create(ctx, station.SlotSpec{
		SlotID: slot.ID, StationName: slot.StationName, BookingID: slot.BookingID})
	if err != nil {
		return fmt.Errorf("gateway: create station: %w", err)
	}
	tokenSum := sha256.Sum256([]byte(st.TrackBToken))
	if err := g.cfg.Journal.SetChannelSecret(slot.ID,
		hex.EncodeToString(st.ChannelSecret), hex.EncodeToString(tokenSum[:])); err != nil {
		_, _ = g.cfg.Driver.Destroy(ctx, st)
		return fmt.Errorf("gateway: register channel secret: %w", err)
	}
	info := station.SessionInfo{
		RenterPubKey: slot.RenterPubKey, ContractSHA256: slot.ContractSHA256,
		NotAfter: slot.NotAfter, GatewayEndpoint: g.cfg.Endpoint,
	}
	if err := g.cfg.Driver.StartSession(ctx, st, info); err != nil {
		_, _ = g.cfg.Driver.Destroy(ctx, st)
		return fmt.Errorf("gateway: start session: %w", err)
	}
	if err := g.cfg.Journal.MarkStarted(slot.ID); err != nil {
		_, _ = g.cfg.Driver.Destroy(ctx, st)
		return fmt.Errorf("gateway: journal started: %w", err)
	}
	g.mu.Lock()
	g.stations[slot.ID] = st
	g.mu.Unlock()
	return g.dmRenter(ctx, slot, "ready")
}

// Tick ends every started slot whose not_after has passed, regardless
// of chain state.
func (g *Gateway) Tick(ctx context.Context) {
	now := g.cfg.Now().Unix()
	for _, slot := range g.cfg.Journal.All() {
		if slot.Started && !slot.Ended && !slot.Destroyed && now >= slot.NotAfter {
			g.endSlot(ctx, slot.ID, "not_after", "slot ended")
		}
	}
}

// DestroySlot ends the session and destroys the station (home and
// Track B token removed by the driver). Journal records are kept.
func (g *Gateway) DestroySlot(ctx context.Context, slotID string) (station.DestroyReport, error) {
	slot, ok := g.cfg.Journal.Get(slotID)
	if !ok {
		return station.DestroyReport{}, fmt.Errorf("gateway: no slot %s", slotID)
	}
	g.endSlot(ctx, slotID, "destroyed", "")
	g.mu.Lock()
	st := g.stations[slotID]
	delete(g.stations, slotID)
	g.mu.Unlock()
	var report station.DestroyReport
	var err error
	if st != nil {
		report, err = g.cfg.Driver.Destroy(ctx, st)
		if err != nil {
			return report, err
		}
	} else {
		report = station.DestroyReport{Kept: append([]string(nil), station.KeptElsewhere...)}
		_ = slot
	}
	if err := g.cfg.Journal.MarkDestroyed(slotID); err != nil {
		return report, err
	}
	return report, nil
}

// SendFinalMessage delivers the closer's end-of-slot message
// (summary, deliverables, revoke txid) to the renter, signed with
// the agent key. The closer (M4b) calls it after slot end and
// before DestroySlot; after destruction it is refused, so the
// required order end -> final message -> destroy is enforceable.
func (g *Gateway) SendFinalMessage(ctx context.Context, slotID, content string) error {
	slot, ok := g.cfg.Journal.Get(slotID)
	if !ok {
		return fmt.Errorf("gateway: no slot %s", slotID)
	}
	if slot.Destroyed {
		return fmt.Errorf("gateway: slot %s destroyed: final message must precede destroy", slotID)
	}
	if content == "" {
		return fmt.Errorf("gateway: empty final message")
	}
	return g.dmRenter(ctx, slot, content)
}

// endSlot durably ends a slot, stops its station process (session
// end, not destroy), notifies the station queue, and optionally DMs
// the renter. It never extends or reopens a slot.
func (g *Gateway) endSlot(ctx context.Context, slotID, reason, renterDM string) {
	slot, ok := g.cfg.Journal.Get(slotID)
	if !ok || slot.Ended {
		// Still record destroy-flavoured ends for unknown state below.
		if !ok {
			return
		}
	}
	_ = g.cfg.Journal.MarkEnded(slotID, reason)
	g.mu.Lock()
	st := g.stations[slotID]
	g.mu.Unlock()
	if st != nil {
		_ = g.cfg.Driver.End(ctx, st, reason)
	}
	q := g.queueFor(slotID)
	select {
	case q <- &stationlink.Frame{Type: stationlink.TypeEnd, SlotID: slotID, Reason: reason}:
	default:
	}
	if renterDM != "" {
		fresh, _ := g.cfg.Journal.Get(slotID)
		_ = g.dmRenter(ctx, fresh, renterDM)
	}
}

func (g *Gateway) kernelCheck(ctx context.Context, slot *journal.Slot, nowUnix int64) (kernel.Receipt, error) {
	cert, err := base64.StdEncoding.DecodeString(slot.CertificateB64)
	if err != nil {
		return kernel.Receipt{Verdict: kernel.Refused, Reason: "stored certificate undecodable"}, err
	}
	return g.cfg.Kernel.Check(ctx, cert, slot.StationName, slot.RenterPubKey, nowUnix)
}

// kernelCheckSender is the per-message check: the sender is the
// authenticated inner seal key, never the gift-wrap key, and never a
// value taken from message content.
func (g *Gateway) kernelCheckSender(ctx context.Context, slot *journal.Slot, senderHex string, nowUnix int64) (kernel.Receipt, error) {
	cert, err := base64.StdEncoding.DecodeString(slot.CertificateB64)
	if err != nil {
		return kernel.Receipt{Verdict: kernel.Refused, Reason: "stored certificate undecodable"}, err
	}
	return g.cfg.Kernel.Check(ctx, cert, slot.StationName, senderHex, nowUnix)
}

// dmRenter sends one NIP-17 DM from the agent key to the slot renter.
// This is the only signing path for outbound traffic.
func (g *Gateway) dmRenter(ctx context.Context, slot *journal.Slot, content string) error {
	if slot == nil {
		return fmt.Errorf("gateway: no slot for DM")
	}
	wrap, _, err := nostr.WrapDM(g.cfg.AgentKey, slot.RenterPubKey, content, nil, g.cfg.Now().Unix())
	if err != nil {
		return err
	}
	return g.cfg.Publisher.Publish(ctx, wrap)
}
