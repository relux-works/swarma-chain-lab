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
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/exchange"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/journal"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernel"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/screen"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/station"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/stationlink"
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
	AgentKey *nostr.PrivKey
	Kernel   kernel.Checker
	// Presenter, when set, enables inline certificate presentation
	// (detached grants): a renter's first message carries the
	// envelope, later messages are checked against the kernel's
	// cached bytes. When nil, only slot-stored certificates are used.
	Presenter kernel.Presenter
	// AgentName is the rented agent's pinned kernel name
	// (Policy.AgentName form, e.g. "id/agent"). Empty falls back to
	// the slot's station name (unit tests / legacy wiring).
	AgentName     string
	Screener      screen.Screener
	Journal       *journal.Store
	Publisher     Publisher
	Driver        station.Driver
	Endpoint      string // station-facing endpoint advertised in StartSession
	ScreenTimeout time.Duration
	PullTimeout   time.Duration
	Now           func() time.Time
	Exchange      *exchange.Engine // optional deterministic non-grantee path; caller closes it
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
	Delivered      bool
	Refused        bool
	Reason         string // precise refusal reason when Refused
	SlotID         string
	SenderHex      string
	WarningSent    bool
	SlotEnded      bool
	ExchangeQueued bool
}

// Gateway is the message router and station manager front-end.
type Gateway struct {
	cfg Config

	mu       sync.Mutex
	stations map[string]*station.Station
	queues   map[string]chan *stationlink.Frame
	bound    map[string]*connState    // slot id -> live authenticated station binding
	starting map[string]chan struct{} // live launch completion; absent after restart/failure

	opMu     sync.Mutex
	inFlight map[string]*opCall // slot\x00kind\x00op id -> running closer operation

	startMu sync.Mutex // serializes explicit/lazy starts and startup recovery
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
	g := &Gateway{cfg: cfg, stations: map[string]*station.Station{},
		queues:   map[string]chan *stationlink.Frame{},
		bound:    map[string]*connState{},
		starting: map[string]chan struct{}{},
		inFlight: map[string]*opCall{}}
	if cfg.Exchange != nil {
		if cfg.AgentName != cfg.Exchange.AgentName() {
			return nil, fmt.Errorf("gateway: exchange agent name mismatch")
		}
		if err := cfg.Exchange.Bind(cfg.AgentKey, cfg.Publisher, exchange.Hooks{Register: g.registerIssued, Check: g.checkExchangeGrant}); err != nil {
			return nil, err
		}
	}
	return g, nil
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
	g.startMu.Lock()
	defer g.startMu.Unlock()
	slot, ok := g.cfg.Journal.Get(slotID)
	if !ok {
		return fmt.Errorf("gateway: no slot %s", slotID)
	}
	if slot.Ended || slot.Destroyed {
		return fmt.Errorf("gateway: slot %s ended", slotID)
	}
	if slot.Started || slot.Starting {
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
	if err := g.startStation(ctx, slot); err != nil {
		return err
	}
	return g.dmRenter(ctx, slot, "ready")
}

// startStation creates and starts the slot's station instance and
// durably marks the slot started. The caller has already obtained a
// live kernel verdict inside the slot window; this is the shared
// second half of StartSlot and of the lazy first-presentation start.
func (g *Gateway) startStation(ctx context.Context, slot *journal.Slot) error {
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
	if err := g.cfg.Journal.SetStationHandle(slot.ID, st.Home, st.User); err != nil {
		_, _ = g.cfg.Driver.Destroy(ctx, st)
		return fmt.Errorf("gateway: register station handle: %w", err)
	}
	g.mu.Lock()
	g.stations[slot.ID] = st
	err = g.cfg.Journal.MarkStarting(slot.ID)
	if err == nil {
		g.starting[slot.ID] = make(chan struct{})
	}
	g.mu.Unlock()
	if err != nil {
		return g.failStart(ctx, slot.ID, st, fmt.Errorf("gateway: journal starting: %w", err))
	}
	info := station.SessionInfo{
		RenterPubKey: slot.RenterPubKey, ContractSHA256: slot.ContractSHA256,
		NotAfter: slot.NotAfter, GatewayEndpoint: g.cfg.Endpoint,
	}
	if err := g.cfg.Driver.StartSession(ctx, st, info); err != nil {
		return g.failStart(ctx, slot.ID, st, fmt.Errorf("gateway: start session: %w", err))
	}
	if err := g.cfg.Journal.MarkStarted(slot.ID); err != nil {
		return g.failStart(ctx, slot.ID, st, fmt.Errorf("gateway: journal started: %w", err))
	}
	g.mu.Lock()
	close(g.starting[slot.ID])
	delete(g.starting, slot.ID)
	g.mu.Unlock()
	return nil
}

// failStart revokes admission before I/O. Cleanup still runs if persistence fails
// or the initiating caller cancelled; errors preserve uncertainty for recovery.
func (g *Gateway) failStart(ctx context.Context, id string, st *station.Station, cause error) error {
	g.mu.Lock()
	bound := g.bound[id]
	delete(g.bound, id)
	if done := g.starting[id]; done != nil {
		close(done)
		delete(g.starting, id)
	}
	g.mu.Unlock()
	if bound != nil {
		bound.cancel()
		_ = bound.conn.Close()
	}
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	endErr := g.cfg.Journal.MarkEnded(id, "start_failed")
	_, destroyErr := g.cfg.Driver.Destroy(cleanup, st)
	var recordErr error
	if destroyErr == nil {
		recordErr = g.cfg.Journal.MarkDestroyed(id)
		g.mu.Lock()
		delete(g.stations, id)
		g.mu.Unlock()
	}
	return errors.Join(cause, endErr, destroyErr, recordErr)
}

// RecoverStarting destroys interrupted launches using durable driver handles and
// the existing recorded closer operation. Run after manager RPC is serving but
// before accepting renter traffic. A new Gateway admits no orphan Starting slot,
// including when recovery cannot finish. Payload execution is never replayed.
func (g *Gateway) RecoverStarting(ctx context.Context) error {
	g.startMu.Lock()
	defer g.startMu.Unlock()
	for _, slot := range g.cfg.Journal.All() {
		if slot.Starting {
			opID := "startup-recovery"
			for _, op := range slot.Operations {
				if op.Kind == journal.OpDestroy && op.State == journal.OpStateStarted {
					opID = op.OpID // resume a closer's crash-left operation too
					break
				}
			}
			if _, _, err := g.DestroySlot(ctx, slot.ID, opID); err != nil {
				return fmt.Errorf("gateway: interrupted start recovery: %w", err)
			}
		}
	}
	return nil
}

// ensureStarted lazily starts the slot's station after a live
// kernel verdict (first presented message). Serialized so two
// racing first messages start exactly one instance.
func (g *Gateway) ensureStarted(ctx context.Context, slot *journal.Slot) error {
	g.startMu.Lock()
	defer g.startMu.Unlock()
	fresh, ok := g.cfg.Journal.Get(slot.ID)
	if !ok || fresh.Destroyed || fresh.Ended {
		return fmt.Errorf("gateway: slot %s unavailable", slot.ID)
	}
	if fresh.Started {
		return nil
	}
	if fresh.Starting {
		return fmt.Errorf("gateway: interrupted start requires recovery")
	}
	if err := g.startStation(ctx, fresh); err != nil {
		return err
	}
	// With exchange enabled its current-time timer owns ready notification.
	// Do not duplicate it or synchronously await relay OK from the read pump
	// that delivered this first message. Legacy wiring retains its notice.
	if g.cfg.Exchange == nil {
		_ = g.dmRenter(ctx, fresh, "ready")
	}
	return nil
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

// endSlot is the best-effort internal wrapper for gateway-driven
// ends (Tick, screening, kernel closure, end-early). Closer-driven
// ends go through the recorded EndSlot operation in ops.go.
func (g *Gateway) endSlot(ctx context.Context, slotID, reason, renterDM string) {
	_ = g.endSlotE(ctx, slotID, reason, renterDM)
}

// agentNameFor is the pinned kernel agent name for a slot: the
// gateway config wins, the slot's station name is the legacy
// fallback.
func (g *Gateway) agentNameFor(slot *journal.Slot) string {
	if g.cfg.AgentName != "" {
		return g.cfg.AgentName
	}
	return slot.StationName
}

// envelopeFor resolves the certificate bytes to Check for one
// sender, in order: the kernel's presented-bytes cache, then the
// slot-stored envelope. ok=false means the sender must present.
func (g *Gateway) envelopeFor(slot *journal.Slot, senderHex string) (cert []byte, ok bool, err error) {
	if g.cfg.Presenter != nil {
		raw, perr := g.cfg.Presenter.CachedGrant(senderHex)
		if perr == nil && len(raw) > 0 {
			return raw, true, nil
		}
		// Any cache error (absent or otherwise) falls through to
		// the stored envelope; the fresh Check remains the gate.
	}
	if slot.CertificateB64 != "" {
		raw, derr := base64.StdEncoding.DecodeString(slot.CertificateB64)
		if derr != nil {
			return nil, false, derr
		}
		return raw, true, nil
	}
	return nil, false, nil
}

func (g *Gateway) kernelCheck(ctx context.Context, slot *journal.Slot, nowUnix int64) (kernel.Receipt, error) {
	return g.kernelCheckSender(ctx, slot, slot.RenterPubKey, nowUnix)
}

// kernelCheckSender is the per-message check: the sender is the
// authenticated inner seal key, never the gift-wrap key, and never a
// value taken from message content. With a Presenter wired and no
// known bytes the verdict is refused/presentation_required — the
// renter must attach its certificate inline first.
func (g *Gateway) kernelCheckSender(ctx context.Context, slot *journal.Slot, senderHex string, nowUnix int64) (kernel.Receipt, error) {
	cert, ok, err := g.envelopeFor(slot, senderHex)
	if err != nil {
		return kernel.Receipt{Verdict: kernel.Refused, Reason: "stored certificate undecodable"}, err
	}
	if !ok {
		return kernel.Receipt{Verdict: kernel.Refused, Reason: "presentation_required",
			AgentName: g.agentNameFor(slot), CheckedAt: nowUnix}, nil
	}
	return g.cfg.Kernel.Check(ctx, cert, g.agentNameFor(slot), senderHex, nowUnix)
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
