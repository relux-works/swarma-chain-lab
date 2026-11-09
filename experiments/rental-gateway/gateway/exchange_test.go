package gateway_test

import (
	"context"
	"errors"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"relux.works/swarma-chain-lab/experiments/rental-gateway/exchange"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/gateway"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/nostr"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/testrelay"
)

type slowExchange struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *slowExchange) Catalogue(ctx context.Context) (exchange.Terms, error) {
	s.once.Do(func() { close(s.entered) })
	select {
	case <-ctx.Done():
		return exchange.Terms{}, ctx.Err()
	case <-s.release:
		return exchange.Terms{}, errors.New("fixture unavailable")
	}
}
func (*slowExchange) Book(context.Context, string, exchange.Selection) (exchange.Hold, error) {
	panic("unexpected booking")
}
func (*slowExchange) Consent(context.Context, string, []byte) (exchange.Hold, error) {
	panic("unexpected consent")
}
func (*slowExchange) Status(context.Context, string) (exchange.Hold, error) {
	panic("unexpected status")
}
func (*slowExchange) Lookup(context.Context, exchange.Hold) (*exchange.Issued, error) {
	panic("unexpected issuance")
}
func exchangeEngine(t *testing.T, s *slowExchange) *exchange.Engine {
	t.Helper()
	c := exchange.DefaultConfig()
	c.StateDir = t.TempDir()
	if err := os.Chmod(c.StateDir, 0700); err != nil {
		t.Fatal(err)
	}
	c.AgentName = "id/swarma-station-1"
	c.LandlordName = "id/landlord"
	c.Backend = s
	c.Grants = s
	c.Now = func() time.Time { return time.Unix(nowMid, 0) }
	c.PowBits = 4
	c.QueueSize = 1
	c.Burst = 1
	c.MaxClients = 2
	c.CallTimeout = 5 * time.Second
	e, err := exchange.New(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	return e
}
func exchangeWrap(t *testing.T, key *nostr.PrivKey, recipient, text string, work bool) *nostr.Event {
	t.Helper()
	r := &nostr.Event{PubKey: key.PubKeyHex(), CreatedAt: nowMid, Kind: nostr.KindRumor, Content: text, Tags: [][]string{{"p", recipient}}}
	if work {
		r.Tags = append(r.Tags, []string{"nonce", "0", "4"})
		for n := 0; ; n++ {
			r.Tags[1][1] = strconv.Itoa(n)
			r.ID = r.ComputeID()
			if exchange.CheckWork(r, 4) {
				break
			}
		}
	} else {
		r.ID = r.ComputeID()
	}
	w, err := nostr.GiftWrap(r, key, recipient, nowMid)
	if err != nil {
		t.Fatal(err)
	}
	return w
}
func enteredExchange(t *testing.T, s *slowExchange) {
	t.Helper()
	select {
	case <-s.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("exchange worker did not enter catalogue")
	}
}

// Unknown signed senders cannot screen/start a station. A blocked worker plus
// full queue drops further strangers without blocking a live, PoW-free grantee.
// The kernel and station driver are fixtures; genuine-Core admission is separate.
func TestExchangeQueueIsolationAndGranteeBypass(t *testing.T) {
	s := &slowExchange{entered: make(chan struct{}), release: make(chan struct{})}
	e := exchangeEngine(t, s)
	h := newHarness(t, harnessOpts{exchange: e, agentName: e.AgentName(), skipStart: true})
	stranger, _ := nostr.GeneratePrivKey()
	r := h.handle(exchangeWrap(t, stranger, h.agent.PubKeyHex(), "terms", true))
	if !r.ExchangeQueued || r.Delivered {
		t.Fatalf("exchange admission: %+v", r)
	}
	enteredExchange(t, s)
	// One queued slot is consumed; neither this sender nor new keys may block.
	r = h.handle(exchangeWrap(t, stranger, h.agent.PubKeyHex(), "flood-1", false))
	if !r.ExchangeQueued {
		t.Fatalf("queue valid neighbour: %+v", r)
	}
	for i := 0; i < 12; i++ {
		key := stranger
		if i%2 == 0 {
			key, _ = nostr.GeneratePrivKey()
		}
		r = h.handle(exchangeWrap(t, key, h.agent.PubKeyHex(), strconv.Itoa(i), true))
		if !r.Refused || r.ExchangeQueued || r.Delivered {
			t.Fatalf("full exchange queue did not drop: %+v", r)
		}
	}
	slot, _ := h.store.Get("slot-1")
	if slot.Started || h.scr.Calls != 0 || h.kern.Calls != 0 {
		t.Fatal("non-grantee reached instance, model, or kernel")
	}
	r = h.handle(h.renterDM("live without proof of work", nowMid))
	if !r.Delivered || r.ExchangeQueued {
		t.Fatalf("live grantee throttled by exchange: %+v", r)
	}
	c, conn := h.stationClient()
	defer conn.Close()
	f := pull(t, c)
	if f.Content != "live without proof of work" {
		t.Fatalf("wrong delivery: %+v", f)
	}
	if h.scr.Calls != 1 {
		t.Fatal("exchange traffic reached screening")
	}
	close(s.release)
}

// A real localhost relay supplies an inbound event and independent OKs on the
// same socket. Blocking catalogue work must not occupy RelayClient's read pump.
func TestExchangeSlowBackendDoesNotBlockRelayACK(t *testing.T) {
	s := &slowExchange{entered: make(chan struct{}), release: make(chan struct{})}
	e := exchangeEngine(t, s)
	h := newHarness(t, harnessOpts{exchange: e, agentName: e.AgentName(), skipRegister: true})
	relay, err := testrelay.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	client := &gateway.RelayClient{URL: relay.URL}
	defer client.Close()
	sender := &gateway.RelayClient{URL: relay.URL}
	defer sender.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stranger, _ := nostr.GeneratePrivKey()
	// Publish before subscribing: the test relay replays stored matches, avoiding
	// a timing-based subscription-readiness assumption.
	if err = sender.Publish(ctx, exchangeWrap(t, stranger, h.agent.PubKeyHex(), "terms", true)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- client.SubscribeGiftWraps(ctx, h.agent.PubKeyHex(), func(c context.Context, w *nostr.Event) { h.gw.HandleGiftWrap(c, w) })
	}()
	enteredExchange(t, s)
	ackctx, ackcancel := context.WithTimeout(ctx, time.Second)
	defer ackcancel()
	reply, _, err := nostr.WrapDM(h.agent, stranger.PubKeyHex(), "independent ACK control", nil, nowMid)
	if err != nil {
		t.Fatal(err)
	}
	if err = client.Publish(ackctx, reply); err != nil {
		t.Fatalf("exchange blocked relay ACK: %v", err)
	}
	if h.scr.Calls != 0 {
		t.Fatal("exchange reached model")
	}
	close(s.release)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("relay subscriber did not stop")
	}
}

// Gateway and exchange cannot advertise different agent names with one key.
// The already-constructed correctly bound gateway is the positive neighbour.
func TestExchangeGatewayIdentity(t *testing.T) {
	s := &slowExchange{entered: make(chan struct{}), release: make(chan struct{})}
	e := exchangeEngine(t, s)
	h := newHarness(t, harnessOpts{exchange: e, agentName: e.AgentName(), skipRegister: true})
	_, err := gateway.New(gateway.Config{AgentKey: h.agent, AgentName: "id/wrong", Kernel: h.kern, Screener: h.scr, Journal: h.store, Publisher: h.pub, Driver: h.driver, Exchange: e})
	if err == nil || err.Error() != "gateway: exchange agent name mismatch" {
		t.Fatalf("gateway exchange identity mismatch accepted: %v", err)
	}
	if h.gw.AgentPubKey() != h.agent.PubKeyHex() {
		t.Fatal("valid gateway identity neighbour")
	}
}
