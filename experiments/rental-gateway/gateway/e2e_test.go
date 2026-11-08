package gateway_test

import (
	"context"
	"encoding/hex"
	"net"
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
	"relux.works/swarma-chain-lab/experiments/rental-gateway/testrelay"
)

// TestStationStubProcess is not a test in the parent run: the
// local-test driver re-executes this test binary as the scripted
// station child process when M2_STATION_STUB_PROCESS=1.
func TestStationStubProcess(t *testing.T) {
	if os.Getenv("M2_STATION_STUB_PROCESS") != "1" {
		t.Skip("child-process stub only")
	}
	conn, err := net.Dial("unix", os.Getenv("GATEWAY_SOCKET"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	c := stationlink.NewClient(conn)
	secretRaw, err := os.ReadFile(os.Getenv("CHANNEL_SECRET_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	secret, err := hex.DecodeString(strings.TrimSpace(string(secretRaw)))
	if err != nil {
		t.Fatal(err)
	}
	sys, err := c.Hello(os.Getenv("SLOT_ID"), os.Getenv("STATION_NAME"), secret)
	if err != nil || sys.Type != stationlink.TypeSystem {
		t.Fatalf("hello = %+v %v", sys, err)
	}
	for {
		f, err := c.Pull()
		if err != nil {
			t.Fatal(err)
		}
		switch f.Type {
		case stationlink.TypeDeliver:
			if _, err := c.Reply("echo: " + f.Content); err != nil {
				t.Fatal(err)
			}
		case stationlink.TypeEnd:
			return
		}
	}
}

// TestStubProcessEndToEnd proves the local-test driver runs a real
// child-process station that dials the gateway itself, receives a
// delivery and replies; the renter gets the echo signed by the agent.
func TestStubProcessEndToEnd(t *testing.T) {
	t.Setenv("M2_STATION_STUB_PROCESS", "1")
	h := newHarness(t, harnessOpts{stubCmd: []string{os.Args[0],
		"-test.run=^TestStationStubProcess$", "-test.count=1"}})
	defer func() { _, _ = h.gw.DestroySlot(context.Background(), "slot-1") }()
	res := h.handle(h.renterDM("ping via process", nowMid))
	if !res.Delivered {
		t.Fatalf("delivery refused: %+v", res)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, dm := range h.pub.dmsTo(h.renter) {
			if dm == "echo: ping via process" {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("no echo from stub process; renter DMs = %v", h.pub.dmsTo(h.renter))
}

// TestRelayEndToEnd proves the whole local loop through the
// in-process test relay: renter publishes a gift wrap, the gateway
// (subscribed as the agent) routes it to the station, the station
// reply returns through the relay to the renter. The genuine-Core
// regtest twin of this test stays pending until M1's kernel binds
// (kernelbind); here the stub kernel stands in, by design.
func TestRelayEndToEnd(t *testing.T) {
	relay, err := testrelay.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()

	agent, _ := nostr.GeneratePrivKey()
	renter, _ := nostr.GeneratePrivKey()
	store, err := journal.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	relayClient := &gateway.RelayClient{URL: relay.URL}
	sockDir, _ := os.MkdirTemp("", "gw")
	defer os.RemoveAll(sockDir)
	sockPath := sockDir + "/s.sock"
	clock := &testClock{t: nowMid}
	gw, err := gateway.New(gateway.Config{
		AgentKey: agent, Kernel: &kernel.Stub{Verdict: kernel.Live},
		Screener: &screen.Stub{}, Journal: store, Publisher: relayClient,
		Driver: &station.LocalTestDriver{Root: t.TempDir()}, Endpoint: sockPath,
		PullTimeout: 200 * time.Millisecond, Now: clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := relayClient.Dial(ctx); err != nil {
		t.Fatal(err)
	}
	go func() {
		_ = relayClient.SubscribeGiftWraps(ctx, gw.AgentPubKey(),
			func(ctx context.Context, ev *nostr.Event) { gw.HandleGiftWrap(ctx, ev) })
	}()
	if err := gw.RegisterSlot(gateway.SlotSpec{
		ID: "slot-1", StationName: "id/swarma-station-1",
		RenterPubKey: renter.PubKeyHex(), Certificate: []byte("cert"),
		ContractSHA256: strings.Repeat("b", 64),
		NotBefore:      slotNotBefore, NotAfter: slotNotAfter,
	}); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() { _ = gw.ServeStations(ln) }()
	if err := gw.StartSlot(ctx, "slot-1"); err != nil {
		t.Fatal(err)
	}

	// Station side (simulated process): hello, then answer one delivery.
	stationDone := make(chan error, 1)
	go func() {
		conn, err := net.Dial("unix", sockPath)
		if err != nil {
			stationDone <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		c := stationlink.NewClient(conn)
		slotRec, _ := store.Get("slot-1")
		secret, _ := hex.DecodeString(slotRec.ChannelSecretHex)
		if _, err := c.Hello("slot-1", "id/swarma-station-1", secret); err != nil {
			stationDone <- err
			return
		}
		for {
			f, err := c.Pull()
			if err != nil {
				stationDone <- err
				return
			}
			if f.Type == stationlink.TypeDeliver {
				_, err = c.Reply("relay echo: " + f.Content)
				stationDone <- err
				return
			}
		}
	}()

	// Renter side: collect DMs addressed to the renter from the relay.
	renterClient := &gateway.RelayClient{URL: relay.URL}
	if err := renterClient.Dial(ctx); err != nil {
		t.Fatal(err)
	}
	got := make(chan string, 4)
	go func() {
		_ = renterClient.SubscribeGiftWraps(ctx, renter.PubKeyHex(),
			func(ctx context.Context, ev *nostr.Event) {
				if u, err := nostr.UnwrapDM(ev, renter); err == nil {
					got <- u.Rumor.Content
				}
			})
	}()
	// Give the renter subscription a moment, then send the DM.
	time.Sleep(200 * time.Millisecond)
	wrap, _, err := nostr.WrapDM(renter, agent.PubKeyHex(), "hello through relay", nil, nowMid)
	if err != nil {
		t.Fatal(err)
	}
	publisher := &gateway.RelayClient{URL: relay.URL}
	if err := publisher.Dial(ctx); err != nil {
		t.Fatal(err)
	}
	if err := publisher.Publish(ctx, wrap); err != nil {
		t.Fatal(err)
	}
	seenReady, seenEcho := false, false
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) && !(seenReady && seenEcho) {
		select {
		case content := <-got:
			seenReady = seenReady || content == "ready"
			seenEcho = seenEcho || content == "relay echo: hello through relay"
		case <-time.After(100 * time.Millisecond):
		}
	}
	if err := <-stationDone; err != nil {
		t.Fatalf("station: %v", err)
	}
	if !seenEcho {
		t.Fatalf("renter never received relay echo (ready seen: %v)", seenReady)
	}
}
