package main

import (
	"context"
	"encoding/hex"
	"github.com/gorilla/websocket"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/journal"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Actual serve keeps its Tick alive through initial unavailability and repeated
// post-upgrade drops. A pre-existing started slot reaches durable End/not_after;
// a future neighbor remains live. Kernel/booking node are explicit stubs, and
// no remote destruction, Core, or physical wipe is inferred from this journal test.
func TestServeExpiryDuringRelayOutage(t *testing.T) {
	for _, upgrade := range []bool{false, true} {
		t.Run(map[bool]string{false: "unavailable", true: "drops"}[upgrade], func(t *testing.T) {
			var calls atomic.Int32
			relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if !upgrade {
					http.Error(w, "unavailable", 503)
					return
				}
				c, e := (&websocket.Upgrader{}).Upgrade(w, r, nil)
				if e == nil {
					c.Close()
				}
			}))
			defer relay.Close()
			booking, _, _, _, _ := bookingV2Fixture(t, "nmc")
			c := testConfig(t)
			agent, _ := nostr.GeneratePrivKey()
			c.AgentPubkey = agent.PubKeyHex()
			c.RelayURL = "ws" + strings.TrimPrefix(relay.URL, "http")
			c.Kernel.Kind = "stub"
			c.Kernel.StubVerdict = "live"
			c.Exchange.BookingURL = booking.origin
			c.Exchange.PrivacySHA256 = booking.privacy
			c.Exchange.TemplateSHA256 = booking.template
			c.Exchange.ProfileSHA256 = booking.profile
			short, e := os.MkdirTemp("", "rk1-expiry-")
			if e != nil {
				t.Fatal(e)
			}
			defer os.RemoveAll(short)
			short, e = filepath.EvalSymlinks(short)
			if e != nil {
				t.Fatal(e)
			}
			c.StationSocket = filepath.Join(short, "s.sock")
			writeInstalled(t, c.AgentKeyFile, []byte(hex.EncodeToString(agent.Bytes())))
			writeInstalled(t, c.Kernel.RPCRouteFile, jsonCanonical(su.Route{Host: c.Kernel.RPCHost, Port: c.Kernel.RPCPort, Username: "w3-observer", Password: "fixture-only-not-a-live-route"}))
			if e = os.Mkdir(c.Exchange.PresentationsDir, 0755); e != nil {
				t.Fatal(e)
			}
			store, e := journal.Open(c.JournalDir)
			if e != nil {
				t.Fatal(e)
			}
			now := time.Now().Unix()
			renter, _ := nostr.GeneratePrivKey()
			future, _ := nostr.GeneratePrivKey()
			for _, slot := range []*journal.Slot{{ID: "expiry", StationName: "fixture", RenterPubKey: renter.PubKeyHex(), Started: true, NotBefore: now - 10, NotAfter: now + 2, ChannelSecretHex: journal.NewChannelSecretHex(strings.Repeat("a", 64))}, {ID: "future", StationName: "fixture", RenterPubKey: future.PubKeyHex(), Started: true, NotBefore: now - 10, NotAfter: now + 100, ChannelSecretHex: journal.NewChannelSecretHex(strings.Repeat("b", 64))}} {
				if e = store.Put(slot); e != nil {
					t.Fatal(e)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- serve(ctx, c) }()
			defer func() {
				cancel()
				select {
				case e := <-done:
					if e != nil {
						t.Error("serve cancellation", e)
					}
				case <-time.After(3 * time.Second):
					t.Error("serve outage shutdown leaked")
				}
			}()
			deadline := time.Now().Add(5 * time.Second)
			for {
				select {
				case e := <-done:
					done <- e
					t.Fatal("relay outage killed expiry worker", e)
				default:
				}
				fresh, e := journal.Open(c.JournalDir)
				if e != nil {
					t.Fatal(e)
				}
				s, _ := fresh.Get("expiry")
				neighbor, _ := fresh.Get("future")
				if s.Ended {
					if s.EndReason != "not_after" || s.ChannelSecretHex.Reveal() != "" || neighbor.Ended || neighbor.ChannelSecretHex.Reveal() == "" || calls.Load() < 2 {
						t.Fatal("expiry or neighboring slot invariant")
					}
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("relay outage starved expiry End")
				}
				time.Sleep(10 * time.Millisecond)
			}
		})
	}
}
