package main

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/journal"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernel"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/station"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/testrelay"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// The actual serve entrypoint destroys an interrupted local-test launch before
// normal service, or returns the fixed startup error if cleanup fails. Real
// booking HTTP and relay fixtures are used, but kernel admission is an explicit
// stub; no Core, remote helper, remembered PID or model API is exercised.
func TestServeStartupRecovery(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "destroy", true: "cleanup_failure"}[fail], func(t *testing.T) {
			c := testConfig(t)
			client, _, _, _, _ := bookingV2Fixture(t, "nmc")
			c.Exchange.BookingURL = client.origin
			c.Exchange.PrivacySHA256 = client.privacy
			c.Exchange.TemplateSHA256 = client.template
			c.Exchange.ProfileSHA256 = client.profile
			key, _ := nostr.GeneratePrivKey()
			c.AgentPubkey = key.PubKeyHex()
			c.Kernel.Kind = "stub"
			c.Kernel.StubVerdict = kernel.Live
			write := func(path string, b []byte, mode os.FileMode) {
				t.Helper()
				if err := os.WriteFile(path, b, 0640); err != nil {
					t.Fatal(err)
				}
			}
			write(c.AgentKeyFile, []byte(hex.EncodeToString(key.Bytes())), 0600)
			write(c.Kernel.RPCRouteFile, jsonCanonical(su.Route{Host: c.Kernel.RPCHost, Port: c.Kernel.RPCPort, Username: "w3-observer", Password: "public-fixture-placeholder"}), 0400)
			if err := os.MkdirAll(c.Exchange.PresentationsDir, 0755); err != nil {
				t.Fatal(err)
			}
			sock, err := os.MkdirTemp("", "startup-sock-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.RemoveAll(sock) })
			sock, err = filepath.EvalSymlinks(sock)
			if err != nil {
				t.Fatal(err)
			}
			c.StationSocket = filepath.Join(sock, "s.sock")
			relay, err := testrelay.Start()
			if err != nil {
				t.Fatal(err)
			}
			defer relay.Close()
			c.RelayURL = relay.URL
			j, err := journal.Open(c.JournalDir)
			if err != nil {
				t.Fatal(err)
			}
			if err = j.Put(&journal.Slot{ID: "interrupted", StationName: "id/interrupted", RenterPubKey: strings.Repeat("a", 64), NotBefore: 1, NotAfter: 2}); err != nil {
				t.Fatal(err)
			}
			driver := &station.LocalTestDriver{Root: c.Station.Root}
			st, err := driver.Create(context.Background(), station.SlotSpec{SlotID: "interrupted", StationName: "id/interrupted"})
			if err != nil {
				t.Fatal(err)
			}
			if err = j.SetChannelSecret(st.SlotID, hex.EncodeToString(st.ChannelSecret), ""); err != nil {
				t.Fatal(err)
			}
			if err = j.SetStationHandle(st.SlotID, st.Home, st.User); err != nil {
				t.Fatal(err)
			}
			if err = j.MarkStarting(st.SlotID); err != nil {
				t.Fatal(err)
			}
			if fail {
				if err = os.Chmod(st.Home, 0500); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(st.Home, 0700) })
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err = serve(ctx, c)
			if fail {
				if err == nil || err.Error() != "GATEWAY_START_RECOVERY" {
					t.Fatalf("serve ignored failed start recovery: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			j, err = journal.Open(c.JournalDir)
			if err != nil {
				t.Fatal(err)
			}
			s, _ := j.Get(st.SlotID)
			if !s.Ended || s.Started || s.ChannelSecretHex != "" || s.Starting != fail || s.Destroyed == fail {
				t.Fatal("serve skipped interrupted launch recovery")
			}
			if !fail {
				if _, err = os.Stat(st.Home); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("recovered station home retained")
				}
			}
		})
	}
}
