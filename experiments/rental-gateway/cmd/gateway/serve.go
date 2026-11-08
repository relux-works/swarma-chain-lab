package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"relux.works/swarma-chain-lab/experiments/rental-gateway/gateway"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/journal"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/kernel"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/nostr"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/screen"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/station"
)

type slotFile struct {
	ID             string `json:"id"`
	StationName    string `json:"station_name"`
	RenterPubKey   string `json:"renter_pubkey"`
	CertificateB64 string `json:"certificate_b64"`
	ContractSHA256 string `json:"contract_sha256"`
	NotBefore      int64  `json:"not_before"`
	NotAfter       int64  `json:"not_after"`
	StartNow       bool   `json:"start_now"`
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	keyPath := fs.String("key", "", "agent key file (0600)")
	journalDir := fs.String("journal", "", "journal directory")
	relayURL := fs.String("relay", "", "relay websocket URL")
	stationUnix := fs.String("station-unix", "", "unix socket path for station-initiated connections")
	slotPath := fs.String("slot-file", "", "optional slot JSON to register (and start when start_now)")
	stubVerdict := fs.String("stub-verdict", kernel.Live, "stub kernel verdict (live|pending|refused) until M1 binds")
	stationsRoot := fs.String("stations-root", "", "local-test station root directory")
	stubAgent := fs.Bool("stub-agent", false, "launch `gateway station-stub` (this binary) per station")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" || *journalDir == "" || *relayURL == "" || *stationUnix == "" || *stationsRoot == "" {
		return fmt.Errorf("-key, -journal, -relay, -station-unix and -stations-root are required")
	}
	agentKey, err := gateway.LoadAgentKey(*keyPath)
	if err != nil {
		return err
	}
	store, err := journal.Open(*journalDir)
	if err != nil {
		return err
	}
	relay := &gateway.RelayClient{URL: *relayURL}
	ctx := context.Background()
	if err := relay.Dial(ctx); err != nil {
		return fmt.Errorf("relay dial: %w", err)
	}
	driver := &station.LocalTestDriver{Root: *stationsRoot}
	if *stubAgent {
		self, err := os.Executable()
		if err != nil {
			return err
		}
		driver.StubCommand = []string{self, "station-stub"}
	}
	gw, err := gateway.New(gateway.Config{
		AgentKey:  agentKey,
		Kernel:    &kernel.Stub{Verdict: *stubVerdict},
		Screener:  &screen.Stub{},
		Journal:   store,
		Publisher: relay,
		Driver:    driver,
		Endpoint:  *stationUnix,
	})
	if err != nil {
		return err
	}
	var startSlotID string
	if *slotPath != "" {
		raw, err := os.ReadFile(*slotPath)
		if err != nil {
			return err
		}
		var sf slotFile
		if err := json.Unmarshal(raw, &sf); err != nil {
			return err
		}
		cert, err := base64.StdEncoding.DecodeString(sf.CertificateB64)
		if err != nil {
			return err
		}
		if err := gw.RegisterSlot(gateway.SlotSpec{
			ID: sf.ID, StationName: sf.StationName, RenterPubKey: sf.RenterPubKey,
			Certificate: cert, ContractSHA256: sf.ContractSHA256,
			NotBefore: sf.NotBefore, NotAfter: sf.NotAfter,
		}); err != nil {
			return err
		}
		if sf.StartNow {
			startSlotID = sf.ID
		}
	}
	// Listen before starting any station: stations dial the gateway,
	// so the socket must exist when their processes launch.
	_ = os.Remove(*stationUnix)
	ln, err := net.Listen("unix", *stationUnix)
	if err != nil {
		return err
	}
	defer ln.Close()
	go func() {
		for {
			gw.Tick(ctx)
			time.Sleep(time.Second)
		}
	}()
	go func() { _ = gw.ServeStations(ln) }()
	if startSlotID != "" {
		if err := gw.StartSlot(ctx, startSlotID); err != nil {
			return err
		}
	}
	fmt.Fprintf(os.Stderr, "gateway: agent %s serving (pid %d)\n", gw.AgentPubKey(), os.Getpid())
	err = relay.SubscribeGiftWraps(ctx, gw.AgentPubKey(), func(ctx context.Context, ev *nostr.Event) {
		res := gw.HandleGiftWrap(ctx, ev)
		fmt.Fprintf(os.Stderr, "gateway: inbound slot=%s delivered=%v refused=%v reason=%s\n",
			res.SlotID, res.Delivered, res.Refused, res.Reason)
	})
	return err
}
