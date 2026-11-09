package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	pc "github.com/relux-works/swarma-chain-lab/experiments/payment-chain"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	booking "github.com/relux-works/swarma-chain-lab/experiments/rental-booking"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/exchange"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/gateway"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/journal"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/testrelay"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// Genuine pinned Core, the actual serve CLI, real HTTP booking/consent/payment
// watcher, actual V2 exporter and SG1 custody loop prove the full encrypted exchange-to-station route.
// Local-test is explicit and screening is off; this does not execute LinuxUser.
// Foreign consent and pre-grant messages create no station. A real spent seal
// closes the cached grant and cannot deliver a second station message.
func TestCoreServe(t *testing.T) {
	if os.Getenv("GW1_REGTEST") != "1" {
		t.Skip("requires explicit genuine Core GW1_REGTEST=1")
	}
	agent, _ := nostr.GeneratePrivKey()
	renter, _ := nostr.GeneratePrivKey()
	provider, _ := nostr.GeneratePrivKey()
	l := newCoreLab(t, agent.PubKeyHex())
	mkdir := func(name string) string {
		t.Helper()
		p := filepath.Join(l.private, name)
		if e := os.Mkdir(p, 0700); e != nil {
			t.Fatal(e)
		}
		return p
	}
	write := func(path string, raw []byte, mode os.FileMode) {
		t.Helper()
		if e := os.WriteFile(path, raw, mode); e != nil {
			t.Fatal(e)
		}
	}
	binary := filepath.Join(l.private, "gateway")
	buildctx, buildcancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer buildcancel()
	build := exec.CommandContext(buildctx, "go", "build", "-race", "-trimpath", "-buildvcs=false", "-o", binary, ".")
	build.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOWORK=off", "GOPROXY=off")
	if e := build.Run(); e != nil {
		l.recordCmd(build)
		t.Fatal("actual CLI build", e)
	}
	l.recordCmd(build)
	relay, e := testrelay.Start()
	if e != nil {
		t.Fatal(e)
	}
	defer relay.Close()
	master, e := hdkeychain.NewMaster([]byte("public-gw1-core-booking-fixture!!"), &chaincfg.RegressionNetParams)
	if e != nil {
		t.Fatal(e)
	}
	public, e := master.Neuter()
	if e != nil {
		t.Fatal(e)
	}
	profile := []byte("public CLI laboratory profile\n")
	tmpl := booking.Template{Version: 1, ID: "demo", ProfileID: "lab", ProfileVersion: "1", ProfileSHA256: booking.Hash(profile), Allowed: []string{"deliver", "pay"}, Forbidden: []string{"publish", "repository.push", "secret.release"}, BudgetSat: 1000000}
	now := time.Now().Unix()
	cfg := booking.ConfigV2{StateDir: mkdir("booking"), AgentPubkey: agent.PubKeyHex(), ProviderPubkey: provider.PubKeyHex(), HoldSeconds: 1200, PriceUSDCents: 100, Template: tmpl, TemplateSHA256: booking.Hash(jsonCanonical(tmpl)), Slots: []booking.Slot{{ID: "one", StationName: e2eAgentName, NotBefore: now + 45, NotAfter: now + 600, PaymentPolicy: "advance"}}, Coins: map[string]booking.CoinConfig{"nmc": {PublicBranch: public.String(), PublicBranchSHA256: booking.Hash([]byte(public.String())), USDMicrosPerCoin: 100000000, RateAsOf: now, MaxRateAgeSeconds: 7200, MinConfirmations: 2}}, Limits: booking.Limits{MaxBlocks: 512, MaxMempool: 2000, MaxCalls: 10000, MaxBytes: 64 << 20}}
	pk, _ := btcec.PrivKeyFromBytes(provider.Bytes())
	paymentNode, e := pc.NewRPC(pc.Route{Host: l.route.Host, Port: l.route.Port, Username: "payment-observer", Password: l.route.Password})
	if e != nil {
		t.Fatal(e)
	}
	service, e := booking.NewServiceV2(cfg, profile, pk, map[string]booking.Node{"nmc": paymentNode}, l.observer, packagePublisher{}, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	defer service.Close()
	server := httptest.NewUnstartedServer(nil)
	handler, e := booking.NewHTTPHandlerV2(service, "http://"+server.Listener.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	server.Config.Handler = handler
	server.Start()
	defer server.Close()
	c := testConfig(t)
	// A short owned directory is necessary for macOS Unix socket path limits.
	socketDir, e := os.MkdirTemp("", "gw-cli-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(socketDir)
	socketDir, e = filepath.EvalSymlinks(socketDir)
	if e != nil {
		t.Fatal(e)
	}
	c.AgentPubkey = agent.PubKeyHex()
	c.AgentKeyFile = filepath.Join(l.private, "agent.key")
	c.RelayURL = relay.URL
	c.JournalDir = filepath.Join(l.private, "journal")
	c.StationSocket = filepath.Join(socketDir, "s.sock")
	c.Kernel.AgentName = e2eAgentName
	c.Kernel.LandlordName = e2eLandlordName
	c.Kernel.IssuerPubkey = l.issuerPub
	c.Kernel.SealScript, e = rental.GrantSealScript(l.issuerPub)
	if e != nil {
		t.Fatal(e)
	}
	c.Kernel.StateDir = filepath.Join(l.private, "kernel")
	c.Kernel.RPCHost = l.route.Host
	c.Kernel.RPCPort = l.route.Port
	c.Kernel.RPCRouteFile = filepath.Join(l.private, "observer.json")
	c.Exchange.BookingVersion = 2
	c.Exchange.StateDir = filepath.Join(l.private, "exchange")
	c.Exchange.BookingURL = server.URL
	c.Exchange.PresentationsDir = mkdir("presentations")
	if e = os.Chmod(c.Exchange.PresentationsDir, 0755); e != nil {
		t.Fatal(e)
	}
	c.Exchange.TemplateSHA256 = cfg.TemplateSHA256
	c.Exchange.ProfileSHA256 = tmpl.ProfileSHA256
	c.Exchange.Burst = 16
	c.Exchange.MaxReplay = 32
	c.Station.Root = filepath.Join(l.private, "stations")
	c.Station.StubAgent = true
	write(c.AgentKeyFile, []byte(hex.EncodeToString(agent.Bytes())), 0600)
	write(c.Kernel.RPCRouteFile, jsonCanonical(l.route), 0400)
	configPath := filepath.Join(l.private, "gateway.json")
	write(configPath, jsonCanonical(c), 0600)
	logPath := filepath.Join(l.private, "gateway.log")
	log, e := os.OpenFile(logPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer log.Close()
	cmd := exec.Command(binary, "serve", "-config", configPath)
	cmd.Stdout = log
	cmd.Stderr = log
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	l.recordCmd(cmd)
	t.Logf("gateway CLI started pid=%d", cmd.Process.Pid)
	write(filepath.Join(l.root, "gateway.pid"), []byte(strconv.Itoa(cmd.Process.Pid)), 0600)
	stopped := false
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		_ = cmd.Process.Signal(os.Interrupt)
		select {
		case e := <-done:
			if e != nil {
				t.Errorf("gateway CLI exit: %v (private log retained)", e)
			}
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
			<-done
			t.Error("gateway CLI shutdown timeout")
		}
		t.Logf("gateway CLI stopped pid=%d", cmd.Process.Pid)
	}
	defer stop()
	deadline := time.Now().Add(10 * time.Second)
	for {
		b, _ := os.ReadFile(logPath)
		if strings.Contains(string(b), "screening=off mode=test kernel=real station=local-test") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("gateway startup missing (private log retained)")
		}
		time.Sleep(20 * time.Millisecond)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	peer := &gateway.RelayClient{URL: relay.URL}
	defer peer.Close()
	inbox := make(chan *nostr.Event, 64)
	subDone := make(chan error, 1)
	go func() {
		subDone <- peer.SubscribeGiftWraps(ctx, renter.PubKeyHex(), func(_ context.Context, ev *nostr.Event) {
			select {
			case inbox <- ev:
			default:
				t.Error("test response inbox overflow")
			}
		})
	}()
	defer func() {
		cancel()
		peer.Close()
		select {
		case <-subDone:
		case <-time.After(time.Second):
			t.Error("test subscriber leaked")
		}
	}()
	send := func(key *nostr.PrivKey, text string, work bool, tags [][]string) {
		t.Helper()
		r := &nostr.Event{PubKey: key.PubKeyHex(), CreatedAt: time.Now().Unix(), Kind: nostr.KindRumor, Content: text, Tags: append([][]string{{"p", agent.PubKeyHex()}}, tags...)}
		if work {
			r.Tags = append(r.Tags, []string{"nonce", "0", "4"})
			for n := 0; ; n++ {
				r.Tags[len(r.Tags)-1][1] = strconv.Itoa(n)
				r.ID = r.ComputeID()
				if exchange.CheckWork(r, 4) {
					break
				}
			}
		} else {
			r.ID = r.ComputeID()
		}
		wrap, e := nostr.GiftWrap(r, key, agent.PubKeyHex(), time.Now().Unix())
		if e != nil {
			t.Fatal(e)
		}
		callctx, callcancel := context.WithTimeout(ctx, 3*time.Second)
		defer callcancel()
		if e = peer.Publish(callctx, wrap); e != nil {
			t.Fatal("peer publish", e)
		}
	}
	receive := func(prefix string) string {
		t.Helper()
		timer := time.NewTimer(10 * time.Second)
		defer timer.Stop()
		for {
			select {
			case ev := <-inbox:
				u, e := nostr.UnwrapDM(ev, renter)
				if e != nil || u.SenderHex != agent.PubKeyHex() {
					t.Fatal("response identity")
				}
				if strings.HasPrefix(u.Rumor.Content, prefix) {
					return u.Rumor.Content
				}
				t.Fatalf("unexpected response type %q while waiting for %q", strings.SplitN(u.Rumor.Content, "\n", 2)[0], prefix)
			case <-timer.C:
				t.Fatalf("missing response %q (private log retained)", prefix)
			}
		}
	}
	send(renter, "terms", true, nil)
	var terms exchange.Terms
	if json.Unmarshal([]byte(strings.TrimPrefix(receive("terms\n"), "terms\n")), &terms) != nil || len(terms.Slots) != 1 {
		t.Fatal("terms shape")
	}
	entries, e := os.ReadDir(c.Station.Root)
	if e != nil || len(entries) != 0 {
		t.Fatal("non-grantee started station")
	}
	send(renter, "book demo one nmc", false, nil)
	var reply struct {
		BookingID string `json:"booking_id"`
		Hash      string `json:"contract_sha256"`
		Contract  string `json:"contract_base64"`
	}
	if json.Unmarshal([]byte(strings.TrimPrefix(receive("contract\n"), "contract\n")), &reply) != nil {
		t.Fatal("contract response")
	}
	raw, e := base64.StdEncoding.DecodeString(reply.Contract)
	if e != nil {
		t.Fatal(e)
	}
	var contract booking.ContractV2
	if booking.Strict(raw, &contract) != nil || contract.Hash() != reply.Hash || contract.BookingID != reply.BookingID || contract.RenterPubkey != renter.PubKeyHex() {
		t.Fatal("contract binding")
	}
	wrong, _ := nostr.GeneratePrivKey()
	wk, _ := btcec.PrivKeyFromBytes(wrong.Bytes())
	bad := booking.ConsentV2(contract, time.Now().Unix())
	if e = bad.Sign(wk); e != nil {
		t.Fatal(e)
	}
	send(renter, "consent "+string(jsonCanonical(bad)), false, nil)
	if receive(exchange.Help) != exchange.Help {
		t.Fatal("foreign consent response")
	}
	before, e := service.Get(contract.BookingID)
	if e != nil || before.Package != nil {
		t.Fatal("foreign consent changed booking")
	}
	rk, _ := btcec.PrivKeyFromBytes(renter.Bytes())
	consent := booking.ConsentV2(contract, time.Now().Unix())
	if e = consent.Sign(rk); e != nil {
		t.Fatal(e)
	}
	send(renter, "consent "+string(jsonCanonical(consent)), false, nil)
	var pay struct {
		Address          string `json:"address"`
		Amount           int64  `json:"amount_atomic"`
		Coin             string `json:"coin"`
		MinConfirmations int64  `json:"min_confirmations"`
	}
	if json.Unmarshal([]byte(strings.TrimPrefix(receive("pay\n"), "pay\n")), &pay) != nil || pay.Address != contract.Payment.Address || pay.Amount != contract.Payment.AmountAtoms || pay.Coin != "nmc" || pay.MinConfirmations != 2 {
		t.Fatal("pay binding")
	}
	l.rpc("issuer", "sendtoaddress", pay.Address, su.Coins(pay.Amount))
	l.mine(1)
	if e = service.Refresh(ctx); e != nil {
		t.Fatal(e)
	}
	under, e := service.Get(contract.BookingID)
	if e != nil || under.Issuance != nil {
		t.Fatal("underconfirmed payment issued")
	}
	l.mine(1)
	if e = service.Refresh(ctx); e != nil {
		t.Fatal(e)
	}
	b, e := service.Get(contract.BookingID)
	if e != nil || b.Issuance == nil {
		t.Fatal("real payment missing issuance")
	}
	proof := l.issueBookingV2(b, provider.PubKeyHex(), cfg.StateDir, c.Exchange.PresentationsDir)
	receive("issued\n")
	snapshot := func() *journal.Slot {
		t.Helper()
		s, e := journal.Open(c.JournalDir)
		if e != nil {
			t.Fatal(e)
		}
		v, ok := s.Get(contract.BookingID)
		if !ok {
			t.Fatal("journal slot absent")
		}
		return v
	}
	if snapshot().Started {
		t.Fatal("issuance started station")
	}
	for time.Now().Unix() < contract.NotBefore {
		time.Sleep(50 * time.Millisecond)
	}
	receive("ready")
	tag, e := gateway.GrantCertTag(proof)
	if e != nil {
		t.Fatal(e)
	}
	send(renter, "genuine CLI delivery", false, [][]string{tag})
	receive("echo: genuine CLI delivery")
	slot := snapshot()
	if !slot.Started || len(slot.SeenRumorIDs) != 1 || slot.Refusals != 0 {
		t.Fatal("live delivery journal")
	}
	parsed, e := rental.ParseGrantPresentation(proof)
	if e != nil {
		t.Fatal(e)
	}
	l.revoke(parsed.SignedGrant.Grant.Seal)
	send(renter, "must never reach station", false, nil)
	deadline = time.Now().Add(10 * time.Second)
	for !snapshot().Ended {
		if time.Now().After(deadline) {
			t.Fatal("spent seal did not close slot")
		}
		time.Sleep(20 * time.Millisecond)
	}
	slot = snapshot()
	if len(slot.SeenRumorIDs) != 1 {
		t.Fatal("spent seal delivered/burned rumor")
	}
	stop()
	data, e := os.ReadFile(logPath)
	if e != nil {
		t.Fatal(e)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "gateway: test station pid=") {
			pid, e := strconv.Atoi(strings.TrimPrefix(line, "gateway: test station pid="))
			if e != nil || pid <= 0 {
				t.Fatal("invalid owned child PID")
			}
			l.pids[pid] = true
		}
	}
	if strings.Contains(string(data), "DATA RACE") || strings.Contains(string(data), hex.EncodeToString(agent.Bytes())) || strings.Contains(string(data), l.route.Password) {
		t.Fatal("race or credential logging")
	}
	t.Log("actual CLI: exchange, foreign-consent refusal, real V2 payment/exporter/SG1 issuance, station echo and fresh spent-seal closure pass")
}
