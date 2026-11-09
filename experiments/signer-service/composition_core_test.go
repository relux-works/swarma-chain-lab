package signerservice

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pc "github.com/relux-works/swarma-chain-lab/experiments/payment-chain"
	rental "github.com/relux-works/swarma-chain-lab/experiments/rental"
	booking "github.com/relux-works/swarma-chain-lab/experiments/rental-booking"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/presentationdir"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// The exact built booking CLI serves real HTTP and watches an isolated genuine
// BTC node. Its unmodified exported index feeds SG1/P1 on a separate NMC node;
// confirmed atomic publication is consumed by the command's actual gateway
// reader. Library fixtures cover all three coins; this process composition uses
// BTC only. No real wallet, host allocation or deployment adapter is involved.
func TestCoreBookingComposition(t *testing.T) {
	if os.Getenv("SG1_REGTEST") != "1" {
		t.Skip("explicit genuine Core SG1_REGTEST=1 required")
	}
	binary := os.Getenv("BG1_BOOKING_CLI")
	if !filepath.IsAbs(binary) {
		t.Fatal("absolute BG1_BOOKING_CLI required")
	}
	binaryRaw, e := os.ReadFile(binary)
	if e != nil {
		t.Fatal("booking CLI unavailable")
	}
	l := newCore(t)
	lab := newPaymentCoreLab(t, "btc")
	ctx := context.Background()
	seal, fund := l.fund("seal", 200000), l.fund("funding", 2000000)
	now := time.Now().Unix()
	cfg, profile := serviceBookingConfig(t, l, "btc", now)
	cfg.Slots[0].NotBefore = now + 3600
	cfg.Slots[0].NotAfter = now + 7200
	cc := cfg.Coins["btc"]
	cc.MaxRateAgeSeconds = 600
	cfg.Coins["btc"] = cc
	routes := filepath.Join(l.private, "payment-route.json")
	write(t, routes, encode(lab.readRoute))
	configPath := filepath.Join(l.private, "booking-config.json")
	write(t, configPath, encode(map[string]any{"service_version": 2, "config": cfg, "payment_route_files": map[string]string{"btc": routes}}))
	profilePath := filepath.Join(l.private, "profile.txt")
	write(t, profilePath, profile)
	provider, _, _ := testKey(4)
	keyPath := filepath.Join(l.private, "provider.key")
	write(t, keyPath, []byte(hex.EncodeToString(provider.Serialize())))
	identityPath := filepath.Join(l.private, "identity-route.json")
	write(t, identityPath, encode(su.OperatorRoute{Network: "regtest", Genesis: su.RegtestGenesis, NodeCLI: l.cli, NodeCLISHA256: "5cccdfe19aef6b427373c200bda72d4dd66b5be2c5f93b7e8b08b9d6a81fdd4d", NodeConfig: l.conf, NodeDataDir: l.private}))
	relay, e := booking.NewLocalRelay(dir(t))
	if e != nil {
		t.Fatal(e)
	}
	defer relay.Close()
	relayServer := httptest.NewServer(relay)
	defer relayServer.Close()
	args := []string{"-config", configPath, "-profile", profilePath, "-provider-key", keyPath, "-route", identityPath, "-listen", "127.0.0.1:0", "-relay", "ws" + strings.TrimPrefix(relayServer.URL, "http"), "-poll", "1s"}
	starts := 0
	start := func() (string, func()) {
		t.Helper()
		starts++
		cmd := exec.Command(binary, args...)
		log, e := os.OpenFile(filepath.Join(l.private, "booking-process-"+string(rune('0'+starts))+".log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			t.Fatal(e)
		}
		cmd.Stderr = log
		out, e := cmd.StdoutPipe()
		if e != nil {
			t.Fatal(e)
		}
		if e = cmd.Start(); e != nil {
			t.Fatal(e)
		}
		pid := cmd.Process.Pid
		l.events = append(l.events, map[string]any{"booking_start_pid": pid, "binary_sha256": hash(binaryRaw)})
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		stopped := false
		stop := func() {
			t.Helper()
			if stopped {
				return
			}
			stopped = true
			_ = cmd.Process.Signal(os.Interrupt)
			select {
			case e := <-done:
				if e != nil {
					t.Error("booking exit", e)
				}
			case <-time.After(8 * time.Second):
				_ = cmd.Process.Kill()
				<-done
				t.Error("booking graceful stop deadline")
			}
			log.Close()
			l.events = append(l.events, map[string]any{"booking_stopped_pid": pid})
		}
		t.Cleanup(stop)
		ready := make(chan string, 1)
		go func() {
			scanner := bufio.NewScanner(out)
			if scanner.Scan() {
				ready <- scanner.Text()
			} else {
				ready <- ""
			}
		}()
		select {
		case line := <-ready:
			if !strings.HasPrefix(line, "listening http://127.0.0.1:") {
				t.Fatal("booking CLI startup failed")
			}
			return strings.TrimPrefix(line, "listening "), stop
		case <-time.After(15 * time.Second):
			t.Fatal("booking CLI startup deadline")
		}
		return "", stop
	}
	origin, stop := start()
	client := &http.Client{Timeout: 10 * time.Second}
	call := func(method, path string, input any) []byte {
		t.Helper()
		var body io.Reader
		if input != nil {
			body = bytes.NewReader(eventBytes(input))
		}
		req, e := http.NewRequestWithContext(ctx, method, origin+path, body)
		if e != nil {
			t.Fatal(e)
		}
		req.Header.Set("Origin", origin)
		req.Header.Set("Content-Type", "application/json")
		res, e := client.Do(req)
		if e != nil {
			t.Fatal("booking HTTP unavailable", e)
		}
		defer res.Body.Close()
		raw, e := io.ReadAll(io.LimitReader(res.Body, 65537))
		if e != nil || res.StatusCode >= 400 || len(raw) > 65536 {
			t.Fatalf("booking HTTP refused: %d", res.StatusCode)
		}
		return raw
	}
	renter, renterPub, _ := testKey(2)
	var held struct {
		Booking booking.BookingV2 `json:"booking"`
		Hash    string            `json:"contract_sha256"`
	}
	if booking.Strict(call("POST", "/book", booking.BookInputV2{SlotID: "slot", Coin: pc.CoinBTC, RenterPubkey: renterPub, PrivacyAcknowledged: true}), &held) != nil {
		t.Fatal("HTTP booking schema")
	}
	consent := booking.ConsentV2(held.Booking.Contract, time.Now().Unix())
	if e = consent.Sign(renter); e != nil {
		t.Fatal(e)
	}
	call("POST", "/consent", map[string]any{"booking_id": held.Booking.Contract.BookingID, "event": consent})
	lab.pay(held.Booking.Contract.Payment.Address, held.Booking.Contract.Payment.AmountAtoms)
	lab.mine(2)
	var ready booking.BookingV2
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); {
		if booking.Strict(call("GET", "/booking?id="+held.Booking.Contract.BookingID, nil), &ready) != nil {
			t.Fatal("HTTP issued schema")
		}
		if ready.Issuance != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if ready.Issuance == nil {
		t.Fatal("booking watcher did not export confirmed issue")
	}
	originalIndex, e := os.ReadFile(filepath.Join(cfg.StateDir, "index.json"))
	if e != nil {
		t.Fatal(e)
	}
	stop()
	origin, stop = start()
	var restored booking.BookingV2
	if booking.Strict(call("GET", "/booking?id="+held.Booking.Contract.BookingID, nil), &restored) != nil || !bytes.Equal(eventBytes(ready.Issuance), eventBytes(restored.Issuance)) {
		t.Fatal("CLI restart changed issuance")
	}
	afterIndex, _ := os.ReadFile(filepath.Join(cfg.StateDir, "index.json"))
	if !bytes.Equal(originalIndex, afterIndex) {
		t.Fatal("CLI restart duplicated outbox")
	}
	stop()
	l.cfg.Profile = "v2"
	l.cfg.PaymentPolicies = map[string]rental.PaymentAdmissionPolicy{"btc": {MaxRateAgeSeconds: 600, MinConfirmations: 2, Limits: pc.Limits{MaxBlocks: 2016, MaxMempool: 100000, MaxCalls: 200000, MaxBytes: 512 << 20}}}
	l.cfg.PresentationDir = publicDir(t)
	adapter := V2Issuer{rental.IssuerPolicyV2{IssuerPolicy: l.cfg.Policy, PaymentPolicies: l.cfg.PaymentPolicies}, l.observer, map[string]su.Node{"btc": lab.issuer}, l.cfg.GrantKeyPath}
	broadcast, e := NewRPCBroadcast(l.send, l.read)
	if e != nil {
		t.Fatal(e)
	}
	x, e := Open(l.cfg, adapter, l.observer, broadcast, l.sink)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { x.Close() }()
	if e = x.Enroll(ctx, []su.PlanInput{seal, fund}, time.Now().Unix()); e != nil {
		t.Fatal(e)
	}
	source, e := OpenFileSource(cfg.StateDir)
	if e != nil {
		t.Fatal(e)
	}
	if e = x.Pull(ctx, source, BookingSource, time.Now().Unix()); e != nil {
		t.Fatal(e)
	}
	reader, e := presentationdir.Open(l.cfg.PresentationDir)
	if e != nil {
		t.Fatal(e)
	}
	defer reader.Close()
	id := held.Booking.Contract.BookingID
	result := x.Step(ctx, time.Now().Unix())
	if len(result) != 1 || result[0].Phase != "stored" || result[0].Reason != "PRESENTATION_UNCONFIRMED" {
		t.Fatal("unconfirmed publication gate", result)
	}
	if raw, e := reader.Presentation(ctx, id); e != nil || raw != nil {
		t.Fatal("unconfirmed presentation published", e)
	}
	record, e := x.readRecord(x.state.Operations[0])
	if e != nil {
		t.Fatal(e)
	}
	// An orphaned confirmation also leaves no published file.
	l.mine(1)
	block := text(t, l.rpc("", "getbestblockhash"))
	l.rpc("", "invalidateblock", block)
	result = x.Step(ctx, time.Now().Unix())
	if len(result) != 1 || result[0].Reason == "" {
		t.Fatal("orphaned issuance published", result)
	}
	if raw, e := reader.Presentation(ctx, id); e != nil || raw != nil {
		t.Fatal("orphaned presentation file", e)
	}
	l.rpc("", "reconsiderblock", block)
	// Active-chain and stable-tip guards are tested on the real confirmed tx.
	for _, mode := range []string{"membership", "unstable"} {
		fault := &publicationFault{Node: l.observer, mode: mode}
		probe := &Engine{cfg: l.cfg, node: fault}
		probe.cfg.PresentationDir = publicDir(t)
		e := probe.publishConfirmed(ctx, x.state.Operations[0], record)
		want := map[string]string{"membership": "BLOCK_MEMBERSHIP", "unstable": "TIP_CHANGED"}[mode]
		if e == nil || e.Error() != want {
			t.Fatal("untrusted confirmation published", mode, e)
		}
		names, _ := os.ReadDir(probe.cfg.PresentationDir)
		if len(names) != 0 {
			t.Fatal("failed observation published bytes")
		}
	}
	result = x.Step(ctx, time.Now().Unix())
	if len(result) != 1 || result[0].Reason != "" {
		t.Fatal("confirmed publication refused", result)
	}
	raw, e := reader.Presentation(ctx, id)
	if e != nil || !bytes.Equal(raw, record.Presentation) {
		t.Fatal("gateway did not read final SG1 presentation", e)
	}
	proof, e := rental.ParseGrantPresentation(raw)
	if e != nil || proof.Issuance.TxID != record.TxID {
		t.Fatal("published canonical proof")
	}
	before, _ := os.Stat(filepath.Join(l.cfg.PresentationDir, id+".json"))
	state := encode(x.state)
	x.Close()
	x, e = Open(l.cfg, adapter, l.observer, broadcast, l.sink)
	if e != nil {
		t.Fatal(e)
	}
	if e = x.Pull(ctx, source, BookingSource, time.Now().Unix()); e != nil {
		t.Fatal(e)
	}
	result = x.Step(ctx, time.Now().Unix())
	if len(result) != 1 || result[0].Reason != "" || !bytes.Equal(state, encode(x.state)) {
		t.Fatal("publisher restart changed durable operation", result)
	}
	after, _ := os.Stat(filepath.Join(l.cfg.PresentationDir, id+".json"))
	if before.ModTime() != after.ModTime() {
		t.Fatal("publisher restart rewrote proof")
	}
	l.save("booking-composition.json", map[string]any{"booking_cli_sha256": hash(binaryRaw), "booking_id": id, "issuance_txid": record.TxID, "presentation_sha256": hash(raw), "unconfirmed_absent": true, "orphan_absent": true, "confirmed_gateway_read": true, "restart_idempotent": true})
}

type publicationFault struct {
	su.Node
	mode   string
	starts int
}

func (n *publicationFault) Call(ctx context.Context, method string, args ...any) (json.RawMessage, error) {
	raw, e := n.Node.Call(ctx, method, args...)
	if e != nil {
		return nil, e
	}
	if method == "getblockchaininfo" {
		n.starts++
		if n.mode == "unstable" && n.starts > 1 {
			var v map[string]any
			json.Unmarshal(raw, &v)
			v["bestblockhash"] = strings.Repeat("f", 64)
			return encode(v), nil
		}
	}
	if n.mode == "membership" && method == "getblock" {
		var v map[string]any
		json.Unmarshal(raw, &v)
		v["tx"] = []string{strings.Repeat("f", 64)}
		return encode(v), nil
	}
	return raw, nil
}
