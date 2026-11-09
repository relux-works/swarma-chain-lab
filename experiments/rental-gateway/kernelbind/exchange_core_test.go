package kernelbind_test

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	booking "github.com/relux-works/swarma-chain-lab/experiments/rental-booking"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/exchange"
	gw "github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/gateway"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/journal"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernelbind"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernelbind/bookingbind"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/screen"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/station"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/stationlink"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// This source only reads a presentation deposited by the independent lab issuer.
// The exchange has no issuer key, funding, or broadcast interface.
type exchangePresentation struct {
	mu  sync.Mutex
	id  string
	raw []byte
}

func (s *exchangePresentation) Presentation(_ context.Context, id string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id != s.id {
		return nil, nil
	}
	return append([]byte{}, s.raw...), nil
}
func (s *exchangePresentation) put(id string, raw []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.id = id
	s.raw = append([]byte{}, raw...)
}

type packagePublisher struct{}

func (packagePublisher) Publish(_ context.Context, e booking.Event) error { return e.Verify() }

// issueBooking uses the actual booking package and watcher request unchanged.
// Only this regtest harness owns the separate issuer and isolated-wallet keys.
func (l *coreLab) issueBooking(b booking.Booking, provider string) []byte {
	l.t.Helper()
	ctx := context.Background()
	seal := l.seal()
	funding := l.output(l.address, l.script)
	dir := filepath.Join(l.private, "exchange-issuer")
	if err := os.Mkdir(dir, 0700); err != nil {
		l.t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "grant-key")
	if err := os.WriteFile(keyPath, l.issuer.Serialize(), 0600); err != nil {
		l.t.Fatal(err)
	}
	sealScript, _ := rental.GrantSealScript(l.issuerPub)
	policy := rental.Policy{Network: "regtest", Genesis: su.RegtestGenesis, AgentName: e2eAgentName, LandlordName: e2eLandlordName, SealScript: sealScript, FundingScript: l.script, StateDir: dir}
	spec := rental.PlanSpec{Kind: "grant-issue", Inputs: []su.PlanInput{{Point: su.Point{TxID: funding.TxID, Vout: funding.Vout}, ValueSat: 1000000, Script: l.script, Role: "funding"}}, ChangeScript: l.script}
	result := rental.IssueGrant(ctx, l.observer, rental.IssuerPolicy{Policy: policy, ProviderPubkey: provider}, jsonBytes(l.t, b.Issuance), jsonBytes(l.t, b.PackageEvent), seal, spec, keyPath, 500)
	if result.Verdict != "prepared" || result.Plan == nil {
		l.t.Fatalf("actual booking issuance: %s/%s", result.Verdict, result.Reason)
	}
	tx := su.Transaction{Version: result.Plan.TransactionVersion}
	for _, in := range result.Plan.Inputs {
		tx.Inputs = append(tx.Inputs, su.Input{Point: in.Point, Sequence: 0xfffffffe})
	}
	for _, out := range result.Plan.Outputs {
		script, err := hex.DecodeString(out.Script)
		if err != nil {
			l.t.Fatal(err)
		}
		tx.Outputs = append(tx.Outputs, su.Output{Value: out.ValueSat, Script: script})
	}
	id := l.send(hex.EncodeToString(tx.Bytes()), true)
	proof, err := rental.PresentIssuedGrant(result.SignedGrant, id)
	if err != nil {
		l.t.Fatal(err)
	}
	for name, raw := range map[string][]byte{"exchange-issuance.json": jsonBytes(l.t, result), "exchange-presentation.json": proof, "exchange-booking.json": jsonBytes(l.t, b)} {
		if err = os.WriteFile(filepath.Join(l.root, name), raw, 0600); err != nil {
			l.t.Fatal(err)
		}
	}
	return proof
}

// Genuine pinned Core proves the complete no-site flow with a real booking
// service, consent verifier, payment watcher, issuer, and kernel. NIP-17 is
// encrypted/signed; the publication collector is local (relay ACK has its own
// websocket control). Issuance is not liveness and never starts an instance.
func TestExchangeCoreLifecycle(t *testing.T) { runExchangeCore(t, false) }

// Spending the real seal after issuance but before start must produce one
// fixed non-live notice and refuse the first message without an instance.
func TestExchangeCoreNonLive(t *testing.T) { runExchangeCore(t, true) }

func runExchangeCore(t *testing.T, revoked bool) {
	agent, _ := nostr.GeneratePrivKey()
	renter, _ := nostr.GeneratePrivKey()
	provider, _ := nostr.GeneratePrivKey()
	l := newCoreLab(t, agent.PubKeyHex())
	ctx := context.Background()
	var now atomic.Int64
	now.Store(500)
	clock := func() time.Time { return time.Unix(now.Load(), 0) }
	privateDir := func(name string) string {
		p := filepath.Join(l.private, name)
		if err := os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
		return p
	}
	seed := []byte("public-e1-regtest-branch-fixture!!")
	master, err := hdkeychain.NewMaster(seed, &chaincfg.RegressionNetParams)
	if err != nil {
		t.Fatal(err)
	}
	public, err := master.Neuter()
	if err != nil {
		t.Fatal(err)
	}
	profile := []byte("E1 public laboratory profile\n")
	template := booking.Template{Version: 1, ID: "demo", ProfileID: "lab", ProfileVersion: "1", ProfileSHA256: booking.Hash(profile), Allowed: []string{"deliver", "pay"}, Forbidden: []string{"publish", "repository.push", "secret.release"}, BudgetSat: 1000000}
	cfg := booking.Config{StateDir: privateDir("booking"), PublicBranch: public.String(), PublicBranchSHA256: booking.Hash([]byte(public.String())), AgentPubkey: agent.PubKeyHex(), ProviderPubkey: provider.PubKeyHex(), HoldSeconds: 1200, PriceUSDCents: 100, USDMicrosPerNMC: 100000000, RateAsOf: 500, MaxRateAge: 7200, Template: template, TemplateSHA256: booking.Hash(jsonBytes(t, template)), Slots: []booking.Slot{{ID: "one", StationName: e2eAgentName, NotBefore: 600, NotAfter: 1000, PaymentPolicy: "advance"}}, Limits: booking.Limits{MaxBlocks: 512, MaxMempool: 2000, MaxCalls: 10000, MaxBytes: 64 << 20}}
	pk, _ := btcec.PrivKeyFromBytes(provider.Bytes())
	service, err := booking.NewService(cfg, profile, pk, l.observer, packagePublisher{}, clock)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	backend := &bookingbind.Adapter{Service: service, AgentName: e2eAgentName, LandlordName: e2eLandlordName, AgentPubkey: agent.PubKeyHex(), Now: clock}
	source := &exchangePresentation{}
	ec := exchange.DefaultConfig()
	ec.StateDir = privateDir("exchange")
	ec.AgentName = e2eAgentName
	ec.LandlordName = e2eLandlordName
	ec.Backend = backend
	ec.Grants = bookingbind.Grants{Source: source}
	ec.Now = clock
	ec.PowBits = 4
	ec.Burst = 16
	ec.PollInterval = 20 * time.Millisecond
	ec.CallTimeout = 5 * time.Second
	engine, err := exchange.New(ec)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	kernel, err := kernelbind.New(l.observer, privateDir("kernel"), e2eAgentName, e2eLandlordName, l.issuerPub)
	if err != nil {
		t.Fatal(err)
	}
	store, err := journal.Open(filepath.Join(l.root, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	sockDir, err := os.MkdirTemp("", "gw-exchange")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(sockDir)
	sock := filepath.Join(sockDir, "s.sock")
	pub := &collectPub{}
	screener := &screen.Stub{}
	g, err := gw.New(gw.Config{AgentKey: agent, Kernel: kernel, Presenter: kernel, AgentName: e2eAgentName, Journal: store, Publisher: pub, Screener: screener, Driver: &station.LocalTestDriver{Root: filepath.Join(l.root, "stations")}, Endpoint: sock, PullTimeout: 50 * time.Millisecond, Now: clock, Exchange: engine})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() { _ = g.ServeStations(ln) }()
	send := func(text string, work bool, tags [][]string) gw.Result {
		t.Helper()
		r := &nostr.Event{PubKey: renter.PubKeyHex(), CreatedAt: now.Load(), Kind: nostr.KindRumor, Content: text, Tags: append([][]string{{"p", agent.PubKeyHex()}}, tags...)}
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
		w, e := nostr.GiftWrap(r, renter, agent.PubKeyHex(), now.Load())
		if e != nil {
			t.Fatal(e)
		}
		return g.HandleGiftWrap(ctx, w)
	}
	offset := 0
	receive := func(prefix string) string {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			pub.mu.Lock()
			evs := append([]*nostr.Event{}, pub.evs[offset:]...)
			offset = len(pub.evs)
			pub.mu.Unlock()
			for _, ev := range evs {
				u, e := nostr.UnwrapDM(ev, renter)
				if e != nil || u.SenderHex != agent.PubKeyHex() {
					t.Fatal("response identity/encryption")
				}
				if strings.HasPrefix(u.Rumor.Content, prefix) {
					return u.Rumor.Content
				}
				t.Fatalf("unexpected exchange text, want %q: %q", prefix, u.Rumor.Content)
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("no exchange response %q", prefix)
		return ""
	}
	if r := send("terms", true, nil); !r.ExchangeQueued || r.Delivered {
		t.Fatalf("terms admission: %+v", r)
	}
	var terms exchange.Terms
	if err = json.Unmarshal([]byte(strings.TrimPrefix(receive("terms\n"), "terms\n")), &terms); err != nil || len(terms.Slots) != 1 || terms.Slots[0].ID != "one" {
		t.Fatalf("terms: %+v %v", terms, err)
	}
	send("book demo one", false, nil)
	var contractReply struct {
		BookingID string `json:"booking_id"`
		Hash      string `json:"contract_sha256"`
		Contract  string `json:"contract_base64"`
	}
	if err = json.Unmarshal([]byte(strings.TrimPrefix(receive("contract\n"), "contract\n")), &contractReply); err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(contractReply.Contract)
	if err != nil {
		t.Fatal(err)
	}
	var contract booking.Contract
	if booking.Strict(raw, &contract) != nil || contract.Hash() != contractReply.Hash || contract.BookingID != contractReply.BookingID || contract.RenterPubkey != renter.PubKeyHex() {
		t.Fatal("exact contract binding")
	}
	// Real booking consent: another key must fail without a provider package.
	wrong, _ := nostr.GeneratePrivKey()
	wk, _ := btcec.PrivKeyFromBytes(wrong.Bytes())
	bad := booking.Consent(contract, now.Load())
	if err = bad.Sign(wk); err != nil {
		t.Fatal(err)
	}
	send("consent "+string(jsonBytes(t, bad)), false, nil)
	if receive(exchange.Help) != exchange.Help {
		t.Fatal("foreign consent response")
	}
	before, err := service.Get(contract.BookingID)
	if err != nil || before.Package != nil {
		t.Fatal("foreign consent changed booking")
	}
	rk, _ := btcec.PrivKeyFromBytes(renter.Bytes())
	consent := booking.Consent(contract, now.Load())
	if err = consent.Sign(rk); err != nil {
		t.Fatal(err)
	}
	send("consent "+string(jsonBytes(t, consent)), false, nil)
	var pay struct {
		Address string `json:"address"`
		Amount  int64  `json:"amount_atomic"`
		Coin    string `json:"coin"`
	}
	if err = json.Unmarshal([]byte(strings.TrimPrefix(receive("pay\n"), "pay\n")), &pay); err != nil || pay.Address != contract.PaymentAddress || pay.Amount != contract.PriceNMCSat || pay.Coin != "nmc" {
		t.Fatal("payment response binding")
	}
	b, err := service.Get(contract.BookingID)
	if err != nil || b.Issuance != nil || !b.Published {
		t.Fatal("issuance before payment or unpublished package")
	}
	// Real isolated regtest payment, confirmed and discovered by booking itself.
	l.rpc("issuer", "sendtoaddress", pay.Address, su.Coins(pay.Amount))
	l.mine(1)
	if err = service.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	b, err = service.Get(contract.BookingID)
	if err != nil || b.Issuance == nil || b.Payment == nil {
		t.Fatal("payment watcher did not produce issuance request")
	}
	proof := l.issueBooking(b, provider.PubKeyHex())
	source.put(b.Contract.BookingID, proof)
	var issued struct {
		GrantID      string `json:"grant_id"`
		Presentation string `json:"presentation_base64"`
		NotBefore    int64  `json:"not_before"`
		Notice       string `json:"notice"`
	}
	if err = json.Unmarshal([]byte(strings.TrimPrefix(receive("issued\n"), "issued\n")), &issued); err != nil {
		t.Fatal(err)
	}
	delivered, err := base64.StdEncoding.DecodeString(issued.Presentation)
	if err != nil || string(delivered) != string(proof) || issued.GrantID != proofGrant(t, proof).ID() || issued.NotBefore != 600 || !strings.Contains(issued.Notice, "not a live verdict") {
		t.Fatal("issued grant response")
	}
	slot, ok := store.Get(contract.BookingID)
	if !ok || slot.Started || screener.Calls != 0 {
		t.Fatal("exchange started instance or reached model")
	}
	tag, err := gw.GrantCertTag(proof)
	if err != nil {
		t.Fatal(err)
	}
	if r := send("too early", false, [][]string{tag}); r.Delivered || !r.ExchangeQueued {
		t.Fatalf("prewindow admitted: %+v", r)
	}
	if receive(exchange.NotYet) != exchange.NotYet {
		t.Fatal("prewindow text")
	}
	if revoked {
		l.revoke(proofGrant(t, proof).Grant.Seal)
		now.Store(600)
		if receive(exchange.NotLive) != exchange.NotLive {
			t.Fatal("revoked grant ready")
		}
		slot, _ = store.Get(contract.BookingID)
		if slot.Started || screener.Calls != 0 {
			t.Fatal("non-live notice started instance")
		}
		if r := send("revoked first message", false, [][]string{tag}); r.Delivered {
			t.Fatal("revoked grant reached instance")
		}
		slot, _ = store.Get(contract.BookingID)
		if slot.Started || screener.Calls != 0 {
			t.Fatal("revoked message started instance or model")
		}
		return
	}
	now.Store(600)
	if receive("ready") != "ready" {
		t.Fatal("current-time ready")
	}
	slot, _ = store.Get(contract.BookingID)
	if slot.Started || screener.Calls != 0 {
		t.Fatal("ready started instance or reached model")
	}
	if r := send("first live message", false, [][]string{tag}); !r.Delivered || r.ExchangeQueued {
		t.Fatalf("first grant message: %+v", r)
	}
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	client := stationlink.NewClient(conn)
	slot, _ = store.Get(contract.BookingID)
	secret, err := hex.DecodeString(slot.ChannelSecretHex)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.Hello(slot.ID, slot.StationName, secret); err != nil {
		t.Fatal(err)
	}
	frame, err := client.Pull()
	if err != nil || frame.Type != stationlink.TypeDeliver || frame.Content != "first live message" || screener.Calls != 1 {
		t.Fatalf("first instance delivery: %+v %v", frame, err)
	}
	engine.Close()
	pub.mu.Lock()
	readyCount := 0
	for _, event := range pub.evs {
		unwrapped, err := nostr.UnwrapDM(event, renter)
		if err == nil && unwrapped.Rumor.Content == "ready" {
			readyCount++
		}
	}
	pub.mu.Unlock()
	if readyCount != 1 {
		t.Fatal("lazy instance start duplicated exchange ready")
	}
	if err = os.WriteFile(filepath.Join(l.root, "exchange-transcript.json"), jsonBytes(t, map[string]any{"terms": terms, "contract_sha256": contract.Hash(), "consent_id": consent.ID, "payment_txid": b.Payment.TxID, "grant_id": issued.GrantID, "issued_at": 500, "ready_at": 600, "instance_started_only_on_live_message": true}), 0600); err != nil {
		t.Fatal(err)
	}
}
