package booking

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	pc "github.com/relux-works/swarma-chain-lab/experiments/payment-chain"
)

type ledgerOutput struct {
	txid, script  string
	value, height int64
}
type ledgerNode struct {
	coin       string
	height     int64
	generation int
	outputs    []ledgerOutput
	fail       bool
	calls      int
}

func (n *ledgerNode) hash(height int64) string {
	return Hash([]byte(fmt.Sprintf("%s/%d/%d", n.coin, n.generation, height)))
}
func (n *ledgerNode) tx(o ledgerOutput) any {
	return map[string]any{"txid": o.txid, "vin": []any{map[string]any{"txid": Hash([]byte("input")), "vout": 0}}, "vout": []any{map[string]any{"n": 0, "value": json.RawMessage(fmt.Sprintf("%d.%08d", o.value/100000000, o.value%100000000)), "scriptPubKey": map[string]any{"hex": o.script}}}}
}
func (n *ledgerNode) Call(_ context.Context, method string, args ...any) (json.RawMessage, error) {
	n.calls++
	if n.fail {
		return nil, refuse("offline")
	}
	switch method {
	case "getnetworkinfo":
		sub := "/Satoshi:32.1.0/"
		protocol := 70017
		if n.coin == "ltc" {
			sub = "/LitecoinCore:0.21.5.8/"
		}
		if n.coin == "nmc" {
			protocol = 110016
		}
		return canonical(map[string]any{"subversion": sub, "protocolversion": protocol}), nil
	case "getblockchaininfo":
		return canonical(map[string]any{"chain": "regtest", "blocks": n.height, "headers": n.height, "bestblockhash": n.hash(n.height), "initialblockdownload": false}), nil
	case "getblockhash":
		var h int64
		_ = json.Unmarshal(canonical(args[0]), &h)
		if h == 0 {
			p, _ := pc.ForCoin(n.coin)
			return canonical(p.Genesis), nil
		}
		return canonical(n.hash(h)), nil
	case "getblock":
		for h := int64(100); h <= n.height; h++ {
			if args[0] == n.hash(h) {
				txs := []any{}
				for _, o := range n.outputs {
					if o.height == h {
						txs = append(txs, n.tx(o))
					}
				}
				return canonical(map[string]any{"hash": n.hash(h), "previousblockhash": n.hash(h - 1), "height": h, "confirmations": n.height - h + 1, "tx": txs}), nil
			}
		}
	case "getrawmempool":
		ids := []string{}
		for _, o := range n.outputs {
			if o.height == 0 {
				ids = append(ids, o.txid)
			}
		}
		return canonical(ids), nil
	case "getrawtransaction":
		for _, o := range n.outputs {
			if o.height == 0 && o.txid == args[0] {
				return canonical(n.tx(o)), nil
			}
		}
	}
	return nil, refuse("unexpected method")
}

type ledgerFixture struct {
	s                *ServiceV2
	cfg              ConfigV2
	profile          []byte
	provider, renter *btcec.PrivateKey
	nodes            map[string]Node
	concrete         map[string]*ledgerNode
	relay            *memoryRelay
	now              int64
}

func newLedger(t *testing.T) *ledgerFixture {
	t.Helper()
	f := &ledgerFixture{profile: []byte("ledger fixture profile"), provider: testKey(2), renter: testKey(3), nodes: map[string]Node{}, concrete: map[string]*ledgerNode{}, relay: &memoryRelay{}, now: 2000000000}
	template := Template{1, "demo", "curator-test", "1.0.0", Hash(f.profile), []string{"deliver", "pay"}, []string{"publish", "repository.push", "secret.release"}, 10000}
	branch := fixtureBranch(t)
	f.cfg = ConfigV2{StateDir: privateDir(t), AgentPubkey: keyHex(testKey(4)), ProviderPubkey: keyHex(f.provider), HoldSeconds: 1200, PriceUSDCents: 100, Template: template, TemplateSHA256: Hash(canonical(template)), Coins: map[string]CoinConfig{}, Limits: Limits{512, 2000, 10000, 64 << 20}}
	for i, coin := range []string{"btc", "ltc", "nmc"} {
		f.cfg.Coins[coin] = CoinConfig{branch, Hash([]byte(branch)), 1000000, f.now, 7200, 2}
		f.cfg.Slots = append(f.cfg.Slots, Slot{fmt.Sprintf("slot%d", i), fmt.Sprintf("id/station%d", i), f.now + 3600, f.now + 7200, "advance"})
		n := &ledgerNode{coin: coin, height: 100}
		f.nodes[coin] = n
		f.concrete[coin] = n
	}
	f.open(t)
	t.Cleanup(func() { f.s.Close() })
	return f
}
func (f *ledgerFixture) open(t *testing.T) {
	t.Helper()
	var e error
	f.s, e = NewServiceV2(f.cfg, f.profile, f.provider, f.nodes, nil, f.relay, func() time.Time { return time.Unix(f.now, 0) })
	if e != nil {
		t.Fatal(e)
	}
}
func (f *ledgerFixture) book(t *testing.T, slot, coin string) BookingV2 {
	t.Helper()
	b, e := f.s.Book(context.Background(), BookInputV2{slot, pc.Coin(coin), keyHex(f.renter), "", true})
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func (f *ledgerFixture) consent(t *testing.T, b BookingV2) BookingV2 {
	t.Helper()
	event := ConsentV2(b.Contract, f.now)
	if e := event.Sign(f.renter); e != nil {
		t.Fatal(e)
	}
	out, e := f.s.AcceptConsent(context.Background(), b.Contract.BookingID, event)
	if e != nil {
		t.Fatal(e)
	}
	return out
}
func (f *ledgerFixture) get(t *testing.T, b BookingV2) BookingV2 {
	t.Helper()
	out, e := f.s.Get(b.Contract.BookingID)
	if e != nil {
		t.Fatal(e)
	}
	return out
}
func (f *ledgerFixture) refresh(t *testing.T) {
	t.Helper()
	if e := f.s.Refresh(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e := f.s.validateStateV2(); e != nil {
		t.Fatal("produced invalid state", e)
	}
}
func (f *ledgerFixture) raw(t *testing.T) string {
	t.Helper()
	raw, e := os.ReadFile(filepath.Join(f.cfg.StateDir, "state.json"))
	if e != nil {
		t.Fatal(e)
	}
	return string(raw)
}

// Concurrent different-coin requests share one interval reservation; per-coin
// counters remain independent and expiry/restart never reuse an issued address.
func TestLedgerV2Calendar(t *testing.T) {
	f := newLedger(t)
	var wg sync.WaitGroup
	results := make(chan error, 3)
	for _, coin := range []string{"btc", "ltc", "nmc"} {
		wg.Add(1)
		go func(coin string) {
			defer wg.Done()
			_, e := f.s.Book(context.Background(), BookInputV2{"slot0", pc.Coin(coin), keyHex(f.renter), "", true})
			results <- e
		}(coin)
	}
	wg.Wait()
	close(results)
	ok, denied := 0, 0
	for e := range results {
		if e == nil {
			ok++
		} else if e.Error() == "CAPACITY_FULL" {
			denied++
		} else {
			t.Fatal(e)
		}
	}
	if ok != 1 || denied != 2 || len(f.s.state.Bookings) != 1 {
		t.Fatal("cross-coin double booking")
	}
	first := copyBookingV2(f.s.state.Bookings[0])
	used := first.Contract.Payment.Coin
	if f.s.state.NextIndices[used] != 1 {
		t.Fatal("missing address reservation")
	}
	f.now = first.HoldExpiresAt
	next := f.book(t, "slot0", used)
	if next.AddressIndex != 1 || next.Contract.Payment.Address == first.Contract.Payment.Address {
		t.Fatal("address reuse")
	}
	for _, coin := range []string{"btc", "ltc", "nmc"} {
		if coin != used {
			other := f.book(t, "slot1", coin)
			if other.AddressIndex != 0 {
				t.Fatal("shared address index")
			}
			break
		}
	}
	before := f.raw(t)
	f.s.Close()
	f.open(t)
	if f.raw(t) != before {
		t.Fatal("restart rewrote state")
	}
	if e := f.s.validateStateV2(); e != nil {
		t.Fatal(e)
	}
}

// Refusal paths preserve both durable bytes and in-memory reservations, then a
// valid neighbor books successfully. These are local ledger controls, not Core.
func TestLedgerV2Refusals(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		edit       func(*ledgerFixture, *BookInputV2)
	}{
		{"privacy", "PRIVACY_REQUIRED", func(_ *ledgerFixture, i *BookInputV2) { i.PrivacyAcknowledged = false }},
		{"coin", "COIN_PROFILE", func(_ *ledgerFixture, i *BookInputV2) { i.Coin = "BTC" }},
		{"name-route", "RENTER_NAME_NODE", func(_ *ledgerFixture, i *BookInputV2) { i.RenterName = "renter" }},
		{"clock", "CLOCK_REVERSED", func(f *ledgerFixture, _ *BookInputV2) { f.now-- }},
		{"node", "NODE_UNAVAILABLE", func(f *ledgerFixture, _ *BookInputV2) { f.concrete["btc"].fail = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newLedger(t)
			before := f.raw(t)
			mem := string(canonical(f.s.state))
			in := BookInputV2{"slot0", pc.CoinBTC, keyHex(f.renter), "", true}
			tc.edit(f, &in)
			b, e := f.s.Book(context.Background(), in)
			if e == nil || e.Error() != tc.code || b.Contract.BookingID != "" || f.raw(t) != before || string(canonical(f.s.state)) != mem {
				t.Fatalf("refusal/state: %v", e)
			}
			f.now = 2000000000
			f.concrete["btc"].fail = false
			f.book(t, "slot0", "btc")
		})
	}
}

// The service owns copies of its config and returned contracts, and refuses
// closed/poisoned writes without returning an address or altering durable state.
func TestLedgerV2Ownership(t *testing.T) {
	f := newLedger(t)
	f.cfg.Slots[0].StationName = "id/changed"
	f.cfg.Template.Allowed[0] = "changed"
	delete(f.cfg.Coins, "btc")
	b := f.book(t, "slot0", "btc")
	if b.Contract.StationName != "id/station0" || b.Contract.Allowed[0] != "deliver" {
		t.Fatal("config alias")
	}
	b.Contract.Allowed[0] = "changed"
	got := f.get(t, b)
	if got.Contract.Allowed[0] != "deliver" {
		t.Fatal("return alias")
	}
	before := f.raw(t)
	f.s.Close()
	out, e := f.s.Book(context.Background(), BookInputV2{"slot1", pc.CoinNMC, keyHex(f.renter), "", true})
	if e == nil || e.Error() != "STATE_UNAVAILABLE" || out.Contract.BookingID != "" || f.raw(t) != before {
		t.Fatal("closed write", e)
	}
}

// A legacy state root is rejected byte-for-byte; no migration or reset occurs.
// The same v2 config can still open a new empty root afterward.
func TestLedgerV2LegacyRoot(t *testing.T) {
	old := newFixture(t)
	old.book(t, "one")
	old.s.Close()
	path := filepath.Join(old.cfg.StateDir, "state.json")
	before, _ := os.ReadFile(path)
	f := newLedger(t)
	f.s.Close()
	f.cfg.StateDir = old.cfg.StateDir
	s, e := NewServiceV2(f.cfg, f.profile, f.provider, f.nodes, nil, f.relay, func() time.Time { return time.Unix(f.now, 0) })
	if s != nil || e == nil || e.Error() != "STATE_BINDING" {
		t.Fatal("legacy accepted", e)
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(before) {
		t.Fatal("legacy modified")
	}
	f.cfg.StateDir = privateDir(t)
	f.open(t)
	f.book(t, "slot0", "btc")
}

// Complete threshold must be observed before the deadline; mempool and two
// underpayments never aggregate into payment. Each coin has a valid control.
func TestLedgerV2PaymentThreshold(t *testing.T) {
	for _, coin := range []string{"btc", "ltc", "nmc"} {
		t.Run(coin, func(t *testing.T) {
			f := newLedger(t)
			b := f.consent(t, f.book(t, "slot0", coin))
			n := f.concrete[coin]
			amount := b.Contract.Payment.AmountAtoms
			n.outputs = []ledgerOutput{{Hash([]byte("one")), b.Script, amount / 2, 0}, {Hash([]byte("two")), b.Script, amount / 2, 0}}
			f.refresh(t)
			if f.get(t, b).Payment != nil {
				t.Fatal("summed mempool")
			}
			for i := range n.outputs {
				n.outputs[i].height = 101
			}
			n.height = 102
			f.refresh(t)
			if f.get(t, b).Issuance != nil {
				t.Fatal("summed confirmed outputs")
			}
			n.outputs = []ledgerOutput{{Hash([]byte("full")), b.Script, amount + 100, 103}}
			n.height = 103
			f.refresh(t)
			if f.get(t, b).Issuance != nil {
				t.Fatal("below confirmation threshold")
			}
			n.height = 104
			f.refresh(t)
			got := f.get(t, b)
			if got.Issuance == nil || got.Payment == nil || got.Payment.TxID != Hash([]byte("full")) {
				t.Fatal("valid payment missing")
			}
			r := got.Receipts[len(got.Receipts)-1]
			if r.SurplusAtoms != 100 || !r.RefundReview || r.Disposition != "selected" {
				t.Fatal("surplus lost")
			}
			before := f.raw(t)
			f.s.Close()
			f.open(t)
			if f.raw(t) != before || !reflect.DeepEqual(f.get(t, b).Issuance, got.Issuance) {
				t.Fatal("restart changed issuance")
			}
		})
	}
	t.Run("late-threshold", func(t *testing.T) {
		f := newLedger(t)
		b := f.consent(t, f.book(t, "slot0", "btc"))
		n := f.concrete["btc"]
		n.outputs = []ledgerOutput{{Hash([]byte("late")), b.Script, b.Contract.Payment.AmountAtoms, 101}}
		n.height = 101
		f.now = b.HoldExpiresAt - 1
		f.refresh(t)
		f.now++
		n.height = 102
		f.refresh(t)
		got := f.get(t, b)
		if got.Issuance != nil || got.Payment != nil || got.Status != "expired" {
			t.Fatal("late threshold admitted")
		}
	})
}

// Once requested, reorg or missing payment produces one durable revoke. Even a
// restored original chain and an alternative payment cannot issue it again.
func TestLedgerV2StickyRevoke(t *testing.T) {
	for _, coin := range []string{"btc", "ltc", "nmc"} {
		t.Run(coin, func(t *testing.T) {
			f := newLedger(t)
			b := f.consent(t, f.book(t, "slot0", coin))
			n := f.concrete[coin]
			n.outputs = []ledgerOutput{{Hash([]byte("issued")), b.Script, b.Contract.Payment.AmountAtoms, 101}}
			n.height = 102
			f.refresh(t)
			issued := f.get(t, b)
			if issued.Issuance == nil {
				t.Fatal("valid control not issued")
			}
			issuePath := filepath.Join(f.cfg.StateDir, "issue-"+b.Contract.BookingID+".json")
			issueBytes, _ := os.ReadFile(issuePath)
			n.generation++
			f.refresh(t)
			revoked := f.get(t, b)
			if revoked.Revoke == nil || revoked.Payment != nil || revoked.Status != "revoked" {
				t.Fatal("reorg not revoked")
			}
			revokeBytes := canonical(revoked.Revoke)
			f.s.Close()
			f.open(t)
			n.generation--
			n.outputs = append(n.outputs, ledgerOutput{Hash([]byte("replacement")), b.Script, b.Contract.Payment.AmountAtoms, 101})
			f.refresh(t)
			got := f.get(t, b)
			after, _ := os.ReadFile(issuePath)
			if got.Payment != nil || string(canonical(got.Revoke)) != string(revokeBytes) || !reflect.DeepEqual(got.Issuance, issued.Issuance) || string(after) != string(issueBytes) {
				t.Fatal("revocation reversed or request rewritten")
			}
		})
	}
}

// If one required route fails, no other coin's newly eligible issuance is
// committed. Restoring it allows the same observation to commit atomically.
func TestLedgerV2AtomicRefresh(t *testing.T) {
	f := newLedger(t)
	btc := f.consent(t, f.book(t, "slot0", "btc"))
	f.consent(t, f.book(t, "slot1", "ltc"))
	n := f.concrete["btc"]
	n.outputs = []ledgerOutput{{Hash([]byte("btc")), btc.Script, btc.Contract.Payment.AmountAtoms, 101}}
	n.height = 102
	f.concrete["ltc"].fail = true
	before := f.raw(t)
	e := f.s.Refresh(context.Background())
	if e == nil || e.Error() != "NODE_UNAVAILABLE" || f.raw(t) != before || f.get(t, btc).Issuance != nil {
		t.Fatal("partial refresh", e)
	}
	f.concrete["ltc"].fail = false
	f.refresh(t)
	if f.get(t, btc).Issuance == nil {
		t.Fatal("recovered refresh failed")
	}
}

// Persisted corruption refuses before recreating any missing public outbox.
func TestLedgerV2StateRefusals(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*stateV2)
	}{
		{"index", func(s *stateV2) { s.NextIndices["btc"] = 0 }},
		{"unknown-coin", func(s *stateV2) { s.NextIndices["doge"] = 0 }},
		{"hold", func(s *stateV2) { s.Bookings[0].HoldExpiresAt += 3600 }},
		{"payment", func(s *stateV2) {
			s.Bookings[0].Payment = &pc.Payment{TxID: Hash([]byte("invented")), ValueAtoms: 100000000, Height: 101, BlockHash: Hash([]byte("block"))}
		}},
		{"receipt", func(s *stateV2) {
			s.Bookings[0].Receipts = append(s.Bookings[0].Receipts, ReceiptV2{Payment: pc.Payment{TxID: "bad"}})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newLedger(t)
			b := f.consent(t, f.book(t, "slot0", "btc"))
			st := copyStateV2(f.s.state)
			tc.edit(&st)
			f.s.Close()
			path := filepath.Join(f.cfg.StateDir, "state.json")
			if e := os.WriteFile(path, canonical(st), 0600); e != nil {
				t.Fatal(e)
			}
			out := filepath.Join(f.cfg.StateDir, "package-"+b.Contract.BookingID+".json")
			if e := os.Remove(out); e != nil {
				t.Fatal(e)
			}
			s, e := NewServiceV2(f.cfg, f.profile, f.provider, f.nodes, nil, f.relay, func() time.Time { return time.Unix(f.now, 0) })
			if e == nil || s != nil {
				t.Fatal("corrupt root accepted")
			}
			if _, e = os.Stat(out); !os.IsNotExist(e) {
				t.Fatal("outbox published before validation")
			}
			if f.raw(t) != string(canonical(st)) {
				t.Fatal("corrupt state changed")
			}
		})
	}
}
