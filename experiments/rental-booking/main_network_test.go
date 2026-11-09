package booking

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	pc "github.com/relux-works/swarma-chain-lab/experiments/payment-chain"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

type mainBookingNode struct {
	base         *ledgerNode
	wrongGenesis bool
}

func (n *mainBookingNode) Call(ctx context.Context, method string, args ...any) (json.RawMessage, error) {
	raw, err := n.base.Call(ctx, method, args...)
	if err != nil {
		return raw, err
	}
	if method == "getblockchaininfo" {
		var fields map[string]any
		json.Unmarshal(raw, &fields)
		fields["chain"] = "main"
		return canonical(fields), nil
	}
	if method == "getblockhash" && string(canonical(args[0])) == "0" && !n.wrongGenesis {
		return canonical(su.MainGenesis), nil
	}
	return raw, nil
}

// Synthetic main booking preserves signed network/address terms and restart
// binding. Missing explicit payment policy or a wrong observed genesis refuses;
// watcher rejection leaves the durable calendar unchanged. No main RPC occurs.
func TestMainBookingPins(t *testing.T) {
	f := newLedger(t)
	f.s.Close()
	f.cfg.Network, f.cfg.Genesis = "main", su.MainGenesis
	f.cfg.StateDir = privateDir(t)
	f.cfg.MinStartNowRemainingSeconds = 1500
	f.cfg.PriceUSDCents = 1000
	f.cfg.Template.ID, f.cfg.Template.BudgetSat = "demo-60", 3000000
	f.cfg.TemplateSHA256 = Hash(canonical(f.cfg.Template))
	seed := make([]byte, 32)
	seed[0] = 21
	master, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		t.Fatal(err)
	}
	branch, _ := master.Neuter()
	f.cfg.Coins = map[string]CoinConfig{"nmc": {PublicBranch: branch.String(), PublicBranchSHA256: Hash([]byte(branch.String())), USDMicrosPerCoin: 1000000, RateAsOf: f.now, MaxRateAgeSeconds: 7200, MinConfirmations: 1}}
	node := &mainBookingNode{base: &ledgerNode{coin: "nmc", height: 100}}
	f.nodes = map[string]Node{"nmc": node}
	f.s, err = NewServiceV2(f.cfg, f.profile, f.provider, f.nodes, node, f.relay, func() time.Time { return time.Unix(f.now, 0) })
	if err != nil {
		t.Fatal("explicit main startup", err)
	}
	b, err := f.s.Book(context.Background(), BookInputV2{SlotID: f.cfg.Slots[0].ID, Coin: pc.CoinNMC, RenterPubkey: keyHex(f.renter), PrivacyAcknowledged: true})
	if err != nil || b.Contract.Payment.Network != "main" || b.Contract.Payment.Genesis != su.MainGenesis || b.Contract.Payment.MinConfirmations != 1 {
		t.Fatal(b, err)
	}
	p, _ := pc.ForNetwork("nmc", "main", su.MainGenesis)
	if script, err := p.Script(b.Contract.Payment.Address); err != nil || script != b.Script {
		t.Fatal("main address binding", err)
	}
	before := canonical(f.s.state)
	node.wrongGenesis = true
	if err = f.s.Refresh(context.Background()); err == nil || err.Error() != "NODE_GENESIS" {
		t.Fatal("wrong own-node genesis", err)
	}
	if !bytes.Equal(before, canonical(f.s.state)) {
		t.Fatal("rejected watcher mutated calendar")
	}
	node.wrongGenesis = false
	f.s.Close()
	f.s, err = NewServiceV2(f.cfg, f.profile, f.provider, f.nodes, node, f.relay, func() time.Time { return time.Unix(f.now, 0) })
	if err != nil || !bytes.Equal(before, canonical(f.s.state)) {
		t.Fatal("main restart", err)
	}
	h, err := NewHTTPHandlerV2(f.s, "http://127.0.0.1:18819")
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "http://127.0.0.1:18819/", nil))
	if !strings.Contains(w.Body.String(), "Payments use real NMC") || strings.Contains(w.Body.String(), "disposable regtest") {
		t.Fatal("main payment page mislabelled")
	}
	for _, mutate := range []func(*ConfigV2){
		func(c *ConfigV2) { c.Genesis = su.RegtestGenesis },
		func(c *ConfigV2) { c.Network = "regtest" },
		func(c *ConfigV2) { v := c.Coins["nmc"]; v.MinConfirmations = 0; c.Coins["nmc"] = v },
		func(c *ConfigV2) { c.Coins["btc"] = c.Coins["nmc"] },
		func(c *ConfigV2) { c.HoldSeconds = 0 },
	} {
		var bad ConfigV2
		json.Unmarshal(canonical(f.cfg), &bad)
		mutate(&bad)
		calls := node.base.calls
		if bad.ValidateNetworkProfile() == nil {
			t.Fatal("incomplete main accepted")
		}
		if calls != node.base.calls {
			t.Fatal("preflight called node")
		}
	}
}
