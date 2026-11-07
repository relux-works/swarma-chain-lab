package sealwatch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

func digest(n int) string { return fmt.Sprintf("%064x", n) }
func ptr[T any](v T) *T   { return &v }
func normalTx(id string, p Point) tx {
	return tx{TxID: id, Vin: []input{{TxID: p.TxID, Vout: ptr(p.Vout)}}}
}
func coinbase(id string) tx { return tx{TxID: id, Vin: []input{{Coinbase: "00"}}} }

type fixture struct {
	mu         sync.Mutex
	bind       Binding
	tip        Tip
	hashes     map[int64]string
	blocks     map[string]block
	pool       []tx
	fail       string
	substitute map[string]string
	methods    []string
	after      func(string)
}

func setup() (*fixture, Binding, Limits) {
	now := time.Now()
	b := Binding{Seal: Point{digest(100), 1}, SealScript: "51", Anchor: Anchor{Tip{10, digest(10)}, digest(200)},
		Commitment: digest(300), Genesis: digest(999), Chain: "regtest", StartTip: Tip{10, digest(10)},
		Deadline: now.Add(time.Minute), ProofValidUntil: now.Add(time.Minute), LastBlockAt: now.Add(-time.Minute)}
	f := &fixture{bind: b, tip: b.StartTip, hashes: map[int64]string{0: b.Genesis, 10: b.StartTip.Hash}, blocks: map[string]block{}, substitute: map[string]string{}}
	l := DefaultLimits()
	l.Polls = 1
	return f, b, l
}
func (f *fixture) addBlock(txs ...tx) {
	f.tip = Tip{f.tip.Height + 1, digest(int(f.tip.Height + 1))}
	f.hashes[f.tip.Height] = f.tip.Hash
	f.blocks[f.tip.Hash] = block{Hash: f.tip.Hash, Height: ptr(f.tip.Height), Tx: append([]tx{coinbase(digest(1000 + int(f.tip.Height)))}, txs...)}
}
func (f *fixture) spends(t tx) bool {
	for _, v := range t.Vin {
		if v.TxID == f.bind.Seal.TxID && v.Vout != nil && *v.Vout == f.bind.Seal.Vout {
			return true
		}
	}
	return false
}
func (f *fixture) Call(ctx context.Context, m string, p ...any) (io.ReadCloser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	f.methods = append(f.methods, m)
	if m == f.fail {
		return nil, errors.New("synthetic private broker detail must never enter verdict")
	}
	if raw, ok := f.substitute[m]; ok {
		return io.NopCloser(strings.NewReader(raw)), nil
	}
	var result any
	switch m {
	case "getblockchaininfo":
		result = map[string]any{"chain": f.bind.Chain, "blocks": f.tip.Height, "headers": f.tip.Height, "bestblockhash": f.tip.Hash, "initialblockdownload": false}
	case "getblockhash":
		h := p[0].(int64)
		result = f.hashes[h]
	case "getrawtransaction":
		id := p[0].(string)
		if id == f.bind.Anchor.TxID {
			result = tx{TxID: id, BlockHash: f.bind.Anchor.Hash, Confirmations: ptr(int64(1)), Vout: []output{{N: ptr(uint32(0)), Script: struct {
				Hex string `json:"hex"`
			}{"6a20" + f.bind.Commitment}}}}
		} else {
			found := false
			for _, t := range f.pool {
				if t.TxID == id {
					result = t
					found = true
				}
			}
			if !found {
				return nil, errors.New("transaction unavailable")
			}
		}
	case "getblock":
		result = f.blocks[p[0].(string)]
	case "getrawmempool":
		ids := []string{}
		for _, t := range f.pool {
			ids = append(ids, t.TxID)
		}
		result = ids
	case "gettxout":
		// UTXO truth is derived from actual transaction inputs, not a verdict label.
		spent := false
		for _, b := range f.blocks {
			for _, t := range b.Tx {
				spent = spent || f.spends(t)
			}
		}
		if p[2].(bool) {
			for _, t := range f.pool {
				spent = spent || f.spends(t)
			}
		}
		if !spent {
			result = map[string]any{"bestblock": f.tip.Hash, "confirmations": 1, "scriptPubKey": map[string]any{"hex": f.bind.SealScript}}
		}
	default:
		return nil, fmt.Errorf("unexpected method %s", m)
	}
	raw, err := json.Marshal(result)
	if f.after != nil {
		f.after(m)
	}
	return io.NopCloser(strings.NewReader(string(raw))), err
}
func verdict(t *testing.T, f *fixture, b Binding, l Limits, state string) Verdict {
	t.Helper()
	v := New(f).Watch(context.Background(), b, l)
	if v.State != state {
		t.Fatalf("want %s: %+v", state, v)
	}
	if v.PrivilegedCommandsAllowed {
		t.Fatal("adapter authorized a command")
	}
	if v.SealChainOK != (state == Unspent) {
		t.Fatal("seal result disagrees with state")
	}
	raw, _ := json.Marshal(v)
	t.Log(string(raw))
	return v
}

func TestCausalUnspentMempoolFirstBlock(t *testing.T) {
	f, b, l := setup()
	live := verdict(t, f, b, l, Unspent)
	if live.ValidUntil.Sub(live.ObservedAt) > time.Second || live.Tip != b.StartTip {
		t.Fatal("positive observation not bounded")
	}
	spend := normalTx(digest(400), b.Seal)
	f.pool = []tx{spend}
	suspended := verdict(t, f, b, l, Suspend)
	if suspended.SpendTxID != spend.TxID || suspended.Reason != "MEMPOOL_SEAL_INPUT" {
		t.Fatal(suspended)
	}
	// No positive UTXO read or later poll can delay suspension once found.
	if f.methods[len(f.methods)-1] != "getrawtransaction" {
		t.Fatal("read after immediate suspension")
	}
	// Change exactly the spending input: an unrelated transaction does not revoke.
	f.pool[0] = normalTx(spend.TxID, Point{b.Seal.TxID, 2})
	verdict(t, f, b, l, Unspent)
	f.pool = nil
	f.addBlock(spend)
	b.Prior = suspended
	final := verdict(t, f, b, l, FinalRevoked)
	if final.SpendTxID != spend.TxID || final.SpendBlock != f.tip.Hash {
		t.Fatal(final)
	}
	// Remove the causal input from the block and the seal becomes unspent again
	// only in a fresh unsuspended fixture. The prior suspension remains sticky.
	f.blocks[f.tip.Hash] = block{Hash: f.tip.Hash, Height: ptr(f.tip.Height), Tx: []tx{coinbase(digest(1001)), normalTx(spend.TxID, Point{b.Seal.TxID, 2})}}
	verdict(t, f, b, l, Suspend)
	b.Prior = Verdict{}
	verdict(t, f, b, l, Unspent)
}

func TestDroppedSpendNeverResumes(t *testing.T) {
	f, b, l := setup()
	f.pool = []tx{normalTx(digest(400), b.Seal)}
	b.Prior = verdict(t, f, b, l, Suspend)
	f.pool = nil
	v := verdict(t, f, b, l, Suspend)
	if v.Reason != "PRIOR_SPEND_REQUIRES_RECONCILIATION" {
		t.Fatal(v)
	}
	b.Prior.Seal.Vout++
	verdict(t, f, b, l, Unknown)
}

func TestReorgAndTipRace(t *testing.T) {
	t.Run("anchor", func(t *testing.T) {
		f, b, l := setup()
		f.hashes[10] = digest(777)
		v := verdict(t, f, b, l, Unknown)
		if v.Reason != "REORG" {
			t.Fatal(v)
		}
	})
	t.Run("rollback", func(t *testing.T) {
		f, b, l := setup()
		f.tip.Height = 9
		v := verdict(t, f, b, l, Unknown)
		if v.Reason != "REORG" {
			t.Fatal(v)
		}
	})
	t.Run("during-read", func(t *testing.T) {
		f, b, l := setup()
		f.after = func(m string) {
			if m == "gettxout" {
				f.tip.Hash = digest(888)
			}
		}
		v := verdict(t, f, b, l, Unknown)
		if v.Reason != "TIP_CHANGED_DURING_READ" && v.Reason != "SEAL_BINDING" {
			t.Fatal(v)
		}
	})
	t.Run("confirmed-spend-race", func(t *testing.T) {
		f, b, l := setup()
		f.addBlock(normalTx(digest(400), b.Seal))
		f.after = func(m string) {
			if m == "getblock" {
				f.hashes[11] = digest(888)
			}
		}
		v := verdict(t, f, b, l, Unknown)
		if v.Reason != "REORG" {
			t.Fatal(v)
		}
	})
}

func TestUnknownCannotAdmit(t *testing.T) {
	cases := []struct{ name, method, raw string }{
		{"empty-pool-missing-utxo", "gettxout", "null"},
		{"pool-not-a-list", "getrawmempool", "null"},
		{"missing-node-fields", "getblockchaininfo", "{}"},
		{"malformed-json", "getblockchaininfo", "{"},
		{"duplicate-json", "getblockchaininfo", `{"chain":"regtest","chain":"main"}`},
		{"duplicate-case-json", "getblockchaininfo", `{"chain":"regtest","CHAIN":"main"}`},
		{"trailing-json", "getblockchaininfo", `{} {}`},
		{"wrong-chain", "getblockchaininfo", `{"chain":"main","blocks":10,"headers":10,"initialblockdownload":false,"bestblockhash":"` + digest(10) + `"}`},
		{"bad-anchor", "getrawtransaction", `{"txid":"` + digest(200) + `","blockhash":"` + digest(10) + `","confirmations":1,"vout":[]}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { f, b, l := setup(); f.substitute[c.method] = c.raw; verdict(t, f, b, l, Unknown) })
	}
	f, b, l := setup()
	f.fail = "getrawmempool"
	v := verdict(t, f, b, l, Unknown)
	raw, _ := json.Marshal(v)
	if strings.Contains(string(raw), "private broker") {
		t.Fatal("broker error leaked")
	}
	// Failed retrieval of a listed transaction is unknown, never absent/unspent.
	f, b, l = setup()
	f.substitute["getrawmempool"] = `["` + digest(400) + `"]`
	verdict(t, f, b, l, Unknown)
}

func TestProofAndNoBlockTimeBounds(t *testing.T) {
	f, b, l := setup()
	b.ProofValidUntil = time.Now().Add(-time.Second)
	v := verdict(t, f, b, l, Stop)
	if v.Reason != "EXPIRED_PROOF" || v.Calls != 0 {
		t.Fatal(v)
	}
	f, b, l = setup()
	b.LastBlockAt = time.Now().Add(-30 * time.Minute)
	v = verdict(t, f, b, l, Stop)
	if v.Reason != "NO_NEW_BLOCK_30_MIN" || v.Calls != 0 {
		t.Fatal(v)
	}
	f, b, l = setup()
	b.Deadline = time.Now().Add(-time.Second)
	v = verdict(t, f, b, l, Stop)
	if v.Calls != 0 {
		t.Fatal(v)
	}
	f, b, l = setup()
	b.LastBlockAt = time.Now().Add(time.Minute)
	verdict(t, f, b, l, Unknown)
	f, b, l = setup()
	b.LastBlockAt = time.Now().Add(-29 * time.Minute)
	verdict(t, f, b, l, Unspent)
}

func TestSixSuccessorsCannotMoveWithPoll(t *testing.T) {
	f, b, l := setup()
	for i := 0; i < 5; i++ {
		f.addBlock()
	}
	verdict(t, f, b, l, Unspent)
	f.addBlock()
	v := verdict(t, f, b, l, Stop)
	if v.Reason != "SIX_SUCCESSOR_STOP" {
		t.Fatal(v)
	}
	// Exact spend at successor six is revoked on its first active block.
	f, b, l = setup()
	for i := 0; i < 5; i++ {
		f.addBlock()
	}
	f.addBlock(normalTx(digest(400), b.Seal))
	verdict(t, f, b, l, FinalRevoked)
	// A skipped poll must not widen the original window to successor seven.
	f, b, l = setup()
	for i := 0; i < 6; i++ {
		f.addBlock()
	}
	f.addBlock(normalTx(digest(400), b.Seal))
	v = verdict(t, f, b, l, Stop)
	if v.Reason != "SIX_SUCCESSOR_STOP" {
		t.Fatal(v)
	}
}

func TestResourceBounds(t *testing.T) {
	t.Run("calls", func(t *testing.T) {
		f, b, l := setup()
		l.Calls = 1
		v := verdict(t, f, b, l, Unknown)
		if v.Calls != 1 || v.Reason != "CALL_BOUND" {
			t.Fatal(v)
		}
	})
	t.Run("response", func(t *testing.T) {
		f, b, l := setup()
		l.ResponseBytes = 16
		v := verdict(t, f, b, l, Unknown)
		if v.Bytes != 17 || v.Reason != "BYTE_BOUND" {
			t.Fatal(v)
		}
	})
	t.Run("total", func(t *testing.T) {
		f, b, l := setup()
		l.TotalBytes = 10
		v := verdict(t, f, b, l, Unknown)
		if v.Bytes != 11 || v.Reason != "BYTE_BOUND" {
			t.Fatal(v)
		}
	})
	t.Run("mempool", func(t *testing.T) {
		f, b, l := setup()
		l.MempoolTransactions = 1
		f.pool = []tx{normalTx(digest(400), Point{digest(555), 0}), normalTx(digest(401), Point{digest(556), 0})}
		verdict(t, f, b, l, Unknown)
	})
	t.Run("blocks", func(t *testing.T) {
		f, b, l := setup()
		l.BlockTransactions = 1
		f.addBlock(normalTx(digest(400), Point{digest(555), 0}))
		verdict(t, f, b, l, Unknown)
	})
	t.Run("poll-count", func(t *testing.T) {
		f, b, l := setup()
		l.Polls = 2
		l.Interval = 100 * time.Millisecond
		v := verdict(t, f, b, l, Unspent)
		if v.Polls != 2 {
			t.Fatal(v)
		}
	})
	t.Run("invalid-limit", func(t *testing.T) {
		f, b, l := setup()
		l.Polls = 65
		v := verdict(t, f, b, l, Unknown)
		if v.Calls != 0 {
			t.Fatal(v)
		}
	})
}

type blockedRPC struct{ entered chan struct{} }

func (b blockedRPC) Call(ctx context.Context, m string, p ...any) (io.ReadCloser, error) {
	close(b.entered)
	<-ctx.Done()
	return nil, ctx.Err()
}
func TestCancellationDeadlineAndConcurrentOperation(t *testing.T) {
	_, b, l := setup()
	l.CallTimeout = 100 * time.Millisecond
	enter := make(chan struct{})
	w := New(blockedRPC{enter})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan Verdict, 1)
	go func() { done <- w.Watch(ctx, b, l) }()
	<-enter
	v := w.Watch(context.Background(), b, l)
	if v.Reason != "CONCURRENT_OPERATION" {
		t.Fatal(v)
	}
	cancel()
	select {
	case v = <-done:
		if v.SealChainOK {
			t.Fatal(v)
		}
	case <-time.After(time.Second):
		t.Fatal("cancel did not terminate")
	}
	enter = make(chan struct{})
	w = New(blockedRPC{enter})
	start := time.Now()
	v = w.Watch(context.Background(), b, l)
	if v.SealChainOK || time.Since(start) > time.Second {
		t.Fatal("call timeout failed", v)
	}
}

func TestJSONVerdictIsMachineReadableAndNeverExecutes(t *testing.T) {
	f, b, l := setup()
	v := verdict(t, f, b, l, Unspent)
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err = json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got["state"] != Unspent || got["seal_chain_ok"] != true || got["privileged_commands_allowed"] != false {
		t.Fatal(string(raw))
	}
	allowed := map[string]bool{"getblockchaininfo": true, "getblockhash": true, "getrawtransaction": true, "getrawmempool": true, "gettxout": true, "getblock": true}
	for _, m := range f.methods {
		if !allowed[m] {
			t.Fatal("unexpected RPC", m)
		}
	}
	t.Log(string(raw))
}

func TestInvalidInputDoesNotReflectCallerText(t *testing.T) {
	f, b, l := setup()
	b.Seal.TxID = "untrusted arbitrary caller text"
	v := New(f).Watch(context.Background(), b, l)
	raw, _ := json.Marshal(v)
	if strings.Contains(string(raw), "untrusted") || v.Calls != 0 || v.SealChainOK {
		t.Fatal(string(raw))
	}
}

func TestPriorConfirmedSpendReorgStaysClosed(t *testing.T) {
	f, b, l := setup()
	f.addBlock(normalTx(digest(400), b.Seal))
	b.Prior = verdict(t, f, b, l, FinalRevoked)
	f.hashes[11] = digest(987)
	f.tip.Hash = digest(987)
	f.blocks = map[string]block{}
	v := verdict(t, f, b, l, Unknown)
	if v.Reason != "REORG" {
		t.Fatal(v)
	}
}
