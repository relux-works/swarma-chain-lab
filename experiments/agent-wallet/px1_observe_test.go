package wallet

// Owner S3. Unit layer of T11 (tracker, reorg, conflict), T13 (startup
// reconciliation), T14 (canary) and the status projection, against fakes of
// the frozen interfaces: a simulated own node (su.Node) and an in-memory
// JournalV2. The regtest Core layer is px1_observe_core_test.go.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// ---------------------------------------------------------------------------
// Fakes.

// px1FakeJournal is an in-memory JournalV2 of one layer.
type px1FakeJournal struct {
	header    JournalHeaderV2
	records   []JournalRecordV2
	usage     JournalUsageV2
	poisoned  bool
	appendErr error
	iterErr   error
}

func px1Journal(layer string) *px1FakeJournal {
	return &px1FakeJournal{header: JournalHeaderV2{Version: 2, Layer: layer, Binding: strings.Repeat("0", 64)}}
}
func (j *px1FakeJournal) Header() JournalHeaderV2 { return j.header }
func (j *px1FakeJournal) Append(r JournalRecordV2) (JournalRecordV2, error) {
	if j.appendErr != nil {
		return JournalRecordV2{}, j.appendErr
	}
	r.Seq = uint64(len(j.records) + 1)
	j.records = append(j.records, r)
	return r, nil
}
func (j *px1FakeJournal) Iterate(from uint64, fn func(JournalRecordV2) error) error {
	if j.iterErr != nil {
		return j.iterErr
	}
	for _, r := range j.records {
		if r.Seq >= from {
			if e := fn(r); e != nil {
				return e
			}
		}
	}
	return nil
}
func (j *px1FakeJournal) Usage() JournalUsageV2 { return j.usage }
func (j *px1FakeJournal) Poisoned() bool        { return j.poisoned }
func (j *px1FakeJournal) Close()                {}

// add appends a record with the next Seq (test setup, no validation).
func (j *px1FakeJournal) add(r JournalRecordV2) JournalRecordV2 {
	r.Seq = uint64(len(j.records) + 1)
	if r.Inputs == nil {
		r.Inputs = []su.Point{}
	}
	j.records = append(j.records, r)
	return r
}

func px1Hex(c byte, n int) string {
	return strings.Repeat(string(c), 64)[:64-len(fmt.Sprint(n))] + fmt.Sprint(n)
}

// px1Reserve is a wallet-layer reserve record of grant g, wallet nonce n.
func px1Reserve(g, n, txid string, reserved int64, day string, inputs ...su.Point) JournalRecordV2 {
	return JournalRecordV2{Kind: RecordReserve, GrantID: g, Nonce: n, RequestHash: strings.Repeat("9", 64), Action: "spend", Phase: "reserved", Reserved: reserved, Fee: 1000, Day: day, Inputs: inputs, TxID: txid, Created: 100, LastTime: 100}
}
func px1Follow(kind, phase string, reserve JournalRecordV2) JournalRecordV2 {
	r := reserve
	r.Kind, r.Phase = kind, phase
	return r
}

// px1FakeChain simulates the own node: active chain, mempool, UTXO set,
// wallet balances and listtransactions, with injectable failures.
type px1FakeChain struct {
	height     int64
	epoch      int // changes block hashes after a reorg
	mempool    map[string][]su.Point
	mined      map[string]int64 // txid -> height on the active chain
	stale      map[string]bool  // txid known only from a stale block (txindex)
	inputs     map[string][]su.Point
	utxo       map[su.Point]int64
	noIndex    bool
	failures   map[string]error
	trusted    string
	pending    string
	rows       []map[string]any
	calls      map[string]int
	onCall     func(method string, n int) // hook after each call
	balanceRaw string
}

func px1NewChain() *px1FakeChain {
	return &px1FakeChain{height: 200, mempool: map[string][]su.Point{}, mined: map[string]int64{}, stale: map[string]bool{}, inputs: map[string][]su.Point{}, utxo: map[su.Point]int64{}, failures: map[string]error{}, trusted: "0.01935400", pending: "0.00000000", rows: []map[string]any{}, calls: map[string]int{}}
}
func (c *px1FakeChain) hash(h int64) string { return fmt.Sprintf("%032x%032x", c.epoch, h) }
func (c *px1FakeChain) raw(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// broadcast puts tx in the mempool and spends its inputs.
func (c *px1FakeChain) broadcast(txid string, in ...su.Point) {
	c.mempool[txid] = in
	c.inputs[txid] = in
	for _, p := range in {
		delete(c.utxo, p)
	}
}

// mine moves every mempool tx into a new block.
func (c *px1FakeChain) mine(n int) {
	for i := 0; i < n; i++ {
		c.height++
		for txid := range c.mempool {
			c.mined[txid] = c.height
			delete(c.mempool, txid)
		}
	}
}

// reorg disconnects blocks above h; their txs return to the mempool.
func (c *px1FakeChain) reorg(h int64) {
	for txid, at := range c.mined {
		if at > h {
			delete(c.mined, txid)
			c.mempool[txid] = c.inputs[txid]
		}
	}
	c.height = h
	c.epoch++
}

func (c *px1FakeChain) Call(_ context.Context, method string, args ...any) (json.RawMessage, error) {
	c.calls[method]++
	defer func() {
		if c.onCall != nil {
			c.onCall(method, c.calls[method])
		}
	}()
	if e := c.failures[method]; e != nil {
		return nil, e
	}
	switch method {
	case "getblockchaininfo":
		return c.raw(map[string]any{"chain": "regtest", "blocks": c.height, "headers": c.height, "bestblockhash": c.hash(c.height), "initialblockdownload": false}), nil
	case "getrawtransaction":
		txid := args[0].(string)
		if _, ok := c.mempool[txid]; ok {
			return c.raw(map[string]any{"txid": txid, "hex": "00"}), nil
		}
		if at, ok := c.mined[txid]; ok && !c.noIndex {
			return c.raw(map[string]any{"txid": txid, "blockhash": c.hash(at), "confirmations": c.height - at + 1}), nil
		}
		if c.stale[txid] {
			return c.raw(map[string]any{"txid": txid, "blockhash": strings.Repeat("e", 64), "confirmations": 0}), nil
		}
		return nil, errors.New("RPC_REMOTE_ERROR")
	case "gettxout":
		p := su.Point{TxID: args[0].(string), Vout: args[1].(uint32)}
		if v, ok := c.utxo[p]; ok {
			return c.raw(map[string]any{"bestblock": c.hash(c.height), "confirmations": 1, "value": json.RawMessage(su.Coins(v)), "scriptPubKey": map[string]any{"hex": "76a9"}, "coinbase": false}), nil
		}
		return json.RawMessage("null"), nil
	case "getblockhash":
		return c.raw(c.hash(args[0].(int64))), nil
	case "getblock":
		hash := args[0].(string)
		var height int64 = -1
		for h := int64(0); h <= c.height; h++ {
			if c.hash(h) == hash {
				height = h
			}
		}
		txs := []map[string]any{}
		ids := []string{}
		for txid := range c.mined {
			ids = append(ids, txid)
		}
		sort.Strings(ids) // deterministic block order
		for _, txid := range ids {
			if c.mined[txid] == height {
				vin := []map[string]any{}
				for _, p := range c.inputs[txid] {
					vin = append(vin, map[string]any{"txid": p.TxID, "vout": p.Vout})
				}
				txs = append(txs, map[string]any{"txid": txid, "vin": vin})
			}
		}
		return c.raw(map[string]any{"hash": hash, "height": height, "tx": txs}), nil
	case "getbalances":
		if c.balanceRaw != "" {
			return json.RawMessage(c.balanceRaw), nil
		}
		return json.RawMessage(`{"mine":{"trusted":` + c.trusted + `,"untrusted_pending":` + c.pending + `,"immature":0.00000000}}`), nil
	case "listtransactions":
		count, skip := args[1].(int), args[2].(int)
		page := []map[string]any{}
		for i := skip; i < skip+count && i < len(c.rows); i++ {
			page = append(page, c.rows[i])
		}
		return c.raw(page), nil
	}
	return nil, errors.New("RPC_METHOD_FORBIDDEN")
}

func px1Point(c byte, vout uint32) su.Point {
	return su.Point{TxID: strings.Repeat(string(c), 64), Vout: vout}
}

var (
	px1G   = strings.Repeat("a", 64)
	px1N1  = strings.Repeat("1", 64)
	px1N2  = strings.Repeat("2", 64)
	px1Tx1 = strings.Repeat("d", 64)
	px1Tx2 = strings.Repeat("f", 64)
)

// px1TrackerWith builds a tracker over one complete payment px1Tx1 spending
// input e:1, already broadcast into the fake mempool at tip 200.
func px1TrackerWith(t *testing.T, chain *px1FakeChain) (Tracker, *px1FakeJournal) {
	t.Helper()
	in := px1Point('e', 1)
	chain.utxo[in] = 100000
	chain.broadcast(px1Tx1, in)
	j := px1Journal(JournalLayerWallet)
	r := j.add(px1Reserve(px1G, px1N1, px1Tx1, 64600, "2026-11-12", in))
	j.add(px1Follow(RecordComplete, "complete", r))
	tr, e := NewTracker(chain, TrackerConfig{ConfirmationsK: 2, ConflictBlocksN: 6}, j)
	if e != nil {
		t.Fatal(e)
	}
	return tr, j
}

func px1Tick(t *testing.T, tr Tracker) []TrackTransition {
	t.Helper()
	out, e := tr.Tick(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	return out
}

// ---------------------------------------------------------------------------
// Tracker (T11 unit layer).

// Claim (T11): a payment becomes confirmed exactly when its depth reaches
// ConfirmationsK, with one confirmed record at the observed tip; depth K-1 is
// still pending (valid neighbour) and a confirmed payment is not re-recorded.
func TestPX1TrackerConfirmsAtK(t *testing.T) {
	chain := px1NewChain()
	tr, _ := px1TrackerWith(t, chain)
	if out := px1Tick(t, tr); len(out) != 0 || tr.Snapshot()[0].State != TrackPending {
		t.Fatal("mempool payment must stay pending")
	}
	chain.mine(1)
	if out := px1Tick(t, tr); len(out) != 0 || tr.Snapshot()[0].Confirmations != 1 || tr.Snapshot()[0].State != TrackPending {
		t.Fatal("confirmed before K: depth 1 of 2 must stay pending")
	}
	chain.mine(1)
	out := px1Tick(t, tr)
	if len(out) != 1 || out[0].Record != (TrackRecordV2{State: TrackConfirmed, Height: 202, BlockHash: chain.hash(202), Confirmations: 2}) || out[0].Payment.State != TrackConfirmed {
		t.Fatalf("confirmed record at depth K missing: %+v", out)
	}
	chain.mine(3)
	if out := px1Tick(t, tr); len(out) != 0 || tr.Snapshot()[0].Confirmations != 5 {
		t.Fatal("confirmed payment re-recorded")
	}
}

// Claim (T11): a mined payment that a reorg returns to the mempool drops to
// pending without a record, and a conflicting spend of its input then makes
// it conflicted, citing the mined spender. Valid neighbour: a mined spend of
// an unrelated outpoint leaves it pending.
func TestPX1TrackerReorgThenConflict(t *testing.T) {
	chain := px1NewChain()
	tr, _ := px1TrackerWith(t, chain)
	chain.mine(2)
	if out := px1Tick(t, tr); len(out) != 1 || out[0].Record.State != TrackConfirmed {
		t.Fatal("setup: payment not confirmed")
	}
	chain.reorg(200) // invalidateblock of the payment's block
	if out := px1Tick(t, tr); len(out) != 0 || tr.Snapshot()[0].State != TrackPending || tr.Snapshot()[0].Confirmations != 0 {
		t.Fatalf("reorged payment must be pending without a record: %+v", tr.Snapshot())
	}
	other := px1Point('7', 0)
	chain.utxo[other] = 5000
	delete(chain.mempool, px1Tx1) // mine only the unrelated spend
	chain.broadcast(strings.Repeat("6", 64), other)
	chain.mine(1)
	chain.mempool[px1Tx1] = chain.inputs[px1Tx1]
	if out := px1Tick(t, tr); len(out) != 0 || tr.Snapshot()[0].State != TrackPending {
		t.Fatal("unrelated spend marked the payment conflicted")
	}
	delete(chain.mempool, px1Tx1) // the conflict evicts the payment
	unrelated := px1Point('8', 0)
	chain.utxo[unrelated] = 5000
	chain.broadcast(strings.Repeat("0", 64), unrelated) // listed first in the block
	chain.broadcast(px1Tx2, px1Point('e', 1))
	chain.mine(1)
	out := px1Tick(t, tr)
	if len(out) != 1 || out[0].Record.State != TrackConflicted || out[0].Record.ConflictTxID != px1Tx2 || out[0].Record.Height != chain.height {
		t.Fatalf("conflicting spend not detected: %+v", out)
	}
	if out := px1Tick(t, tr); len(out) != 0 {
		t.Fatal("conflicted payment re-recorded")
	}
}

// Claim (T11): a payment absent from mempool and chain with its inputs still
// unspent becomes conflicted only after ConflictBlocksN blocks (N-1 is still
// pending), with an empty conflict txid; reappearing resets MissingSince.
func TestPX1TrackerAbsentForNBlocks(t *testing.T) {
	chain := px1NewChain()
	tr, _ := px1TrackerWith(t, chain)
	delete(chain.mempool, px1Tx1)
	chain.utxo[px1Point('e', 1)] = 100000 // evicted, input available again
	if out := px1Tick(t, tr); len(out) != 0 || tr.Snapshot()[0].MissingSince != 200 {
		t.Fatal("first absence not recorded")
	}
	chain.mine(5)
	if out := px1Tick(t, tr); len(out) != 0 {
		t.Fatal("absent payment conflicted before N blocks")
	}
	chain.mine(1)
	out := px1Tick(t, tr)
	if len(out) != 1 || out[0].Record.State != TrackConflicted || out[0].Record.ConflictTxID != "" {
		t.Fatalf("absent payment not conflicted after N blocks: %+v", out)
	}
	chain.broadcast(px1Tx1, px1Point('e', 1))
	if out := px1Tick(t, tr); len(out) != 0 || tr.Snapshot()[0].MissingSince != 0 || tr.Snapshot()[0].State != TrackConflicted {
		t.Fatal("conflicted must stay conflicted until confirmed, with MissingSince reset")
	}
	chain.mine(2)
	if out := px1Tick(t, tr); len(out) != 1 || out[0].Record.State != TrackConfirmed {
		t.Fatal("conflicted payment that confirms must record confirmed")
	}
}

// Claim: on a node without a transaction index, a mined payment (inputs
// spent, transaction not found) is found in the newest blocks and confirmed,
// not reported as conflicted.
func TestPX1TrackerMinedWithoutIndex(t *testing.T) {
	chain := px1NewChain()
	chain.noIndex = true
	tr, _ := px1TrackerWith(t, chain)
	chain.mine(2)
	out := px1Tick(t, tr)
	if len(out) != 1 || out[0].Record.State != TrackConfirmed || out[0].Record.Confirmations != 2 {
		t.Fatalf("own spend mistaken for a conflict: %+v", out)
	}
}

// Claim: a tip that moves during a pass discards the pass (TRACKER_TIP_MOVED)
// with no state change; the next stable pass applies. A stale-block-only
// transaction (txindex, confirmations 0) is absent, not confirmed.
func TestPX1TrackerTipMoved(t *testing.T) {
	chain := px1NewChain()
	tr, _ := px1TrackerWith(t, chain)
	chain.mine(2)
	chain.onCall = func(method string, n int) {
		if method == "getrawtransaction" && n == 1 {
			chain.mine(1)
		}
	}
	if _, e := tr.Tick(context.Background()); e == nil || e.Error() != "TRACKER_TIP_MOVED" {
		t.Fatalf("tip move during the pass not detected: %v", e)
	}
	if tr.Snapshot()[0].State != TrackPending {
		t.Fatal("discarded pass changed state")
	}
	chain.onCall = nil
	if out := px1Tick(t, tr); len(out) != 1 || out[0].Record.State != TrackConfirmed {
		t.Fatal("stable pass after a moved tip must apply")
	}
	stale := px1NewChain()
	tr2, _ := px1TrackerWith(t, stale)
	delete(stale.mempool, px1Tx1)
	stale.stale[px1Tx1] = true
	stale.utxo[px1Point('e', 1)] = 100000
	if px1Tick(t, tr2); tr2.Snapshot()[0].MissingSince != 200 || tr2.Snapshot()[0].Confirmations != 0 {
		t.Fatal("stale-block transaction treated as present")
	}
}

// Claim: an unreachable node fails the pass and never counts as absence; a
// node that answers "no such transaction" (RPC_REMOTE_ERROR) does.
func TestPX1TrackerNodeFailure(t *testing.T) {
	chain := px1NewChain()
	tr, _ := px1TrackerWith(t, chain)
	delete(chain.mempool, px1Tx1)
	chain.utxo[px1Point('e', 1)] = 100000
	chain.failures["getrawtransaction"] = errors.New("RPC_UNAVAILABLE")
	if _, e := tr.Tick(context.Background()); e == nil || e.Error() != "RPC_UNAVAILABLE" || tr.Snapshot()[0].MissingSince != 0 {
		t.Fatalf("unreachable node counted as absence: %v %+v", e, tr.Snapshot())
	}
	delete(chain.failures, "getrawtransaction")
	if px1Tick(t, tr); tr.Snapshot()[0].MissingSince != 200 {
		t.Fatal("remote no-such-transaction not counted as absence")
	}
	chain.failures["getblockchaininfo"] = errors.New("unbounded text from a node")
	if _, e := tr.Tick(context.Background()); e == nil || e.Error() != "RPC_UNAVAILABLE" {
		t.Fatalf("unbounded node error leaked: %v", e)
	}
}

// Claim: startup reload tracks completed, uncertain and still-reserved
// requests in ReserveSeq order, restores the latest track state, and skips
// refuse-retained requests; a complete record without its reserve refuses
// JOURNAL_SEGMENT, as do invalid configs and a service-layer journal.
func TestPX1TrackerReload(t *testing.T) {
	j := px1Journal(JournalLayerWallet)
	in := func(c byte) su.Point { return px1Point(c, 0) }
	a := j.add(px1Reserve(px1G, px1N1, px1Hex('d', 1), 1000, "d", in('1')))
	b := j.add(px1Reserve(px1G, px1N2, px1Hex('d', 2), 1000, "d", in('2')))
	c := j.add(px1Reserve(px1G, px1Hex('3', 3), px1Hex('d', 3), 1000, "d", in('3')))
	d := j.add(px1Reserve(px1G, px1Hex('4', 4), px1Hex('d', 4), 1000, "d", in('4')))
	j.add(px1Follow(RecordComplete, "complete", a))
	tr := px1Follow(RecordTrack, TrackConfirmed, a)
	tr.Track = &TrackRecordV2{State: TrackConfirmed, Height: 9, BlockHash: strings.Repeat("b", 64), Confirmations: 2}
	j.add(tr)
	j.add(px1Follow(RecordUncertain, "uncertain", b))
	j.add(px1Follow(RecordRefuseRetained, "refused", c))
	_ = d // left reserved: a crash before any later record
	tracker, e := NewTracker(px1NewChain(), TrackerConfig{ConfirmationsK: 2, ConflictBlocksN: 6}, j)
	if e != nil {
		t.Fatal(e)
	}
	s := tracker.Snapshot()
	if len(s) != 3 || s[0].TxID != a.TxID || s[0].State != TrackConfirmed || s[0].Confirmations != 2 || s[1].TxID != b.TxID || s[2].TxID != d.TxID || s[2].State != TrackPending {
		t.Fatalf("reload set wrong: %+v", s)
	}
	bad := px1Journal(JournalLayerWallet)
	bad.add(px1Follow(RecordComplete, "complete", a))
	cfg := TrackerConfig{ConfirmationsK: 2, ConflictBlocksN: 6}
	if _, e := NewTracker(px1NewChain(), cfg, bad); e == nil || e.Error() != CodeJournalSegment {
		t.Fatalf("orphan complete record accepted: %v", e)
	}
	for _, c := range []TrackerConfig{{0, 6}, {2, 0}, {101, 6}, {2, 1001}} {
		if _, e := NewTracker(px1NewChain(), c, j); e == nil || e.Error() != "SERVICE_CONFIG" {
			t.Fatalf("config %+v accepted", c)
		}
	}
	if _, e := NewTracker(px1NewChain(), cfg, px1Journal(JournalLayerService)); e == nil {
		t.Fatal("service-layer journal accepted")
	}
	if _, e := NewTracker(nil, cfg, j); e == nil {
		t.Fatal("nil node accepted")
	}
	if _, e := NewTracker(px1NewChain(), cfg, nil); e == nil {
		t.Fatal("nil journal accepted")
	}
}

// Claim: Enqueue keeps ReserveSeq order, is idempotent for the same payment,
// and refuses another txid under a known reservation or a malformed payment.
func TestPX1TrackerEnqueue(t *testing.T) {
	tr, e := NewTracker(px1NewChain(), TrackerConfig{ConfirmationsK: 2, ConflictBlocksN: 6}, px1Journal(JournalLayerWallet))
	if e != nil {
		t.Fatal(e)
	}
	p := func(seq uint64, txid string) TrackedPayment {
		return TrackedPayment{GrantID: px1G, Nonce: px1Hex('1', int(seq)), TxID: txid, Inputs: []su.Point{px1Point('e', uint32(seq))}, ReserveSeq: seq, BroadcastTip: 300, State: TrackConfirmed}
	}
	for _, seq := range []uint64{5, 2, 9} {
		if e := tr.Enqueue(p(seq, px1Hex('d', int(seq)))); e != nil {
			t.Fatal(e)
		}
	}
	if e := tr.Enqueue(p(5, px1Hex('d', 5))); e != nil {
		t.Fatal("same payment twice must be a no-op")
	}
	s := tr.Snapshot()
	if len(s) != 3 || s[0].ReserveSeq != 2 || s[1].ReserveSeq != 5 || s[2].ReserveSeq != 9 || s[0].State != TrackPending {
		t.Fatalf("enqueue order or initial state wrong: %+v", s)
	}
	s[0].Inputs[0].Vout = 77
	if tr.Snapshot()[0].Inputs[0].Vout == 77 {
		t.Fatal("snapshot aliases tracker state")
	}
	bad := []TrackedPayment{p(5, px1Hex('d', 6)), p(0, px1Hex('d', 1)), {GrantID: px1G, Nonce: px1N1, TxID: px1Tx1, ReserveSeq: 3}, {GrantID: "x", Nonce: px1N1, TxID: px1Tx1, Inputs: []su.Point{px1Point('e', 0)}, ReserveSeq: 3}}
	for i, b := range bad {
		if e := tr.Enqueue(b); e == nil || e.Error() != "TRACKER_PAYMENT" {
			t.Fatalf("bad payment %d accepted: %v", i, e)
		}
	}
}

// ---------------------------------------------------------------------------
// Canary (T14 unit layer), float, reconciliation (T13 unit layer), alerts.

// Claim (T14): the canary reads unspent while its outpoint holds the
// configured value, spent once gettxout is null (and stays spent if the
// outpoint reappears), and unknown on a node failure or another value; only
// the canary outpoint is excluded from planning.
func TestPX1CanaryStates(t *testing.T) {
	chain := px1NewChain()
	cfg := px1Operator().Canary
	chain.utxo[cfg.Outpoint] = cfg.ValueSat
	c, e := NewCanary(chain, cfg)
	if e != nil {
		t.Fatal(e)
	}
	if !c.Excluded(cfg.Outpoint) || c.Excluded(su.Point{TxID: cfg.Outpoint.TxID, Vout: 1}) {
		t.Fatal("canary exclusion wrong")
	}
	if s, e := c.Check(context.Background()); s != CanaryUnspent || e != nil {
		t.Fatalf("unspent canary read as %s %v", s, e)
	}
	chain.utxo[cfg.Outpoint] = cfg.ValueSat + 1
	if s, e := c.Check(context.Background()); s != CanaryUnknown || e == nil || e.Error() != "CANARY_VALUE" {
		t.Fatalf("canary with another value read as %s %v", s, e)
	}
	chain.utxo[cfg.Outpoint] = cfg.ValueSat
	chain.failures["gettxout"] = errors.New("RPC_UNAVAILABLE")
	if s, e := c.Check(context.Background()); s != CanaryUnknown || e == nil {
		t.Fatalf("node failure read as %s", s)
	}
	delete(chain.failures, "gettxout")
	delete(chain.utxo, cfg.Outpoint)
	if s, _ := c.Check(context.Background()); s != CanarySpent {
		t.Fatalf("spent canary read as %s", s)
	}
	chain.utxo[cfg.Outpoint] = cfg.ValueSat
	if s, _ := c.Check(context.Background()); s != CanarySpent {
		t.Fatal("spent canary must stay spent after it reappears")
	}
	for _, bad := range []CanaryConfig{{Outpoint: su.Point{TxID: "c"}, ValueSat: 10000}, {Outpoint: cfg.Outpoint, ValueSat: DustLimitSat - 1}} {
		if _, e := NewCanary(chain, bad); e == nil || e.Error() != "SERVICE_CONFIG" {
			t.Fatalf("bad canary config accepted: %+v", bad)
		}
	}
	if _, e := NewCanary(nil, cfg); e == nil {
		t.Fatal("nil node accepted")
	}
}

// Claim: the float is ok on both boundaries (low and max inclusive), low one
// atom below, excess one atom above, and unknown on a malformed reply.
func TestPX1FloatMonitor(t *testing.T) {
	chain := px1NewChain()
	f, e := NewFloatMonitor(chain, 2000000, 500000)
	if e != nil {
		t.Fatal(e)
	}
	for _, c := range []struct {
		trusted, pending string
		want             string
		balance          int64
	}{{"0.00500000", "0", "ok", 500000}, {"0.00499999", "0", "low", 499999}, {"0.01999999", "0.00000001", "ok", 2000000}, {"0.02000000", "0.00000001", "excess", 2000001}} {
		chain.trusted, chain.pending = c.trusted, c.pending
		r, e := f.Check(context.Background())
		if e != nil || r.State != c.want || r.BalanceSat != c.balance || r.MaxFloatSat != 2000000 || r.LowFloatSat != 500000 {
			t.Fatalf("float boundary %s+%s: %+v %v", c.trusted, c.pending, r, e)
		}
	}
	chain.balanceRaw = `{"mine":{"trusted":"x"}}`
	if r, e := f.Check(context.Background()); e == nil || r.State != "unknown" || r.BalanceSat != 0 {
		t.Fatal("malformed balances accepted")
	}
	for _, b := range [][2]int64{{0, 0}, {100, 101}, {100, -1}} {
		if _, e := NewFloatMonitor(chain, b[0], b[1]); e == nil {
			t.Fatalf("float bounds %v accepted", b)
		}
	}
}

func px1Rows(n int, category string, txid func(i int) string) []map[string]any {
	rows := make([]map[string]any, n)
	for i := range rows {
		rows[i] = map[string]any{"txid": txid(i), "category": category, "amount": -0.001, "confirmations": 1, "time": 1}
	}
	return rows
}

// Claim (T13): startup reconciliation accepts a wallet whose every send is
// carried by a wallet-layer record (receives never matter), and refuses
// STATE_RECONCILE_REQUIRED for one unknown send, including one on the second
// listtransactions page, and when the history exceeds the page bound.
func TestPX1ReconcilerT13(t *testing.T) {
	j := px1Journal(JournalLayerWallet)
	known := j.add(px1Reserve(px1G, px1N1, px1Tx1, 1000, "d", px1Point('e', 0)))
	chain := px1NewChain()
	chain.rows = append(px1Rows(1, "send", func(int) string { return known.TxID }), px1Rows(3, "receive", func(i int) string { return px1Hex('5', i) })...)
	r, e := NewStartupReconciler(chain)
	if e != nil {
		t.Fatal(e)
	}
	if e := r.Reconcile(context.Background(), j); e != nil {
		t.Fatalf("known sends refused: %v", e)
	}
	chain.rows = append(chain.rows, px1Rows(1, "send", func(int) string { return px1Tx2 })...)
	if e := r.Reconcile(context.Background(), j); e == nil || e.Error() != CodeStateReconcileRequired {
		t.Fatalf("unknown send accepted: %v", e)
	}
	chain.rows = append(px1Rows(px1ReconcilePage, "receive", func(i int) string { return px1Hex('5', i) }), px1Rows(1, "send", func(int) string { return px1Tx2 })...)
	if e := r.Reconcile(context.Background(), j); e == nil || e.Error() != CodeStateReconcileRequired {
		t.Fatalf("unknown send on page two accepted: %v", e)
	}
	chain.rows = px1Rows(px1ReconcilePage*px1ReconcileMaxPages, "receive", func(i int) string { return px1Hex('5', i) })
	if e := r.Reconcile(context.Background(), j); e == nil || e.Error() != CodeStateReconcileRequired {
		t.Fatalf("unbounded history accepted: %v", e)
	}
	chain.rows = nil
	chain.failures["listtransactions"] = errors.New("RPC_UNAVAILABLE")
	if e := r.Reconcile(context.Background(), j); e == nil || e.Error() != "RPC_UNAVAILABLE" {
		t.Fatal("wallet failure accepted")
	}
	if e := r.Reconcile(context.Background(), nil); e == nil {
		t.Fatal("nil journal accepted")
	}
	if _, e := NewStartupReconciler(nil); e == nil {
		t.Fatal("nil route accepted")
	}
}

// Claim: the log sink writes one bounded line per alert of the closed set,
// redacts any detail outside the schema alphabet, and drops unknown codes.
func TestPX1LogAlertSink(t *testing.T) {
	var lines []string
	s := NewLogAlertSink(func(l string) { lines = append(lines, l) })
	s.Raise(Alert{Code: AlertPaymentConflicted, At: 7, Detail: px1Tx1})
	s.Raise(Alert{Code: AlertCanarySpent, At: 8, Detail: "secret key=abc\nnext"})
	s.Raise(Alert{Code: "ALERT_NOT_IN_SET", At: 9, Detail: "x"})
	s.Raise(Alert{Code: AlertFloatLow, At: -1, Detail: strings.Repeat("a", px1AlertDetailMax+1)})
	want := []string{"PX1_ALERT code=ALERT_PAYMENT_CONFLICTED at=7 detail=" + px1Tx1, "PX1_ALERT code=ALERT_CANARY_SPENT at=8 detail=REDACTED", "PX1_ALERT code=ALERT_FLOAT_LOW at=0 detail=REDACTED"}
	if strings.Join(lines, "|") != strings.Join(want, "|") {
		t.Fatalf("alert lines not bounded: %q", lines)
	}
	NewLogAlertSink(nil).Raise(Alert{Code: AlertCanarySpent})
}

// ---------------------------------------------------------------------------
// Status projection.

// px1StatusJournals builds journals behind the frozen status fixture: one
// completed 64600-atom payment, four admissions, two terminal refusals.
func px1StatusJournals(day string) (*px1FakeJournal, *px1FakeJournal) {
	w := px1Journal(JournalLayerWallet)
	r := w.add(px1Reserve(strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("d", 64), 64600, day, su.Point{TxID: strings.Repeat("e", 64), Vout: 1}))
	w.add(px1Follow(RecordComplete, "complete", r))
	s := px1Journal(JournalLayerService)
	for _, verdict := range []struct{ v, reason string }{{"executed", "EXECUTED"}, {"refused", "TRANSFER_CAP_EXCEEDED"}, {"refused", "ADDRESS_NOT_ALLOWED"}} {
		s.add(JournalRecordV2{Kind: RecordTerminal, Service: &ServiceRecordV2{Receipt: &SignedActionReceipt{Receipt: ActionReceipt{Verdict: verdict.v, Reason: verdict.reason}}}})
	}
	s.usage = JournalUsageV2{Admitted: 4, SpendCapacity: 2048, Segments: 1}
	return w, s
}

func px1FixtureInputs(w, s JournalV2) StatusInputs {
	f := px1StatusFixture()
	g := f.Grants[0]
	return StatusInputs{Service: s, Wallet: w, Limits: []EffectiveLimits{{GrantID: g.GrantID, TotalCapSat: 500000, SpendCapSat: 500000, TransferCapSat: 100000, DayCapSat: 300000, DayCountCap: 5, FeeCapSat: 100000, RecipientMode: RecipientModeAllow}},
		Seals: map[string]StatusSealCheck{g.GrantID: g.Seal}, Tip: f.Tip, Tracked: f.Payments.Items, Float: f.Float, Canary: f.Canary, Alerts: nil, ReceiptKey: f.ReceiptKey, Network: f.Network, Now: f.GeneratedAt}
}

// Claim: ProjectStatus reproduces the frozen golden projection from journals
// and cached observations, byte for byte except the grant day, which is
// derived from generated_at (the fixture's day disagrees with its own
// generated_at; freeze amendment S3-A1). Empty lists encode as [].
func TestPX1ProjectStatusGolden(t *testing.T) {
	day := px1StatusDay(px1StatusFixture().GeneratedAt)
	w, s := px1StatusJournals(day)
	got, e := ProjectStatus(px1FixtureInputs(w, s))
	if e != nil {
		t.Fatal(e)
	}
	want := px1StatusFixture()
	want.Grants[0].Day = day
	if !bytes.Equal(canonical(got), canonical(want)) {
		t.Fatalf("projection differs from the golden\n got %s\nwant %s", canonical(got), canonical(want))
	}
	golden := bytes.Replace(px1Golden(t, "status-projection-v1.json"), []byte(`"day":"2026-11-12"`), []byte(`"day":"`+day+`"`), 1)
	if !bytes.Equal(canonical(got), golden) {
		t.Fatal("projection differs from the golden bytes")
	}
	empty, e := ProjectStatus(StatusInputs{Service: px1Journal(JournalLayerService), Wallet: px1Journal(JournalLayerWallet), ReceiptKey: px1ExecutorKey, Network: "regtest", Now: 5})
	if e != nil {
		t.Fatal(e)
	}
	for _, m := range []string{`"grants":[]`, `"items":[]`, `"refusals":[]`, `"alerts":[]`, `"state":"unknown"`, `"percent_used":100`} {
		if !strings.Contains(string(canonical(empty)), m) {
			t.Fatalf("empty projection lacks %s: %s", m, canonical(empty))
		}
	}
}

// Claim: status day usage follows the frozen rule: an uncertain or reserved
// request from an earlier day counts today, a completed or refused one from
// an earlier day does not, today's refuse-retained does; a reconcile release
// lowers retained and day usage, and a fully released request leaves the day
// count. Releasing more than retained refuses JOURNAL_SEGMENT.
func TestPX1StatusDayRule(t *testing.T) {
	const today, earlier = "2026-11-06", "2026-11-05"
	w := px1Journal(JournalLayerWallet)
	n := func(i int) string { return px1Hex('1', i) }
	tx := func(i int) string { return px1Hex('d', i) }
	in := su.Point{TxID: strings.Repeat("e", 64)}
	old1 := w.add(px1Reserve(px1G, n(1), tx(1), 1000, earlier, in))
	w.add(px1Follow(RecordUncertain, "uncertain", old1))
	w.add(px1Reserve(px1G, n(2), tx(2), 2000, earlier, in)) // still reserved
	old3 := w.add(px1Reserve(px1G, n(3), tx(3), 4000, earlier, in))
	w.add(px1Follow(RecordComplete, "complete", old3))
	old4 := w.add(px1Reserve(px1G, n(4), tx(4), 8000, earlier, in))
	w.add(px1Follow(RecordRefuseRetained, "refused", old4))
	new5 := w.add(px1Reserve(px1G, n(5), tx(5), 16000, today, in))
	w.add(px1Follow(RecordRefuseRetained, "refused", new5))
	new6 := w.add(px1Reserve(px1G, n(6), tx(6), 32000, today, in))
	w.add(px1Follow(RecordComplete, "complete", new6))
	w.add(JournalRecordV2{Kind: RecordReconcile, GrantID: px1G, Nonce: n(6), Reconcile: &ReconcileRecordV2{TargetSeq: new6.Seq, Evidence: "conflict", ReleasedSat: 32000}})
	w.add(JournalRecordV2{Kind: RecordReconcile, GrantID: px1G, Nonce: n(1), Reconcile: &ReconcileRecordV2{TargetSeq: old1.Seq, Evidence: "absent", ReleasedSat: 400}})
	s := px1Journal(JournalLayerService)
	s.usage = JournalUsageV2{Admitted: 6, SpendCapacity: 2048, Segments: 1}
	in2 := StatusInputs{Service: s, Wallet: w, Limits: []EffectiveLimits{{GrantID: px1G, TotalCapSat: 500000, SpendCapSat: 400000, TransferCapSat: 100000, DayCapSat: 300000, DayCountCap: 5}}, ReceiptKey: px1ExecutorKey, Network: "regtest", Now: 1794000600}
	got, e := ProjectStatus(in2)
	if e != nil {
		t.Fatal(e)
	}
	g := got.Grants[0]
	// counted today: n1 uncertain (600), n2 reserved (2000), n5 refused today (16000); n6 fully released.
	want := StatusGrant{GrantID: px1G, TotalCapSat: 500000, SpendCapSat: 400000, TransferCapSat: 100000, DayCapSat: 300000, DayCountCap: 5, SpentSat: 4000, ReservedSat: 600 + 2000 + 4000 + 8000 + 16000, UncertainSat: 600, ReleasedSat: 32400,
		TotalRemainingSat: 500000 - 30600, Day: today, DayUsedSat: 18600, DayCount: 3, DayRemainingSat: 300000 - 18600, DayCountRemaining: 2, Seal: px1UnobservedSeal()}
	if g != want {
		t.Fatalf("day rule wrong\n got %+v\nwant %+v", g, want)
	}
	// n1 retains 600 after its 400 release: releasing 601 exceeds the retained debit.
	w.add(JournalRecordV2{Kind: RecordReconcile, GrantID: px1G, Nonce: n(1), Reconcile: &ReconcileRecordV2{TargetSeq: old1.Seq, ReleasedSat: 601}})
	if _, e := ProjectStatus(in2); e == nil || e.Error() != CodeJournalSegment {
		t.Fatalf("over-release accepted: %v", e)
	}
}

// Claim: ProjectStatus refuses missing or swapped journals, a bad network or
// receipt key, duplicate grants and unknown tracker states; it reports a
// poisoned journal, keeps only the last 64 alerts, and replaces an invalid
// cached seal by unknown/UNOBSERVED.
func TestPX1ProjectStatusRefusals(t *testing.T) {
	w, s := px1StatusJournals("2026-11-06")
	base := px1FixtureInputs(w, s)
	for name, mutate := range map[string]func(*StatusInputs){
		"nil service":   func(in *StatusInputs) { in.Service = nil },
		"swapped":       func(in *StatusInputs) { in.Service, in.Wallet = in.Wallet, in.Service },
		"network":       func(in *StatusInputs) { in.Network = "testnet" },
		"receipt key":   func(in *StatusInputs) { in.ReceiptKey = strings.Repeat("z", 64) },
		"duplicate":     func(in *StatusInputs) { in.Limits = append(in.Limits, in.Limits[0]) },
		"tracker state": func(in *StatusInputs) { in.Tracked = []TrackedPayment{{State: "lost"}} },
	} {
		in := base
		mutate(&in)
		if _, e := ProjectStatus(in); e == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	in := base
	s.poisoned = true
	for i := 0; i < 70; i++ {
		in.Alerts = append(in.Alerts, Alert{Code: AlertFloatLow, At: int64(i)})
	}
	in.Seals = map[string]StatusSealCheck{px1StatusFixture().Grants[0].GrantID: {Verdict: "open", Reason: "lower case"}}
	got, e := ProjectStatus(in)
	if e != nil || !got.Poisoned || len(got.Alerts) != px1AlertTail || got.Alerts[0].At != 6 || got.Grants[0].Seal != px1UnobservedSeal() {
		t.Fatalf("poison, alert tail or seal sanitation wrong: %+v %v", got, e)
	}
}

// Claim: the status day equals S2's UTCDay for UTC boundaries. Pending S2:
// skipped while UTCDay is the fail-closed stub.
func TestPX1StatusDayMatchesUTCDay(t *testing.T) {
	if UTCDay(0) == "" {
		t.Skip("pending S2: UTCDay is a stub")
	}
	for _, u := range []int64{0, 86399, 86400, 1794000600, 1794009599, 1794009600} {
		if px1StatusDay(u) != UTCDay(u) {
			t.Fatalf("day of %d differs from UTCDay", u)
		}
	}
}

// Claim: the status grant numbers equal S2's folded ledger over the same
// journal (same numbers as the budget read). Pending S2: skipped while
// FoldLedgerV2 is the stub.
func TestPX1StatusMatchesLedger(t *testing.T) {
	w, s := px1StatusJournals("2026-11-06")
	ledger, e := FoldLedgerV2(w)
	if errors.Is(e, ErrNotImplemented) {
		t.Skip("pending S2: FoldLedgerV2 is a stub")
	}
	if e != nil {
		t.Fatal(e)
	}
	got, e := ProjectStatus(px1FixtureInputs(w, s))
	if e != nil {
		t.Fatal(e)
	}
	g := got.Grants[0]
	used, count := ledger.DayUsage(g.GrantID, g.Day)
	if ledger.SpendUsed(g.GrantID) != g.ReservedSat || used != g.DayUsedSat || count != g.DayCount || ledger.UncertainSat(g.GrantID) != g.UncertainSat {
		t.Fatal("status numbers differ from the folded ledger")
	}
}

// ---------------------------------------------------------------------------
// Status socket.

// Claim: one canonical status request gets the canonical projection, which
// ExchangeStatus decodes; any other request, a source error, or an
// oversized frame closes the connection without a reply, and the source is
// never called for an invalid request.
func TestPX1ServeStatus(t *testing.T) {
	want := px1StatusFixture()
	serve := func(request []byte, source func() (StatusProjectionV1, error)) ([]byte, error) {
		client, server := net.Pipe()
		done := make(chan error, 1)
		go func() { done <- ServeStatus(context.Background(), server, source) }()
		client.SetDeadline(time.Now().Add(5 * time.Second))
		px1WriteFrame(client, request, 1<<20)
		reply, _ := px1ReadFrame(client, px1StatusResponseMax)
		client.Close()
		return reply, <-done
	}
	called := 0
	source := func() (StatusProjectionV1, error) { called++; return want, nil }
	reply, e := serve([]byte(`{"v":1,"action":"status"}`), source)
	if e != nil || !bytes.Equal(reply, canonical(want)) || called != 1 {
		t.Fatalf("valid status request not served: %v", e)
	}
	for _, bad := range []string{`{"action":"status","v":1}`, `{"v":2,"action":"status"}`, `{"v":1,"action":"status","x":1}`, `{"v":1,"action":"balance"}`, ` {"v":1,"action":"status"}`} {
		reply, e := serve([]byte(bad), source)
		if reply != nil || e == nil || e.Error() != "STATUS_REQUEST" {
			t.Fatalf("status request %s accepted", bad)
		}
	}
	if called != 1 {
		t.Fatal("source called for an invalid request")
	}
	if reply, e := serve(px1StatusRequest, func() (StatusProjectionV1, error) { return StatusProjectionV1{}, errors.New("STATE_UNAVAILABLE") }); reply != nil || e == nil {
		t.Fatal("source error produced a reply")
	}
	if reply, e := serve(bytes.Repeat([]byte("x"), px1StatusRequestMax+1), source); reply != nil || e == nil || e.Error() != "STATUS_FRAME_SIZE" {
		t.Fatal("oversized status request accepted")
	}
	client, server := net.Pipe()
	go ServeStatus(context.Background(), server, source)
	got, e := ExchangeStatus(context.Background(), client)
	if e != nil || !bytes.Equal(canonical(got), canonical(want)) {
		t.Fatalf("status exchange failed: %v", e)
	}
}

// Claim: the status socket refuses an existing path and an operator group
// equal to the agent socket group, binds 0660 otherwise, and serves the
// projection to ReadPX1Status until its context ends.
func TestPX1StatusSocket(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "status.sock")
	gid := uint32(os.Getgid())
	if _, e := px1ListenStatus(path, gid, gid); e == nil || e.Error() != "STATUS_SOCKET_CONFIG" {
		t.Fatalf("operator group equal to the agent group accepted: %v", e)
	}
	if _, e := px1ListenStatus("relative.sock", gid, gid+1); e == nil {
		t.Fatal("relative socket path accepted")
	}
	l, e := px1ListenStatus(path, gid, gid+1)
	if e != nil {
		t.Fatal(e)
	}
	i, e := os.Lstat(path)
	if e != nil || i.Mode().Perm() != 0660 {
		t.Fatal("status socket mode")
	}
	if _, e := px1ListenStatus(path, gid, gid+1); e == nil || e.Error() != "STATUS_SOCKET_EXISTS" {
		t.Fatal("existing socket path accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- px1ServeStatusListener(ctx, l, func() (StatusProjectionV1, error) { return px1StatusFixture(), nil })
	}()
	got, e := ReadPX1Status(context.Background(), path)
	if e != nil || got.ReceiptKey != px1ExecutorKey {
		t.Fatalf("status over the socket: %v", e)
	}
	cancel()
	if e := <-done; e != nil {
		t.Fatal(e)
	}
}

// ---------------------------------------------------------------------------
// Runtime.

type px1FakeTracker struct {
	out      []TrackTransition
	err      error
	enqueued []TrackedPayment
}

func (f *px1FakeTracker) Enqueue(p TrackedPayment) error {
	f.enqueued = append(f.enqueued, p)
	return nil
}
func (f *px1FakeTracker) Tick(context.Context) ([]TrackTransition, error) {
	out := f.out
	f.out = nil
	return out, f.err
}
func (f *px1FakeTracker) Snapshot() []TrackedPayment {
	return append([]TrackedPayment{}, f.enqueued...)
}

type px1FakeCanary struct{ state string }

func (c *px1FakeCanary) Excluded(su.Point) bool                { return false }
func (c *px1FakeCanary) Check(context.Context) (string, error) { return c.state, nil }

type px1ErrCanary struct{}

func (px1ErrCanary) Excluded(su.Point) bool { return false }
func (px1ErrCanary) Check(context.Context) (string, error) {
	return CanaryUnknown, errors.New("RPC_UNAVAILABLE")
}

type px1FakeReconciler struct {
	err   error
	calls int
}

func (r *px1FakeReconciler) Reconcile(context.Context, JournalV2) error { r.calls++; return r.err }

type px1RuntimeLab struct {
	r          *px1Runtime
	env        px1Env
	tracker    *px1FakeTracker
	canary     *px1FakeCanary
	reconciler *px1FakeReconciler
	chain      *px1FakeChain
	poisons    int
	lines      []string
	seal       error
}

func px1NewRuntimeLab(t *testing.T) *px1RuntimeLab {
	l := &px1RuntimeLab{tracker: &px1FakeTracker{}, canary: &px1FakeCanary{state: CanaryUnspent}, reconciler: &px1FakeReconciler{}, chain: px1NewChain()}
	deps := px1RuntimeDeps{
		newTracker:    func(su.Node, TrackerConfig, JournalV2) (Tracker, error) { return l.tracker, nil },
		newCanary:     func(su.Node, CanaryConfig) (Canary, error) { return l.canary, nil },
		newFloat:      NewFloatMonitor,
		newReconciler: func(su.Node) (StartupReconciler, error) { return l.reconciler, nil },
	}
	l.r = &px1Runtime{deps: &deps, sink: NewLogAlertSink(func(s string) { l.lines = append(l.lines, s) })}
	op := px1Operator()
	w := px1Journal(JournalLayerWallet)
	s := px1Journal(JournalLayerService)
	s.usage = JournalUsageV2{SpendCapacity: 2048}
	l.env = px1Env{profile: &op, service: s, wallet: w, observer: l.chain, walletRoute: l.chain, receiptKey: px1ExecutorKey, network: "regtest", now: 1794000600, poison: func() { l.poisons++ },
		limitsFor: func(id string) (EffectiveLimits, error) {
			return EffectiveLimits{GrantID: id, TotalCapSat: 500000, SpendCapSat: 500000, TransferCapSat: 100000, DayCapSat: 300000, DayCountCap: 5}, nil
		},
		sealFor: func(context.Context, string) error { return l.seal }}
	return l
}

func (l *px1RuntimeLab) codes() []string {
	out := []string{}
	for _, a := range l.r.alerts {
		out = append(out, a.Code)
	}
	return out
}

// Claim (T14): a spent canary poisons the service on every pass, raises
// ALERT_CANARY_SPENT exactly once, and the projection shows poisoned with a
// spent canary; an unspent canary (valid neighbour) never poisons.
func TestPX1RuntimeCanarySpentPoisons(t *testing.T) {
	l := px1NewRuntimeLab(t)
	if e := l.r.tick(context.Background(), l.env); e != nil || l.poisons != 0 || len(l.r.alerts) != 0 {
		t.Fatalf("unspent canary poisoned or alerted: %v %d", e, l.poisons)
	}
	l.canary.state = CanarySpent
	for i := 0; i < 2; i++ {
		if e := l.r.tick(context.Background(), l.env); e != nil {
			t.Fatal(e)
		}
	}
	if l.poisons != 2 || strings.Join(l.codes(), ",") != AlertCanarySpent {
		t.Fatalf("spent canary must poison every pass and alert once: poisons=%d alerts=%v", l.poisons, l.codes())
	}
	p, e := l.r.status(l.env)
	if e != nil || !p.Poisoned || p.Canary.State != CanarySpent || !strings.HasPrefix(l.lines[0], "PX1_ALERT code=ALERT_CANARY_SPENT") {
		t.Fatalf("status does not show the spent canary: %+v %v", p.Canary, e)
	}
	l.canary.state = CanaryUnspent
	if l.r.tick(context.Background(), l.env); l.poisons != 3 {
		t.Fatal("a spent canary must stay spent for the runtime")
	}
}

// Claim (T13): a STATE_RECONCILE_REQUIRED startup refusal poisons the
// service, is sticky across passes without re-running reconciliation, and
// refuses PX1Enqueue; a reconciled start (valid neighbour) is ready.
func TestPX1RuntimeReconcileRefusal(t *testing.T) {
	l := px1NewRuntimeLab(t)
	l.reconciler.err = errors.New(CodeStateReconcileRequired)
	for i := 0; i < 2; i++ {
		if e := l.r.tick(context.Background(), l.env); e == nil || e.Error() != CodeStateReconcileRequired {
			t.Fatalf("reconciliation refusal not returned: %v", e)
		}
	}
	if l.poisons != 2 || l.reconciler.calls != 1 || l.r.ready {
		t.Fatalf("reconciliation refusal must poison and stay sticky: poisons=%d calls=%d", l.poisons, l.reconciler.calls)
	}
	if e := l.r.enqueue(TrackedPayment{}); e == nil || e.Error() != CodeStateReconcileRequired {
		t.Fatal("enqueue accepted after a reconciliation refusal")
	}
	ok := px1NewRuntimeLab(t)
	ok.reconciler.err = errors.New("RPC_UNAVAILABLE")
	if e := ok.r.tick(context.Background(), ok.env); e == nil || ok.poisons != 0 || ok.r.failed != "" {
		t.Fatal("a wallet RPC failure is not a reconciliation refusal")
	}
	ok.reconciler.err = nil
	if e := ok.r.tick(context.Background(), ok.env); e != nil || !ok.r.ready {
		t.Fatalf("reconciled start not ready: %v", e)
	}
}

// Claim (T11): each tracker transition becomes one wallet-layer track record
// carrying the reserve record's binding fields; a conflicted transition
// raises ALERT_PAYMENT_CONFLICTED and a confirmed one does not. A transition
// without its reserve record refuses JOURNAL_SEGMENT.
func TestPX1RuntimeTrackRecords(t *testing.T) {
	l := px1NewRuntimeLab(t)
	w := l.env.wallet.(*px1FakeJournal)
	reserve := w.add(px1Reserve(px1G, px1N1, px1Tx1, 64600, "2026-11-06", px1Point('e', 1)))
	w.add(px1Follow(RecordComplete, "complete", reserve))
	pay := TrackedPayment{GrantID: px1G, Nonce: px1N1, TxID: px1Tx1, Inputs: reserve.Inputs, ReserveSeq: reserve.Seq}
	l.tracker.out = []TrackTransition{{Payment: pay, Record: TrackRecordV2{State: TrackConfirmed, Height: 202, BlockHash: strings.Repeat("b", 64), Confirmations: 2}}}
	if e := l.r.tick(context.Background(), l.env); e != nil {
		t.Fatal(e)
	}
	l.tracker.out = []TrackTransition{{Payment: pay, Record: TrackRecordV2{State: TrackConflicted, Height: 210, BlockHash: strings.Repeat("c", 64), ConflictTxID: px1Tx2}}}
	if e := l.r.tick(context.Background(), l.env); e != nil {
		t.Fatal(e)
	}
	if len(w.records) != 4 {
		t.Fatalf("want two track records, have %d records", len(w.records))
	}
	for i, state := range []string{TrackConfirmed, TrackConflicted} {
		r := w.records[2+i]
		if r.Kind != RecordTrack || r.Phase != state || r.Track.State != state || r.TxID != px1Tx1 || r.Reserved != 64600 || r.RequestHash != reserve.RequestHash || r.Day != reserve.Day || len(r.Inputs) != 1 || r.LastTime != l.env.now {
			t.Fatalf("track record %d lacks the binding fields: %+v", i, r)
		}
	}
	if strings.Join(l.codes(), ",") != AlertPaymentConflicted {
		t.Fatalf("conflict alert wrong: %v", l.codes())
	}
	l.tracker.out = []TrackTransition{{Payment: TrackedPayment{GrantID: px1G, Nonce: px1N2, TxID: px1Tx2, ReserveSeq: 99}, Record: TrackRecordV2{State: TrackConfirmed}}}
	if e := l.r.tick(context.Background(), l.env); e == nil || e.Error() != CodeJournalSegment {
		t.Fatalf("transition without a reserve accepted: %v", e)
	}
}

// Claim: the pass raises each threshold alert once per crossing: float low
// and excess, journal high-water at 80%, clock rollback, a new uncertain
// record, and a closed seal; it caches limits and seal verdicts for status.
func TestPX1RuntimeAlerts(t *testing.T) {
	l := px1NewRuntimeLab(t)
	s := l.env.service.(*px1FakeJournal)
	w := l.env.wallet.(*px1FakeJournal)
	l.chain.trusted = "0.00400000"
	s.usage = JournalUsageV2{Admitted: 1638, SpendCapacity: 2048}
	if l.r.tick(context.Background(), l.env); strings.Join(l.codes(), ",") != AlertFloatLow {
		t.Fatalf("low float or premature high-water: %v", l.codes())
	}
	s.usage.Admitted = 1639 // 80.03%
	s.usage.LastTime = l.env.now + 10
	reserve := w.add(px1Reserve(px1G, px1N1, px1Tx1, 1000, "d", px1Point('e', 1)))
	w.add(px1Follow(RecordUncertain, "uncertain", reserve))
	l.seal = errors.New("GRANT_SEAL_SPENT")
	l.r.tick(context.Background(), l.env)
	l.chain.trusted = "0.03000000"
	l.r.tick(context.Background(), l.env)
	want := []string{AlertFloatLow, AlertClockRollback, AlertUncertainVerdict, AlertJournalHighWater, AlertSealClosed, AlertFloatExcess}
	if strings.Join(l.codes(), ",") != strings.Join(want, ",") {
		t.Fatalf("alerts not once per crossing:\n got %v\nwant %v", l.codes(), want)
	}
	p, e := l.r.status(l.env)
	if e != nil || len(p.Grants) != 1 || p.Grants[0].Seal.Verdict != "closed" || p.Grants[0].Seal.Reason != "GRANT_SEAL_SPENT" || p.Float.State != "excess" {
		t.Fatalf("status lacks cached grant, seal or float: %+v %v", p, e)
	}
	// A float or grant-limit read failure shows only in the projection; a
	// canary read failure fails the pass (valid neighbour of the same pass).
	l.chain.failures["getbalances"] = errors.New("RPC_UNAVAILABLE")
	l.env.limitsFor = func(string) (EffectiveLimits, error) { return EffectiveLimits{}, errors.New("CONTRACT_SCHEMA") }
	l.r.limits = nil
	if e := l.r.tick(context.Background(), l.env); e != nil || l.r.floatLast.State != "unknown" {
		t.Fatalf("status-only read failure failed the pass: %v", e)
	}
	if p, _ := l.r.status(l.env); len(p.Grants) != 0 {
		t.Fatal("grant without limits must be left out of the projection")
	}
	l.canary.state = CanaryUnknown
	l.r.canary = px1ErrCanary{}
	if e := l.r.tick(context.Background(), l.env); e == nil || e.Error() != "RPC_UNAVAILABLE" {
		t.Fatalf("canary read failure must fail the pass: %v", e)
	}
	for code, verdict := range map[string]string{"GRANT_EXPIRED": "closed", "GRANT_ISSUANCE_UNCONFIRMED": "pending", "RPC_UNAVAILABLE": "unknown"} {
		if px1SealVerdict(errors.New(code)).Verdict != verdict {
			t.Fatalf("%s is not %s", code, verdict)
		}
	}
	if px1SealVerdict(nil) != (StatusSealCheck{Verdict: "live", Reason: "LIVE"}) {
		t.Fatal("live seal")
	}
}

// Claim: before the first pass, enqueue is a no-op (startup reload covers
// the durable complete record) and status reports unknown observations;
// after it, enqueue reaches the tracker. A W2 env (no profile) refuses.
func TestPX1RuntimeEnqueueAndStatus(t *testing.T) {
	l := px1NewRuntimeLab(t)
	pay := TrackedPayment{GrantID: px1G, Nonce: px1N1, TxID: px1Tx1, Inputs: []su.Point{px1Point('e', 1)}, ReserveSeq: 1, State: TrackPending}
	if e := l.r.enqueue(pay); e != nil || len(l.tracker.enqueued) != 0 {
		t.Fatal("enqueue before the first pass must be a no-op")
	}
	p, e := l.r.status(l.env)
	if e != nil || p.Canary.State != CanaryUnknown || p.Float.State != "unknown" || len(p.Payments.Items) != 0 {
		t.Fatalf("status before the first pass: %+v %v", p, e)
	}
	l.r.tick(context.Background(), l.env)
	if e := l.r.enqueue(pay); e != nil || len(l.tracker.enqueued) != 1 {
		t.Fatal("enqueue after the first pass must reach the tracker")
	}
	w2 := l.env
	w2.profile = nil
	if e := l.r.tick(context.Background(), w2); e == nil || e.Error() != "SERVICE_PROFILE" {
		t.Fatal("W2 env accepted")
	}
}

// Claim: until S2's `px1 px1Runtime` field binds the runtime to the service,
// every ActionService seam refuses PX1_NOT_IMPLEMENTED (fail closed).
func TestPX1RuntimeSeamsUnbound(t *testing.T) {
	var s ActionService
	if !errors.Is(s.PX1Enqueue(TrackedPayment{}), ErrNotImplemented) || !errors.Is(s.PX1Tick(context.Background()), ErrNotImplemented) {
		t.Fatal("runtime seams must fail closed")
	}
	if _, e := s.PX1Status(); !errors.Is(e, ErrNotImplemented) {
		t.Fatal(e)
	}
}

// Claim: the tick loop calls tick at the interval, reports each failure as
// a bounded code, and stops when its context ends; a zero interval never ticks.
func TestPX1TickLoop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ticks := 0
	codes := []string{}
	done := make(chan struct{})
	go func() {
		px1TickLoop(ctx, 5*time.Millisecond, func(context.Context) error {
			ticks++
			if ticks == 3 {
				cancel()
			}
			return errors.New("RPC_UNAVAILABLE: with text")
		}, func(c string) { codes = append(codes, c) })
		close(done)
	}()
	<-done
	if ticks < 3 || len(codes) < 2 || codes[0] != "SERVICE_FAILURE" {
		t.Fatalf("tick loop: ticks=%d codes=%v", ticks, codes)
	}
	px1TickLoop(context.Background(), 0, func(context.Context) error { t.Fatal("zero interval ticked"); return nil }, nil)
}
