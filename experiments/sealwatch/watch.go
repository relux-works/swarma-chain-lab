// Package sealwatch implements a finite, read-only seal observation for one
// operation. It trusts only an externally pinned, fully validating own node.
package sealwatch

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"time"
)

const (
	Unspent      = "UNSPENT"
	Suspend      = "SUSPEND"
	FinalRevoked = "FINALREVOKED"
	Unknown      = "UNKNOWN"
	Stop         = "STOP"
)

// RPC returns the JSON result (not an RPC envelope). The broker must enforce
// these read methods at the node, stream without prebuffering unbounded data,
// and interrupt BOTH Call and Read on ctx cancellation. Errors are never logged.
// This interface is a cooperation contract, not an OS security boundary.
type RPC interface {
	Call(ctx context.Context, method string, params ...any) (io.ReadCloser, error)
}

type Point struct {
	TxID string `json:"txid"`
	Vout uint32 `json:"vout"`
}
type Tip struct {
	Height int64  `json:"height"`
	Hash   string `json:"hash"`
}
type Anchor struct {
	Tip
	TxID string `json:"txid"`
}
type Binding struct {
	Seal       Point
	SealScript string
	Anchor     Anchor
	// Commitment is computed by the EXISTING canonical certificate codec. The
	// wrapper verifies certificate signatures, scope, enrollment and this binding.
	Commitment string
	Genesis    string
	Chain      string
	StartTip   Tip
	// These cutoffs are fixed by the wrapper, never renewed by polling.
	Deadline        time.Time
	ProofValidUntil time.Time
	LastBlockAt     time.Time
	Prior           Verdict
}

type Limits struct {
	Polls               int
	Interval            time.Duration
	Duration            time.Duration
	CallTimeout         time.Duration
	Calls               int
	ResponseBytes       int64
	TotalBytes          int64
	MempoolTransactions int
	BlockTransactions   int
}

// DefaultLimits stays below the existing 1500-second operation bound. A call
// may stop earlier on any count/byte/time cap. It never starts a new operation.
func DefaultLimits() Limits {
	return Limits{Polls: 6, Interval: time.Second,
		Duration: 10 * time.Second, CallTimeout: 2 * time.Second, Calls: 256,
		ResponseBytes: 8 << 20, TotalBytes: 64 << 20, MempoolTransactions: 128,
		BlockTransactions: 10000}
}

type Verdict struct {
	State                     string    `json:"state"`
	Reason                    string    `json:"reason"`
	SealChainOK               bool      `json:"seal_chain_ok"`
	PrivilegedCommandsAllowed bool      `json:"privileged_commands_allowed"`
	Seal                      Point     `json:"seal"`
	Anchor                    Anchor    `json:"anchor"`
	Commitment                string    `json:"certificate_commitment"`
	Tip                       Tip       `json:"tip"`
	SpendTxID                 string    `json:"spend_txid,omitempty"`
	SpendBlock                string    `json:"spend_block,omitempty"`
	ObservedAt                time.Time `json:"observed_at"`
	ValidUntil                time.Time `json:"valid_until"`
	LastBlockAt               time.Time `json:"last_block_at"`
	Polls                     int       `json:"polls"`
	Calls                     int       `json:"calls"`
	Bytes                     int64     `json:"bytes"`
}

// Watcher refuses concurrent use; each Watch owns a single finite operation.
// Construct a new watcher for a new operation, preserving a prior suspension.
type Watcher struct {
	rpc  RPC
	busy atomic.Bool
}

func New(rpc RPC) *Watcher { return &Watcher{rpc: rpc} }

type run struct {
	w    *Watcher
	ctx  context.Context
	b    Binding
	l    Limits
	v    Verdict
	last Tip
}
type failure string

func (e failure) Error() string { return string(e) }
func hash(s string) bool {
	if len(s) != 64 {
		return false
	}
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && s == strings.ToLower(s)
}
func script(s string) bool {
	if len(s) == 0 || len(s) > 20000 {
		return false
	}
	b, e := hex.DecodeString(s)
	return e == nil && len(b) > 0 && len(b) <= 10000 && s == strings.ToLower(s)
}
func validTip(t Tip) bool { return t.Height >= 0 && t.Height <= 2147483647 && hash(t.Hash) }

func valid(b Binding, l Limits, now time.Time) bool {
	return hash(b.Seal.TxID) && script(b.SealScript) && validTip(b.Anchor.Tip) && hash(b.Anchor.TxID) &&
		hash(b.Commitment) && hash(b.Genesis) && (b.Chain == "main" || b.Chain == "regtest") &&
		validTip(b.StartTip) && b.Anchor.Height <= b.StartTip.Height &&
		!b.Deadline.IsZero() && !b.ProofValidUntil.IsZero() && !b.LastBlockAt.IsZero() && !b.LastBlockAt.After(now) &&
		l.Polls >= 1 && l.Polls <= 64 && l.Interval >= 100*time.Millisecond && l.Interval <= 30*time.Second &&
		l.Duration > 0 && l.Duration <= 1500*time.Second && l.CallTimeout > 0 && l.CallTimeout <= 10*time.Second &&
		l.Calls >= 1 && l.Calls <= 4096 && l.ResponseBytes >= 1 && l.ResponseBytes <= 8<<20 &&
		l.TotalBytes >= 1 && l.TotalBytes <= 64<<20 && l.MempoolTransactions >= 1 && l.MempoolTransactions <= 1024 &&
		l.BlockTransactions >= 1 && l.BlockTransactions <= 100000
}

// Watch checks a bounded sequence of snapshots. UNSPENT is local evidence at a
// specific stable tip, never a claim about the globally latest state. Its short
// validity is for this single operation; the wrapper must recheck before use.
func (w *Watcher) Watch(parent context.Context, b Binding, l Limits) Verdict {
	now := time.Now()
	v := Verdict{State: Unknown, Reason: "INVALID_INPUT", ObservedAt: now}
	if !w.busy.CompareAndSwap(false, true) {
		v.Reason = "CONCURRENT_OPERATION"
		return v
	}
	defer w.busy.Store(false)
	if w.rpc == nil || parent == nil || !valid(b, l, now) {
		return v
	}
	v.Seal = b.Seal
	v.Anchor = b.Anchor
	v.Commitment = b.Commitment
	v.LastBlockAt = b.LastBlockAt
	until := now.Add(l.Duration)
	if b.Deadline.Before(until) {
		until = b.Deadline
	}
	if b.ProofValidUntil.Before(until) {
		until = b.ProofValidUntil
	}
	ctx, cancel := context.WithDeadline(parent, until)
	defer cancel()
	r := run{w: w, ctx: ctx, b: b, l: l, v: v, last: b.StartTip}
	if b.Prior.State != "" {
		if (b.Prior.State != Suspend && b.Prior.State != FinalRevoked) || b.Prior.Seal != b.Seal ||
			b.Prior.Anchor != b.Anchor || b.Prior.Commitment != b.Commitment || !hash(b.Prior.SpendTxID) {
			r.v.Reason = "PRIOR_BINDING"
			return r.v
		}
		r.v.SpendTxID = b.Prior.SpendTxID
	}
	for i := 0; i < l.Polls; i++ {
		r.v.Polls = i + 1
		err := r.snapshot()
		if err != nil {
			r.v.State = Unknown
			r.v.SealChainOK = false
			r.v.Reason = "RPC_UNAVAILABLE_OR_MALFORMED"
			r.v.ObservedAt = time.Now()
			var f failure
			if errors.As(err, &f) {
				r.v.Reason = string(f)
			}
			if r.v.Reason == "NO_NEW_BLOCK_30_MIN" || r.v.Reason == "SIX_SUCCESSOR_STOP" || r.v.Reason == "DEADLINE_OR_CANCEL" || r.v.Reason == "EXPIRED_PROOF" {
				r.v.State = Stop
			}
			return r.v
		}
		if r.v.State != Unspent || i == l.Polls-1 {
			return r.v
		}
		timer := time.NewTimer(l.Interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			r.v.State = Stop
			r.v.Reason = "DEADLINE_OR_CANCEL"
			r.v.SealChainOK = false
			return r.v
		case <-timer.C:
		}
	}
	return r.v
}

func (r *run) bounds() error {
	now := time.Now()
	if !now.Before(r.b.ProofValidUntil) {
		return failure("EXPIRED_PROOF")
	}
	if r.ctx.Err() != nil || !now.Before(r.b.Deadline) {
		return failure("DEADLINE_OR_CANCEL")
	}
	if now.Sub(r.v.LastBlockAt) >= 30*time.Minute {
		return failure("NO_NEW_BLOCK_30_MIN")
	}
	return nil
}

func (r *run) call(method string, out any, args ...any) error {
	if err := r.bounds(); err != nil {
		return err
	}
	switch method {
	case "getblockchaininfo", "getblockhash", "getrawtransaction", "getrawmempool", "gettxout", "getblock":
	default:
		return failure("RPC_METHOD_DENIED")
	}
	if r.v.Calls >= r.l.Calls {
		return failure("CALL_BOUND")
	}
	r.v.Calls++
	ctx, cancel := context.WithTimeout(r.ctx, r.l.CallTimeout)
	defer cancel()
	body, err := r.w.rpc.Call(ctx, method, args...)
	if err != nil {
		if body != nil {
			body.Close()
		}
		return failure("RPC_UNAVAILABLE_OR_MALFORMED")
	}
	if body == nil {
		return failure("RPC_UNAVAILABLE_OR_MALFORMED")
	}
	defer body.Close()
	cap := r.l.ResponseBytes
	if left := r.l.TotalBytes - r.v.Bytes; left < cap {
		cap = left
	}
	data, err := io.ReadAll(io.LimitReader(body, cap+1))
	r.v.Bytes += int64(len(data))
	if int64(len(data)) > cap {
		return failure("BYTE_BOUND")
	}
	if err != nil || ctx.Err() != nil {
		return failure("RPC_UNAVAILABLE_OR_MALFORMED")
	}
	if err = r.bounds(); err != nil {
		return err
	}
	if err = uniqueJSON(data); err != nil {
		return failure("RPC_UNAVAILABLE_OR_MALFORMED")
	}
	if err = json.Unmarshal(data, out); err != nil {
		return failure("RPC_UNAVAILABLE_OR_MALFORMED")
	}
	return nil
}

// Reject fold-equal object keys and excessive nesting before typed decoding.
// Unknown Core fields remain allowed; conflicting copies of a field do not.
func uniqueJSON(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 64 {
			return failure("JSON_DEPTH")
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			keys := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return err
				}
				s, ok := key.(string)
				s = foldJSONKey(s)
				if !ok || keys[s] {
					return failure("JSON_DUPLICATE")
				}
				keys[s] = true
				if err = value(depth + 1); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil {
				return err
			}
			if end != json.Delim('}') {
				return failure("JSON_OBJECT")
			}
		case '[':
			for d.More() {
				if err = value(depth + 1); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil {
				return err
			}
			if end != json.Delim(']') {
				return failure("JSON_ARRAY")
			}
		default:
			return failure("JSON_DELIMITER")
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return failure("JSON_TRAILING")
	}
	return nil
}

type info struct {
	Chain   string `json:"chain"`
	Blocks  *int64 `json:"blocks"`
	Headers *int64 `json:"headers"`
	Best    string `json:"bestblockhash"`
	IBD     *bool  `json:"initialblockdownload"`
}
type input struct {
	TxID     string  `json:"txid"`
	Vout     *uint32 `json:"vout"`
	Coinbase string  `json:"coinbase"`
}
type output struct {
	N      *uint32      `json:"n"`
	Script scriptPubKey `json:"scriptPubKey"`
}
type tx struct {
	TxID          string   `json:"txid"`
	BlockHash     string   `json:"blockhash"`
	Confirmations *int64   `json:"confirmations"`
	Vin           []input  `json:"vin"`
	Vout          []output `json:"vout"`
}
type block struct {
	Hash   string `json:"hash"`
	Height *int64 `json:"height"`
	Tx     []tx   `json:"tx"`
}
type utxo struct {
	Best          string       `json:"bestblock"`
	Confirmations *int64       `json:"confirmations"`
	Script        scriptPubKey `json:"scriptPubKey"`
}

func (r *run) active(t Tip) error {
	var got string
	if err := r.call("getblockhash", &got, t.Height); err != nil {
		return err
	}
	if got != t.Hash {
		return failure("REORG")
	}
	return nil
}
func (r *run) network() (Tip, error) {
	var x info
	if err := r.call("getblockchaininfo", &x); err != nil {
		return Tip{}, err
	}
	if x.Chain != r.b.Chain || x.Blocks == nil || x.Headers == nil || x.IBD == nil || *x.IBD || *x.Headers != *x.Blocks || !validTip(Tip{*x.Blocks, x.Best}) {
		return Tip{}, failure("NODE_NOT_READY")
	}
	return Tip{*x.Blocks, x.Best}, nil
}
func (r *run) inspect(t tx, expected string) (bool, error) {
	if !hash(t.TxID) || t.TxID != expected || len(t.Vin) == 0 || len(t.Vin) > 10000 {
		return false, failure("TRANSACTION_SCHEMA")
	}
	found := false
	for _, v := range t.Vin {
		if v.Coinbase != "" {
			if len(t.Vin) != 1 || v.TxID != "" || v.Vout != nil {
				return false, failure("INPUT_SCHEMA")
			}
			continue
		}
		if !hash(v.TxID) || v.Vout == nil {
			return false, failure("INPUT_SCHEMA")
		}
		if v.TxID == r.b.Seal.TxID && *v.Vout == r.b.Seal.Vout {
			found = true
		}
	}
	return found, nil
}
func (r *run) finish(state, reason string, t Tip, spend, spendBlock string) error {
	// Positive and confirmed-spend verdicts require a second independent tip
	// read. Immediate SUSPEND is handled before this: instability cannot admit.
	end, err := r.network()
	if err != nil {
		return err
	}
	if end != t {
		return failure("TIP_CHANGED_DURING_READ")
	}
	if err = r.bounds(); err != nil {
		return err
	}
	r.v.State = state
	r.v.Reason = reason
	r.v.SealChainOK = state == Unspent
	r.v.Tip = t
	r.v.SpendTxID = spend
	r.v.SpendBlock = spendBlock
	r.v.ObservedAt = time.Now()
	r.v.ValidUntil = r.v.ObservedAt.Add(time.Second)
	if r.b.ProofValidUntil.Before(r.v.ValidUntil) {
		r.v.ValidUntil = r.b.ProofValidUntil
	}
	if r.b.Deadline.Before(r.v.ValidUntil) {
		r.v.ValidUntil = r.b.Deadline
	}
	return nil
}

func (r *run) snapshot() error {
	if err := r.bounds(); err != nil {
		return err
	}
	tip, err := r.network()
	if err != nil {
		return err
	}
	r.v.Tip = tip
	var genesis string
	if err = r.call("getblockhash", &genesis, int64(0)); err != nil {
		return err
	}
	if genesis != r.b.Genesis {
		return failure("WRONG_GENESIS")
	}
	if tip.Height < r.last.Height {
		return failure("REORG")
	}
	for _, t := range []Tip{r.b.StartTip, r.last, r.b.Anchor.Tip, tip} {
		if err = r.active(t); err != nil {
			return err
		}
	}
	if r.b.Prior.State != "" {
		if !validTip(r.b.Prior.Tip) || tip.Height < r.b.Prior.Tip.Height {
			return failure("REORG")
		}
		if err = r.active(r.b.Prior.Tip); err != nil {
			return err
		}
	}
	if tip.Height > r.last.Height {
		r.v.LastBlockAt = time.Now()
	}
	r.last = tip
	var anchor tx
	if err = r.call("getrawtransaction", &anchor, r.b.Anchor.TxID, true, r.b.Anchor.Hash); err != nil {
		return err
	}
	if anchor.TxID != r.b.Anchor.TxID || anchor.BlockHash != r.b.Anchor.Hash || anchor.Confirmations == nil || *anchor.Confirmations < 1 {
		return failure("ANCHOR_BINDING")
	}
	committed := 0
	for _, o := range anchor.Vout {
		if o.Script.Hex == "6a20"+r.b.Commitment {
			committed++
		}
	}
	if committed != 1 {
		return failure("CERTIFICATE_COMMITMENT")
	}
	// Chain scans start at the immutable operation tip, not a moving poll tip.
	// Older spent seals remain UNKNOWN through gettxout; no historical gap admits.
	successors := tip.Height - r.b.StartTip.Height
	scan := successors
	if scan > 6 {
		scan = 6
	}
	for h := r.b.StartTip.Height + 1; h <= r.b.StartTip.Height+scan; h++ {
		var bh string
		if err = r.call("getblockhash", &bh, h); err != nil {
			return err
		}
		if !hash(bh) {
			return failure("BLOCK_SCHEMA")
		}
		var b block
		if err = r.call("getblock", &b, bh, 2); err != nil {
			return err
		}
		if b.Hash != bh || b.Height == nil || *b.Height != h || len(b.Tx) == 0 || len(b.Tx) > r.l.BlockTransactions {
			return failure("BLOCK_BOUND_OR_SCHEMA")
		}
		for _, t := range b.Tx {
			spends, e := r.inspect(t, t.TxID)
			if e != nil {
				return e
			}
			if spends {
				if err = r.active(Tip{h, bh}); err != nil {
					return err
				}
				return r.finish(FinalRevoked, "FIRST_ACTIVE_BLOCK_SPEND", tip, t.TxID, bh)
			}
		}
	}
	if successors >= 6 {
		return failure("SIX_SUCCESSOR_STOP")
	}
	var ids []string
	if err = r.call("getrawmempool", &ids, false); err != nil {
		return err
	}
	if ids == nil || len(ids) > r.l.MempoolTransactions {
		return failure("MEMPOOL_BOUND_OR_SCHEMA")
	}
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if !hash(id) || seen[id] {
			return failure("MEMPOOL_SCHEMA")
		}
		seen[id] = true
		var t tx
		if err = r.call("getrawtransaction", &t, id, true); err != nil {
			return err
		}
		spends, e := r.inspect(t, id)
		if e != nil {
			return e
		}
		if spends {
			// The fully validating node accepted these actual inputs. No finality is
			// inferred from confirmations/peer height, inv traffic or a caller label.
			r.v.State = Suspend
			r.v.Reason = "MEMPOOL_SEAL_INPUT"
			r.v.SealChainOK = false
			r.v.SpendTxID = id
			r.v.ObservedAt = time.Now()
			return nil
		}
	}
	if r.b.Prior.State != "" {
		return r.finish(Suspend, "PRIOR_SPEND_REQUIRES_RECONCILIATION", tip, r.b.Prior.SpendTxID, "")
	}
	// Both local UTXO views must agree and bind the exact script at this tip.
	// Empty mempool alone never creates an UNSPENT verdict.
	for _, pool := range []bool{false, true} {
		var u *utxo
		if err = r.call("gettxout", &u, r.b.Seal.TxID, r.b.Seal.Vout, pool); err != nil {
			return err
		}
		if u == nil {
			return failure("SEAL_SPENT_OR_UNAVAILABLE")
		}
		if u.Best != tip.Hash || u.Confirmations == nil || *u.Confirmations < 1 || u.Script.Hex != r.b.SealScript {
			return failure("SEAL_BINDING")
		}
	}
	return r.finish(Unspent, "LOCAL_VALIDATED_UNSPENT_AT_TIP", tip, "", "")
}
