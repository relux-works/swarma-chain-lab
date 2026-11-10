package singleuse

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

type witnessNode struct {
	tx      map[string]*WTransaction
	heights map[string]int64
	order   []string
	calls   []string
}

func (n *witnessNode) Call(ctx context.Context, method string, args ...any) (json.RawMessage, error) {
	n.calls = append(n.calls, method)
	var result any
	block := func(h int64) string {
		if h == 0 {
			return RegtestGenesis
		}
		return fmt.Sprintf("%064x", h)
	}
	switch method {
	case "getblockchaininfo":
		result = map[string]any{"chain": "regtest", "blocks": int64(200), "headers": int64(200), "bestblockhash": block(200), "initialblockdownload": false}
	case "getblockhash":
		var h int64
		switch v := args[0].(type) {
		case int:
			h = int64(v)
		case int64:
			h = v
		default:
			return nil, fmt.Errorf("height type")
		}
		result = block(h)
	case "getblockheader", "getblock":
		id := args[0].(string)
		var h int64
		fmt.Sscanf(id, "%x", &h)
		if id == RegtestGenesis {
			h = 0
		}
		if method == "getblockheader" {
			result = map[string]any{"hash": id, "height": h, "confirmations": 201 - h}
		} else {
			ids := []string{}
			for _, txid := range n.order {
				if n.heights[txid] == h {
					ids = append(ids, txid)
				}
			}
			result = map[string]any{"hash": id, "height": h, "tx": ids}
		}
	case "getrawtransaction":
		id := args[0].(string)
		w := n.tx[id]
		if w == nil {
			return nil, fmt.Errorf("missing fixture")
		}
		vin := []any{}
		for _, in := range w.Body.Inputs {
			if in.TxID == zeroHash {
				vin = append(vin, map[string]any{"coinbase": hex.EncodeToString(in.Script)})
			} else {
				vin = append(vin, map[string]any{"txid": in.TxID, "vout": in.Vout, "scriptSig": map[string]any{"hex": hex.EncodeToString(in.Script)}})
			}
		}
		vout := []any{}
		for i, o := range w.Body.Outputs {
			vout = append(vout, map[string]any{"n": i, "value": json.Number(fmt.Sprintf("%d.%08d", o.Value/100000000, o.Value%100000000)), "scriptPubKey": map[string]any{"hex": hex.EncodeToString(o.Script)}})
		}
		raw := w.Body.Bytes()
		if len(w.Stacks) > 0 {
			raw = w.Bytes()
		}
		view := map[string]any{"txid": id, "hex": hex.EncodeToString(raw), "vin": vin, "vout": vout}
		if h := n.heights[id]; h > 0 {
			view["blockhash"] = block(h)
			view["confirmations"] = 201 - h
		}
		result = view
	default:
		return nil, fmt.Errorf("unexpected method")
	}
	return json.Marshal(result)
}
func witnessGraph(t *testing.T, mutate func(*witnessNode, *WTransaction, *WTransaction)) (*witnessNode, Point, string) {
	t.Helper()
	key := secp.PrivKeyFromBytes([]byte{1})
	defer key.Zero()
	script, _ := WitnessKeyScript(key.PubKey().SerializeCompressed())
	n := &witnessNode{tx: map[string]*WTransaction{}, heights: map[string]int64{}}
	add := func(w *WTransaction, height int64) {
		id := w.Body.ID()
		n.tx[id] = w
		n.heights[id] = height
		n.order = append(n.order, id)
	}
	seed := &WTransaction{Body: &Transaction{Version: 2, Inputs: []Input{{Point: Point{zeroHash, 0xffffffff}, Script: []byte{1, 1}, Sequence: 0xffffffff}}, Outputs: []Output{{1000000, script}, {1000000, script}}}}
	add(seed, 1)
	sign := func(w *WTransaction) {
		w.Stacks = nil
		for i, in := range w.Body.Inputs {
			p := n.tx[in.TxID].Body.Outputs[in.Vout]
			h, e := WitnessSignatureHash(w.Body, i, p)
			if e != nil {
				t.Fatal(e)
			}
			w.Stacks = append(w.Stacks, [][]byte{append(ecdsa.Sign(key, h).Serialize(), 1), key.PubKey().SerializeCompressed()})
		}
	}
	seal := &WTransaction{Body: &Transaction{Version: 2, Inputs: []Input{{Point: Point{seed.Body.ID(), 0}, Sequence: 0xfffffffe}}, Outputs: []Output{{100000, []byte{0x51}}, {899000, script}}}}
	sign(seal)
	add(seal, 200)
	anchor := &WTransaction{Body: &Transaction{Version: 2, Inputs: []Input{{Point: Point{seal.Body.ID(), 1}, Sequence: 0xfffffffe}}, Outputs: []Output{{898000, script}, {0, []byte{0x6a}}}}}
	sign(anchor)
	add(anchor, 200)
	if mutate != nil {
		mutate(n, seal, anchor)
	}
	return n, Point{seal.Body.ID(), 0}, anchor.Body.ID()
}

// An own-node graph proves the exact T:L dependency and ordinary parent block
// precedence. Invalid graph metadata/roles never produce a partial construction;
// no write RPC is available. These fixtures supplement, not replace, Core tests.
func TestWitnessConstructionGraph(t *testing.T) {
	cases := []struct {
		name, reason string
		change       func(*witnessNode, *WTransaction, *WTransaction)
	}{
		{"same-block", "", nil},
		{"mempool-linkage", "", func(n *witnessNode, t, a *WTransaction) { n.heights[t.Body.ID()] = 0; n.heights[a.Body.ID()] = 0 }},
		{"unconfirmed-ordinary", "W_UNCONFIRMED_NON_LINKAGE_PARENT", func(n *witnessNode, t, a *WTransaction) { n.heights[t.Body.Inputs[0].TxID] = 0 }},
		{"same-block-ordinary", "W_UNCONFIRMED_NON_LINKAGE_PARENT", func(n *witnessNode, t, a *WTransaction) { n.heights[t.Body.Inputs[0].TxID] = 200 }},
		{"reversed-order", "W_DEPENDENCY_ORDER", func(n *witnessNode, t, a *WTransaction) { n.order[1], n.order[2] = n.order[2], n.order[1] }},
		{"changed-T-body", "W_BODY_BINDING", func(n *witnessNode, t, a *WTransaction) { t.Body.Outputs[0].Value++ }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n, seal, anchor := witnessGraph(t, nil)
			// Capture authenticated locators before any response/body mutation.
			if tc.change != nil {
				tc.change(n, n.tx[seal.TxID], n.tx[anchor])
			}
			o := NewReadObservation(context.Background(), n)
			defer o.Close()
			if e := o.Start("regtest", RegtestGenesis); e != nil {
				t.Fatal(e)
			}
			got, e := o.WitnessIssuance("W", seal, anchor)
			if tc.reason == "" {
				if e != nil || got.Linkage != (Point{seal.TxID, 1}) || got.SealTransaction == nil || got.AnchorTransaction == nil {
					t.Fatal("W valid graph refused", e)
				}
			} else {
				if e == nil || e.Error() != tc.reason {
					t.Fatalf("W graph guard %s: %v", tc.reason, e)
				}
				if got.SealTransaction != nil || got.AnchorTransaction != nil {
					t.Fatal("W partial construction escaped")
				}
			}
			for _, m := range n.calls {
				if !readMethods[m] {
					t.Fatal("W verifier wrote state")
				}
			}
		})
	}
}

func signWitnessFixture(t *testing.T, n *witnessNode, w *WTransaction) {
	t.Helper()
	key := secp.PrivKeyFromBytes([]byte{1})
	defer key.Zero()
	w.Stacks = nil
	for i, in := range w.Body.Inputs {
		prev := n.tx[in.TxID].Body.Outputs[in.Vout]
		h, e := WitnessSignatureHash(w.Body, i, prev)
		if e != nil {
			t.Fatal(e)
		}
		w.Stacks = append(w.Stacks, [][]byte{append(ecdsa.Sign(key, h).Serialize(), 1), key.PubKey().SerializeCompressed()})
	}
}
func addWitnessFixture(n *witnessNode, w *WTransaction, height int64) string {
	id := w.Body.ID()
	n.tx[id] = w
	n.heights[id] = height
	n.order = append(n.order, id)
	return id
}

// T:L + Q:0 is the concrete undecidable payment-role counterexample. SW1
// linkage-only rejects Q even if fully native/ALL; confirmed Q is a control.
// A third unconfirmed parent, including legacy ancestry, adds no authority.
func TestWitnessAdditionalParentRefusal(t *testing.T) {
	for _, tc := range []struct {
		name          string
		height        int64
		third, legacy bool
	}{
		{"confirmed-neighbor", 199, false, false},
		{"unconfirmed-payment", 0, false, false},
		{"same-block-payment", 200, false, false},
		{"third-parent", 0, true, false},
		{"legacy-ancestry", 0, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n, seal, anchor := witnessGraph(t, nil)
			original := n.tx[anchor]
			seedID := n.tx[seal.TxID].Body.Inputs[0].TxID
			script := n.tx[seedID].Body.Outputs[1].Script
			q := &WTransaction{Body: &Transaction{Version: 2, Inputs: []Input{{Point: Point{seedID, 1}, Sequence: 0xfffffffe}}, Outputs: []Output{{900000, script}}}}
			if tc.third {
				q.Body.Outputs = []Output{{400000, script}, {400000, script}}
			}
			signWitnessFixture(t, n, q)
			if tc.legacy {
				q.Stacks = nil
				q.Body.Inputs[0].Script = []byte{0x51}
			}
			qid := addWitnessFixture(n, q, tc.height)
			original.Body.Inputs = append(original.Body.Inputs, Input{Point: Point{qid, 0}, Sequence: 0xfffffffe})
			if tc.third {
				r := &WTransaction{Body: &Transaction{Version: 2, Inputs: []Input{{Point: Point{qid, 1}, Sequence: 0xfffffffe}}, Outputs: []Output{{300000, script}}}}
				signWitnessFixture(t, n, r)
				rid := addWitnessFixture(n, r, 0)
				original.Body.Inputs = append(original.Body.Inputs, Input{Point: Point{rid, 0}, Sequence: 0xfffffffe})
			}
			signWitnessFixture(t, n, original)
			delete(n.tx, anchor)
			delete(n.heights, anchor)
			anchor = addWitnessFixture(n, original, 0)
			before, _ := json.Marshal(n.tx)
			o := NewReadObservation(context.Background(), n)
			defer o.Close()
			if e := o.Start("regtest", RegtestGenesis); e != nil {
				t.Fatal(e)
			}
			got, e := o.WitnessIssuance("W", seal, anchor)
			if tc.height == 199 {
				if e != nil || got.AnchorTransaction == nil {
					t.Fatal("confirmed Q neighbor", e)
				}
			} else {
				// Q in the current block is confirmed for a mempool A, so make A
				// confirmed in that same block to exercise historical block precedence.
				if tc.height == 200 {
					n.heights[anchor] = 200
					got, e = o.WitnessIssuance("W", seal, anchor)
				}
				if e == nil || e.Error() != "W_UNCONFIRMED_NON_LINKAGE_PARENT" {
					t.Fatal("extra parent accepted/wrong refusal", e)
				}
				if got.AnchorTransaction != nil || got.SealTransaction != nil {
					t.Fatal("partial authority")
				}
			}
			after, _ := json.Marshal(n.tx)
			if !bytes.Equal(before, after) {
				t.Fatal("refusal changed transaction state")
			}
			for _, m := range n.calls {
				if !readMethods[m] {
					t.Fatal("effect RPC", m)
				}
			}
		})
	}
}

// L is identified from T's exact non-seal output, never a caller-supplied role.
// T itself remains genuinely signed native/ALL when its L output is non-native;
// the graph rejects that output before considering A's input signatures.
func TestWitnessLinkageScript(t *testing.T) {
	for _, tc := range []struct {
		name   string
		script []byte
	}{
		{"legacy", append(append([]byte{0x76, 0xa9, 20}, make([]byte, 20)...), 0x88, 0xac)},
		{"wrapped", append(append([]byte{0xa9, 20}, make([]byte, 20)...), 0x87)},
		{"p2wsh", append([]byte{0, 32}, make([]byte, 32)...)},
		{"taproot", append([]byte{0x51, 32}, make([]byte, 32)...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n, seal, anchor := witnessGraph(t, nil)
			creation, a := n.tx[seal.TxID], n.tx[anchor]
			creation.Body.Outputs[1].Script = tc.script
			signWitnessFixture(t, n, creation)
			delete(n.tx, seal.TxID)
			delete(n.heights, seal.TxID)
			seal.TxID = addWitnessFixture(n, creation, 0)
			a.Body.Inputs[0].TxID = seal.TxID
			delete(n.tx, anchor)
			delete(n.heights, anchor)
			anchor = addWitnessFixture(n, a, 0)
			o := NewReadObservation(context.Background(), n)
			defer o.Close()
			if e := o.Start("regtest", RegtestGenesis); e != nil {
				t.Fatal(e)
			}
			got, e := o.WitnessIssuance("W", seal, anchor)
			if e == nil || e.Error() != "W_LINKAGE_SCRIPT" || got.SealTransaction != nil || got.AnchorTransaction != nil {
				t.Fatal("W linkage script guard", e)
			}
			good, s, id := witnessGraph(t, nil)
			neighbor := NewReadObservation(context.Background(), good)
			defer neighbor.Close()
			if e := neighbor.Start("regtest", RegtestGenesis); e != nil {
				t.Fatal(e)
			}
			if _, e := neighbor.WitnessIssuance("W", s, id); e != nil {
				t.Fatal("valid linkage", e)
			}
		})
	}
}
