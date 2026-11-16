package grantcheck

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// identityNode is the existing single-use witnessGraph fixture model extended
// with name projections. Headers/membership are synthetic and never qualify
// consensus. The actual kernel checks all projections and witness signatures.
type identityNode struct {
	tx      map[string]*su.WTransaction
	heights map[string]int64
	names   map[string]map[string]any
	order   []string
	spent   bool
	calls   int
}

func identityRead(t *testing.T, name string) []byte {
	t.Helper()
	b, e := os.ReadFile("testdata/identity-interop/" + name)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func identityDecode(t *testing.T, name string, v any) {
	t.Helper()
	if e := json.Unmarshal(identityRead(t, name), v); e != nil {
		t.Fatal(e)
	}
}
func identityBlock(h int64) string {
	if h == 0 {
		return su.RegtestGenesis
	}
	return fmt.Sprintf("%064x", h)
}
func (n *identityNode) add(w *su.WTransaction, height int64) string {
	id := w.Body.ID()
	n.tx[id] = w
	n.heights[id] = height
	n.order = append(n.order, id)
	return id
}
func newIdentityNode(t *testing.T) *identityNode {
	t.Helper()
	n := &identityNode{tx: map[string]*su.WTransaction{}, heights: map[string]int64{}, names: map[string]map[string]any{}}
	for _, stem := range []string{"seal", "anchor"} {
		var request struct {
			Funding struct {
				Inputs []struct {
					PrevTxHex string `json:"prev_tx_hex"`
				} `json:"inputs"`
			} `json:"funding"`
		}
		identityDecode(t, stem+"-request.json", &request)
		for _, in := range request.Funding.Inputs {
			raw, e := hex.DecodeString(in.PrevTxHex)
			if e != nil {
				t.Fatal(e)
			}
			body, e := su.DecodePaymentTransaction(raw)
			if e != nil {
				t.Fatal(e)
			}
			n.add(&su.WTransaction{Body: body}, 1)
		}
		var result struct {
			Transaction struct {
				Hex string `json:"unsigned_tx_hex"`
				ID  string `json:"unsigned_txid"`
			} `json:"transaction"`
		}
		identityDecode(t, stem+"-result.json", &result)
		raw, e := hex.DecodeString(result.Transaction.Hex)
		if e != nil {
			t.Fatal(e)
		}
		body, e := su.DecodePaymentTransaction(raw)
		if e != nil {
			t.Fatal(e)
		}
		key := secp.PrivKeyFromBytes([]byte{1})
		w := &su.WTransaction{Body: body}
		for i, in := range body.Inputs {
			prev := n.tx[in.TxID].Body.Outputs[in.Vout]
			h, e := su.WitnessSignatureHash(body, i, prev)
			if e != nil {
				t.Fatal(e)
			}
			w.Stacks = append(w.Stacks, [][]byte{append(ecdsa.Sign(key, h).Serialize(), 1), key.PubKey().SerializeCompressed()})
		}
		key.Zero()
		height := int64(10)
		if stem == "seal" {
			height = 9
		}
		if id := n.add(w, height); id != result.Transaction.ID {
			t.Fatal("witness changed issuer's unsigned txid")
		}
	}
	// Name generations use public offline name_update bodies, as in the rental
	// identity fixtures; the model supplies no registration/consensus evidence.
	for _, role := range []string{"agent", "landlord"} {
		name, file := "id/landlord-a-agent", "agent-value.json"
		if role == "landlord" {
			name, file = "id/landlord-a", "landlord-legacy.json"
		}
		value := string(identityRead(t, file))
		body := &su.Transaction{Version: 2, Inputs: []su.Input{{Point: su.Point{TxID: identityBlock(99)}, Sequence: 0xffffffff}}, Outputs: []su.Output{{Value: 1000000, Script: su.NameUpdateScript(name, value, []byte{0x51})}}}
		id := n.add(&su.WTransaction{Body: body}, 2)
		n.names[name] = map[string]any{"name": name, "value": value, "txid": id, "vout": 0, "height": 2, "expired": false, "expires_in": 1000, "name_encoding": "ascii", "value_encoding": "ascii"}
	}

	return n
}
func (n *identityNode) Call(_ context.Context, method string, args ...any) (json.RawMessage, error) {
	n.calls++
	var value any
	switch method {
	case "getblockchaininfo":
		value = map[string]any{"chain": "regtest", "blocks": int64(100), "headers": int64(100), "bestblockhash": identityBlock(100), "initialblockdownload": false}
	case "getblockhash":
		var h int64
		switch x := args[0].(type) {
		case int:
			h = int64(x)
		case int64:
			h = x
		default:
			return nil, fmt.Errorf("height type")
		}
		value = identityBlock(h)
	case "getblockheader", "getblock":
		id := args[0].(string)
		var h int64
		fmt.Sscanf(id, "%x", &h)
		if method == "getblockheader" {
			value = map[string]any{"hash": id, "height": h, "confirmations": 101 - h, "time": int64(1795000000)}
		} else {
			ids := []string{}
			for _, txid := range n.order {
				if n.heights[txid] == h {
					ids = append(ids, txid)
				}
			}
			value = map[string]any{"hash": id, "height": h, "tx": ids}
		}
	case "getrawmempool":
		value = []string{}
	case "name_show":
		value = n.names[args[0].(string)]
		if value == nil {
			return nil, fmt.Errorf("missing name")
		}
	case "gettxout":
		if n.spent {
			return json.RawMessage("null"), nil
		}
		id := args[0].(string)
		vout := args[1].(uint32)
		w := n.tx[id]
		if w == nil || int(vout) >= len(w.Body.Outputs) {
			return json.RawMessage("null"), nil
		}
		out := w.Body.Outputs[vout]
		value = map[string]any{"bestblock": identityBlock(100), "confirmations": 101 - n.heights[id], "value": json.Number(fmt.Sprintf("%d.%08d", out.Value/100000000, out.Value%100000000)), "scriptPubKey": map[string]any{"hex": hex.EncodeToString(out.Script)}}
	case "getrawtransaction":
		id := args[0].(string)
		w := n.tx[id]
		if w == nil {
			return nil, fmt.Errorf("missing fixture transaction")
		}
		vin := []any{}
		vout := []any{}
		for _, in := range w.Body.Inputs {
			vin = append(vin, map[string]any{"txid": in.TxID, "vout": in.Vout, "scriptSig": map[string]any{"hex": hex.EncodeToString(in.Script)}})
		}
		for i, out := range w.Body.Outputs {
			script := map[string]any{"hex": hex.EncodeToString(out.Script)}
			for name, rec := range n.names {
				if rec["txid"] == id {
					script["nameOp"] = map[string]any{"op": "name_update", "name": name, "value": rec["value"], "name_encoding": "ascii", "value_encoding": "ascii"}
				}
			}
			vout = append(vout, map[string]any{"n": i, "value": json.Number(fmt.Sprintf("%d.%08d", out.Value/100000000, out.Value%100000000)), "scriptPubKey": script})
		}
		raw := w.Body.Bytes()
		if len(w.Stacks) > 0 {
			raw = w.Bytes()
		}
		value = map[string]any{"txid": id, "hex": hex.EncodeToString(raw), "vin": vin, "vout": vout, "blockhash": identityBlock(n.heights[id]), "confirmations": 101 - n.heights[id]}
	default:
		return nil, fmt.Errorf("unexpected fixture method: %s", method)
	}
	return json.Marshal(value)
}
