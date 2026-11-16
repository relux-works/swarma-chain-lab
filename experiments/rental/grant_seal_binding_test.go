package rental

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

// sealBindingNode serves exact read-only RPC fixtures. Raw bodies, projections,
// membership and witness signatures agree; headers are synthetic, not Core or
// consensus evidence. Unexpected calls (including writes) fail the test.
type sealBindingNode map[string]json.RawMessage

func sealBindingCallKey(method string, args []any) string {
	b, _ := json.Marshal(args)
	return method + string(b)
}
func (n sealBindingNode) Call(_ context.Context, method string, args ...any) (json.RawMessage, error) {
	b, ok := n[sealBindingCallKey(method, args)]
	if !ok {
		return nil, fmt.Errorf("unexpected seal fixture call: %s", method)
	}
	return b, nil
}

func sealBindingFixture(t *testing.T, owner byte) (sealBindingNode, Policy, Grant, []byte) {
	t.Helper()
	n := sealBindingNode{}
	put := func(method string, result any, args ...any) {
		t.Helper()
		b, e := json.Marshal(result)
		if e != nil {
			t.Fatal(e)
		}
		n[sealBindingCallKey(method, args)] = b
	}
	block := func(h int64) string { return fmt.Sprintf("%064x", h) }
	put("getblockchaininfo", map[string]any{"chain": "regtest", "blocks": 100, "headers": 100, "bestblockhash": block(100), "initialblockdownload": false})
	put("getblockhash", su.RegtestGenesis, 0)
	put("getblockhash", block(100), 100)
	put("getblockheader", map[string]any{"hash": block(100), "height": 100, "confirmations": 1}, block(100))
	put("getrawmempool", []string{})
	txs := map[string]*su.WTransaction{}
	members := map[int64][]string{}
	coins := func(v int64) json.Number { return json.Number(fmt.Sprintf("%d.%08d", v/100000000, v%100000000)) }
	add := func(w *su.WTransaction, height int64, name, value string) string {
		t.Helper()
		id := w.Body.ID()
		txs[id] = w
		members[height] = append(members[height], id)
		vin, vout := []any{}, []any{}
		for _, in := range w.Body.Inputs {
			if in.TxID == block(0) {
				vin = append(vin, map[string]any{"coinbase": hex.EncodeToString(in.Script)})
			} else {
				vin = append(vin, map[string]any{"txid": in.TxID, "vout": in.Vout, "scriptSig": map[string]any{"hex": hex.EncodeToString(in.Script)}})
			}
		}
		for i, out := range w.Body.Outputs {
			script := map[string]any{"hex": hex.EncodeToString(out.Script)}
			if name != "" {
				script["nameOp"] = map[string]any{"op": "name_update", "name": name, "value": value, "name_encoding": "ascii", "value_encoding": "ascii"}
			}
			vout = append(vout, map[string]any{"n": i, "value": coins(out.Value), "scriptPubKey": script})
			put("gettxout", map[string]any{"bestblock": block(100), "confirmations": 101 - height, "value": coins(out.Value), "scriptPubKey": map[string]any{"hex": hex.EncodeToString(out.Script)}}, id, uint32(i), true)
		}
		raw := w.Body.Bytes()
		if len(w.Stacks) > 0 {
			raw = w.Bytes()
		}
		put("getrawtransaction", map[string]any{"txid": id, "hex": hex.EncodeToString(raw), "vin": vin, "vout": vout, "blockhash": block(height), "confirmations": 101 - height}, id, true)
		return id
	}
	key := secp.PrivKeyFromBytes([]byte{7})
	defer key.Zero()
	fundingScript, e := su.WitnessKeyScript(key.PubKey().SerializeCompressed())
	if e != nil {
		t.Fatal(e)
	}
	sign := func(body *su.Transaction) *su.WTransaction {
		t.Helper()
		w := &su.WTransaction{Body: body}
		for i, in := range body.Inputs {
			prev := txs[in.TxID].Body.Outputs[in.Vout]
			h, e := su.WitnessSignatureHash(body, i, prev)
			if e != nil {
				t.Fatal(e)
			}
			w.Stacks = append(w.Stacks, [][]byte{append(ecdsa.Sign(key, h).Serialize(), 1), key.PubKey().SerializeCompressed()})
		}
		return w
	}
	seed := add(&su.WTransaction{Body: &su.Transaction{Version: 2, Inputs: []su.Input{{Point: su.Point{TxID: block(0), Vout: 0xffffffff}, Script: []byte{1, 1}, Sequence: 0xffffffff}}, Outputs: []su.Output{{Value: 1000000, Script: fundingScript}, {Value: 1000000, Script: fundingScript}, {Value: 1010000, Script: fundingScript}, {Value: 1010000, Script: fundingScript}}}}, 1, "", "")
	g := testGrant(t)
	_, sealKey := testKey(owner)
	sealScript, e := GrantSealScript(sealKey)
	if e != nil {
		t.Fatal(e)
	}
	sealID := add(sign(&su.Transaction{Version: 2, Inputs: []su.Input{{Point: su.Point{TxID: seed, Vout: 0}, Sequence: 0xfffffffe}}, Outputs: []su.Output{{Value: 100000, Script: mustDecodeKey(sealScript)}}}), 9, "", "")
	// Like detached foreign-seal, choose the owner before signing. Rebuild the
	// issuance from these exact signed bytes, so no stale commitment masks binding.
	g.Seal = Point{TxID: sealID, Vout: 0}
	raw := signGrantTest(t, g, 1)
	issuanceID := add(sign(&su.Transaction{Version: 2, Inputs: []su.Input{{Point: su.Point{TxID: seed, Vout: 1}, Sequence: 0xfffffffe}}, Outputs: []su.Output{{Value: 0, Script: framedGrantScript(t, raw)}, {Value: 999000, Script: fundingScript}}}), 10, "", "")
	proof, e := PresentIssuedGrant(raw, issuanceID)
	if e != nil {
		t.Fatal(e)
	}
	agentValue, e := AgentBindingValue(AgentBinding{g.GranteeKey, g.LandlordName})
	if e != nil {
		t.Fatal(e)
	}
	landlordValue, e := LandlordValue(LandlordBinding{g.IssuerKey})
	if e != nil {
		t.Fatal(e)
	}
	for i, role := range []struct{ name, value string }{{g.AgentName, agentValue}, {g.LandlordName, landlordValue}} {
		name, value := role.name, role.value
		id := add(sign(&su.Transaction{Version: 2, Inputs: []su.Input{{Point: su.Point{TxID: seed, Vout: uint32(i + 2)}, Sequence: 0xffffffff}}, Outputs: []su.Output{{Value: 1000000, Script: su.NameUpdateScript(name, value, []byte{0x51})}}}), 2, name, value)
		put("name_show", map[string]any{"name": name, "value": value, "txid": id, "vout": 0, "height": 2, "expired": false, "expires_in": 1000, "name_encoding": "ascii", "value_encoding": "ascii"}, name, map[string]any{"allowExpired": true, "nameEncoding": "ascii", "valueEncoding": "ascii"})
	}
	for h, ids := range members {
		put("getblockhash", block(h), h)
		put("getblockheader", map[string]any{"hash": block(h), "height": h, "confirmations": 101 - h}, block(h))
		put("getblock", map[string]any{"hash": block(h), "height": h, "tx": ids}, block(h), 1)
	}
	expectedScript, e := GrantSealScript(g.IssuerKey)
	if e != nil {
		t.Fatal(e)
	}
	stateDir := t.TempDir()
	if e := os.Chmod(stateDir, 0700); e != nil {
		t.Fatal(e)
	}
	p := Policy{ConstructionProfile: "W", Network: g.Network, Genesis: g.Genesis, AgentName: g.AgentName, LandlordName: g.LandlordName, SealScript: expectedScript, StateDir: stateDir}
	return n, p, g, proof
}

func TestGrantSealBinding(t *testing.T) {
	// Claim: a correctly signed v3 grant with matching framed issuance and valid
	// witness funding reaches exactly SEAL_BINDING for a positive-value seal owned
	// by another key, without closing or persisting the refused grant/seal.
	t.Run("foreign-seal", func(t *testing.T) {
		n, p, g, proof := sealBindingFixture(t, 5)
		r := Check(context.Background(), n, p, proof, g.AgentName, g.GranteeKey, 500)
		if r.Verdict != "refused" || r.Reason != "SEAL_BINDING" || r.Closed {
			t.Fatalf("foreign seal: want refused/SEAL_BINDING unclosed, got %+v", r)
		}
		assertNoIssuerBurn(t, p.StateDir)
	})
	// Claim: the same construction with the issuer-owned seal passes all gates
	// and stays live on replay; the foreign vector cannot pass by rejecting both.
	t.Run("issuer-seal", func(t *testing.T) {
		n, p, g, proof := sealBindingFixture(t, 1)
		for i := 0; i < 2; i++ {
			r := Check(context.Background(), n, p, proof, g.AgentName, g.GranteeKey, 500)
			if r.Verdict != "live" || r.Reason != "LIVE" || r.Closed {
				t.Fatalf("issuer seal: want live/LIVE unclosed, got %+v", r)
			}
		}
	})
}
