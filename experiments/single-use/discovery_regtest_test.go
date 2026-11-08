package singleuse

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"
)

// noiseSeed creates independent confirmed inputs before the seal. Wallet keys
// stay in this isolated Core regtest; verbose/raw receipts are public evidence.
func (l *coreLab) noiseSeed(count int, witness bool) []Point {
	l.t.Helper()
	kind := "legacy"
	if witness {
		kind = "bech32"
	}
	address := textValue(l.t, l.rpc("issuer", "getnewaddress", "noise", kind))
	info := object(l.t, l.rpc("issuer", "getaddressinfo", address))
	script, e := hex.DecodeString(textValue(l.t, info["scriptPubKey"]))
	if e != nil {
		l.t.Fatal(e)
	}
	tx := Transaction{Version: 2}
	for i := 0; i < count; i++ {
		tx.Outputs = append(tx.Outputs, Output{Value: 1000000, Script: script})
	}
	funded := object(l.t, l.rpc("issuer", "fundrawtransaction", hex.EncodeToString(tx.Bytes()), map[string]any{"fee_rate": 200, "changePosition": count}))
	id := l.noiseSend(textValue(l.t, funded["hex"]), "noise-seed")
	l.mine(1)
	points := make([]Point, count)
	for i := range points {
		points[i] = Point{id, uint32(i)}
	}
	// Prevent later wallet-funded seal/anchor creation from consuming fixtures.
	l.rpc("issuer", "lockunspent", false, points)
	return points
}

// Deliberately avoids the product's legacy decoder: Core must sign, admit,
// decode and relay both witness and >64-input fixtures on their real paths.
func (l *coreLab) noiseSend(raw, label string) string {
	l.t.Helper()
	signed := object(l.t, l.rpc("issuer", "signrawtransactionwithwallet", raw))
	if string(signed["complete"]) != "true" {
		l.t.Fatal("incomplete noise signature")
	}
	signedHex := textValue(l.t, signed["hex"])
	id := textValue(l.t, l.rpc("", "sendrawtransaction", signedHex))
	l.save(label+"-raw.json", map[string]string{"txid": id, "hex": signedHex})
	return id
}

func (l *coreLab) noiseSpend(points []Point, label string) string {
	l.t.Helper()
	script, e := hex.DecodeString(l.payment)
	if e != nil {
		l.t.Fatal(e)
	}
	// Reserve per input so the 65-input control clears Core's real relay fee.
	tx := Transaction{Version: 2, Outputs: []Output{{Value: int64(len(points)) * 800000, Script: script}}}
	for _, p := range points {
		tx.Inputs = append(tx.Inputs, Input{Point: p, Sequence: 0xfffffffd})
	}
	return l.noiseSend(hex.EncodeToString(tx.Bytes()), label)
}

func discoveryNoise(t *testing.T, witness, block bool, inputs, count int) {
	l := newCoreLab(t)
	seed := l.noiseSeed(inputs*count, witness)
	p := l.newPolicy()
	// Same genuine candidate without noise is the positive control on both
	// base and patched executables; each observation has isolated local state.
	use := l.use(p, "grantee", "ALL", nil, true)
	control := l.state(p, "clean-control")
	r, exit := l.invoke(control, l.request, "clean-control")
	if exit != 0 || r.Status != "executed" || effectCount(t, control) != 1 || journalCount(t, control) != 1 {
		t.Fatalf("clean control %+v exit%d", r, exit)
	}
	var ids []string
	for i := 0; i < count; i++ {
		ids = append(ids, l.noiseSpend(seed[i*inputs:(i+1)*inputs], fmt.Sprintf("noise-%03d", i)))
	}
	if block {
		l.mine(1)
	}
	for _, id := range ids {
		raw := l.rpc("", "getrawtransaction", id, true)
		view := object(t, raw)
		var vin []json.RawMessage
		if e := json.Unmarshal(view["vin"], &vin); e != nil {
			t.Fatal(e)
		}
		wire := textValue(t, view["hex"])
		if len(vin) != inputs || (len(wire) >= 12 && wire[8:12] == "0001") != witness {
			t.Fatal("noise did not exercise requested format")
		}
		if block && len(view["blockhash"]) == 0 {
			t.Fatal("noise not confirmed")
		}
		l.save("noise-view-"+id+".json", raw)
	}
	var mempool []string
	if e := json.Unmarshal(l.rpc("", "getrawmempool"), &mempool); e != nil {
		t.Fatal(e)
	}
	if !block && len(mempool) < count {
		t.Fatal("missing mempool noise")
	}
	p = l.state(p, "with-noise")
	r, exit = l.invoke(p, l.request, "with-noise")
	// Core's seal confirmations equal the inclusive scan length on this stable
	// isolated chain. These extra harness reads are not executor read calls.
	sealView := object(t, l.rpc("", "getrawtransaction", p.Seal.TxID, true))
	var blocks int
	if e := json.Unmarshal(sealView["confirmations"], &blocks); e != nil {
		t.Fatal(e)
	}
	expectedCalls := 26 + 2*blocks + len(mempool)
	l.save("noise-result.json", map[string]any{"witness": witness, "noise_in_block": block, "inputs_per_noise": inputs, "noise_count": count, "mempool_count": len(mempool), "scanned_blocks": blocks, "expected_calls": expectedCalls, "use": use, "receipt": r, "exit": exit, "journal_count": journalCount(t, p), "effect_count": effectCount(t, p)})
	if exit != 0 || r.Status != "executed" || r.Reason != "CONFIRMED_GRANTEE_USE" || r.SpendTxID != use || r.JournalPhase != "complete" || journalCount(t, p) != 1 || effectCount(t, p) != 1 {
		t.Fatalf("noise must not block valid candidate: %+v exit%d journal%d effect%d", r, exit, journalCount(t, p), effectCount(t, p))
	}
	if r.Calls != expectedCalls {
		t.Fatalf("calls%d want%d (26+2N+M)", r.Calls, expectedCalls)
	}
	r, exit = l.invoke(p, l.request, "noise-replay")
	if exit != 0 || r.Status != "already-executed" || r.Calls != 0 || journalCount(t, p) != 1 || effectCount(t, p) != 1 {
		t.Fatalf("replay %+v exit%d", r, exit)
	}
	if count > 256 {
		// The same finite large mempool also runs through the subprocess adapter
		// used by the mainnet capability, against this isolated regtest only.
		p = l.state(p, "large-operator-route")
		binary, e := os.ReadFile(l.cli)
		if e != nil {
			t.Fatal(e)
		}
		route := OperatorRoute{Network: "regtest", Genesis: RegtestGenesis, NodeCLI: l.cli, NodeCLISHA256: Hash(binary), NodeConfig: l.conf, NodeDataDir: l.private}
		node, e := NewOperatorRPC(route, p.Network, p.Genesis, p.StateDir)
		if e != nil {
			t.Fatal(e)
		}
		start := time.Now()
		r = Execute(context.Background(), node, p, l.certificate, l.request, time.Now(), nil)
		l.save("large-operator-receipt.json", map[string]any{"receipt": r, "elapsed_ms": time.Since(start).Milliseconds(), "journal_count": journalCount(t, p), "effect_count": effectCount(t, p)})
		if r.Status != "executed" || r.Calls != expectedCalls || journalCount(t, p) != 1 || effectCount(t, p) != 1 {
			t.Fatal(r)
		}
	}
	l.save("result.json", map[string]any{"status": "PASS", "noise_count": count, "inputs_per_noise": inputs, "witness": witness, "noise_in_block": block, "clean_positive": true, "executed_once": true, "replay_zero_reads": true})
}

// Actual unrelated segwit transactions must not block a valid confirmed use,
// whether they appear later in its block scan or in the mempool.
func TestGenuineCoreWitnessMempool(t *testing.T) { discoveryNoise(t, true, false, 1, 2) }
func TestGenuineCoreWitnessBlock(t *testing.T)   { discoveryNoise(t, true, true, 1, 2) }

// The legacy candidate's 64-input cap must not constrain unrelated valid txs.
func TestGenuineCoreManyInputsMempool(t *testing.T) { discoveryNoise(t, false, false, 65, 1) }
func TestGenuineCoreManyInputsBlock(t *testing.T)   { discoveryNoise(t, false, true, 65, 1) }

// 257 independent, non-witness mempool txs isolate the former cardinality gate
// from witness decoding. This is a finite availability witness, not an unlimited
// mempool guarantee; global observation budgets still apply.
func TestGenuineCoreLargeMempool(t *testing.T) { discoveryNoise(t, false, false, 1, 257) }

type discoveryMutation struct {
	Node
	use, noise, mode string
	seal             Point
	applied          int
}

func (n *discoveryMutation) Call(ctx context.Context, method string, args ...any) (json.RawMessage, error) {
	raw, e := n.Node.Call(ctx, method, args...)
	if e != nil || method != "getblock" || len(args) != 2 || args[1] != 2 {
		return raw, e
	}
	var b map[string]any
	if e = json.Unmarshal(raw, &b); e != nil {
		return nil, e
	}
	for _, value := range b["tx"].([]any) {
		tx := value.(map[string]any)
		id := n.use
		if n.mode == "noise-forged-candidate" {
			id = n.noise
		}
		if tx["txid"] != id {
			continue
		}
		n.applied++
		switch n.mode {
		case "alias-vin":
			tx["VIN"] = tx["vin"]
			delete(tx, "vin")
		case "null-vout":
			tx["vin"].([]any)[0].(map[string]any)["vout"] = nil
		case "extra-projected-input":
			tx["vin"] = append(tx["vin"].([]any), tx["vin"].([]any)[0])
		case "witness-candidate":
			tx["hex"] = "02000000000100000000"
		case "conflicting-block":
			tx["blockhash"] = RegtestGenesis
		case "conflicting-confirmations":
			tx["confirmations"] = -1
		case "noise-forged-candidate":
			in := tx["vin"].([]any)[0].(map[string]any)
			in["txid"], in["vout"] = n.seal.TxID, n.seal.Vout
		}
	}
	return json.Marshal(b)
}

// Labelled mutations of genuine Core verbose replies must fail before any
// reservation/effect. They supplement, rather than replace, the unmodified
// Core noise controls. Valid neighbors use identical real transactions.
func TestGenuineCoreDiscoveryRefusals(t *testing.T) {
	l := newCoreLab(t)
	seed := l.noiseSeed(2, true)
	p := l.newPolicy()
	use := l.use(p, "grantee", "ALL", nil, true)
	noise := l.noiseSpend(seed[:1], "negative-witness")
	l.mine(1)
	node, e := NewRPC(l.route)
	if e != nil {
		t.Fatal(e)
	}
	cases := []struct{ mode, reason string }{
		{"alias-vin", "NODE_PROJECTION"}, {"null-vout", "NODE_PROJECTION"},
		{"extra-projected-input", "RAW_TX_BINDING"}, {"witness-candidate", "LEGACY_INPUT_BOUND"},
		{"conflicting-block", "BLOCK_CANDIDATE_BINDING"}, {"conflicting-confirmations", "BLOCK_CANDIDATE_BINDING"},
		{"noise-forged-candidate", "LEGACY_INPUT_BOUND"},
	}
	for _, tc := range cases {
		state := l.state(p, tc.mode)
		mutated := &discoveryMutation{Node: node, use: use, noise: noise, mode: tc.mode, seal: p.Seal}
		r := Execute(context.Background(), mutated, state, l.certificate, l.request, time.Now(), nil)
		l.save(tc.mode+"-control.json", map[string]any{"receipt": r, "mutation_applied": mutated.applied, "node_reply_modified": true, "journal_count": journalCount(t, state), "effect_count": effectCount(t, state)})
		if mutated.applied != 1 || r.Status != "refused" || r.Reason != tc.reason || journalCount(t, state) != 0 || effectCount(t, state) != 0 {
			t.Fatalf("%s: applied%d %+v journal%d effect%d", tc.mode, mutated.applied, r, journalCount(t, state), effectCount(t, state))
		}
	}
	valid := l.state(p, "unmodified-neighbor")
	r, exit := l.invoke(valid, l.request, "unmodified-neighbor")
	if exit != 0 || r.Status != "executed" || journalCount(t, valid) != 1 || effectCount(t, valid) != 1 {
		t.Fatal(r, exit)
	}
	// Actual signed wrong commitment with witness noise in the same scan must
	// retain REQUEST_COMMITMENT; unrelated noise never bypasses candidate checks.
	bad := l.state(l.newPolicy(), "wrong-commitment-with-noise")
	l.noiseSpend(seed[1:], "wrong-commitment-noise")
	l.use(bad, "grantee", "ALL", func(tx *Transaction) { tx.Outputs[1].Script[2] ^= 1 }, true)
	l.refused(bad, l.request, "wrong-commitment-with-noise", "REQUEST_COMMITMENT")
	l.save("result.json", map[string]any{"status": "PASS", "labelled_reply_mutations": len(cases), "unmodified_neighbor": true, "real_wrong_commitment_with_noise_refused": true})
}
