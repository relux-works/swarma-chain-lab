package signerservice

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"os"
	"path/filepath"
	"testing"

	rental "github.com/relux-works/swarma-chain-lab/experiments/rental"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// Genuine isolated Namecoin accepts the service's native/ALL T then A spending
// its unconfirmed L. Their bodies survive confirmation in one block; real
// rental admission and publication verify the graph. No mainnet/shared node.
func TestCoreWitnessSameBlock(t *testing.T) {
	l := newCore(t)
	ctx := context.Background()
	fund := l.fund("funding", 2000000)
	ordinary := l.fund("funding", 2000000)
	item := l.item("witness-same-block", true)
	x := l.engine()
	defer x.Close()
	if e := x.Enroll(ctx, []su.PlanInput{fund}, 500); e != nil {
		t.Fatal(e)
	}
	refill, e := x.Refill(ctx, 500)
	if e != nil || refill.Phase != "broadcast" {
		t.Fatal("T", refill, e)
	}
	// A separate inventory cannot pair an unconfirmed T with unrelated
	// confirmed funding. Refusal is before any enrollment ledger mutation.
	sealIn, e := x.pick("seal")
	if e != nil {
		t.Fatal(e)
	}
	linkIn, e := x.pickIssuanceFunding(sealIn)
	if e != nil {
		t.Fatal(e)
	}
	cfg := l.cfg
	cfg.StateDir = dir(t)
	cfg.Policy.Policy.StateDir = dir(t)
	y, e := Open(cfg, V1Issuer{cfg.Policy, l.observer, cfg.GrantKeyPath}, l.observer, noBroadcast{t}, noStore{t})
	if e != nil {
		t.Fatal(e)
	}
	defer y.Close()
	beforeEnroll := encode(y.state)
	diskBefore, beforeErr := os.ReadFile(filepath.Join(cfg.StateDir, "ledger.json"))
	if beforeErr != nil && !os.IsNotExist(beforeErr) {
		t.Fatal(beforeErr)
	}
	wantError(t, y.Enroll(ctx, []su.PlanInput{sealIn, ordinary}, 500), "W_LINKAGE_REQUIRED")
	diskAfter, afterErr := os.ReadFile(filepath.Join(cfg.StateDir, "ledger.json"))
	if afterErr != nil && !os.IsNotExist(afterErr) {
		t.Fatal(afterErr)
	}
	if os.IsNotExist(beforeErr) != os.IsNotExist(afterErr) {
		t.Fatal("refusal created or removed ledger")
	}
	if !bytes.Equal(beforeEnroll, encode(y.state)) || !bytes.Equal(diskBefore, diskAfter) {
		t.Fatal("missing linkage changed inventory")
	}
	if e = y.Enroll(ctx, []su.PlanInput{sealIn, linkIn}, 500); e != nil {
		t.Fatal("enrolled link control", e)
	}
	issued, e := x.Process(ctx, encode(item), BookingSource, 500)
	if e != nil || issued.Phase != "stored" {
		t.Fatal("A", issued, e)
	}
	var creation, anchor record
	var anchorOp operation
	for _, op := range x.state.Operations {
		r, e := x.readRecord(op)
		if e != nil {
			t.Fatal(e)
		}
		if op.Kind == "refill" {
			creation = r
		} else if op.Kind == "grant-issue" {
			anchor = r
			anchorOp = op
		}
	}
	if anchor.Spec.Pool.Point.TxID != refill.TxID {
		t.Fatal("grant does not authenticate T")
	}
	if len(anchor.Plan.Inputs) != 1 || anchor.Plan.Inputs[0].Point.TxID != refill.TxID || anchor.Plan.Inputs[0].Point.Vout == anchor.Spec.Pool.Point.Vout {
		t.Fatal("A did not spend exact L")
	}
	var mempool []string
	if e = json.Unmarshal(l.rpc("", "getrawmempool"), &mempool); e != nil {
		t.Fatal(e)
	}
	seen := map[string]bool{}
	for _, id := range mempool {
		seen[id] = true
	}
	if !seen[refill.TxID] || !seen[issued.TxID] {
		t.Fatal("T/A not simultaneously unconfirmed")
	}
	l.mine(1)
	var tv, av su.TransactionView
	if e = json.Unmarshal(l.rpc("", "getrawtransaction", refill.TxID, true), &tv); e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(l.rpc("", "getrawtransaction", issued.TxID, true), &av); e != nil {
		t.Fatal(e)
	}
	if tv.Block == "" || tv.Block != av.Block || tv.Hex != creation.RawTx || av.Hex != anchor.RawTx {
		t.Fatal("T/A body/witness changed or different blocks")
	}
	for _, r := range []record{creation, anchor} {
		raw, _ := hex.DecodeString(r.RawTx)
		w, e := su.DecodeWitnessTransaction(raw)
		if e != nil || w.Body.ID() != r.TxID {
			t.Fatal("W body", e)
		}
		if e = verifySignedPlan(*r.Plan, raw); e != nil {
			t.Fatal(e)
		}
	}
	// Exercise real confirmed publication after the initially unconfirmed issue.
	x.cfg.PresentationDir = dir(t)
	if e = os.Chmod(x.cfg.PresentationDir, 0755); e != nil {
		t.Fatal(e)
	}
	if e = x.publishConfirmed(ctx, anchorOp, anchor); e != nil {
		t.Fatal("W publication", e)
	}
	p := l.cfg.Policy.Policy
	p.StateDir = dir(t)
	_, renter, _ := testKey(2)
	live := rental.Check(ctx, l.observer, p, anchor.Presentation, p.AgentName, renter, 500)
	if live.Verdict != "live" {
		t.Fatal("same-block live", live)
	}
	// A wrong construction pin must not consume or overwrite an admitted cache.
	before := encode(x.state)
	for _, profile := range []string{"", "L", "unknown"} {
		bad := p
		bad.ConstructionProfile = profile
		got := rental.Check(ctx, l.observer, bad, anchor.Presentation, p.AgentName, renter, 500)
		if got.Reason != "W_PROFILE_REQUIRED" || got.Calls != 0 || got.Closed {
			t.Fatal("pin refusal", got)
		}
	}
	if !bytes.Equal(before, encode(x.state)) {
		t.Fatal("pin refusal changed signer state")
	}
	l.save("witness-same-block.json", map[string]any{"creation": refill.TxID, "anchor": issued.TxID, "block": tv.Block, "verdict": live, "profile": "W", "subset": "linkage-only", "status": "PASS"})
}

// Core accepts each transaction below as consensus-valid before W admission
// rejects it. This distinguishes W policy from node consensus, including a
// mixed legacy/native transaction and valid NONE/SINGLE/ANYONECANPAY signatures.
// Refusals preserve both the in-memory ledger and exact persisted ledger bytes.
func TestCoreWitnessRefusals(t *testing.T) {
	l := newCore(t)
	ctx := context.Background()
	x := l.engine()
	defer x.Close()
	key, e := loadKey(l.cfg.FundingKeyPath, l.cfg.Policy.Policy.FundingScript)
	if e != nil {
		t.Fatal(e)
	}
	defer key.Zero()
	native, _ := hex.DecodeString(l.cfg.Policy.Policy.FundingScript)
	sealScript, _ := hex.DecodeString(l.cfg.Policy.Policy.SealScript)
	makeT := func(mode string) su.PlanInput {
		t.Helper()
		prev := l.fund("funding", 2000000)
		script := native
		switch mode {
		case "legacy", "mixed-legacy":
			script = append([]byte{0x76, 0xa9, 0x14}, native[2:]...)
			script = append(script, 0x88, 0xac)
		case "wrapped":
			script = append([]byte{0xa9, 0x14}, btcutil.Hash160(native)...)
			script = append(script, 0x87)
		case "p2wsh":
			h := sha256.Sum256([]byte{0x51})
			script = append([]byte{0, 32}, h[:]...)
		case "taproot":
			script, e = txscript.PayToTaprootScript(txscript.ComputeTaprootKeyNoScript(key.PubKey()))
			if e != nil {
				t.Fatal(e)
			}
		}
		if !bytes.Equal(script, native) {
			conversion := rental.Plan{ConstructionProfile: "W", Kind: "refill", TransactionVersion: 2, Inputs: []su.PlanInput{prev}, Outputs: []su.PlanOutput{{ValueSat: 1000000, Script: hex.EncodeToString(script)}, {ValueSat: 900000, Script: hex.EncodeToString(native)}}, MaxSignedVBytes: 1000}
			raw, id, e := signPlan(conversion, key)
			if e != nil {
				t.Fatal(e)
			}
			if got := text(t, l.rpc("", "sendrawtransaction", hex.EncodeToString(raw))); got != id {
				t.Fatal("conversion id")
			}
			l.mine(1)
			prev = su.PlanInput{Point: su.Point{TxID: id, Vout: 0}, ValueSat: 1000000, Script: hex.EncodeToString(script), Role: "funding"}
		}
		tx := &su.Transaction{Version: 2, Inputs: []su.Input{{Point: prev.Point, Sequence: 0xfffffffe}}, Outputs: []su.Output{{Value: 200000, Script: sealScript}, {Value: prev.ValueSat - 300000, Script: native}}}
		prevs := []su.PlanInput{prev}
		if mode == "mixed-legacy" {
			extra := l.fund("funding", 2000000)
			prevs = append(prevs, extra)
			tx.Inputs = append(tx.Inputs, su.Input{Point: extra.Point, Sequence: 0xfffffffe})
			tx.Outputs[1].Value += extra.ValueSat
		}
		var wireTx wire.MsgTx
		if e := wireTx.Deserialize(bytes.NewReader(tx.Bytes())); e != nil {
			t.Fatal(e)
		}
		fetch := txscript.NewMultiPrevOutFetcher(nil)
		for i, in := range wireTx.TxIn {
			p, _ := hex.DecodeString(prevs[i].Script)
			fetch.AddPrevOut(in.PreviousOutPoint, wire.NewTxOut(prevs[i].ValueSat, p))
		}
		hashes := txscript.NewTxSigHashes(&wireTx, fetch)
		w := &su.WTransaction{Body: tx, Stacks: make([][][]byte, len(tx.Inputs))}
		for i := range tx.Inputs {
			switch {
			case i == 0 && (mode == "legacy" || mode == "mixed-legacy"):
				sig := append(ecdsa.Sign(key, tx.SignatureHash(i, script)).Serialize(), 1)
				tx.Inputs[i].Script = append([]byte{byte(len(sig))}, sig...)
				tx.Inputs[i].Script = append(tx.Inputs[i].Script, 33)
				tx.Inputs[i].Script = append(tx.Inputs[i].Script, key.PubKey().SerializeCompressed()...)
			case mode == "p2wsh":
				w.Stacks[i] = [][]byte{{0x51}}
			case mode == "taproot":
				sig, e := txscript.TaprootWitnessSignature(&wireTx, hashes, i, prev.ValueSat, script, txscript.SigHashDefault, key)
				if e != nil {
					t.Fatal(e)
				}
				w.Stacks[i] = sig
			default:
				modeByte := txscript.SigHashAll
				switch mode {
				case "none":
					modeByte = txscript.SigHashNone
				case "single":
					modeByte = txscript.SigHashSingle
				case "anyonecanpay":
					modeByte = txscript.SigHashAll | txscript.SigHashAnyOneCanPay
				}
				code := append([]byte{0x76, 0xa9, 0x14}, native[2:]...)
				code = append(code, 0x88, 0xac)
				digest, e := txscript.CalcWitnessSigHash(code, hashes, modeByte, &wireTx, i, prevs[i].ValueSat)
				if e != nil {
					t.Fatal(e)
				}
				w.Stacks[i] = [][]byte{append(ecdsa.Sign(key, digest).Serialize(), byte(modeByte)), key.PubKey().SerializeCompressed()}
				if mode == "wrapped" {
					tx.Inputs[i].Script = append([]byte{22}, native...)
				}
			}
		}
		raw := w.Bytes()
		if mode == "legacy" {
			raw = tx.Bytes()
		}
		id := text(t, l.rpc("", "sendrawtransaction", hex.EncodeToString(raw)))
		if id != tx.ID() {
			t.Fatal("Core txid")
		}
		return su.PlanInput{Point: su.Point{TxID: id, Vout: 0}, ValueSat: 200000, Script: l.cfg.Policy.Policy.SealScript, Role: "seal"}
	}
	good := makeT("valid")
	if e = x.Enroll(ctx, []su.PlanInput{good}, 500); e != nil {
		t.Fatal("valid W neighbor", e)
	}
	for _, tc := range []struct{ mode, reason string }{
		{"legacy", "W_WITNESS_REQUIRED"}, {"mixed-legacy", "W_NATIVE_P2WPKH_REQUIRED"},
		{"wrapped", "W_NATIVE_P2WPKH_REQUIRED"}, {"p2wsh", "W_NATIVE_P2WPKH_REQUIRED"}, {"taproot", "W_NATIVE_P2WPKH_REQUIRED"},
		{"none", "W_SIGHASH_ALL_REQUIRED"}, {"single", "W_SIGHASH_ALL_REQUIRED"}, {"anyonecanpay", "W_SIGHASH_ALL_REQUIRED"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			bad := makeT(tc.mode)
			memory := encode(x.state)
			disk, e := os.ReadFile(filepath.Join(x.cfg.StateDir, "ledger.json"))
			if e != nil {
				t.Fatal(e)
			}
			wantError(t, x.Enroll(ctx, []su.PlanInput{bad}, 500), tc.reason)
			after, e := os.ReadFile(filepath.Join(x.cfg.StateDir, "ledger.json"))
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(memory, encode(x.state)) || !bytes.Equal(disk, after) {
				t.Fatal("W refusal changed ledger")
			}
			if e = x.observe(ctx, []su.PlanInput{good}); e != nil {
				t.Fatal("valid W after refusal", e)
			}
			l.save("w-refusal-"+tc.mode+".json", map[string]any{"txid": bad.Point.TxID, "reason": tc.reason, "core_accepted": true, "state_unchanged": true, "status": "PASS"})
		})
	}
}
