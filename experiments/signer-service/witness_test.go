package signerservice

import (
	"bytes"
	"encoding/hex"
	"path/filepath"
	"testing"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	rental "github.com/relux-works/swarma-chain-lab/experiments/rental"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// btcd independently computes each BIP143 digest and executes every native
// witness produced by the signer. Changing an amount must break that execution;
// the test does not use our verifier as the expected-signature oracle.
func TestWitnessSigningIndependentEngine(t *testing.T) {
	c := config(t)
	key, e := loadKey(c.FundingKeyPath, c.Policy.Policy.FundingScript)
	if e != nil {
		t.Fatal(e)
	}
	defer key.Zero()
	script, _ := hex.DecodeString(c.Policy.Policy.FundingScript)
	inputs := []su.PlanInput{}
	for i := 0; i < 2; i++ {
		inputs = append(inputs, su.PlanInput{Point: su.Point{TxID: hash([]byte{byte(i)})}, ValueSat: 2000000, Script: c.Policy.Policy.FundingScript, Role: "funding"})
	}
	plan, e := rental.MakePlan(c.Policy, rental.PlanSpec{Kind: "refill", Inputs: inputs, ChangeScript: c.Policy.Policy.FundingScript, Count: 1, ValueSat: 200000}, nil, nil, nil, 500)
	if e != nil {
		t.Fatal(e)
	}
	raw, id, e := signPlan(plan, key)
	if e != nil {
		t.Fatal(e)
	}
	var tx wire.MsgTx
	if e = tx.Deserialize(bytes.NewReader(raw)); e != nil {
		t.Fatal(e)
	}
	if tx.TxHash().String() != id {
		t.Fatal("stripped txid mismatch")
	}
	prevs := txscript.NewMultiPrevOutFetcher(nil)
	for i, in := range tx.TxIn {
		prevs.AddPrevOut(in.PreviousOutPoint, wire.NewTxOut(inputs[i].ValueSat, script))
	}
	hashes := txscript.NewTxSigHashes(&tx, prevs)
	decoded, e := su.DecodeWitnessTransaction(raw)
	if e != nil {
		t.Fatal(e)
	}
	code := append([]byte{0x76, 0xa9, 0x14}, script[2:]...)
	code = append(code, 0x88, 0xac)
	for i := range inputs {
		want, e := txscript.CalcWitnessSigHash(code, hashes, txscript.SigHashAll, &tx, i, inputs[i].ValueSat)
		if e != nil {
			t.Fatal(e)
		}
		got, e := su.WitnessSignatureHash(decoded.Body, i, su.Output{Value: inputs[i].ValueSat, Script: script})
		if e != nil || !bytes.Equal(want, got) {
			t.Fatal("BIP143 disagreement", e)
		}
		for _, delta := range []int64{0, 1} {
			vm, e := txscript.NewEngine(script, &tx, i, txscript.StandardVerifyFlags, nil, hashes, inputs[i].ValueSat+delta, prevs)
			if e != nil {
				t.Fatal(e)
			}
			e = vm.Execute()
			if delta == 0 && e != nil {
				t.Fatal("btcd rejected native ALL", e)
			}
			if delta != 0 && e == nil {
				t.Fatal("btcd accepted wrong amount")
			}
		}
	}
}

// W is explicitly selected in trusted configuration. Missing or unsupported
// pins refuse before opening keys/state; a valid W neighbor still validates.
func TestWitnessProfileStartup(t *testing.T) {
	c := config(t)
	for _, profile := range []string{"", "L", "w", "future"} {
		bad := c
		bad.Policy.Policy.ConstructionProfile = profile
		bad.StateDir = "/missing"
		bad.GrantKeyPath = "/missing"
		_, e := Open(bad, nil, nil, nil, nil)
		wantError(t, e, "W_PROFILE_REQUIRED")
	}
	if e := c.validate(); e != nil {
		t.Fatal("valid W", e)
	}
}

// Full-compressed funding keys retain odd parity; normalization is only a seal
// convention. Both native parities sign, while the opposite-parity pin refuses.
func TestWitnessFundingKeyParity(t *testing.T) {
	for _, n := range []byte{1, 6} {
		k, _, _ := testKey(n)
		raw, _ := su.WitnessKeyScript(k.PubKey().SerializeCompressed())
		path := filepath.Join(dir(t), "funding.key")
		write(t, path, k.Serialize())
		got, e := loadKey(path, hex.EncodeToString(raw))
		if e != nil {
			t.Fatal(e)
		}
		if !bytes.Equal(got.PubKey().SerializeCompressed(), k.PubKey().SerializeCompressed()) {
			t.Fatal("funding parity changed")
		}
		got.Zero()
		opposite := k.PubKey().SerializeCompressed()
		opposite[0] ^= 1
		other, _ := su.WitnessKeyScript(opposite)
		_, e = loadKey(path, hex.EncodeToString(other))
		wantError(t, e, "SIGNING_KEY_PIN")
	}
}
