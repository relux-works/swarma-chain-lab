package signerservice

import (
	"bytes"
	"encoding/hex"
	"path/filepath"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	rental "relux.works/swarma-chain-lab/experiments/rental"
	su "relux.works/swarma-chain-lab/experiments/single-use"
)

// Keys are read only after configuration/regtest admission. Both P2PKH roles
// use the even-y point for an explicitly pinned x-only key, matching K1.
func loadKey(path, script string) (*btcec.PrivateKey, error) {
	resolved, e := filepath.EvalSymlinks(path)
	if e != nil || resolved != path {
		return nil, fail("SIGNING_KEY_PATH")
	}
	b, e := privateRead(path, 32)
	if e != nil || len(b) != 32 {
		return nil, fail("SIGNING_KEY_FILE")
	}
	defer clear(b)
	var scalar btcec.ModNScalar
	if scalar.SetByteSlice(b) || scalar.IsZero() {
		return nil, fail("SIGNING_KEY_SCALAR")
	}
	key := btcec.PrivKeyFromScalar(&scalar)
	scalar.Zero()
	if key.PubKey().SerializeCompressed()[0] == 3 {
		key.Key.Negate()
	}
	pub := hex.EncodeToString(schnorr.SerializePubKey(key.PubKey()))
	actual, e := rental.GrantSealScript(pub)
	if e != nil || actual != script {
		key.Zero()
		return nil, fail("SIGNING_KEY_PIN")
	}
	return key, nil
}
func signPlan(plan rental.Plan, key *btcec.PrivateKey) ([]byte, string, error) {
	tx := su.Transaction{Version: plan.TransactionVersion}
	for _, in := range plan.Inputs {
		if !digest(in.Point.TxID) {
			return nil, "", fail("TX_INPUT")
		}
		tx.Inputs = append(tx.Inputs, su.Input{Point: in.Point, Sequence: 0xfffffffe})
	}
	for _, out := range plan.Outputs {
		b, e := hex.DecodeString(out.Script)
		if e != nil {
			return nil, "", fail("TX_OUTPUT")
		}
		tx.Outputs = append(tx.Outputs, su.Output{Value: out.ValueSat, Script: b})
	}
	pub := key.PubKey().SerializeCompressed()
	for i, in := range plan.Inputs {
		prev, e := hex.DecodeString(in.Script)
		if e != nil {
			return nil, "", fail("TX_INPUT")
		}
		sig := append(ecdsa.Sign(key, tx.SignatureHash(i, prev)).Serialize(), byte(1))
		script := append([]byte{byte(len(sig))}, sig...)
		script = append(script, byte(len(pub)))
		script = append(script, pub...)
		tx.Inputs[i].Script = script
	}
	if len(tx.Bytes()) > plan.MaxSignedVBytes {
		return nil, "", fail("SIGNED_FEE_BOUND")
	}
	return tx.Bytes(), tx.ID(), nil
}

// Durable bytes are not trusted merely because their txid is well-formed.
// Recovery revalidates the entire template and every actual SIGHASH_ALL input.
func verifySignedPlan(plan rental.Plan, raw []byte) error {
	tx, e := su.DecodeTransaction(raw)
	if e != nil || tx.Version != plan.TransactionVersion || tx.Version != 2 || tx.Locktime != 0 || len(tx.Inputs) != len(plan.Inputs) || len(tx.Outputs) != len(plan.Outputs) || len(raw) > plan.MaxSignedVBytes {
		return fail("SIGNED_TEMPLATE")
	}
	for i, in := range tx.Inputs {
		expected := plan.Inputs[i]
		if in.Point != expected.Point || in.Sequence != 0xfffffffe || len(in.Script) < 1 {
			return fail("SIGNED_TEMPLATE")
		}
		n := int(in.Script[0])
		script := in.Script
		if n < 9 || n > 73 || len(script) != 1+n+1+33 || script[1+n] != 33 || script[n] != 1 {
			return fail("SIGNED_SIGNATURE")
		}
		encodedPub := script[2+n:]
		if encodedPub[0] != 2 {
			return fail("SIGNED_KEY")
		}
		pub, e := btcec.ParsePubKey(encodedPub)
		if e != nil {
			return fail("SIGNED_KEY")
		}
		want, e := rental.GrantSealScript(hex.EncodeToString(schnorr.SerializePubKey(pub)))
		if e != nil || want != expected.Script {
			return fail("SIGNED_KEY")
		}
		der := script[1:n]
		sig, e := ecdsa.ParseDERSignature(der)
		if e != nil || !bytes.Equal(sig.Serialize(), der) {
			return fail("SIGNED_SIGNATURE")
		}
		prev, _ := hex.DecodeString(expected.Script)
		if !sig.Verify(tx.SignatureHash(i, prev), pub) {
			return fail("SIGNED_SIGNATURE")
		}
	}
	for i, out := range tx.Outputs {
		want := plan.Outputs[i]
		if out.Value != want.ValueSat || hex.EncodeToString(out.Script) != want.Script {
			return fail("SIGNED_TEMPLATE")
		}
	}
	return nil
}
