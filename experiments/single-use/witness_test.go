package singleuse

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

func wFixture(t *testing.T) (*WTransaction, []Output) {
	t.Helper()
	key := secp.PrivKeyFromBytes([]byte{1})
	t.Cleanup(key.Zero)
	script, e := WitnessKeyScript(key.PubKey().SerializeCompressed())
	if e != nil {
		t.Fatal(e)
	}
	if hex.EncodeToString(script) != "0014751e76e8199196d454941c45d1b3a323f1433bd6" {
		t.Fatal("known keyhash program")
	}
	prev := []Output{{Value: 100000, Script: script}, {Value: 200000, Script: script}}
	tx := &Transaction{Version: 2, Inputs: []Input{{Point: Point{strings.Repeat("a", 64), 0}, Sequence: 0xfffffffe}, {Point: Point{strings.Repeat("b", 64), 1}, Sequence: 0xfffffffe}}, Outputs: []Output{{Value: 299000, Script: []byte{0x51}}}}
	w := &WTransaction{Body: tx}
	for i := range tx.Inputs {
		h, e := WitnessSignatureHash(tx, i, prev[i])
		if e != nil {
			t.Fatal(e)
		}
		w.Stacks = append(w.Stacks, [][]byte{append(ecdsa.Sign(key, h).Serialize(), 1), key.PubKey().SerializeCompressed()})
	}
	return w, prev
}

// Every input is checked (mutations target the later input); raw serialization
// and prevouts stay unchanged on refusal. Output scripts are not W-constrained.
func TestWitnessInputProfile(t *testing.T) {
	good, prev := wFixture(t)
	if e := VerifyWitnessInputs(good, prev); e != nil {
		t.Fatal("W valid native ALL control", e)
	}
	cases := []struct {
		name, reason string
		change       func(*WTransaction, []Output)
	}{
		{"legacy", "W_NATIVE_P2WPKH_REQUIRED", func(w *WTransaction, p []Output) {
			p[1].Script = append(append([]byte{0x76, 0xa9, 20}, p[1].Script[2:]...), 0x88, 0xac)
		}},
		{"wrapped", "W_NATIVE_P2WPKH_REQUIRED", func(w *WTransaction, p []Output) {
			p[1].Script = append(append([]byte{0xa9, 20}, hash160(p[1].Script)...), 0x87)
		}},
		{"p2wsh", "W_NATIVE_P2WPKH_REQUIRED", func(w *WTransaction, p []Output) { p[1].Script = append([]byte{0, 32}, make([]byte, 32)...) }},
		{"taproot", "W_NATIVE_P2WPKH_REQUIRED", func(w *WTransaction, p []Output) { p[1].Script = append([]byte{0x51, 32}, make([]byte, 32)...) }},
		{"scriptsig", "W_NATIVE_P2WPKH_REQUIRED", func(w *WTransaction, p []Output) { w.Body.Inputs[1].Script = []byte{0} }},
		{"marker-only", "W_WITNESS_SHAPE", func(w *WTransaction, p []Output) { w.Stacks[1] = nil }},
		{"none", "W_SIGHASH_ALL_REQUIRED", func(w *WTransaction, p []Output) { w.Stacks[1][0][len(w.Stacks[1][0])-1] = 2 }},
		{"single", "W_SIGHASH_ALL_REQUIRED", func(w *WTransaction, p []Output) { w.Stacks[1][0][len(w.Stacks[1][0])-1] = 3 }},
		{"anyonecanpay", "W_SIGHASH_ALL_REQUIRED", func(w *WTransaction, p []Output) { w.Stacks[1][0][len(w.Stacks[1][0])-1] = 0x81 }},
		{"wrong-amount", "W_SIGNATURE_INVALID", func(w *WTransaction, p []Output) { p[1].Value++ }},
		{"body-change", "W_SIGNATURE_INVALID", func(w *WTransaction, p []Output) { w.Body.Outputs[0].Value-- }},
		{"wrong-program", "W_PUBLIC_KEY", func(w *WTransaction, p []Output) { p[1].Script[2] ^= 1 }},
		{"extra-item", "W_WITNESS_SHAPE", func(w *WTransaction, p []Output) { w.Stacks[1] = append(w.Stacks[1], nil) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, e := DecodeWitnessTransaction(good.Bytes())
			if e != nil {
				t.Fatal(e)
			}
			p := []Output{{prev[0].Value, bytes.Clone(prev[0].Script)}, {prev[1].Value, bytes.Clone(prev[1].Script)}}
			tc.change(w, p)
			before := w.Bytes()
			e = VerifyWitnessInputs(w, p)
			if e == nil || e.Error() != tc.reason {
				t.Fatalf("W input guard %s: %v", tc.reason, e)
			}
			if !bytes.Equal(before, w.Bytes()) {
				t.Fatal("W refusal mutated transaction")
			}
			if e := VerifyWitnessInputs(good, prev); e != nil {
				t.Fatal("valid neighbor", e)
			}
		})
	}
}

// A missing/unknown/L profile never selects W by inference. Witness decoding
// preserves the txid body, while the historical legacy decoder still refuses it.
func TestWitnessCodecAndProfile(t *testing.T) {
	for _, pin := range []string{"", "L", "w", "future"} {
		if e := RequireWitnessProfile(pin); e == nil || e.Error() != "W_PROFILE_REQUIRED" {
			t.Fatal("W profile fallback", pin, e)
		}
	}
	if e := RequireWitnessProfile("W"); e != nil {
		t.Fatal(e)
	}
	w, _ := wFixture(t)
	raw := w.Bytes()
	decoded, e := DecodeWitnessTransaction(raw)
	if e != nil || !bytes.Equal(decoded.Bytes(), raw) || decoded.Body.ID() != w.Body.ID() {
		t.Fatal("W codec/body binding", e)
	}
	if _, e := DecodeTransaction(raw); e == nil {
		t.Fatal("legacy decoder widened")
	}
	if _, e := DecodeWitnessTransaction(w.Body.Bytes()); e == nil || e.Error() != "W_WITNESS_REQUIRED" {
		t.Fatal("W legacy wire admitted", e)
	}
	for _, bad := range [][]byte{append(bytes.Clone(raw), 0), raw[:len(raw)-1], append(append(bytes.Clone(raw[:5]), 2), raw[6:]...)} {
		if _, e := DecodeWitnessTransaction(bad); e == nil {
			t.Fatal("W malformed framing admitted")
		}
	}
}
