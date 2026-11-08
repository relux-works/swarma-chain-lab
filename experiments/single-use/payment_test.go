package singleuse

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func paymentFixture() (*Transaction, []byte, []byte) {
	tx := &Transaction{Version: 2, Inputs: []Input{{Point: Point{strings.Repeat("1", 64), 0}, Sequence: 0xfffffffe}, {Point: Point{strings.Repeat("2", 64), 1}, Script: []byte{0x51}, Sequence: 0xfffffffe}}, Outputs: []Output{{Value: 1000000, Script: []byte{0x51}}}}
	legacy := tx.Bytes()
	var w bytes.Buffer
	w.Write(legacy[:4])
	w.Write([]byte{0, 1})
	w.Write(legacy[4 : len(legacy)-4])
	// A witness input followed by a legacy input with an empty witness stack.
	w.Write([]byte{2, 1, 0x51, 0, 0})
	w.Write(legacy[len(legacy)-4:])
	return tx, legacy, w.Bytes()
}

// Payment decoding preserves stripped txid/output bytes for legacy and mixed
// witness input serializations. It deliberately does not validate scripts or
// signatures; Core consensus and active-chain membership establish inclusion.
// The legacy seal/signer decoder must still reject the same witness bytes.
func TestPaymentWitnessDecode(t *testing.T) {
	want, legacy, wire := paymentFixture()
	for _, raw := range [][]byte{legacy, wire} {
		got, e := DecodePaymentTransaction(raw)
		if e != nil || got.ID() != want.ID() || !bytes.Equal(got.Bytes(), legacy) {
			t.Fatal(got, e)
		}
	}
	if want.ID() == hex.EncodeToString(reverse(doubleHash(wire))) {
		t.Fatal("fixture txid equals wtxid")
	}
	if _, e := DecodeTransaction(wire); e == nil || e.Error() != "LEGACY_INPUT_BOUND" {
		t.Fatal("legacy scope widened", e)
	}
}

// Exact malformed witness framing, nonminimal lengths, bounded item counts,
// truncated data, superfluous witness and trailing bytes fail with their own
// refusal. A nearby valid mixed-input transaction must remain decodable.
func TestPaymentWitnessRefusals(t *testing.T) {
	_, legacy, wire := paymentFixture()
	witnessAt := len(legacy) - 4 + 2
	stack := func(b []byte) []byte {
		out := bytes.Clone(wire[:witnessAt])
		out = append(out, b...)
		return append(out, wire[len(wire)-4:]...)
	}
	cases := []struct {
		name   string
		raw    []byte
		reason string
	}{
		{"flag-zero", bytes.Clone(wire), "WITNESS_FLAG"},
		{"flag-unknown", bytes.Clone(wire), "WITNESS_FLAG"},
		{"flag-mixed", bytes.Clone(wire), "WITNESS_FLAG"},
		{"stack-nonminimal", stack([]byte{253, 2, 0, 1, 0x51, 0, 0}), "WITNESS_STACK_BOUND"},
		{"stack-too-many", stack(append([]byte{253, 233, 3}, make([]byte, 1002)...)), "WITNESS_STACK_BOUND"},
		{"item-nonminimal", stack([]byte{1, 253, 1, 0, 0x51, 0}), "WITNESS_ITEM_BOUND"},
		{"item-too-large", stack(append([]byte{1, 253, 17, 39}, make([]byte, 10002)...)), "WITNESS_ITEM_BOUND"},
		{"item-truncated", stack([]byte{1, 100}), "WITNESS_ITEM_BOUND"},
		{"all-empty", stack([]byte{0, 0}), "WITNESS_SUPERFLUOUS"},
		{"truncated-locktime", wire[:len(wire)-1], "TX_TRAILING"},
		{"trailing", append(bytes.Clone(wire), 0), "TX_TRAILING"},
	}
	cases[0].raw[5] = 0
	cases[1].raw[5] = 2
	cases[2].raw[5] = 3
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, e := DecodePaymentTransaction(tc.raw); e == nil || e.Error() != tc.reason {
				t.Fatalf("want %s, got %v", tc.reason, e)
			}
			if _, e := DecodePaymentTransaction(wire); e != nil {
				t.Fatal("positive", e)
			}
		})
	}
}

// Inclusive stack/item limits accept serialization at the stated bounds;
// the over-limit cases above cannot pass by rejecting every witness stack.
func TestPaymentWitnessInclusiveBounds(t *testing.T) {
	_, legacy, wire := paymentFixture()
	at := len(legacy) - 4 + 2
	for _, stack := range [][]byte{append([]byte{253, 232, 3}, make([]byte, 1001)...), append([]byte{1, 253, 16, 39}, make([]byte, 10001)...)} {
		raw := append(bytes.Clone(wire[:at]), stack...)
		raw = append(raw, wire[len(wire)-4:]...)
		if _, e := DecodePaymentTransaction(raw); e != nil {
			t.Fatal(e)
		}
	}
}

// Binding uses stripped txid, raw output atoms/scripts and raw input outpoints;
// neither wtxid substitution nor an altered RPC projection can pass.
func TestPaymentRawBinding(t *testing.T) {
	tx, _, wire := paymentFixture()
	view := rpcTx{TxID: tx.ID(), Hex: hex.EncodeToString(wire)}
	for _, in := range tx.Inputs {
		v := rpcInput{TxID: in.TxID, Vout: in.Vout}
		v.Script.Hex = hex.EncodeToString(in.Script)
		view.Vin = append(view.Vin, v)
	}
	for i, out := range tx.Outputs {
		view.Vout = append(view.Vout, rpcOutput{N: uint32(i), Value: amount(out.Value), Script: rpcScript{Hex: hex.EncodeToString(out.Script)}})
	}
	for _, mode := range []string{"wtxid", "output-value", "output-script", "input-point"} {
		t.Run(mode, func(t *testing.T) {
			v := view
			v.Vin = append([]rpcInput{}, view.Vin...)
			v.Vout = append([]rpcOutput{}, view.Vout...)
			want := "RAW_OUTPUT_BINDING"
			id := view.TxID
			switch mode {
			case "wtxid":
				id = hex.EncodeToString(reverse(doubleHash(wire)))
				v.TxID = id
				want = "RAW_TX_BINDING"
			case "output-value":
				v.Vout[0].Value++
			case "output-script":
				v.Vout[0].Script.Hex = "52"
			case "input-point":
				v.Vin[0].Vout++
				want = "RAW_INPUT_BINDING"
			}
			if _, _, e := bindPaymentTransaction(id, v); e == nil || e.Error() != want {
				t.Fatal(mode, e)
			}
			if _, _, e := bindPaymentTransaction(view.TxID, view); e != nil {
				t.Fatal("positive", e)
			}
		})
	}
}
