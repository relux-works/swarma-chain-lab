package singleuse

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// WitnessProfile is selected by authenticated configuration, never inferred
// from a witness marker or supplied by an untrusted transaction/presentation.
const WitnessProfile = "W"

func RequireWitnessProfile(profile string) error {
	if profile != WitnessProfile {
		return fail("W_PROFILE_REQUIRED")
	}
	return nil
}

func NativeP2WPKH(script []byte) bool { return len(script) == 22 && script[0] == 0 && script[1] == 20 }
func WitnessKeyScript(compressed []byte) ([]byte, error) {
	if len(compressed) != 33 || (compressed[0] != 2 && compressed[0] != 3) {
		return nil, fail("W_PUBLIC_KEY")
	}
	if _, e := secp.ParsePubKey(compressed); e != nil {
		return nil, fail("W_PUBLIC_KEY")
	}
	return append([]byte{0, 20}, hash160(compressed)...), nil
}

// WTransaction retains witness bytes separately from the immutable txid body.
// DecodePaymentTransaction retains its historical stripped projection contract.
type WTransaction struct {
	Body   *Transaction
	Stacks [][][]byte
}

func DecodeWitnessTransaction(raw []byte) (*WTransaction, error) {
	w := new(WTransaction)
	var e error
	w.Body, e = decodeTransaction(raw, true, &w.Stacks)
	if e != nil {
		return nil, e
	}
	if len(w.Stacks) != len(w.Body.Inputs) {
		return nil, fail("W_WITNESS_REQUIRED")
	}
	return w, nil
}
func (w *WTransaction) Bytes() []byte {
	body := w.Body.Bytes()
	var b bytes.Buffer
	b.Write(body[:4])
	b.Write([]byte{0, 1})
	b.Write(body[4 : len(body)-4])
	for _, stack := range w.Stacks {
		putVar(&b, uint64(len(stack)))
		for _, item := range stack {
			writeScript(&b, item)
		}
	}
	b.Write(body[len(body)-4:])
	return b.Bytes()
}

// WitnessSignatureHash is the BIP143 SIGHASH_ALL preimage for a native v0
// keyhash input. It commits every outpoint, sequence, output, amount and body
// field; unsupported modes have no entry point here.
func WitnessSignatureHash(tx *Transaction, index int, prev Output) ([]byte, error) {
	if tx == nil || index < 0 || index >= len(tx.Inputs) || !NativeP2WPKH(prev.Script) || prev.Value < 1 || prev.Value > 21000000*100000000 {
		return nil, fail("W_PREVOUT")
	}
	var points, sequences, outputs bytes.Buffer
	writePoint := func(b *bytes.Buffer, p Point) error {
		h, e := hex.DecodeString(p.TxID)
		if e != nil || len(h) != 32 {
			return fail("W_PREVOUT")
		}
		b.Write(reverse(h))
		_ = binary.Write(b, binary.LittleEndian, p.Vout)
		return nil
	}
	for _, in := range tx.Inputs {
		if e := writePoint(&points, in.Point); e != nil {
			return nil, e
		}
		_ = binary.Write(&sequences, binary.LittleEndian, in.Sequence)
	}
	for _, out := range tx.Outputs {
		_ = binary.Write(&outputs, binary.LittleEndian, out.Value)
		writeScript(&outputs, out.Script)
	}
	var pre bytes.Buffer
	_ = binary.Write(&pre, binary.LittleEndian, tx.Version)
	pre.Write(doubleHash(points.Bytes()))
	pre.Write(doubleHash(sequences.Bytes()))
	if e := writePoint(&pre, tx.Inputs[index].Point); e != nil {
		return nil, e
	}
	code := append([]byte{0x76, 0xa9, 20}, prev.Script[2:]...)
	code = append(code, 0x88, 0xac)
	writeScript(&pre, code)
	_ = binary.Write(&pre, binary.LittleEndian, prev.Value)
	_ = binary.Write(&pre, binary.LittleEndian, tx.Inputs[index].Sequence)
	pre.Write(doubleHash(outputs.Bytes()))
	_ = binary.Write(&pre, binary.LittleEndian, tx.Locktime)
	_ = binary.Write(&pre, binary.LittleEndian, uint32(1))
	return doubleHash(pre.Bytes()), nil
}

// VerifyWitnessInputs checks each actual prevout, exact stack and signature;
// consensus validity or one witnessed input never substitutes for all inputs.
func VerifyWitnessInputs(w *WTransaction, prevouts []Output) error {
	if w == nil || w.Body == nil || len(w.Body.Inputs) == 0 || len(w.Stacks) != len(w.Body.Inputs) || len(prevouts) != len(w.Body.Inputs) {
		return fail("W_WITNESS_REQUIRED")
	}
	seen := map[Point]bool{}
	for i, in := range w.Body.Inputs {
		if seen[in.Point] {
			return fail("W_DUPLICATE_INPUT")
		}
		seen[in.Point] = true
		prev := prevouts[i]
		if !NativeP2WPKH(prev.Script) || len(in.Script) != 0 {
			return fail("W_NATIVE_P2WPKH_REQUIRED")
		}
		stack := w.Stacks[i]
		if len(stack) != 2 || len(stack[0]) < 9 || len(stack[0]) > 73 || len(stack[1]) != 33 {
			return fail("W_WITNESS_SHAPE")
		}
		sigbytes := stack[0]
		if sigbytes[len(sigbytes)-1] != 1 {
			return fail("W_SIGHASH_ALL_REQUIRED")
		}
		script, e := WitnessKeyScript(stack[1])
		if e != nil || !bytes.Equal(script, prev.Script) {
			return fail("W_PUBLIC_KEY")
		}
		der := sigbytes[:len(sigbytes)-1]
		sig, e := ecdsa.ParseDERSignature(der)
		if e != nil || !bytes.Equal(sig.Serialize(), der) {
			return fail("W_SIGNATURE_INVALID")
		}
		pub, e := secp.ParsePubKey(stack[1])
		if e != nil {
			return fail("W_PUBLIC_KEY")
		}
		digest, e := WitnessSignatureHash(w.Body, i, prev)
		if e != nil {
			return e
		}
		if !sig.Verify(digest, pub) {
			return fail("W_SIGNATURE_INVALID")
		}
	}
	return nil
}
