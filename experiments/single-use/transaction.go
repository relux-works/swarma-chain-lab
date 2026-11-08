// Package singleuse is a bounded laboratory executor, not a production effect service.
package singleuse

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/ripemd160"
)

type Point struct {
	TxID string `json:"txid"`
	Vout uint32 `json:"vout"`
}
type Input struct {
	Point
	Script   []byte
	Sequence uint32
}
type Output struct {
	Value  int64
	Script []byte
}
type Transaction struct {
	Version  uint32
	Inputs   []Input
	Outputs  []Output
	Locktime uint32
}

func fail(s string) error    { return errors.New(s) }
func Hash(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func digestHex(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && s == strings.ToLower(s)
}
func doubleHash(raw []byte) []byte { a := sha256.Sum256(raw); b := sha256.Sum256(a[:]); return b[:] }
func reverse(b []byte) []byte {
	out := append([]byte(nil), b...)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}
func hash160(b []byte) []byte {
	a := sha256.Sum256(b)
	h := ripemd160.New()
	_, _ = h.Write(a[:])
	return h.Sum(nil)
}

func readVar(r *bytes.Reader) (uint64, error) {
	b, e := r.ReadByte()
	if e != nil {
		return 0, e
	}
	if b < 253 {
		return uint64(b), nil
	}
	n := 2
	if b == 254 {
		n = 4
	}
	if b == 255 {
		n = 8
	}
	v := make([]byte, n)
	if _, e = io.ReadFull(r, v); e != nil {
		return 0, e
	}
	var x uint64
	for i := n - 1; i >= 0; i-- {
		x = x<<8 | uint64(v[i])
	}
	if x < 253 || (n == 4 && x <= 65535) || (n == 8 && x <= 0xffffffff) {
		return 0, fail("NONMINIMAL_COMPACTSIZE")
	}
	return x, nil
}
func putVar(w *bytes.Buffer, n uint64) {
	switch {
	case n < 253:
		w.WriteByte(byte(n))
	case n <= 65535:
		w.WriteByte(253)
		_ = binary.Write(w, binary.LittleEndian, uint16(n))
	case n <= 0xffffffff:
		w.WriteByte(254)
		_ = binary.Write(w, binary.LittleEndian, uint32(n))
	default:
		w.WriteByte(255)
		_ = binary.Write(w, binary.LittleEndian, n)
	}
}
func readScript(r *bytes.Reader) ([]byte, error) {
	n, e := readVar(r)
	if e != nil {
		return nil, e
	}
	if n > 10000 || n > uint64(r.Len()) {
		return nil, fail("SCRIPT_BOUND")
	}
	b := make([]byte, n)
	_, e = io.ReadFull(r, b)
	return b, e
}
func writeScript(w *bytes.Buffer, b []byte) { putVar(w, uint64(len(b))); w.Write(b) }

// DecodeTransaction accepts bounded legacy serialization only. Witness spends
// are outside this v0 P2SH profile; no decoder fallback guesses their meaning.
func DecodeTransaction(raw []byte) (*Transaction, error) {
	if len(raw) < 10 || len(raw) > 1<<20 {
		return nil, fail("TX_SIZE")
	}
	r := bytes.NewReader(raw)
	tx := new(Transaction)
	if binary.Read(r, binary.LittleEndian, &tx.Version) != nil {
		return nil, fail("TX_VERSION")
	}
	n, e := readVar(r)
	if e != nil || n == 0 || n > 64 {
		return nil, fail("LEGACY_INPUT_BOUND")
	}
	for i := uint64(0); i < n; i++ {
		var prev [32]byte
		var in Input
		if _, e = io.ReadFull(r, prev[:]); e != nil {
			return nil, e
		}
		in.TxID = hex.EncodeToString(reverse(prev[:]))
		if e = binary.Read(r, binary.LittleEndian, &in.Vout); e != nil {
			return nil, e
		}
		in.Script, e = readScript(r)
		if e != nil {
			return nil, e
		}
		if e = binary.Read(r, binary.LittleEndian, &in.Sequence); e != nil {
			return nil, e
		}
		tx.Inputs = append(tx.Inputs, in)
	}
	n, e = readVar(r)
	if e != nil || n == 0 || n > 64 {
		return nil, fail("OUTPUT_BOUND")
	}
	var total int64
	for i := uint64(0); i < n; i++ {
		var out Output
		if e = binary.Read(r, binary.LittleEndian, &out.Value); e != nil {
			return nil, e
		}
		if out.Value < 0 || out.Value > 21000000*100000000-total {
			return nil, fail("VALUE_BOUND")
		}
		total += out.Value
		out.Script, e = readScript(r)
		if e != nil {
			return nil, e
		}
		tx.Outputs = append(tx.Outputs, out)
	}
	if binary.Read(r, binary.LittleEndian, &tx.Locktime) != nil || r.Len() != 0 {
		return nil, fail("TX_TRAILING")
	}
	return tx, nil
}
func (tx *Transaction) Bytes() []byte {
	var w bytes.Buffer
	_ = binary.Write(&w, binary.LittleEndian, tx.Version)
	putVar(&w, uint64(len(tx.Inputs)))
	for _, in := range tx.Inputs {
		p, e := hex.DecodeString(in.TxID)
		if e != nil || len(p) != 32 {
			panic("invalid constructed outpoint")
		}
		w.Write(reverse(p))
		_ = binary.Write(&w, binary.LittleEndian, in.Vout)
		writeScript(&w, in.Script)
		_ = binary.Write(&w, binary.LittleEndian, in.Sequence)
	}
	putVar(&w, uint64(len(tx.Outputs)))
	for _, out := range tx.Outputs {
		_ = binary.Write(&w, binary.LittleEndian, out.Value)
		writeScript(&w, out.Script)
	}
	_ = binary.Write(&w, binary.LittleEndian, tx.Locktime)
	return w.Bytes()
}
func (tx *Transaction) ID() string { return hex.EncodeToString(reverse(doubleHash(tx.Bytes()))) }
func (tx *Transaction) SignatureHash(index int, redeem []byte) []byte {
	copyTx := *tx
	copyTx.Inputs = append([]Input(nil), tx.Inputs...)
	for i := range copyTx.Inputs {
		copyTx.Inputs[i].Script = nil
	}
	copyTx.Inputs[index].Script = redeem
	raw := append(copyTx.Bytes(), 1, 0, 0, 0)
	return doubleHash(raw)
}

func SealScript(issuer, grantee string) (redeem, payment []byte, err error) {
	var keys [][]byte
	for _, s := range []string{issuer, grantee} {
		b, e := hex.DecodeString(s)
		if e != nil || len(b) != 33 || (b[0] != 2 && b[0] != 3) || s != strings.ToLower(s) {
			return nil, nil, fail("CHAIN_KEY")
		}
		if _, e = secp.ParsePubKey(b); e != nil {
			return nil, nil, fail("CHAIN_KEY")
		}
		keys = append(keys, b)
	}
	if bytes.Equal(keys[0], keys[1]) {
		return nil, nil, fail("EQUAL_CHAIN_KEYS")
	}
	redeem = []byte{0x51, 33}
	redeem = append(redeem, keys[0]...)
	redeem = append(redeem, 33)
	redeem = append(redeem, keys[1]...)
	redeem = append(redeem, 0x52, 0xae)
	payment = append([]byte{0xa9, 20}, hash160(redeem)...)
	payment = append(payment, 0x87)
	return redeem, payment, nil
}

// Attribute verifies the seal input's actual transaction signature against both
// independently pinned keys. It never infers the signer from an address label.
func Attribute(tx *Transaction, seal Point, issuer, grantee string) (string, error) {
	redeem, _, e := SealScript(issuer, grantee)
	if e != nil {
		return "", e
	}
	index := -1
	for i, in := range tx.Inputs {
		if in.Point == seal {
			if index != -1 {
				return "", fail("DUPLICATE_SEAL_INPUT")
			}
			index = i
		}
	}
	if index < 0 {
		return "", fail("SEAL_INPUT")
	}
	script := tx.Inputs[index].Script
	if len(script) < 3 || script[0] != 0 || script[1] < 9 || script[1] > 73 {
		return "", fail("SEAL_SCRIPTSIG")
	}
	n := int(script[1])
	if len(script) != 2+n+1+len(redeem) || script[2+n] != byte(len(redeem)) || !bytes.Equal(script[3+n:], redeem) {
		return "", fail("SEAL_REDEEM_SCRIPT")
	}
	signed := script[2 : 2+n]
	if signed[len(signed)-1] != 1 {
		return "", fail("SIGHASH_ALL_REQUIRED")
	}
	der := signed[:len(signed)-1]
	sig, e := ecdsa.ParseDERSignature(der)
	if e != nil || !bytes.Equal(sig.Serialize(), der) {
		return "", fail("STRICT_DER_LOW_S_REQUIRED")
	}
	digest := tx.SignatureHash(index, redeem)
	valid := []bool{}
	for _, s := range []string{issuer, grantee} {
		b, _ := hex.DecodeString(s)
		key, _ := secp.ParsePubKey(b)
		valid = append(valid, sig.Verify(digest, key))
	}
	if valid[0] && !valid[1] {
		return "issuer", nil
	}
	if valid[1] && !valid[0] {
		return "grantee", nil
	}
	return "", fail("AMBIGUOUS_OR_INVALID_SIGNER")
}

func RequestCommitment(tx *Transaction, request []byte) error {
	expected, _ := hex.DecodeString(Hash(request))
	want := append([]byte{0x6a, 32}, expected...)
	count := 0
	for _, out := range tx.Outputs {
		if len(out.Script) > 0 && out.Script[0] == 0x6a {
			count++
			if out.Value != 0 || !bytes.Equal(out.Script, want) {
				return fail("REQUEST_COMMITMENT")
			}
		}
	}
	if count != 1 {
		return fail("OP_RETURN_COUNT")
	}
	return nil
}

func coins(s string) (int64, error) {
	p := strings.Split(s, ".")
	if len(p) > 2 || len(p[0]) == 0 {
		return 0, fail("AMOUNT")
	}
	frac := ""
	if len(p) == 2 {
		frac = p[1]
	}
	if len(frac) > 8 {
		return 0, fail("AMOUNT")
	}
	digits := p[0] + frac + strings.Repeat("0", 8-len(frac))
	var n int64
	for _, c := range digits {
		if c < '0' || c > '9' || n > (21000000*100000000-int64(c-'0'))/10 {
			return 0, fail("AMOUNT")
		}
		n = n*10 + int64(c-'0')
	}
	return n, nil
}
func Coins(n int64) jsonAmount { return jsonAmount(fmt.Sprintf("%d.%08d", n/100000000, n%100000000)) }

type jsonAmount string

func (a jsonAmount) MarshalJSON() ([]byte, error) {
	if _, e := coins(string(a)); e != nil {
		return nil, e
	}
	return []byte(a), nil
}
