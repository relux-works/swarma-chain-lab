// Track A co-signatures cover the exact signed envelope bytes.
package g1bench

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

const CosignatureContentKey = "works.relux.cg1.cosignature"
const CosignatureVersion = "a2a-link-cg1-cosignature/1"
const CosignatureDomain = "a2a-link cg1 cosignature/1"

var ErrInvalid = errors.New("cg1: invalid co-signature")

// BIP340 verifies the separate Track A co-signature, never the Ed25519 author.
type BIP340 struct{}

// Digest signs exact wire bytes, not their canonical form or the envelope content id.
func Digest(envelope []byte) ([32]byte, error) {
	if len(envelope) == 0 || len(envelope) > maxEnvelope {
		return [32]byte{}, ErrInvalid
	}
	tag := sha256.Sum256([]byte(CosignatureDomain))
	h := sha256.New()
	h.Write(tag[:])
	h.Write(tag[:])
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(envelope)))
	h.Write(size[:])
	h.Write(envelope)
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest, nil
}
func decodeHex(s string, n int) ([]byte, error) {
	if len(s) != n*2 || strings.ToLower(s) != s {
		return nil, ErrInvalid
	}
	b, e := hex.DecodeString(s)
	if e != nil {
		return nil, ErrInvalid
	}
	return b, nil
}

func (BIP340) Verify(envelope []byte, content any) (string, error) {
	obj, ok := content.(map[string]any)
	if !ok || len(obj) != 3 || obj["version"] != CosignatureVersion {
		return "", ErrInvalid
	}
	key, ok := obj["key"].(string)
	if !ok || !strings.HasPrefix(key, "bip340:") {
		return "", ErrInvalid
	}
	key = strings.TrimPrefix(key, "bip340:")
	pub, e := decodeHex(key, 32)
	if e != nil {
		return "", ErrInvalid
	}
	pk, e := schnorr.ParsePubKey(pub)
	if e != nil {
		return "", ErrInvalid
	}
	text, ok := obj["sig"].(string)
	if !ok {
		return "", ErrInvalid
	}
	raw, e := decodeHex(text, 64)
	if e != nil {
		return "", ErrInvalid
	}
	sig, e := canonicalSignature(raw)
	if e != nil {
		return "", ErrInvalid
	}
	digest, e := Digest(envelope)
	if e != nil {
		return "", ErrInvalid
	}
	if !sig.Verify(digest[:], pk) {
		return "", ErrInvalid
	}
	return key, nil
}

var bip340FieldPrime = [32]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f}
var bip340GroupOrder = [32]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41}

// TODO: use the shared strict helper once it lands on main.
// canonicalSignature checks BIP-340 wire bounds before btcec can normalize s; verification stays in the library.
func canonicalSignature(raw []byte) (*schnorr.Signature, error) {
	if len(raw) != 64 {
		return nil, ErrInvalid
	}
	if bytes.Compare(raw[:32], bip340FieldPrime[:]) >= 0 {
		return nil, ErrInvalid
	}
	if bytes.Compare(raw[32:], bip340GroupOrder[:]) >= 0 {
		return nil, ErrInvalid
	}
	sig, err := schnorr.ParseSignature(raw)
	if err != nil {
		return nil, ErrInvalid
	}
	return sig, nil
}

// CoSign adds no bytes to the already signed envelope. Optional auxiliary nonce
// data is fixture tooling for independent valid signatures on identical bytes.
func CoSign(k *btcec.PrivateKey, raw []byte, options ...schnorr.SignOption) (map[string]any, error) {
	digest, err := Digest(raw)
	if err != nil || k == nil {
		return nil, ErrInvalid
	}
	sig, err := schnorr.Sign(k, digest[:], options...)
	if err != nil {
		return nil, ErrInvalid
	}
	return map[string]any{"version": CosignatureVersion, "key": "bip340:" + Key(k), "sig": hex.EncodeToString(sig.Serialize())}, nil
}
