package wire

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// Type is a whole registry string, never a separately negotiated version.
type Type string

const (
	Grant             Type = "swarma-grant/4"
	Invocation        Type = "swarma-invocation/1"
	Receipt           Type = "swarma-receipt/1"
	SealEndorsement   Type = "swarma-seal-endorsement/1"
	ContractAssent    Type = "swarma-contract-assent/1"
	Issuance          Type = "swarma-issuance/1"
	NotaryAttestation Type = "swarma-notary-attestation/2"
)

func registered(t Type) bool {
	switch t {
	case Grant, Invocation, Receipt, SealEndorsement, ContractAssent, Issuance, NotaryAttestation:
		return true
	}
	return false
}

// TaggedHash is arithmetic on supplied octets, not object admission.
func TaggedHash(tag string, octets []byte) [32]byte {
	t := sha256.Sum256([]byte(tag))
	h := sha256.New()
	h.Write(t[:])
	h.Write(t[:])
	h.Write(octets)
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

// TypedDigest derives the tag solely from the payload. It checks canonical
// bytes and registry membership, but not a schema: five registry entries have
// no schema yet. A digest alone therefore never constitutes an admitted object.
func TypedDigest(payload []byte) ([32]byte, error) {
	d, err := ParseDocument(payload, 1<<20)
	if err != nil {
		return [32]byte{}, err
	}
	t := Type(d.root.get("type").stringValue())
	if !registered(t) {
		return [32]byte{}, WireType
	}
	return TaggedHash(string(t), payload), nil
}

func hexForm(s string, n int) bool {
	if len(s) != 2*n {
		return false
	}
	for i := range len(s) {
		if !(s[i] >= '0' && s[i] <= '9' || s[i] >= 'a' && s[i] <= 'f') {
			return false
		}
	}
	return true
}
func hashHex(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// PayloadID computes W6.1 on canonical payload octets, without schema admission.
func PayloadID(payload []byte) (string, error) {
	if _, err := ParseDocument(payload, 1<<20); err != nil {
		return "", err
	}
	return hashHex(payload), nil
}

// Signature can only be constructed after the strict wire/range preflight.
// Its bytes are not exported; Bytes returns a copy.
type Signature struct{ raw [64]byte }

func (s *Signature) Bytes() []byte { return bytes.Clone(s.raw[:]) }

var fieldPrime = [32]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f}
var groupOrder = [32]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41}

// ParseSignature checks len=64, r<p and s<n BEFORE invoking a library parser.
// BIP-340 has no ECDSA low-s constraint.
func ParseSignature(raw []byte) (*Signature, error) {
	if len(raw) != 64 {
		return nil, WireSignatureForm
	}
	if bytes.Compare(raw[:32], fieldPrime[:]) >= 0 {
		return nil, WireSignature
	}
	if bytes.Compare(raw[32:], groupOrder[:]) >= 0 {
		return nil, WireSignature
	}
	s := &Signature{}
	copy(s.raw[:], raw)
	return s, nil
}
func decodeSignature(s string) (*Signature, error) {
	if !hexForm(s, 64) {
		return nil, WireSignatureForm
	}
	raw, _ := hex.DecodeString(s)
	return ParseSignature(raw)
}
func CheckSigningKey(key string) error {
	if !hexForm(key, 32) {
		return WireMember
	}
	b, _ := hex.DecodeString(key)
	if _, err := schnorr.ParsePubKey(b); err != nil {
		return WireKey
	}
	return nil
}

// VerifyBIP340 performs strict BIP-340 verification, including even-Y and
// infinity checks, under the given x-only key and 32-byte message.
func VerifyBIP340(key string, digest [32]byte, raw []byte) error {
	s, err := ParseSignature(raw)
	if err != nil {
		return err
	}
	if err := CheckSigningKey(key); err != nil {
		return err
	}
	pkBytes, _ := hex.DecodeString(key)
	pk, err := schnorr.ParsePubKey(pkBytes)
	if err != nil {
		return WireKey
	}
	parsed, err := schnorr.ParseSignature(s.raw[:])
	if err != nil || !parsed.Verify(digest[:], pk) {
		return WireSignature
	}
	return nil
}
