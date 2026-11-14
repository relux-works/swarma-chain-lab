// Package bip340 checks the canonical BIP-340 signature encoding before parsing.
package bip340

import (
	"bytes"
	"errors"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// Secp256k1's field prime and group order, encoded as unsigned big-endian uint256.
var fieldPrime = [32]byte{
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f,
}
var groupOrder = [32]byte{
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
	0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
	0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
}

// ParseBIP340Strict enforces BIP-340 Verify's length, r < p and s < n rules
// before the upstream parser can reduce a scalar. High s below n is valid;
// BIP-340 has no ECDSA low-S rule. Signature validity still requires Verify.
func ParseBIP340Strict(sig []byte) (*schnorr.Signature, error) {
	if len(sig) != 64 {
		return nil, errors.New("BIP340: signature must be 64 bytes")
	}
	if bytes.Compare(sig[:32], fieldPrime[:]) >= 0 {
		return nil, errors.New("BIP340: r >= p")
	}
	if bytes.Compare(sig[32:], groupOrder[:]) >= 0 {
		return nil, errors.New("BIP340: s >= n")
	}
	return schnorr.ParseSignature(sig)
}
