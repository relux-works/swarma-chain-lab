// Package identity implements the checks of the LIP-0021 draft (name
// ownership and history profile for Grant v4 on Namecoin), sections 2 to 5,
// as decisions on stated octets and heights: the owner pin, the reading of a
// name output script against a pin, the writer check of an operation and the
// height comparison for a live name.
//
// LIP-0021 is a Draft whose rules are proposals; nothing here raises its
// status. No function reads a node: every octet and height is stated by the
// caller, and the node reads of section 1 are not part of this module.
package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"

	"golang.org/x/crypto/ripemd160"
)

// PinPart names the part of O2.1 that a value fails.
type PinPart string

const (
	// PinForm: the value is not 66 lowercase hexadecimal characters that
	// start with 02 or 03.
	PinForm PinPart = "form"
	// PinPoint: the form holds, but the 64 characters after the first two
	// are no x coordinate of a point of secp256k1.
	PinPoint PinPart = "point"
)

// PinError reports which part of O2.1 a value fails. The LIP names no code
// for it (the code comes with the members of the object that carries a pin).
type PinError struct{ Part PinPart }

func (e *PinError) Error() string { return "identity: no owner pin (" + string(e.Part) + ")" }

// Pin is an owner pin of O2.1: a compressed secp256k1 public key. The zero
// value is no pin; obtain one only through ParsePin.
type Pin struct {
	key [33]byte
	ok  bool
}

// secp256k1 field prime p = 2^256 - 2^32 - 977.
var fieldPrime, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16)

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// onCurveX reports whether x (32 octets, big-endian) is the x coordinate of
// a point of y^2 = x^3 + 7 over the field: x < p and x^3 + 7 is a square.
func onCurveX(x []byte) bool {
	n := new(big.Int).SetBytes(x)
	if n.Cmp(fieldPrime) >= 0 {
		return false
	}
	rhs := new(big.Int).Exp(n, big.NewInt(3), fieldPrime)
	rhs.Add(rhs, big.NewInt(7))
	rhs.Mod(rhs, fieldPrime)
	if rhs.Sign() == 0 {
		return true
	}
	// Euler's criterion: rhs^((p-1)/2) == 1 for a non-zero square.
	e := new(big.Int).Rsh(new(big.Int).Sub(fieldPrime, big.NewInt(1)), 1)
	return new(big.Int).Exp(rhs, e, fieldPrime).Cmp(big.NewInt(1)) == 0
}

// ParsePin applies O2.1 and O2.2 to a string. The form is checked before the
// point, as the LIP states them apart.
func ParsePin(s string) (Pin, error) {
	if len(s) != 66 || !isLowerHex(s) || !(s[:2] == "02" || s[:2] == "03") {
		return Pin{}, &PinError{Part: PinForm}
	}
	var p Pin
	if _, err := hex.Decode(p.key[:], []byte(s)); err != nil {
		return Pin{}, &PinError{Part: PinForm}
	}
	if !onCurveX(p.key[1:]) {
		return Pin{}, &PinError{Part: PinPoint}
	}
	p.ok = true
	return p, nil
}

// Valid reports whether p came from ParsePin.
func (p Pin) Valid() bool { return p.ok }

// Bytes returns a copy of the 33 octets of the compressed key.
func (p Pin) Bytes() []byte {
	b := p.key
	return b[:]
}

// String returns the 66 lowercase hexadecimal characters of the pin.
func (p Pin) String() string { return hex.EncodeToString(p.key[:]) }

// Hash160 returns RIPEMD-160(SHA-256(the 33 octets of the pin)), the 20
// octets that both supported address scripts of O3.3 hold.
func (p Pin) Hash160() [20]byte {
	s := sha256.Sum256(p.key[:])
	r := ripemd160.New()
	r.Write(s[:])
	var out [20]byte
	copy(out[:], r.Sum(nil))
	return out
}

// ErrSigningKeyForm reports a signing key that is not 64 lowercase
// hexadecimal characters (the form of LIP-0020 W3.6).
var ErrSigningKeyForm = errors.New("identity: signing key is not 64 lowercase hexadecimal characters")

// ErrSigningKeyPoint reports a signing key whose 64 characters are no x
// coordinate of a point of the curve (LIP-0020 W3.6).
var ErrSigningKeyPoint = errors.New("identity: signing key is no x coordinate of the curve")

// ErrNoPin reports a zero Pin handed to a check.
var ErrNoPin = errors.New("identity: no owner pin")

// SameKeyAsSigning applies O2.3: an owner pin and a LIP-0020 signing key are
// the same key when the 64 characters after the first two of the pin equal
// the signing key. A signing key that fails W3.6 is refused, never compared.
func SameKeyAsSigning(p Pin, signingKey string) (bool, error) {
	if !p.ok {
		return false, ErrNoPin
	}
	if len(signingKey) != 64 || !isLowerHex(signingKey) {
		return false, ErrSigningKeyForm
	}
	x, _ := hex.DecodeString(signingKey)
	if !onCurveX(x) {
		return false, ErrSigningKeyPoint
	}
	return p.String()[2:] == signingKey, nil
}
