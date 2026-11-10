package configguard

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"

	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

const SignatureDomain = "swarma-config-install-v1\x00"

type Signature struct {
	Version   int    `json:"v"`
	Algorithm string `json:"algorithm"`
	Value     string `json:"signature"`
}

// PKIX public key and algorithm are pinned independently of the signed input.
// Supported algorithms are explicit and extensible; unknown algorithms refuse.
func verifySignature(raw, encoded []byte, algorithm, key string) error {
	var sig Signature
	if su.StrictInput(encoded, &sig) != nil || sig.Version != 1 || sig.Algorithm != algorithm {
		return fail("DK5_SIGNATURE_SCHEMA")
	}
	pub, e := parsePublicKey(algorithm, key)
	if e != nil {
		return e
	}
	value, e := base64.StdEncoding.Strict().DecodeString(sig.Value)
	if e != nil || len(value) > 16384 || base64.StdEncoding.EncodeToString(value) != sig.Value {
		return fail("DK5_SIGNATURE_SCHEMA")
	}
	message := append([]byte(SignatureDomain), raw...)
	defer clear(message)
	switch algorithm {
	case "ed25519":
		p, ok := pub.(ed25519.PublicKey)
		if !ok {
			return fail("DK5_SIGNATURE_KEY")
		}
		if !ed25519.Verify(p, message, value) {
			return fail("DK5_SIGNATURE_INVALID")
		}
	case "rsa-pss-sha256":
		p, ok := pub.(*rsa.PublicKey)
		if !ok || p.N.BitLen() < 3072 || p.N.BitLen() > 8192 || p.E != 65537 {
			return fail("DK5_SIGNATURE_KEY")
		}
		h := sha256.Sum256(message)
		if rsa.VerifyPSS(p, crypto.SHA256, h[:], value, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}) != nil {
			return fail("DK5_SIGNATURE_INVALID")
		}
	default:
		return fail("DK5_SIGNATURE_ALGORITHM")
	}
	return nil
}

// Key validation is shared by the renderer and verifier; the caller pins the
// algorithm independently from the signature. Private-key DER is never accepted.
func parsePublicKey(algorithm, key string) (crypto.PublicKey, error) {
	if algorithm != "ed25519" && algorithm != "rsa-pss-sha256" {
		return nil, fail("DK5_SIGNATURE_ALGORITHM")
	}
	der, e := base64.StdEncoding.Strict().DecodeString(key)
	if e != nil || len(der) > 16384 || base64.StdEncoding.EncodeToString(der) != key {
		return nil, fail("DK5_SIGNATURE_KEY")
	}
	pub, e := x509.ParsePKIXPublicKey(der)
	if e != nil {
		return nil, fail("DK5_SIGNATURE_KEY")
	}
	switch algorithm {
	case "ed25519":
		if p, ok := pub.(ed25519.PublicKey); !ok || len(p) != ed25519.PublicKeySize {
			return nil, fail("DK5_SIGNATURE_KEY")
		}
	case "rsa-pss-sha256":
		if p, ok := pub.(*rsa.PublicKey); !ok || p.N.BitLen() < 3072 || p.N.BitLen() > 8192 || p.E != 65537 {
			return nil, fail("DK5_SIGNATURE_KEY")
		}
	}
	return pub, nil
}
