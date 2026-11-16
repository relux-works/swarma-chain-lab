package service

import "github.com/btcsuite/btcd/btcec/v2"

// signingKey keeps fmt's method-bypassing diagnostics away from the scalar.
// A *PrivateKey is unsafe: badVerb restarts at depth zero and dereferences
// pointers to aggregates. A **PrivateKey points to a pointer, so even that
// restart prints only an address. Keep the single field unexported, like the
// scalar-pointer storage in payloadbootstrap/codec.Secret and rpcPassword.
// This is a diagnostic boundary, not protection against memory access.
type signingKey struct{ value **btcec.PrivateKey }

func newSigningKey(key *btcec.PrivateKey) *signingKey {
	return &signingKey{value: &key}
}

func (k *signingKey) privateKey() *btcec.PrivateKey {
	if k == nil || k.value == nil {
		return nil
	}
	return *k.value
}

func (k *signingKey) Zero() {
	if key := k.privateKey(); key != nil {
		key.Zero()
	}
}
