// Package payloadjournal defines the immutable v1 binding and lock bytes for a
// provisioned station payload journal. It performs no filesystem operations;
// callers must establish custody and read through validated descriptors first.
package payloadjournal

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
)

const (
	Version      uint64 = 1
	BindingName         = "binding.json"
	LockName            = "delivery.lock"
	MaxFileBytes        = 256
)

// Code contains no paths, input bytes or lower-level diagnostics.
type Code string

func (c Code) Error() string { return string(c) }

const (
	ErrMissing     Code = "PAYLOAD_JOURNAL_MISSING"
	ErrUnsupported Code = "PAYLOAD_JOURNAL_UNSUPPORTED"
	ErrCorrupt     Code = "PAYLOAD_JOURNAL_CORRUPT"
	ErrBinding     Code = "PAYLOAD_JOURNAL_BINDING"
)

// File distinguishes an absent file from an existing zero-byte file. Present
// must come from a validated read, not a blanket conversion of any I/O error.
// Bytes are borrowed read-only; validation never repairs or clears them.
type File struct {
	Present bool
	Bytes   []byte
}

type record struct {
	Version         uint64 `json:"v"`
	Kind            string `json:"kind"`
	BootstrapSHA256 string `json:"bootstrap_sha256"`
}

func digestOK(s string) bool {
	if len(s) != 64 {
		return false
	}
	b, e := hex.DecodeString(s)
	return e == nil && hex.EncodeToString(b) == s
}

func encode(r record) []byte {
	// This fixed struct has only uint64/string fields, so Marshal cannot fail.
	raw, _ := json.Marshal(r)
	return append(raw, '\n')
}

// Encode returns fresh exact v1 bytes for slotd to write once during Create.
// The digest must be SHA256(exact canonical bootstrap bytes), lowercase hex.
// This codec does not validate the bootstrap schema or authorize provisioning.
// An invalid digest returns ErrCorrupt and no partial output.
func Encode(bootstrapSHA256 string) (binding, lock []byte, err error) {
	if !digestOK(bootstrapSHA256) {
		return nil, nil, ErrCorrupt
	}
	return encode(record{Version, "binding", bootstrapSHA256}),
		encode(record{Version, "lock", bootstrapSHA256}), nil
}

func check(raw []byte, kind, expected string) error {
	if len(raw) == 0 || len(raw) > MaxFileBytes {
		return ErrCorrupt
	}
	var r record
	if json.Unmarshal(raw, &r) != nil || !bytes.Equal(raw, encode(r)) ||
		r.Version == 0 || r.Kind != kind || !digestOK(r.BootstrapSHA256) {
		return ErrCorrupt
	}
	if r.Version != Version {
		return ErrUnsupported
	}
	if r.BootstrapSHA256 != expected {
		return ErrBinding
	}
	return nil
}

// Validate requires both files and checks binding before lock. Expected is an
// independently established canonical-bootstrap digest, never learned from the
// files being checked. It rejects noncanonical encodings, other versions and
// other bindings without changing either input or initializing missing state.
// See FORMAT.md for error precedence and the separate filesystem obligations.
func Validate(binding, lock File, expected string) error {
	if !digestOK(expected) {
		return ErrCorrupt
	}
	// An absence claim carrying bytes is an inconsistent caller input.
	if (!binding.Present && len(binding.Bytes) != 0) || (!lock.Present && len(lock.Bytes) != 0) {
		return ErrCorrupt
	}
	if !binding.Present || !lock.Present {
		return ErrMissing
	}
	if e := check(binding.Bytes, "binding", expected); e != nil {
		return e
	}
	return check(lock.Bytes, "lock", expected)
}
