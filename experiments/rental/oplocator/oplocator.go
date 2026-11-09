// Package oplocator implements the strict two-direct-push OP_RETURN framing in
// swarma-link-spec v0.1.3 LIP-0005. It does not fetch or authorize the referenced
// object; callers must verify commitments and location-specific pointer hashes.
package oplocator

import (
	"bytes"
	"errors"
)

const (
	Version1                byte = 1
	ActionGrantIssuance     byte = 1
	ActionAnchorBatch       byte = 2
	LocationNone            byte = 0
	LocationBlob            byte = 1
	LocationTorrentV2       byte = 2
	LocationTorrentV1       byte = 3
	LocationSwarmaTorrentV2 byte = 4
	IssuanceBlobScriptBytes      = 72
)

var ErrMalformed = errors.New("malformed Link OP_RETURN")
var ErrNotLink = errors.New("not a Link OP_RETURN")

type Locator struct {
	Type    byte
	Pointer []byte
}
type Message struct {
	Legacy     bool
	Action     byte
	Version    byte
	Commitment [32]byte
	Locator    Locator
}

func pointerLength(kind byte) (int, bool) {
	switch kind {
	case LocationNone:
		return 0, true
	case LocationBlob, LocationTorrentV2, LocationSwarmaTorrentV2:
		return 32, true
	case LocationTorrentV1:
		return 20, true
	}
	return 0, false
}
func actionKnown(action byte) bool {
	return action == ActionGrantIssuance || action == ActionAnchorBatch
}

// Build emits only the current framed version. There is deliberately no new
// bare-form writer. Defined locations fit the 83-byte writer policy by construction.
func Build(action byte, commitment [32]byte, loc Locator) ([]byte, error) {
	n, known := pointerLength(loc.Type)
	if !actionKnown(action) || !known || len(loc.Pointer) != n {
		return nil, ErrMalformed
	}
	script := []byte{0x6a, 3, 0x53, 0x4c, action, byte(34 + n), Version1}
	script = append(script, commitment[:]...)
	script = append(script, loc.Type)
	script = append(script, loc.Pointer...)
	return script, nil
}

// Parse accepts exact bare 34-byte legacy commitments or the two direct pushes.
// Legacy is an explicit result flag, never a fallback for a malformed frame.
// Memo's direct-pushed 0x6d protocol prefix is non-Link. No relay-policy size cap
// is imposed on readers; the defined v1 fields determine their exact lengths.
func Parse(script []byte) (Message, error) {
	var m Message
	if len(script) == 0 || script[0] != 0x6a {
		return m, ErrNotLink
	}
	if len(script) == 34 && script[1] == 32 {
		m.Legacy = true
		copy(m.Commitment[:], script[2:])
		return m, nil
	}
	if len(script) >= 4 && script[1] >= 2 && script[1] <= 75 && script[2] == 0x6d {
		return m, ErrNotLink
	}
	if len(script) < 6 || !bytes.Equal(script[:4], []byte{0x6a, 3, 0x53, 0x4c}) || !actionKnown(script[4]) {
		return m, ErrMalformed
	}
	n := int(script[5])
	if n < 34 || n > 75 || len(script) != 6+n {
		return m, ErrMalformed
	}
	payload := script[6:]
	if payload[0] != Version1 {
		return m, ErrMalformed
	}
	length, known := pointerLength(payload[33])
	if !known || len(payload) != 34+length {
		return m, ErrMalformed
	}
	m.Action = script[4]
	m.Version = payload[0]
	copy(m.Commitment[:], payload[1:33])
	m.Locator = Locator{Type: payload[33], Pointer: bytes.Clone(payload[34:])}
	return m, nil
}
