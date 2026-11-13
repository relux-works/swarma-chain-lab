package executor

import (
	"encoding"
	"encoding/hex"
	"encoding/json"
	"testing"
)

// Typed map keys invoke MarshalText; direct encoder interfaces and typed
// pointers must retain the same redaction as values and containing carriers.
func TestN1bExecutorKeyedOutput(t *testing.T) {
	raw := "3fc728de1a49b506d8e3a27195f0c64bd1946e82a57d3b609f8c2041e5ab763d"
	holder := NewTrackBToken(raw)
	text, e := any(holder).(encoding.TextMarshaler).MarshalText()
	if e != nil || n1bLeaks(string(text), raw) {
		t.Fatal("credential disclosed by text encoding")
	}
	encoded, e := any(holder).(json.Marshaler).MarshalJSON()
	if e != nil || n1bLeaks(string(encoded), raw) {
		t.Fatal("credential disclosed by generic JSON encoding")
	}
	n1bOutputMatrix(t, []any{&holder, map[TrackBToken]string{holder: "public"}}, raw)
}

// Encoded fragment detection preserves the eight-original-byte limit. A public
// four-byte coincidence is not evidence that credential bytes were disclosed.
func TestN1bDetectorEncodedBounds(t *testing.T) {
	secret := "c39e72b51a8f04d6e957bc13a24680fdb64c2e081fd739a56b1025ed7c8a943f"
	if !n1bLeaks(secret[:8], secret) || !n1bLeaks(hex.EncodeToString([]byte(secret[:8])), secret) || n1bLeaks(hex.EncodeToString([]byte(secret[:4])), secret) {
		t.Fatal("encoded leak detector bound changed")
	}
}
