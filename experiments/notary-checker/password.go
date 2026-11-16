package notarycheck

import (
	"fmt"
	"io"
)

const credentialRedacted = "[REDACTED]"

// rpcPassword retains the node credential with redacting value methods. It
// protects diagnostic output, not memory access by a compromised process.
// Keep the credential behind a scalar pointer, as in payloadbootstrap/codec.Secret.
// fmt's bad-verb diagnostics bypass Format and inspect unexported fields. A
// *string still prints only its address, even when fmt restarts at depth zero;
// pointers to a struct, slice, map or array do not provide that guarantee.
type rpcPassword struct{ value *string }

func newRPCPassword(b []byte) rpcPassword {
	value := string(b)
	return rpcPassword{value: &value}
}

func (rpcPassword) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, credentialRedacted) }
func (rpcPassword) MarshalJSON() ([]byte, error) { return []byte(`"[REDACTED]"`), nil }
func (rpcPassword) MarshalText() ([]byte, error) { return []byte(credentialRedacted), nil }

// Reveal is used only while constructing the node's HTTP Basic Auth header.
func (p rpcPassword) Reveal() string {
	if p.value == nil {
		return ""
	}
	return *p.value
}

// fmt does not invoke a field's formatter when reflecting unexported fields.
// Redact the enclosing reader too, including its value and pointer forms.
func (NodeNameReader) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, credentialRedacted) }
func (NodeNameReader) MarshalText() ([]byte, error) { return []byte(credentialRedacted), nil }
