package notarycheck

import (
	"fmt"
	"io"
)

const credentialRedacted = "[REDACTED]"

// rpcPassword retains the node credential with redacting value methods. It
// protects diagnostic output, not memory access by a compromised process.
type rpcPassword struct{ value string }

func (rpcPassword) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, credentialRedacted) }
func (rpcPassword) MarshalJSON() ([]byte, error) { return []byte(`"[REDACTED]"`), nil }
func (rpcPassword) MarshalText() ([]byte, error) { return []byte(credentialRedacted), nil }

// Reveal is used only while constructing the node's HTTP Basic Auth header.
func (p rpcPassword) Reveal() string { return p.value }

// fmt does not invoke a field's formatter when reflecting unexported fields.
// Redact the enclosing reader too, including its value and pointer forms.
func (NodeNameReader) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, credentialRedacted) }
func (NodeNameReader) MarshalJSON() ([]byte, error) { return []byte(`"[REDACTED]"`), nil }
func (NodeNameReader) MarshalText() ([]byte, error) { return []byte(credentialRedacted), nil }
