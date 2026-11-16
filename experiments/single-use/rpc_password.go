package singleuse

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

const rpcPasswordRedaction = "[private RPC password]"

// RPCPassword retains a config password behind a scalar pointer. The pointer
// also protects method-bypassing formatting of containing values.
type RPCPassword struct{ value *string }

func NewRPCPassword(value string) RPCPassword {
	if value == "" {
		return RPCPassword{}
	}
	return RPCPassword{value: &value}
}
func (RPCPassword) String() string             { return rpcPasswordRedaction }
func (RPCPassword) GoString() string           { return rpcPasswordRedaction }
func (RPCPassword) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, rpcPasswordRedaction) }
func (p RPCPassword) MarshalJSON() ([]byte, error) {
	if p.value == nil {
		return json.Marshal("")
	}
	return json.Marshal(rpcPasswordRedaction)
}
func (RPCPassword) MarshalText() ([]byte, error) { return []byte(rpcPasswordRedaction), nil }
func (p *RPCPassword) UnmarshalJSON(raw []byte) error {
	*p = RPCPassword{}
	var value string
	if json.Unmarshal(raw, &value) != nil {
		return errors.New("RPC_PASSWORD_ENCODING")
	}
	*p = NewRPCPassword(value)
	return nil
}

// Valid reports only the route's existing password-length admission predicate.
func (p RPCPassword) Valid() bool {
	return p.ValidLength(16, 256)
}

// SetBasicAuth centralizes the sole legitimate reveal, including route users
// that provide their own RPC transport. It never returns or retains plain text.
func (p RPCPassword) SetBasicAuth(r *http.Request, username string) {
	r.SetBasicAuth(username, p.RevealForBasicAuth())
}

// RevealForBasicAuth is used only at the Basic Auth header construction above.
func (p RPCPassword) RevealForBasicAuth() string {
	if p.value == nil {
		return ""
	}
	return *p.value
}

// ValidLength preserves stricter principal-specific bounds without revealing bytes.
func (p RPCPassword) ValidLength(min, max int) bool {
	return p.value != nil && len(*p.value) >= min && len(*p.value) <= max
}

// JSONInputString declares this holder's unchanged scalar config schema to the
// strict input walker. It grants no object-field or lexical-validation bypass.
func (RPCPassword) JSONInputString() {}
