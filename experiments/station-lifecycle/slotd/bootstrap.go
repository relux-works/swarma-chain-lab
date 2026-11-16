package slotd

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const bootstrapRedaction = "[private socket bootstrap]"

// Bootstrap holds the base64 request credential behind a scalar pointer, so
// containing-value bad-verb formatting cannot traverse its bytes either.
type Bootstrap struct{ value *string }

func NewBootstrap(value string) Bootstrap      { return Bootstrap{value: &value} }
func (Bootstrap) String() string               { return bootstrapRedaction }
func (Bootstrap) GoString() string             { return bootstrapRedaction }
func (Bootstrap) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, bootstrapRedaction) }
func (Bootstrap) MarshalJSON() ([]byte, error) { return json.Marshal(bootstrapRedaction) }
func (Bootstrap) MarshalText() ([]byte, error) { return []byte(bootstrapRedaction), nil }
func (b *Bootstrap) UnmarshalJSON(raw []byte) error {
	*b = Bootstrap{}
	var value string
	if json.Unmarshal(raw, &value) != nil {
		return errors.New("SLOTD_BOOTSTRAP_ENCODING")
	}
	*b = NewBootstrap(value)
	return nil
}
func (b Bootstrap) valid() bool {
	if b.value == nil {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(*b.value)
	return err == nil && len(raw) <= 4096 && base64.StdEncoding.EncodeToString(raw) == *b.value
}

// RevealForRequest is used only by the private Unix request encoder.
func (b Bootstrap) RevealForRequest() string {
	if b.value == nil {
		return ""
	}
	return *b.value
}
