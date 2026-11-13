package codec

import "encoding/json"

// Secret keeps credential bytes behind an unexported scalar pointer. Even fmt's
// method-bypassing bad-verb diagnostics can see only that pointer's address
// when walking a containing value. Generic JSON/text encoding always redacts;
// private wire encoders must explicitly reveal into their private DTOs.
type Secret[T ~[]byte | ~string] struct {
	// A pointer to a slice is insufficient: a bad-verb diagnostic may restart
	// formatting at depth zero and dereference a slice/struct/map/array pointer.
	// A string pointer always formats as an address, including at depth zero.
	value *string
}

// NewSecret takes a private copy, so later changes to an input slice cannot
// change a credential already held by a bootstrap.
func NewSecret[T ~[]byte | ~string](value T) Secret[T] {
	if len(value) == 0 {
		return Secret[T]{}
	}
	copy := string(value)
	return Secret[T]{value: &copy}
}

// Reveal returns the credential for an explicit consumer operation. A returned
// slice is a copy; neither it nor a copied Secret can mutate the stored bytes.
// Do not retain the result in a field of a value that may be formatted.
func (s Secret[T]) Reveal() T {
	if s.value == nil {
		var zero T
		return zero
	}
	return T(*s.value)
}

func (Secret[T]) String() string   { return "[private bootstrap credential]" }
func (Secret[T]) GoString() string { return "[private bootstrap credential]" }

// IsZero lets the optional v1 bearer retain its existing omitted wire field.
func (s Secret[T]) IsZero() bool { return s.value == nil }

func (s Secret[T]) MarshalJSON() ([]byte, error) {
	return json.Marshal("[private bootstrap credential]")
}

func (Secret[T]) MarshalText() ([]byte, error) {
	return []byte("[private bootstrap credential]"), nil
}

func (s *Secret[T]) UnmarshalJSON(raw []byte) error {
	*s = Secret[T]{}
	var value T
	if err := json.Unmarshal(raw, &value); err != nil {
		return err
	}
	*s = NewSecret(value)
	return nil
}
