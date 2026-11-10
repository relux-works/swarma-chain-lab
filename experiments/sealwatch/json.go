package sealwatch

import "encoding/json"

// DecodeJSON exposes the bounded recursive duplicate/fold and unescaped-key
// guard. Ambiguous keys are refused before the destination can be populated.
// Object destinations must still implement an exact field projection.
func DecodeJSON(raw []byte, out any) error {
	if err := ValidateJSON(raw); err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

// ValidateJSON checks lexical key uniqueness/spelling without populating a
// destination. Typed consumers can validate their schema before decoding state.
func ValidateJSON(raw []byte) error {
	if len(raw) == 0 || len(raw) > 8<<20 {
		return failure("JSON_SIZE")
	}
	return uniqueJSON(raw)
}

// ProjectJSON validates the complete JSON object before projecting official
// names. Unknown non-alias extensions retain the existing W7 semantics.
func ProjectJSON(raw []byte, required, optional map[string]any) error {
	var fields map[string]json.RawMessage
	if err := DecodeJSON(raw, &fields); err != nil {
		return err
	}
	return exactProjection(raw, required, optional)
}
