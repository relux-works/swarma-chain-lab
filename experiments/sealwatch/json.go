package sealwatch

import "encoding/json"

// DecodeJSON exposes the W7 bounded duplicate/fold guard for sibling observers.
// Object destinations must still implement an exact field projection.
func DecodeJSON(raw []byte, out any) error {
	if len(raw) == 0 || len(raw) > 8<<20 {
		return failure("JSON_SIZE")
	}
	if err := uniqueJSON(raw); err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
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
