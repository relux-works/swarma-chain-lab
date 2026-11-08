package sealwatch

import "testing"

// The exported path preserves W7 alias/duplicate refusal with a valid neighbor.
func TestPublicProjection(t *testing.T) {
	for _, raw := range []string{`{"height":1}`, `{"HEIGHT":1}`, `{"height":1,"HEIGHT":1}`, `{"height":1,"height":1}`, `{"height":null}`} {
		var height int
		err := ProjectJSON([]byte(raw), map[string]any{"height": &height}, nil)
		if raw == `{"height":1}` {
			if err != nil || height != 1 {
				t.Fatal(height, err)
			}
		} else if err == nil {
			t.Fatalf("ambiguous projection admitted: %s", raw)
		}
	}
}
