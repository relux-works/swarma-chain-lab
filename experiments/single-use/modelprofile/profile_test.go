package modelprofile

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

// Shared literals preserve loader and selected-model boundaries independently:
// malformed canonical config uses CONFIG_FILE, mismatches use PAYLOAD_CONFIG.
func TestGolden(t *testing.T) {
	raw, e := os.ReadFile("testdata/golden.json")
	if e != nil {
		t.Fatal(e)
	}
	var cases []struct {
		Name, Raw, Error string
		Want             TypedProfile
	}
	if json.Unmarshal(raw, &cases) != nil {
		t.Fatal("fixture")
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			b := []byte(c.Raw)
			before := bytes.Clone(b)
			e := ValidatePublicModelConfig(b, c.Want)
			code := ""
			if e != nil {
				code = e.Error()
			}
			if code != c.Error {
				t.Fatalf("model verdict %q want %q", code, c.Error)
			}
			if !bytes.Equal(b, before) {
				t.Fatal("model input mutated")
			}
		})
	}
}
