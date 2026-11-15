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

// The ceiling survives canonical public decoding without weakening unknown, duplicate or non-uint64 field rejection.
func TestDailyCostCeilingSchema(t *testing.T) {
	raw, e := json.Marshal(FileConfig{DailyCostCeilingNanoUSD: 230})
	if e != nil {
		t.Fatal(e)
	}
	c, e := DecodeFileConfig(raw)
	if e != nil || c.DailyCostCeilingNanoUSD != 230 {
		t.Fatal("daily ceiling omitted", e)
	}
	for _, field := range []string{`"daily_cost_ceiling_nano_usd":-1`, `"daily_cost_ceiling_nano_usd":18446744073709551616`, `"daily_cost_ceiling_nano_usd":"230"`, `"daily_cost_ceiling_nano_usd":230,"daily_cost_ceiling_nano_usd":231`, `"daily_cost_ceiling_nano_usd":230,"ceiling_override":231`} {
		bad := bytes.Replace(raw, []byte(`"daily_cost_ceiling_nano_usd":230`), []byte(field), 1)
		if _, e = DecodeFileConfig(bad); e != ErrFile {
			t.Fatal("invalid daily ceiling config accepted", e)
		}
	}
}
