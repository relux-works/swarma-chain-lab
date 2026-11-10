package deploy

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// Every shipped JSON template containing a grant-v3 kernel/issuer policy pins
// W. Walking the complete tree includes newly added template families. This is
// a config contract check, not resolved deployment or key-custody qualification.
func TestShippedWitnessPins(t *testing.T) {
	count := 0
	var visit func(*testing.T, any)
	visit = func(t *testing.T, v any) {
		switch x := v.(type) {
		case []any:
			for _, child := range x {
				visit(t, child)
			}
		case map[string]any:
			if _, ok := x["seal_script"]; ok {
				if _, policy := x["landlord_name"]; policy {
					count++
					if x["construction_profile"] != "W" {
						t.Fatal("shipped W policy missing pin", x["construction_profile"])
					}
				}
			}
			for _, child := range x {
				visit(t, child)
			}
		}
	}
	err := filepath.WalkDir("templates", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			return err
		}
		t.Run(path, func(t *testing.T) { visit(t, v) })
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if count < 4 {
		t.Fatal("template inventory incomplete", count)
	}
}

// Resolve the actual shipped M5 issuer bytes and validate them; changing only
// the construction pin refuses. This catches a template/validator divergence.
func TestResolvedM5IssuerWitnessPin(t *testing.T) {
	raw := resolvedMain(t, "issuer")
	if e := validateIssuer(raw); e != nil {
		t.Fatal("resolved issuer template", e)
	}
	if e := ValidateServiceInputs(mainPolicy("issuer"), [][]byte{raw}); e != nil {
		t.Fatal("resolved issuer inputs", e)
	}
	var v map[string]any
	if e := json.Unmarshal(raw, &v); e != nil {
		t.Fatal(e)
	}
	policy := v["config"].(map[string]any)["policy"].(map[string]any)["policy"].(map[string]any)
	for _, pin := range []string{"", "L", "future"} {
		policy["construction_profile"] = pin
		if e := validateIssuer(encoded(t, v)); e != ErrPolicy {
			t.Fatal("issuer pin refusal", e)
		}
	}
}

// Main gateway public admission refuses an omitted/unsupported construction
// pin next to the exact resolved W template; no resolved bytes are emitted.
func TestMainGatewayWitnessPin(t *testing.T) {
	raw := resolvedMain(t, "gateway")
	if e := ValidateServiceInputs(mainPolicy("gateway"), [][]byte{raw}); e != nil {
		t.Fatal("main W gateway neighbor", e)
	}
	var v map[string]any
	if e := json.Unmarshal(raw, &v); e != nil {
		t.Fatal(e)
	}
	kernel := v["kernel"].(map[string]any)
	for _, pin := range []string{"", "L", "future"} {
		kernel["construction_profile"] = pin
		if e := ValidateServiceInputs(mainPolicy("gateway"), [][]byte{encoded(t, v)}); e != ErrNetwork {
			t.Fatal("main gateway W refusal", e)
		}
	}
}
