package deploy

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func modelPublic() map[string]any {
	return map[string]any{"station": map[string]any{"driver": "manager"}, "relay_auth": "required", "model_proxy": map[string]any{"admin_socket": "/run/swarma-model-proxy/admin.sock", "server_uid": 1001, "origin": "https://proxy.example", "cert_sha256": strings.Repeat("0123456789abcdef", 4), "caps": map[string]any{"input_tokens": 1000, "output_tokens": 100, "requests": 10, "max_tokens": 10, "cost_nano_usd": 10000}}}
}

// The deploy preflight accepts explicit complete values, preserving integers
// above float64 precision. Omission leaves v1; partial/null/placeholder authority
// and non-manager wiring fail before any installer action.
func TestGatewayOptions(t *testing.T) {
	check := func(v any) error { raw, _ := json.Marshal(v); return ValidatePublicJSON(raw) }
	if e := check(modelPublic()); e != nil {
		t.Fatal("valid model section", e)
	}
	v := modelPublic()
	delete(v, "model_proxy")
	if e := check(v); e != nil {
		t.Fatal("v1 absent", e)
	}
	for _, name := range []string{"admin_socket", "server_uid", "origin", "cert_sha256", "caps"} {
		v := modelPublic()
		delete(v["model_proxy"].(map[string]any), name)
		if e := check(v); !errors.Is(e, ErrPolicy) {
			t.Fatal("partial model section accepted", name, e)
		}
	}
	for _, name := range []string{"input_tokens", "output_tokens", "requests", "max_tokens", "cost_nano_usd"} {
		v := modelPublic()
		delete(v["model_proxy"].(map[string]any)["caps"].(map[string]any), name)
		if e := check(v); !errors.Is(e, ErrPolicy) {
			t.Fatal("partial caps accepted", name, e)
		}
	}
	for _, change := range []func(map[string]any){
		func(v map[string]any) { v["model_proxy"] = nil },
		func(v map[string]any) { v["relay_auth"] = "optional" },
		func(v map[string]any) { v["station"] = map[string]any{"driver": "local-test"} },
		func(v map[string]any) { v["model_proxy"].(map[string]any)["origin"] = "https://proxy.example/path" },
		func(v map[string]any) { v["model_proxy"].(map[string]any)["server_uid"] = -1 },
		func(v map[string]any) { v["model_proxy"].(map[string]any)["cert_sha256"] = strings.Repeat("aa", 32) },
		func(v map[string]any) { v["model_proxy"].(map[string]any)["caps"].(map[string]any)["max_tokens"] = 101 },
	} {
		v := modelPublic()
		change(v)
		if e := check(v); !errors.Is(e, ErrPolicy) {
			t.Fatal("invalid optional authority accepted", e)
		}
	}
	v = modelPublic()
	v["model_proxy"].(map[string]any)["caps"].(map[string]any)["cost_nano_usd"] = json.Number("18446744073709551615")
	if e := check(v); e != nil {
		t.Fatal("uint64 precision lost", e)
	}
	v["model_proxy"].(map[string]any)["caps"].(map[string]any)["cost_nano_usd"] = "PLACEHOLDER_COST"
	if e := check(v); e != ErrPlaceholder {
		t.Fatal("cap placeholder accepted", e)
	}
}
