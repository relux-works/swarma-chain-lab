package deploy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func mainPolicy(service string) Policy {
	p := validPolicy(service)
	if newService(service) {
		p = newPolicy(service)
	}
	p.Network = "main"
	p.Genesis = mainGenesis
	return p
}

// Synthetic public fixtures test structural admission, not curve/key custody,
// runtime routes or live mainnet. Every placeholder is resolved only in memory.
func resolvedMain(t *testing.T, service string) []byte {
	t.Helper()
	raw, e := os.ReadFile("templates/m5-test/" + service + "/service.json")
	if e != nil {
		t.Fatal(e)
	}
	var v any
	if e = json.Unmarshal(raw, &v); e != nil {
		t.Fatal(e)
	}
	pin := sha256.Sum256([]byte("synthetic public fixture"))
	hash := hex.EncodeToString(pin[:])
	replacements := map[string]any{
		"agent_pubkey": hash, "provider_pubkey": hash, "issuer_pubkey": hash,
		"agent_name": "id/fixture-agent", "landlord_name": "id/fixture-landlord", "station_name": "id/fixture-agent",
		"public_branch": "xpub-synthetic-structural-fixture", "profile_id": "fixture", "profile_version": "v1",
		"funding_script": "0014" + strings.Repeat("b", 40), "station_script": "76a914" + strings.Repeat("a", 40) + "88ac",
		"seal_script": "76a914" + strings.Repeat("a", 40) + "88ac", "rate_as_of": int64(100), "usd_micros_per_coin": int64(100000000),
		"not_before": int64(1000), "not_after": int64(4600), "server_uid": uint32(1001), "rpc_port": 18888,
		"listen": "192.0.2.10:9443", "payload_listen": "192.0.2.10:9444", "payload_id": "fixture-payload",
		"origin": "https://model.invalid:8443", "public_url": "wss://relay.invalid/",
	}
	var fill func(any, string) any
	fill = func(v any, key string) any {
		switch x := v.(type) {
		case map[string]any:
			for k, w := range x {
				x[k] = fill(w, k)
			}
			return x
		case []any:
			for i, w := range x {
				x[i] = fill(w, key)
			}
			return x
		case string:
			if strings.Contains(x, "PLACEHOLDER") {
				if r, ok := replacements[key]; ok {
					return r
				}
				return hash
			}
		}
		return v
	}
	v = fill(v, "")
	if service == "booking" {
		m := v.(map[string]any)["config"].(map[string]any)["coins"].(map[string]any)["nmc"].(map[string]any)
		h := sha256.Sum256([]byte(m["public_branch"].(string)))
		m["public_branch_sha256"] = hex.EncodeToString(h[:])
	}
	return encoded(t, v)
}
func mainInputs(t *testing.T, service string) [][]byte {
	switch service {
	case "issuer":
		c := issuerFixture()
		c.Config.Policy.Policy.Network = "main"
		c.Config.Policy.Policy.Genesis = mainGenesis
		c.Config.Policy.Policy.FeeRate = 200
		c.Config.Spending = &spendingCaps{MovedPerTx: 1000000, MovedDay: 10000000, EnrolledHot: 20000000}
		return [][]byte{encoded(t, c)}
	case "wallet":
		c := walletFixture()
		c.Network = "main"
		c.Genesis = mainGenesis
		return [][]byte{encoded(t, c)}
	case "model", "stations":
		return [][]byte{nativeFixture(t, service)}
	case "payload":
		c := modelFixture()
		return [][]byte{encoded(t, payloadPair{"messages", "fixture-model", 10, c.Endpoint.URL, c.Endpoint.CertSHA256}), encoded(t, c)}
	default:
		return [][]byte{resolvedMain(t, service)}
	}
}

// All nine services accept a complete explicit main profile; missing/ambiguous
// native files, unresolved templates and crossed network pins refuse beside it.
func TestMainServiceProfiles(t *testing.T) {
	for _, s := range []string{"issuer", "wallet", "model", "stations", "payload", "booking", "gateway", "store", "relay"} {
		t.Run(s, func(t *testing.T) {
			p := mainPolicy(s)
			if got, e := Validate(encoded(t, p)); e != nil || got != p {
				t.Fatal("descriptor neighbor", e)
			}
			inputs := mainInputs(t, s)
			if e := ValidateServiceInputs(p, inputs); e != nil {
				t.Fatal("native neighbor", e)
			}
			for _, bad := range [][][]byte{nil, {[]byte(`{}`)}, append(append([][]byte{}, inputs...), inputs[0])} {
				if e := ValidateServiceInputs(p, bad); e == nil {
					t.Fatal("incomplete native accepted")
				}
			}
			for _, pins := range [][2]string{{"main", ""}, {"main", regtestGenesis}, {"regtest", mainGenesis}, {"", mainGenesis}} {
				bad := p
				bad.Network = pins[0]
				bad.Genesis = pins[1]
				if _, e := Validate(encoded(t, bad)); e != ErrNetwork {
					t.Fatal("crossed descriptor", e)
				}
			}
			raw, e := os.ReadFile("templates/m5-test/" + s + "/deploy.json")
			if e != nil {
				t.Fatal(e)
			}
			if _, e = Validate(raw); e != ErrPlaceholder {
				t.Fatal("unresolved descriptor", e)
			}
			if s != "payload" {
				raw, e = os.ReadFile("templates/m5-test/" + s + "/service.json")
				if e != nil {
					t.Fatal(e)
				}
				if e = ValidateServiceInputs(p, [][]byte{raw}); e != ErrPlaceholder {
					t.Fatal("unresolved native", e)
				}
			}
		})
	}
}

// Exact main-only requirements cannot be supplied by defaults, another coin,
// regtest bytes, missing model/fee/spending policy or values above hard ceilings.
func TestMainNativeRefusals(t *testing.T) {
	cases := []struct {
		service, path string
		value         any
		want          error
	}{
		{"issuer", "config.spending", nil, ErrPolicy}, {"issuer", "config.spending.moved_per_tx", 0, ErrPolicy},
		{"issuer", "config.spending.moved_day", 0, ErrPolicy},
		{"issuer", "config.spending.enrolled_hot", maxMoney + 1, ErrPolicy}, {"issuer", "config.policy.policy.fee_rate", 0, ErrPolicy},
		{"issuer", "config.policy.policy.fee_rate", 1001, ErrPolicy}, {"issuer", "config.caps.count_day", 65, ErrPolicy},
		{"issuer", "config.policy.policy.network", "regtest", ErrNetwork},
		{"wallet", "network", "regtest", ErrNetwork}, {"wallet", "genesis", regtestGenesis, ErrNetwork},
		{"booking", "config.coins.nmc.min_confirmations", 0, ErrPolicy}, {"booking", "config.price_usd_cents", 0, ErrPolicy},
		{"booking", "config.template.budget_sat", 0, ErrPolicy}, {"booking", "config.limits.max_bytes", 0, ErrPolicy},
		{"booking", "config.coins.nmc.public_branch", "tpub-invalid", ErrPolicy},
		{"gateway", "agent_key_file", "/var/lib/swarma-gateway/agent.key", ErrPolicy},
		{"gateway", "relay_max_event_bytes", 0, ErrPolicy}, {"gateway", "relay_max_event_bytes", 131073, ErrPolicy},
		{"gateway", "model_proxy", nil, ErrPolicy}, {"gateway", "model_proxy.caps.requests", 0, ErrPolicy},
		{"gateway", "model_proxy.server_uid", 0, ErrPolicy}, {"gateway", "exchange.payment_coins", []string{"btc"}, ErrNetwork},
		{"gateway", "exchange.payment_coins", []string{"ltc"}, ErrNetwork}, {"gateway", "kernel.genesis", regtestGenesis, ErrNetwork},
		{"gateway", "station.manager", nil, ErrPolicy}, {"gateway", "exchange.max_clients", 65, ErrPolicy},
		{"store", "writers", []string{}, ErrPolicy}, {"store", "max_blobs", 0, ErrPolicy},
		{"relay", "max_events", 0, ErrPolicy}, {"relay", "queue", 2, ErrPolicy},
	}
	for _, tc := range cases {
		t.Run(tc.service+"/"+tc.path+"/"+string(encoded(t, tc.value)), func(t *testing.T) {
			p := mainPolicy(tc.service)
			raw := mainInputs(t, tc.service)[0]
			if e := ValidateServiceInputs(p, [][]byte{raw}); e != nil {
				t.Fatal("neighbor", e)
			}
			var v map[string]any
			d := json.NewDecoder(bytes.NewReader(raw))
			d.UseNumber()
			if e := d.Decode(&v); e != nil {
				t.Fatal(e)
			}
			parts := strings.Split(tc.path, ".")
			m := v
			for _, part := range parts[:len(parts)-1] {
				m = m[part].(map[string]any)
			}
			m[parts[len(parts)-1]] = tc.value
			if e := ValidateServiceInputs(p, [][]byte{encoded(t, v)}); e != tc.want {
				t.Fatalf("want %v got %v", tc.want, e)
			}
		})
	}
}

// These are explicit M5 test template values, never runtime defaults or public
// demo policy. Only demo-60 is advertised; operator-owned pins remain inert.
func TestM5TemplateValues(t *testing.T) {
	checks := map[string]map[string]json.Number{
		"issuer":  {"config.spending.moved_per_tx": "1000000", "config.spending.moved_day": "10000000", "config.spending.enrolled_hot": "20000000", "config.caps.fee_per_tx": "200000", "config.caps.count_hour": "4", "config.caps.count_day": "12", "config.caps.budget_hour": "6000000", "config.caps.budget_day": "10000000", "config.caps.refill_count": "4", "config.caps.seal_value": "200000", "config.caps.refill_value": "800000", "config.caps.low_water": "2", "config.policy.policy.fee_rate": "200"},
		"booking": {"config.price_usd_cents": "1000", "config.template.budget_sat": "3000000", "config.coins.nmc.min_confirmations": "1"},
		"gateway": {"model_proxy.caps.max_tokens": "8192", "model_proxy.caps.requests": "200", "model_proxy.caps.input_tokens": "4000000", "model_proxy.caps.output_tokens": "300000", "model_proxy.caps.cost_nano_usd": "3000000000"},
	}
	for service, fields := range checks {
		raw, e := os.ReadFile("templates/m5-test/" + service + "/service.json")
		if e != nil {
			t.Fatal(e)
		}
		var v map[string]any
		d := json.NewDecoder(bytes.NewReader(raw))
		d.UseNumber()
		if e = d.Decode(&v); e != nil {
			t.Fatal(e)
		}
		for path, want := range fields {
			var got any = v
			for _, part := range strings.Split(path, ".") {
				got = got.(map[string]any)[part]
			}
			if got != want {
				t.Fatal("M5 explicit value", service, path, got, want)
			}
		}
		if service == "booking" {
			c := v["config"].(map[string]any)
			slots := c["slots"].([]any)
			if len(slots) != 1 || slots[0].(map[string]any)["id"] != "demo-60" || c["template"].(map[string]any)["id"] != "demo-60" {
				t.Fatal("single demo-60 offer")
			}
		}
	}
}

// Signed model terms admit the largest browser-exact integer and refuse the
// next integer and uint64 overflow without rounding or truncation.
func TestMainModelIntegerPrecision(t *testing.T) {
	raw := mainInputs(t, "gateway")[0]
	var c map[string]any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if e := d.Decode(&c); e != nil {
		t.Fatal(e)
	}
	caps := c["model_proxy"].(map[string]any)["caps"].(map[string]any)
	caps["requests"] = json.Number("9007199254740991")
	caps["cost_nano_usd"] = json.Number("9007199254740991")
	if e := ValidateServiceInputs(mainPolicy("gateway"), [][]byte{encoded(t, c)}); e != nil {
		t.Fatal("browser-exact cap rejected", e)
	}
	caps["cost_nano_usd"] = json.Number("9007199254740992")
	if e := ValidateServiceInputs(mainPolicy("gateway"), [][]byte{encoded(t, c)}); e != ErrPolicy {
		t.Fatal("browser-inexact cap accepted", e)
	}
	caps["cost_nano_usd"] = json.Number("18446744073709551616")
	if e := ValidateServiceInputs(mainPolicy("gateway"), [][]byte{encoded(t, c)}); e != ErrPolicy {
		t.Fatal("uint64 overflow accepted", e)
	}
}
