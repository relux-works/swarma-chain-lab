package chaingateway_test

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
)

var observationKinds = []string{"attempts", "collection", "label", "bracket", "snapshot_read_failure", "rounds", "seal_history", "utxo_views", "qualification", "snapshot_attempts", "snapshot_stage", "upstream", "reflection"}

type fixtureConfig struct {
	Network string         `json:"network"`
	Names   []string       `json:"names"`
	Seals   []fixturePoint `json:"seals"`
}
type fixturePoint struct {
	TXID string `json:"txid"`
	Vout uint32 `json:"vout"`
}

func decodeObservations(b []byte) ([]observation, error) {
	var vs []observation
	if e := decodeFixture(b, &vs); e != nil {
		return nil, e
	}
	for _, v := range vs {
		if e := observationShape(v); e != nil {
			return nil, fmt.Errorf("fixture %s: %w", v.Name, e)
		}
	}
	return vs, nil
}

func observationShape(v observation) error {
	if !slices.Contains(observationKinds, v.Kind) {
		return bad("fixture kind")
	}
	if v.Config != nil {
		if _, e := fields(v.Config, "network", "names", "seals"); e != nil {
			return bad("fixture config fields")
		}
		var c fixtureConfig
		if e := decodeFixture(wire(v.Config), &c); e != nil {
			return bad("fixture config types")
		}
		if !network(c.Network) || len(c.Names) < 1 || len(c.Seals) < 1 {
			return bad("fixture config values")
		}
		for _, n := range c.Names {
			if !name(n) {
				return bad("fixture config name")
			}
		}
		for _, p := range c.Seals {
			if !hash(p.TXID) {
				return bad("fixture config outpoint")
			}
		}
	}
	if v.KnownTip != nil && tip(v.KnownTip) != nil {
		return bad("fixture known_tip")
	}
	for _, a := range v.Attempts {
		for _, at := range a {
			if tip(at) != nil {
				return bad("fixture attempt tip")
			}
		}
	}
	for _, a := range v.SnapshotAttempts {
		if tip(a.Before) != nil || tip(a.After) != nil {
			return bad("fixture snapshot tip")
		}
		for _, r := range a.Replies {
			if response(r) != nil {
				return bad("fixture snapshot reply")
			}
		}
	}
	for _, h := range v.History {
		if response(h) != nil {
			return bad("fixture history fields")
		}
	}
	for _, r := range v.Requests {
		if request(r) != nil {
			return bad("fixture request fields")
		}
	}
	for _, r := range v.Responses {
		if response(r) != nil {
			return bad("fixture response fields")
		}
	}
	for _, round := range v.Rounds {
		for _, r := range round.Requests {
			if request(r) != nil {
				return bad("fixture round request")
			}
		}
		for _, r := range round.Responses {
			if response(r) != nil {
				return bad("fixture round response")
			}
		}
	}
	for _, view := range []map[string]any{v.Confirmed, v.Mempool} {
		if view == nil {
			continue
		}
		for k, x := range view {
			switch k {
			case "bestblock":
				if _, ok := x.(string); !ok {
					return bad("fixture view hash type")
				}
			case "confirmations":
				if _, ok := x.(json.Number); !ok {
					return bad("fixture view count type")
				}
			case "scriptPubKey":
				script, ok := x.(map[string]any)
				if !ok {
					return bad("fixture view script type")
				}
				for name, value := range script {
					if !slices.Contains([]string{"hex", "asm", "desc"}, name) {
						return bad("fixture view script field")
					}
					if _, ok := value.(string); !ok {
						return bad("fixture view script value")
					}
				}
			default:
				return bad("fixture view field")
			}
		}
	}
	for _, d := range v.Decisions {
		if _, e := fields(d, "refuse_command", "observe_closed", "enforcement_closed", "seen_unspent", "unavailable"); e != nil {
			return bad("fixture decision fields")
		}
		for _, x := range d {
			if !boolean(x) {
				return bad("fixture decision type")
			}
		}
	}
	if v.ResponseWires != nil && v.Responses != nil || v.HistoryWires != nil && v.History != nil {
		return bad("fixture duplicate response representation")
	}
	if v.Kind == "label" && (!slices.Contains([]string{"independent", "none", "self"}, v.LiveTipSource) || v.LagSeconds == nil || v.Enforceable == nil) {
		return bad("fixture label inputs")
	}
	if slices.Contains([]string{"collection", "rounds", "seal_history", "utxo_views", "label"}, v.Kind) && v.Config == nil {
		return bad("fixture missing config")
	}
	if v.Kind == "qualification" && v.Admission == nil || v.Kind == "upstream" && v.Upstream == nil || v.Kind == "reflection" && v.Reflection == nil {
		return bad("fixture missing typed input")
	}
	return nil
}

func inventoryLines(vs []vector, obs []observation) ([]string, error) {
	lines := []string{}
	seen := map[string]bool{}
	for _, v := range vs {
		key := "vector " + v.Kind + " " + v.Name
		if seen[key] {
			return nil, bad("duplicate inventory entry")
		}
		seen[key] = true
		lines = append(lines, key)
	}
	for _, v := range obs {
		lines = append(lines, "observation "+v.Kind+" "+v.Name)
	}
	slices.Sort(lines)
	return lines, nil
}

func checkRequiredInventory(t *testing.T) {
	t.Helper()
	var vs []vector
	readJSON(t, "fixtures/vectors.json", &vs)
	obs := observations(t)
	got, e := inventoryLines(vs, obs)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile("fixtures/inventory.txt")
	if e != nil {
		t.Fatal(e)
	}
	if strings.Join(got, "\n")+"\n" != string(raw) {
		t.Fatal("required fixture inventory mismatch")
	}
	// Every annotated negative names an existing independently executed positive control.
	controls := map[string]bool{}
	for _, v := range vs {
		controls[v.Name] = v.Valid
	}
	for _, v := range obs {
		positive := v.Accepted || v.Label == "fresh" || v.Expected["available"] == true || v.Expected["exit"] == json.Number("0") || v.Expected["code"] == "ok" || v.Expected["code"] == "absent"
		if v.Kind == "seal_history" {
			positive = true
		}
		controls[v.Name] = positive
	}
	for _, v := range vs {
		if v.Claim != "" && !controls[v.Control] {
			t.Fatalf("invalid positive control for %s", v.Name)
		}
	}
	for _, v := range obs {
		if v.Claim != "" && !controls[v.Control] {
			t.Fatalf("invalid positive control for %s", v.Name)
		}
	}
}

// Claim: fixture decoding rejects trailing data and unknown/mistyped inner maps beside a valid control.
func TestFixtureDecoderControls(t *testing.T) {
	control := `[{"name":"control","kind":"seal_history","config":{"network":"regtest","names":["id/example"],"seals":[{"txid":"` + strings.Repeat("a", 64) + `","vout":2}]},"history":[{"error":{"code":"unavailable"},"ok":false,"v":1}]}]`
	cases := []struct{ name, raw, witness string }{
		{"trailing", control + ` {}`, "trailing fixture data"},
		{"config_unknown", strings.Replace(control, `"network":`, `"extra":1,"network":`, 1), "fixture config fields"},
		{"config_type", strings.Replace(control, `"names":["id/example"]`, `"names":[1]`, 1), "fixture config types"},
		{"point_unknown", strings.Replace(control, `"vout":2`, `"vout":2,"extra":0`, 1), "fixture config types"},
		{"point_type", strings.Replace(control, `"vout":2`, `"vout":"2"`, 1), "fixture config types"},
		{"tip_unknown", strings.Replace(control, `"history":`, `"known_tip":{"hash":"`+strings.Repeat("1", 64)+`","height":100,"time":1,"extra":0},"history":`, 1), "fixture known_tip"},
		{"history_unknown", strings.Replace(control, `"ok":false`, `"extra":0,"ok":false`, 1), "fixture history fields"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Claim: this malformed fixture fails its exact guard while the adjacent control decodes.
			if _, e := decodeObservations([]byte(control)); e != nil {
				t.Fatal(e)
			}
			if _, e := decodeObservations([]byte(c.raw)); e == nil || !strings.Contains(e.Error(), c.witness) {
				t.Fatalf("fixture guard %s: %v", c.witness, e)
			}
		})
	}
	// Claim: vector fixture arrays also reject trailing data with the same exact witness.
	var vectors []vector
	if e := decodeFixture([]byte(`[]`), &vectors); e != nil {
		t.Fatal(e)
	}
	if e := decodeFixture([]byte(`[] {}`), &vectors); e == nil || e.Error() != "trailing fixture data" {
		t.Fatalf("vector trailing guard: %v", e)
	}
}
