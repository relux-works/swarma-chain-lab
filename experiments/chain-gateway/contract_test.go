package chaingateway_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type vector struct {
	Name       string  `json:"name"`
	Kind       string  `json:"kind"`
	Valid      bool    `json:"valid"`
	Wire       *string `json:"wire"`
	WireBase64 *string `json:"wire_b64"`
}

func readJSON(t *testing.T, path string, dest any) {
	t.Helper()
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e = d.Decode(dest); e != nil {
		t.Fatal(e)
	}
}

// MIRROR: Each exact shared payload gets its independently specified verdict.
// This checks schema/framing only, not peer auth, RPC or runtime side effects.
func TestSharedVectors(t *testing.T) {
	var vs []vector
	readJSON(t, "fixtures/vectors.json", &vs)
	if len(vs) == 0 {
		t.Fatal("empty fixture corpus")
	}
	seen := map[string]bool{}
	for _, v := range vs {
		if v.Name == "" || seen[v.Name] {
			t.Fatal("missing or repeated fixture name")
		}
		seen[v.Name] = true
		t.Run(v.Name, func(t *testing.T) {
			if (v.Wire == nil) == (v.WireBase64 == nil) {
				t.Fatal("exactly one wire representation required")
			}
			var raw []byte
			if v.Wire != nil {
				raw = []byte(*v.Wire)
			} else {
				var e error
				raw, e = base64.StdEncoding.Strict().DecodeString(*v.WireBase64)
				if e != nil {
					t.Fatal(e)
				}
			}
			e := validate(v.Kind, raw)
			if (e == nil) != v.Valid {
				t.Fatalf("verdict mismatch: valid=%t, validation=%v", v.Valid, e)
			}
		})
	}
}

type observation struct {
	Name      string             `json:"name"`
	Kind      string             `json:"kind"`
	Attempts  [][]map[string]any `json:"attempts,omitempty"`
	Expected  map[string]any     `json:"expected,omitempty"`
	Requests  []map[string]any   `json:"requests,omitempty"`
	Responses []map[string]any   `json:"responses,omitempty"`
	Accepted  bool               `json:"accepted,omitempty"`
	Snapshot  string             `json:"snapshot,omitempty"`
	Now       uint64             `json:"now,omitempty"`
	KnownTip  map[string]any     `json:"known_tip,omitempty"`
	Clock     bool               `json:"clock,omitempty"`
	Label     string             `json:"label,omitempty"`
}

func observations(t *testing.T) []observation {
	t.Helper()
	b, e := os.ReadFile("fixtures/observations.json")
	if e != nil {
		t.Fatal(e)
	}
	var vs []observation
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	d.UseNumber()
	if e = d.Decode(&vs); e != nil {
		t.Fatal(e)
	}
	return vs
}
func wire(v any) []byte  { b, _ := json.Marshal(v); return b }
func same(a, b any) bool { return bytes.Equal(wire(a), wire(b)) }

// A test-only consistency oracle over explicit transition witnesses. This is
// not a node adapter, and does not claim that ordinary RPC supplies a witness.
func attemptOracle(attempts [][]map[string]any) (map[string]any, error) {
	if len(attempts) < 1 || len(attempts) > 3 {
		return nil, bad("attempt count")
	}
	for i, history := range attempts {
		if len(history) == 0 {
			return nil, bad("empty history")
		}
		stable := true
		for _, at := range history {
			if e := tip(at); e != nil {
				return nil, e
			}
			if !same(history[0], at) {
				stable = false
			}
		}
		if stable {
			if i != len(attempts)-1 {
				return nil, bad("retry after success")
			}
			return map[string]any{"method": "getblockcount", "network": "regtest", "ok": true, "result": map[string]any{}, "tip": history[0], "v": json.Number("1")}, nil
		}
	}
	if len(attempts) != 3 {
		return nil, bad("premature exhaustion")
	}
	return map[string]any{"error": map[string]any{"code": "tip_moved"}, "ok": false, "v": json.Number("1")}, nil
}

// The consumer oracle checks correlation, one network/tip, and positive seal
// liveness. It makes no atomic-mempool, journal or application-pin claim.
func collectionOracle(requests, responses []map[string]any) bool {
	if len(requests) < 4 || len(requests) != len(responses) {
		return false
	}
	if requests[0]["method"] != "getblockcount" || requests[len(requests)-1]["method"] != "getblockcount" {
		return false
	}
	for i, r := range requests {
		s := responses[i]
		if request(r) != nil || response(s) != nil || s["ok"] != true || r["method"] != s["method"] || !same(s["tip"], responses[0]["tip"]) || s["network"] != responses[0]["network"] {
			return false
		}
		p := r["params"].(map[string]any)
		result := s["result"].(map[string]any)
		switch r["method"] {
		case "name_show":
			if p["name"] != result["name"] || result["expired"] != false {
				return false
			}
		case "gettxout":
			if p["txid"] != result["txid"] || p["vout"] != result["vout"] || result["state"] != "unspent" {
				return false
			}
		}
	}
	return true
}

// MIRROR: Witnessed movement discards an attempt, ABA is detected, and mismatched
// or negative observations cannot form an admissible consumer collection.
func TestObservationVectors(t *testing.T) {
	for _, v := range observations(t) {
		if v.Kind == "label" {
			continue
		}
		t.Run(v.Name, func(t *testing.T) {
			switch v.Kind {
			case "attempts":
				got, e := attemptOracle(v.Attempts)
				if e != nil {
					t.Fatal(e)
				}
				if response(v.Expected) != nil || !same(got, v.Expected) {
					t.Fatal("attempt result differs from shared expectation")
				}
			case "bracket":
				write := false
				for _, pair := range v.Attempts {
					if len(pair) != 2 || tip(pair[0]) != nil || tip(pair[1]) != nil {
						t.Fatal("bad bracket")
					}
					if same(pair[0], pair[1]) {
						write = true
						break
					}
				}
				code := 12
				if write {
					code = 0
				} else if len(v.Attempts) != 3 {
					t.Fatal("premature exhaustion")
				}
				if v.Expected["write"] != write || v.Expected["exit"] != json.Number(fmt.Sprint(code)) {
					t.Fatal("bracket verdict mismatch")
				}
			case "collection":
				if collectionOracle(v.Requests, v.Responses) != v.Accepted {
					t.Fatal("collection verdict mismatch")
				}
			default:
				t.Fatal("unknown observation kind")
			}
		})
	}
}
func snapshotLabel(raw []byte, now uint64, known map[string]any, clock bool) string {
	if validate("snapshot", raw) != nil {
		return "invalid"
	}
	m, _ := parse(raw, 65536)
	if !clock {
		return "unknown"
	}
	written := uintValue(m["written_at"])
	if written > now {
		return "invalid"
	}
	// This oracle mirrors Source's default consumer lag policy, not a gateway limit.
	at := m["tip"].(map[string]any)
	tipTime := uintValue(at["time"])
	if now-written > 60 || (now > tipTime && now-tipTime > 7200) {
		return "stale"
	}
	if known == nil {
		return "unknown"
	}
	if tip(known) != nil {
		return "unknown"
	}
	if !same(known, m["tip"]) {
		return "stale"
	}
	return "fresh"
}

// MIRROR: Labels are derived, preserve observe-only mode, and distinguish stale,
// future time, unknown tip/clock, and consumer 7200-second lag boundaries.
func TestSnapshotLabels(t *testing.T) {
	for _, v := range observations(t) {
		if v.Kind != "label" {
			continue
		}
		t.Run(v.Name, func(t *testing.T) {
			if got := snapshotLabel([]byte(v.Snapshot), v.Now, v.KnownTip, v.Clock); got != v.Label {
				t.Fatalf("label=%s want %s", got, v.Label)
			}
		})
	}
}

// MIRROR: Paired controls independently exercise exact integer limits and strict
// parsing. The planted fixture experiment separately verifies runner failure.
func TestSchemaControls(t *testing.T) {
	for _, x := range []struct {
		value string
		max   uint64
		valid bool
	}{
		{"0", 4294967295, true}, {"4294967295", 4294967295, true}, {"4294967296", 4294967295, false},
		{"9007199254740991", maxInteger, true}, {"9007199254740992", maxInteger, false},
		{"-0", maxInteger, false}, {"1e0", maxInteger, false}, {"1.0", maxInteger, false},
	} {
		if integer(json.Number(x.value), x.max) != x.valid {
			t.Errorf("integer boundary %s", x.value)
		}
	}
	for _, x := range []struct {
		raw   string
		valid bool
	}{
		{`{"a":{"b":1}}`, true}, {`{"a":{"b":1,"b":2}}`, false},
		{`{"a":[{"b":1}]}`, true}, {`{"a":[{"b":1,"B":2}]}`, false},
		{`{"a":{"\u0062":1}}`, false}, {`{"a":{"s":1,"ſ":2}}`, false},
		{`{"a":"x/y"}`, true}, {`{"a":"x\/y"}`, false},
		{`{"a":{}}`, true}, {`{"a":{}} {}`, false},
	} {
		_, e := parse([]byte(x.raw), 1024)
		if (e == nil) != x.valid {
			t.Errorf("strict control %s: %v", x.raw, e)
		}
	}
	for _, arrays := range []int{6, 7} {
		raw := `{"a":` + strings.Repeat("[", arrays) + `{}` + strings.Repeat("]", arrays) + `}`
		_, err := parse([]byte(raw), 1024)
		if (err == nil) != (arrays == 6) {
			t.Errorf("depth boundary: arrays=%d err=%v", arrays, err)
		}
	}
	for _, limit := range []int{1024, 4096, 65536} {
		for _, delta := range []int{-1, 0, 1} {
			if got := payloadSize([]byte(strings.Repeat("a", limit+delta)), limit); got != (delta <= 0) {
				t.Errorf("size %d delta %d", limit, delta)
			}
		}
	}
}
func payloadSize(raw []byte, limit int) bool { return len(raw) > 0 && len(raw) <= limit }

// Every committed fixture file and observation is accounted for; no silently
// ignored corpus file or duplicate scenario can masquerade as executed evidence.
func TestFixtureInventory(t *testing.T) {
	paths, e := filepath.Glob("fixtures/*.json")
	if e != nil {
		t.Fatal(e)
	}
	slices.Sort(paths)
	if fmt.Sprint(paths) != "[fixtures/observations.json fixtures/vectors.json]" {
		t.Fatalf("uncovered fixture files: %v", paths)
	}
	seen := map[string]bool{}
	for _, v := range observations(t) {
		if v.Name == "" || seen[v.Name] {
			t.Fatal("missing or duplicate scenario")
		}
		seen[v.Name] = true
		if !slices.Contains([]string{"attempts", "collection", "label", "bracket"}, v.Kind) {
			t.Fatal("uncovered scenario kind")
		}
	}
}
