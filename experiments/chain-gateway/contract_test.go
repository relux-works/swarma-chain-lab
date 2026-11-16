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
	Config    map[string]any     `json:"config,omitempty"`
	Rounds    []collectionRound  `json:"rounds,omitempty"`
	History   []map[string]any   `json:"history,omitempty"`
	Decisions []map[string]any   `json:"decisions,omitempty"`
	Confirmed map[string]any     `json:"confirmed,omitempty"`
	Mempool   map[string]any     `json:"mempool,omitempty"`
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

type collectionRound struct {
	Requests  []map[string]any `json:"requests"`
	Responses []map[string]any `json:"responses"`
}

// The oracle requires the configured ONE name/seal and every answer at one tip.
// It proves fixture correlation only, not mempool atomicity or application pins.
func collectionOracle(config map[string]any, requests, responses []map[string]any) bool {
	if len(requests) != 4 || len(responses) != 4 || !network(config["network"]) {
		return false
	}
	names, nok := config["names"].([]any)
	seals, sok := config["seals"].([]any)
	if !nok || !sok || len(names) != 1 || len(seals) != 1 {
		return false
	}
	methods := []string{"getblockcount", "name_show", "gettxout", "getblockcount"}
	for i, r := range requests {
		s := responses[i]
		if request(r) != nil || response(s) != nil || s["ok"] != true || r["method"] != methods[i] || r["method"] != s["method"] || !same(s["tip"], responses[0]["tip"]) || s["network"] != config["network"] {
			return false
		}
		p := r["params"].(map[string]any)
		result := s["result"].(map[string]any)
		switch r["method"] {
		case "name_show":
			if p["name"] != names[0] || p["name"] != result["name"] || result["expired"] != false {
				return false
			}
		case "gettxout":
			if !same(p, seals[0]) || p["txid"] != result["txid"] || p["vout"] != result["vout"] || result["state"] != "unspent" {
				return false
			}
		}
	}
	return true
}

// At most three complete logical rounds; an attempted fourth round is refused
// even if it would succeed. No round's partial data survives into another.
func roundsOracle(config map[string]any, rounds []collectionRound) bool {
	if len(rounds) < 1 || len(rounds) > 3 {
		return false
	}
	for i, r := range rounds {
		if collectionOracle(config, r.Requests, r.Responses) {
			return i == len(rounds)-1
		}
	}
	return false
}

// This models only Source F5/Q2 per-command state. Actual-spend CGW-J1 closures
// are independent; the fixture does not simulate a real durable journal.
func historyOracle(history []map[string]any) ([]map[string]any, error) {
	seen, closed := false, false
	out := []map[string]any{}
	for _, event := range history {
		if response(event) != nil {
			return nil, bad("invalid history response")
		}
		admit := false
		if event["ok"] == true {
			if event["method"] != "gettxout" {
				return nil, bad("history method")
			}
			state := event["result"].(map[string]any)["state"]
			if state == "unspent" {
				seen = true
				admit = !closed
			}
			if state == "not_in_utxo_set" && seen {
				closed = true
			}
		}
		out = append(out, map[string]any{"admit": admit, "closed": closed, "seen_unspent": seen})
	}
	return out, nil
}

// The fixed two-view table classifies confirmed and mempool-only observations.
// The fixture supplies a coherent instant; this does not manufacture a witness.
func projectionOracle(at, point, c, m map[string]any) map[string]any {
	refusal := map[string]any{"error": map[string]any{"code": "unavailable"}, "ok": false, "v": json.Number("1")}
	if tip(at) != nil || !outpoint(point) {
		return refusal
	}
	for _, view := range []map[string]any{c, m} {
		if view == nil {
			continue
		}
		script, ok := view["scriptPubKey"].(map[string]any)
		if !ok || view["bestblock"] != at["hash"] || !integer(view["confirmations"], maxInteger) {
			return refusal
		}
		if _, ok := script["hex"].(string); !ok {
			return refusal
		}
	}
	result := map[string]any{"state": "not_in_utxo_set", "txid": point["txid"], "vout": point["vout"]}
	source := c
	if c != nil {
		if uintValue(c["confirmations"]) < 1 {
			return refusal
		}
		result["state"] = "spend_pending"
		if m != nil {
			if !same(c["confirmations"], m["confirmations"]) || !same(c["scriptPubKey"].(map[string]any)["hex"], m["scriptPubKey"].(map[string]any)["hex"]) {
				return refusal
			}
			result["state"] = "unspent"
		}
	} else if m != nil {
		if uintValue(m["confirmations"]) != 0 {
			return refusal
		}
		source = m
		result["state"] = "unconfirmed"
	}
	if source != nil {
		result["confirmations"] = source["confirmations"]
		result["script_pubkey"] = source["scriptPubKey"].(map[string]any)["hex"]
	}
	if sealRecord(result, at) != nil {
		return refusal
	}
	return map[string]any{"method": "gettxout", "network": "regtest", "ok": true, "result": result, "tip": at, "v": json.Number("1")}
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
				if collectionOracle(v.Config, v.Requests, v.Responses) != v.Accepted {
					t.Fatal("collection verdict mismatch")
				}
			case "utxo_views":
				points, ok := v.Config["seals"].([]any)
				if !ok || len(points) != 1 {
					t.Fatal("projection point")
				}
				point, ok := points[0].(map[string]any)
				if !ok {
					t.Fatal("projection point shape")
				}
				got := projectionOracle(v.KnownTip, point, v.Confirmed, v.Mempool)
				if response(v.Expected) != nil || !same(got, v.Expected) {
					t.Fatalf("two-view verdict mismatch: got %s", wire(got))
				}

			case "rounds":
				if roundsOracle(v.Config, v.Rounds) != v.Accepted {
					t.Fatal("round budget verdict mismatch")
				}
			case "seal_history":
				got, e := historyOracle(v.History)
				if e != nil || !same(got, v.Decisions) {
					t.Fatalf("history verdict mismatch: %v got %s", e, wire(got))
				}
			default:
				t.Fatal("unknown observation kind")
			}
		})
	}
}
func snapshotLabel(raw []byte, now uint64, known map[string]any, clock bool, config map[string]any) string {
	if validate("snapshot", raw) != nil {
		return "invalid"
	}
	m, _ := parse(raw, 65536)
	names := []any{}
	for _, n := range m["names"].([]any) {
		names = append(names, n.(map[string]any)["name"])
	}
	seals := []any{}
	for _, x := range m["seals"].([]any) {
		point := x.(map[string]any)
		seals = append(seals, map[string]any{"txid": point["txid"], "vout": point["vout"]})
	}
	if m["network"] != config["network"] || !same(names, config["names"]) || !same(seals, config["seals"]) {
		return "invalid"
	}
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
			if got := snapshotLabel([]byte(v.Snapshot), v.Now, v.KnownTip, v.Clock, v.Config); got != v.Label {
				t.Fatalf("label=%s want %s", got, v.Label)
			}
		})
	}
}

// MIRROR: Paired controls independently exercise exact integer limits and strict
// parsing. The planted fixture experiment separately verifies runner failure.
func TestSchemaControls(t *testing.T) {
	var vs []vector
	readJSON(t, "fixtures/vectors.json", &vs)
	for _, v := range vs {
		if v.Kind != "lexical" && v.Kind != "integer_n" && v.Kind != "integer_o" {
			continue
		}
		t.Run(v.Name, func(t *testing.T) {
			raw := []byte("")
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
				t.Fatalf("shared control mismatch: %v", e)
			}
		})
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
		if !slices.Contains([]string{"attempts", "collection", "label", "bracket", "rounds", "seal_history", "utxo_views"}, v.Kind) {
			t.Fatal("uncovered scenario kind")
		}
	}
}
