package chaingateway_test

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
)

func snapshotControl(t *testing.T) observation {
	t.Helper()
	for _, v := range observations(t) {
		if v.Name == "snapshot_complete_control" {
			return v
		}
	}
	t.Fatal("missing complete control")
	return observation{}
}

// Claim: impossible snapshot inputs are domain errors with exact witnesses, never supervisor exit 11, beside a complete control.
func TestSnapshotDomainControls(t *testing.T) {
	cases := []struct {
		name, witness string
		change        func(*observation)
	}{
		{"zero_attempts", "attempt count", func(v *observation) { v.SnapshotAttempts = nil }},
		{"four_attempts", "attempt count", func(v *observation) { v.SnapshotAttempts = slices.Repeat(v.SnapshotAttempts, 4) }},
		{"unknown_stage", "stage", func(v *observation) { v.Stage = "typo" }},
		{"unknown_failure", "failure", func(v *observation) { v.SnapshotAttempts[0].Failure = "typo" }},
		{"missing_config", "config", func(v *observation) { v.Config = nil }},
		{"duplicate_config_name", "config", func(v *observation) { v.Config["names"] = []any{"id/example", "id/example"} }},
		{"config_name_cap", "config", func(v *observation) {
			names := []any{}
			for i := range 17 {
				names = append(names, "id/n"+strings.Repeat("a", i))
			}
			v.Config["names"] = names
		}},
		{"config_seal_cap", "config", func(v *observation) {
			seals := []any{}
			for i := range 257 {
				seals = append(seals, map[string]any{"txid": strings.Repeat("a", 64), "vout": json.Number(fmt.Sprint(i))})
			}
			v.Config["seals"] = seals
		}},
		{"rename_without_stage", "rename fact", func(v *observation) { b := true; v.Renamed = &b }},
		{"directory_without_rename", "rename fact", func(v *observation) { v.Stage = "directory_sync" }},
		{"pre_stage_with_rename", "rename fact", func(v *observation) { v.Stage = "temp_write"; b := true; v.Renamed = &b }},
		{"stage_without_collection", "stage without collection", func(v *observation) {
			v.Stage = "directory_sync"
			b := true
			v.Renamed = &b
			v.SnapshotAttempts[0].Replies[0] = map[string]any{"ok": false, "v": json.Number("1"), "error": map[string]any{"code": "unavailable"}}
		}},
		{"stage_after_exhaustion", "stage without collection", func(v *observation) {
			v.Stage = "directory_sync"
			b := true
			v.Renamed = &b
			v.SnapshotAttempts[0].After["hash"] = strings.Repeat("3", 64)
			v.SnapshotAttempts = slices.Repeat(v.SnapshotAttempts, 3)
		}},
		{"premature_movement", "premature exhaustion", func(v *observation) { v.SnapshotAttempts[0].After["hash"] = strings.Repeat("3", 64) }},
		{"premature_rate_limit", "premature exhaustion", func(v *observation) {
			v.SnapshotAttempts[0].Replies[0] = map[string]any{"ok": false, "v": json.Number("1"), "error": map[string]any{"code": "rate_limited"}}
		}},
		{"retry_after_success", "retry after terminal", func(v *observation) { v.SnapshotAttempts = slices.Repeat(v.SnapshotAttempts, 2) }},
		{"two_reply_forms", "reply representation", func(v *observation) {
			v.SnapshotAttempts[0].ReplyWires = []string{string(wire(v.SnapshotAttempts[0].Replies[0]))}
		}},
		{"two_opening_forms", "opening bracket", func(v *observation) { v.SnapshotAttempts[0].BeforeReply = v.SnapshotAttempts[0].Replies[0] }},
		{"missing_closing", "closing bracket", func(v *observation) { v.SnapshotAttempts[0].After = nil }},
		{"reads_after_refusal", "reads after opening refusal", func(v *observation) {
			v.SnapshotAttempts[0].Before = nil
			v.SnapshotAttempts[0].BeforeReply = map[string]any{"ok": false, "v": json.Number("1"), "error": map[string]any{"code": "tip_moved"}}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Claim: only this domain violation is introduced; the untouched complete collection publishes with exit 0.
			v := snapshotControl(t)
			if got, e := snapshotOutcome(v.Config, v.SnapshotAttempts, "", false); e != nil || got["exit"] != json.Number("0") {
				t.Fatalf("complete domain control: %v", e)
			}
			c.change(&v)
			renamed := v.Renamed != nil && *v.Renamed
			got, e := snapshotOutcome(v.Config, v.SnapshotAttempts, v.Stage, renamed)
			if e == nil || e.Error() != "snapshot domain: "+c.witness || got != nil {
				t.Fatalf("domain guard %s: got=%s error=%v", c.witness, wire(got), e)
			}
		})
	}
}

// Claim: the fixture loader rejects unknown stage/failure enums and missing explicit rename facts beside a valid stage fixture.
func TestSnapshotFixtureEnums(t *testing.T) {
	v := snapshotControl(t)
	v.Stage = "temp_write"
	b := false
	v.Renamed = &b
	control := string(wire([]observation{v}))
	for _, c := range []struct{ name, raw, witness string }{
		{"stage", strings.Replace(control, `"stage":"temp_write"`, `"stage":"typo"`, 1), "snapshot domain: stage"},
		{"failure", strings.Replace(control, `"before":`, `"failure":"typo","before":`, 1), "snapshot domain: failure"},
		{"rename", strings.Replace(control, `,"renamed":false`, "", 1), "fixture missing rename fact"},
	} {
		t.Run(c.name, func(t *testing.T) {
			// Claim: only the named enum/fact defect prevents loading this otherwise valid fixture.
			if _, e := decodeObservations([]byte(control)); e != nil {
				t.Fatal(e)
			}
			if _, e := decodeObservations([]byte(c.raw)); e == nil || !strings.Contains(e.Error(), c.witness) {
				t.Fatalf("enum guard %s: %v", c.witness, e)
			}
		})
	}
}

// Claim: each shared cap+1 fixture is valid JSON with the exact at-cap projection, negative only by one byte of trailing whitespace.
func TestUpstreamCapFixtures(t *testing.T) {
	byName := map[string]observation{}
	for _, v := range observations(t) {
		byName[v.Name] = v
	}
	for method, bound := range upstreamBounds {
		t.Run(method, func(t *testing.T) {
			positive := byName["upstream_"+method+"_at_cap"]
			name := "upstream_" + method + "_over_cap"
			if method == "name_show" {
				name = "upstream_byte_overflow"
			}
			negative := byName[name]
			if positive.Upstream == nil || negative.Upstream == nil {
				t.Fatal("missing cap fixture")
			}
			p, n := positive.Upstream.Body, negative.Upstream.Body
			if !json.Valid([]byte(p)) || !json.Valid([]byte(n)) || len(p) != bound.bytes || n != p+" " {
				t.Fatal("cap fixture must be valid JSON differing only by cap+1 whitespace")
			}
			if upstreamOracle(*positive.Upstream) != "ok" || upstreamOracle(*negative.Upstream) != "unavailable" {
				t.Fatal("shared cap outcome mismatch")
			}
			// Claim: removing just the excess byte repairs the negative without changing any parsed field.
			u := *negative.Upstream
			u.Body = u.Body[:len(u.Body)-1]
			if upstreamOracle(u) != "ok" {
				t.Fatal("cap-only repair control")
			}
		})
	}
}
