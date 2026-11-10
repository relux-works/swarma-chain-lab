package rehearsal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func projectionFixture() map[string]any {
	nodes := []any{}
	for i, role := range []string{"booking", "issuer", "gateway", "verifier"} {
		nodes = append(nodes, map[string]any{"role": role, "datadir": "/owned/" + role, "rpc_port": 4000 + i, "p2p": fmt.Sprint("127.0.0.1:", 5000+i), "tip": strings.Repeat("a", 64), "paused": false})
	}
	return map[string]any{"non_w_anchor": map[string]any{"seal_transaction_w": true, "reason": "W_WITNESS_REQUIRED", "no_admission_state": true, "native_w_neighbour": "LIVE", "consensus_accepted_t": strings.Repeat("2", 64), "consensus_accepted_a": strings.Repeat("3", 64), "commitment": strings.Repeat("4", 64), "hostile_grant_id": strings.Repeat("5", 64)}, "verified_presentation_mirror": map[string]any{"original_bytes": true, "published_after_independent_live": true, "sha256": strings.Repeat("1", 64)}, "underquote": map[string]any{"disposition": "refund_review", "issuance_absent": true, "selected_payment_absent": true, "package_unchanged": true, "slot_absent": true}, "wrong_executor": map[string]any{"reason": "GRANT_POLICY", "node_calls": 0, "journal_unchanged": true}, "independent_closed": map[string]any{"verdict": "refused", "reason": "SEAL_SPENT", "durable_closed": true}, "product_base": strings.Repeat("b", 40), "outcome": "PASS_INTERIM", "scenario": "revoke", "canonical_scope": "implemented V2 order, not a spec-adopted profile", "canonical_order": []string{"names", "booking/consent", "confirmed payment", "issuance", "independent verify", "gateway/station", "chat", "closure"}, "core_names_registered": true, "known_secret_log_scan": true, "direct_processes": []any{map[string]any{"pid": 123, "absent": true}}, "independent_nodes": nodes, "independent_verifier": map[string]any{"stale_reason": "NODE_UNAVAILABLE", "converged_verdict": "live", "converged_tip": strings.Repeat("a", 64), "grant_id": strings.Repeat("c", 64), "failed_method": "getrawtransaction", "missing_anchor": strings.Repeat("d", 64), "stale_no_admission_state": true}, "crash_cases": map[string]string{"gateway": "pending-DA1", "station": "pending-DA1", "issuer": "pending-barrier", "booking": "pending-barrier"}, "closure": map[string]any{"journal_ended": true, "journal_destroyed": false, "reason": "kernel_closed", "channel_cleared": true, "helper_bootstrap_removed": true, "application_idle_milliseconds": 1600, "relay_read_deadline_milliseconds": 90000}, "model_accounting": map[string]any{"phase": "revoked", "exposure": map[string]any{"requests": 2}, "observed": map[string]any{"input": 14, "output": 6}}, "upstream_calls": 2}
}
func projectFixture(t *testing.T, m map[string]any) []byte {
	t.Helper()
	b, e := json.Marshal(m)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

// Fresh identities, ports, paths, times and process IDs normalize to the same
// role-bound result; effect/accounting changes remain visible. Failed or missing
// evidence refuses rather than disappearing during projection.
func TestCanonicalProjection(t *testing.T) {
	a := projectionFixture()
	raw := projectFixture(t, a)
	pa, e := CanonicalProjection(raw)
	if e != nil {
		t.Fatal(e)
	}
	b := projectionFixture()
	v := b["independent_verifier"].(map[string]any)
	v["grant_id"] = strings.Repeat("e", 64)
	v["missing_anchor"] = strings.Repeat("f", 64)
	v["converged_tip"] = strings.Repeat("0", 64)
	for i, n := range b["independent_nodes"].([]any) {
		x := n.(map[string]any)
		x["datadir"] = fmt.Sprint("/fresh/", i)
		x["rpc_port"] = 6000 + i
		x["p2p"] = fmt.Sprint("127.0.0.1:", 7000+i)
		x["tip"] = v["converged_tip"]
	}
	b["direct_processes"] = []any{map[string]any{"pid": 999, "absent": true}, map[string]any{"pid": 1000, "absent": true}}
	b["closure"].(map[string]any)["application_idle_milliseconds"] = 3000
	pb, e := CanonicalProjection(projectFixture(t, b))
	if e != nil || !bytes.Equal(pa, pb) {
		t.Fatal("fresh-role positive mismatch", e)
	}
	b["upstream_calls"] = 3
	pb, e = CanonicalProjection(projectFixture(t, b))
	if e != nil || bytes.Equal(pa, pb) {
		t.Fatal("extra-effect comparison plant missed", e)
	}
	b = projectionFixture()
	b["model_accounting"].(map[string]any)["observed"].(map[string]any)["input"] = 15
	pb, e = CanonicalProjection(projectFixture(t, b))
	if e != nil || bytes.Equal(pa, pb) {
		t.Fatal("accounting comparison plant missed", e)
	}
	for _, tc := range []struct {
		name  string
		plant func(map[string]any)
	}{
		{"non-W-wrong-reason", func(m map[string]any) { m["non_w_anchor"].(map[string]any)["reason"] = "GRANT_SIGNATURE" }},
		{"early-mirror", func(m map[string]any) {
			m["verified_presentation_mirror"].(map[string]any)["published_after_independent_live"] = false
		}},
		{"underquote-issued", func(m map[string]any) { m["underquote"].(map[string]any)["issuance_absent"] = false }},
		{"wrong-executor-write", func(m map[string]any) { m["wrong_executor"].(map[string]any)["journal_unchanged"] = false }},
		{"verifier-open", func(m map[string]any) { m["independent_closed"].(map[string]any)["verdict"] = "live" }},
		{"failed", func(m map[string]any) { m["outcome"] = "FAIL" }},
		{"pending-as-pass", func(m map[string]any) { m["crash_cases"].(map[string]string)["station"] = "PASS" }},
		{"missing", func(m map[string]any) { delete(m, "independent_verifier") }},
		{"wrong-failure", func(m map[string]any) {
			m["independent_verifier"].(map[string]any)["failed_method"] = "getblockchaininfo"
		}},
		{"admission-write", func(m map[string]any) { m["independent_verifier"].(map[string]any)["stale_no_admission_state"] = false }},
		{"shared-node", func(m map[string]any) {
			n := m["independent_nodes"].([]any)
			n[1].(map[string]any)["datadir"] = n[0].(map[string]any)["datadir"]
		}},
		{"unconverged", func(m map[string]any) {
			m["independent_nodes"].([]any)[0].(map[string]any)["tip"] = strings.Repeat("0", 64)
		}},
		{"live-process", func(m map[string]any) { m["direct_processes"].([]any)[0].(map[string]any)["absent"] = false }},
		{"secret-scan", func(m map[string]any) { m["known_secret_log_scan"] = false }},
		{"not-closed", func(m map[string]any) { m["closure"].(map[string]any)["journal_ended"] = false }},
		{"order", func(m map[string]any) { m["canonical_order"].([]string)[2] = "issuance" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := projectionFixture()
			tc.plant(m)
			_, e := CanonicalProjection(projectFixture(t, m))
			if e == nil || e.Error() != "CANONICAL_EVIDENCE_INVALID" {
				t.Fatal("evidence plant missed", e)
			}
		})
	}
}
