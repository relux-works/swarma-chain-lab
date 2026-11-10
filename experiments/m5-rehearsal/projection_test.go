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
	return map[string]any{"relay_boundary": map[string]any{"boundary": "signed-event-kind", "unsupported_kind": "invalid: event", "rejected_not_replayed": true, "allowed_stored_and_replayed": true}, "store_boundary": map[string]any{"boundary": "writer-reader-owner ACL", "outsider_upload_status": 403, "reader_delete_status": 403, "refusal_replay_unchanged": true, "writer_upload_reader_get": true, "refused_delete_preserved_blob": true, "owner_delete": true}, "model_auth_boundary": map[string]any{"boundary": "slot bearer", "wrong_credential": "AUTH", "upstream_unchanged": true}, "issuer_crash": map[string]any{"before_a_killed": true, "lost_ack_killed": true, "same_durable_bytes": true, "single_operation": true, "broadcast_effects": 1, "txid": strings.Repeat("a", 64), "raw_sha256": strings.Repeat("b", 64), "outcome": "exact-bytes recovery"}, "booking_crash": map[string]any{"confirmed_payment_seen": true, "killed_before_record": true, "same_consent": true, "payment_receipts": 1, "selected_payment": strings.Repeat("c", 64), "outcome": "resume"}, "non_w_anchor": map[string]any{"seal_transaction_w": true, "reason": "W_WITNESS_REQUIRED", "no_admission_state": true, "native_w_neighbour": "LIVE", "consensus_accepted_t": strings.Repeat("2", 64), "consensus_accepted_a": strings.Repeat("3", 64), "commitment": strings.Repeat("4", 64), "hostile_grant_id": strings.Repeat("5", 64)}, "verified_presentation_mirror": map[string]any{"original_bytes": true, "published_after_independent_live": true, "sha256": strings.Repeat("1", 64)}, "underquote": map[string]any{"disposition": "refund_review", "issuance_absent": true, "selected_payment_absent": true, "package_unchanged": true, "slot_absent": true}, "wrong_executor": map[string]any{"reason": "GRANT_POLICY", "node_calls": 0, "journal_unchanged": true}, "independent_closed": map[string]any{"verdict": "refused", "reason": "SEAL_SPENT", "durable_closed": true}, "product_base": strings.Repeat("b", 40), "outcome": "PASS_INTERIM", "scenario": "revoke", "canonical_scope": "implemented V2 order, not a spec-adopted profile", "canonical_order": []string{"names", "booking/consent", "confirmed payment", "issuance", "independent verify", "gateway/station", "chat", "closure"}, "core_names_registered": true, "known_secret_log_scan": true, "direct_processes": []any{map[string]any{"pid": 123, "absent": true}}, "independent_nodes": nodes, "independent_verifier": map[string]any{"stale_reason": "NODE_UNAVAILABLE", "converged_verdict": "live", "converged_tip": strings.Repeat("a", 64), "grant_id": strings.Repeat("c", 64), "failed_method": "getrawtransaction", "missing_anchor": strings.Repeat("d", 64), "stale_no_admission_state": true}, "crash_cases": map[string]string{"gateway": "pending-DA1", "station": "pending-DA1", "issuer": "transport-barriers-pass", "booking": "transport-barrier-pass"}, "closure": map[string]any{"journal_ended": true, "journal_destroyed": false, "reason": "kernel_closed", "channel_cleared": true, "helper_bootstrap_removed": true, "application_idle_milliseconds": 1600, "relay_read_deadline_milliseconds": 90000}, "model_accounting": map[string]any{"phase": "revoked", "exposure": map[string]any{"requests": 2}, "observed": map[string]any{"input": 14, "output": 6}}, "upstream_calls": 2}
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
		{"relay-refused-event-stored", func(m map[string]any) { m["relay_boundary"].(map[string]any)["rejected_not_replayed"] = false }},
		{"store-refusal-write", func(m map[string]any) { m["store_boundary"].(map[string]any)["refusal_replay_unchanged"] = false }},
		{"model-auth-effect", func(m map[string]any) { m["model_auth_boundary"].(map[string]any)["upstream_unchanged"] = false }},
		{"issuer-double-effect", func(m map[string]any) { m["issuer_crash"].(map[string]any)["broadcast_effects"] = 2 }},
		{"booking-double-receipt", func(m map[string]any) { m["booking_crash"].(map[string]any)["payment_receipts"] = 2 }},
		{"booking-plant-not-applied", func(m map[string]any) { m["booking_crash"].(map[string]any)["killed_before_record"] = false }},
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

func projectionScenario(scenario string) map[string]any {
	m := projectionFixture()
	if scenario == "expiry" {
		m["scenario"] = scenario
		closure := m["closure"].(map[string]any)
		closure["reason"] = "not_after"
		closure["application_idle_milliseconds"] = 90001
		closed := m["independent_closed"].(map[string]any)
		closed["reason"] = "EXPIRED"
		closed["durable_closed"] = false // Expiry does not require a persisted revocation.
		m["model_accounting"].(map[string]any)["phase"] = "expired"
	}
	return m
}

// A completed expiry just beyond the relay deadline is valid; a longer idle
// duration normalizes equally. This is a report fixture, not a live timing test.
func TestCanonicalProjectionExpiry(t *testing.T) {
	m := projectionScenario("expiry")
	first, e := CanonicalProjection(projectFixture(t, m))
	if e != nil || len(first) == 0 {
		t.Fatal("expiry valid neighbor", e)
	}
	m["closure"].(map[string]any)["application_idle_milliseconds"] = 93000
	second, e := CanonicalProjection(projectFixture(t, m))
	if e != nil || !bytes.Equal(first, second) {
		t.Fatal("expiry idle normalization", e)
	}
}

// Each refusal starts with its own accepted scenario. Missing/unapplied crash
// evidence, altered scope, observation effects and closure boundaries must give
// the exact refusal and no projection, leaving the caller's report bytes intact.
// These assert comparator evidence rules, not execution of the reported events.
func TestCanonicalProjectionRefusals(t *testing.T) {
	type refusal struct {
		name, scenario string
		plant          func(map[string]any)
	}
	cases := []refusal{
		{"issuer-before-not-applied", "", func(m map[string]any) { m["issuer_crash"].(map[string]any)["before_a_killed"] = false }},
		{"issuer-ack-not-applied", "", func(m map[string]any) { m["issuer_crash"].(map[string]any)["lost_ack_killed"] = false }},
		{"issuer-status-pending", "", func(m map[string]any) { m["crash_cases"].(map[string]string)["issuer"] = "pending-barrier" }},
		{"gateway-pending-as-pass", "", func(m map[string]any) { m["crash_cases"].(map[string]string)["gateway"] = "PASS" }},
		{"extra-crash-case", "", func(m map[string]any) { m["crash_cases"].(map[string]string)["other"] = "PASS" }},
		{"scope-label", "", func(m map[string]any) { m["canonical_scope"] = "spec-adopted profile" }},
		{"stale-reason", "", func(m map[string]any) { m["independent_verifier"].(map[string]any)["stale_reason"] = "GRANT_POLICY" }},
		{"paused-verifier", "", func(m map[string]any) { m["independent_nodes"].([]any)[3].(map[string]any)["paused"] = true }},
		{"relay-deadline", "", func(m map[string]any) { m["closure"].(map[string]any)["relay_read_deadline_milliseconds"] = 89999 }},
		{"non-W-admission-state", "", func(m map[string]any) { m["non_w_anchor"].(map[string]any)["no_admission_state"] = false }},
		{"wrong-executor-node-call", "", func(m map[string]any) { m["wrong_executor"].(map[string]any)["node_calls"] = 1 }},
		{"changed-booking-consent", "", func(m map[string]any) { m["booking_crash"].(map[string]any)["same_consent"] = false }},
		{"reader-delete-accepted", "", func(m map[string]any) { m["store_boundary"].(map[string]any)["reader_delete_status"] = 200 }},
		{"revoke-not-durable", "revoke", func(m map[string]any) { m["independent_closed"].(map[string]any)["durable_closed"] = false }},
		{"revoke-closure-reason", "revoke", func(m map[string]any) { m["closure"].(map[string]any)["reason"] = "not_after" }},
		{"revoke-verifier-reason", "revoke", func(m map[string]any) { m["independent_closed"].(map[string]any)["reason"] = "EXPIRED" }},
		{"expiry-closure-reason", "expiry", func(m map[string]any) { m["closure"].(map[string]any)["reason"] = "kernel_closed" }},
		{"expiry-idle-at-deadline", "expiry", func(m map[string]any) { m["closure"].(map[string]any)["application_idle_milliseconds"] = 90000 }},
		{"expiry-idle-below-deadline", "expiry", func(m map[string]any) { m["closure"].(map[string]any)["application_idle_milliseconds"] = 89999 }},
		{"expiry-idle-absent", "expiry", func(m map[string]any) { delete(m["closure"].(map[string]any), "application_idle_milliseconds") }},
		{"expiry-verifier-reason", "expiry", func(m map[string]any) { m["independent_closed"].(map[string]any)["reason"] = "SEAL_SPENT" }},
	}
	for _, field := range []string{"issuer_crash", "booking_crash", "crash_cases"} {
		cases = append(cases,
			refusal{field + "-absent", "", func(m map[string]any) { delete(m, field) }},
			refusal{field + "-null", "", func(m map[string]any) { m[field] = nil }},
			refusal{field + "-empty", "", func(m map[string]any) { m[field] = map[string]any{} }},
		)
	}
	for _, scenario := range []string{"revoke", "expiry"} {
		for _, tc := range cases {
			if tc.scenario != "" && tc.scenario != scenario {
				continue
			}
			t.Run(scenario+"/"+tc.name, func(t *testing.T) {
				m := projectionScenario(scenario)
				if projected, e := CanonicalProjection(projectFixture(t, m)); e != nil || len(projected) == 0 {
					t.Fatal("refusal valid neighbor", e)
				}
				tc.plant(m)
				raw := projectFixture(t, m)
				before := append([]byte(nil), raw...)
				projected, e := CanonicalProjection(raw)
				if e == nil || e.Error() != "CANONICAL_EVIDENCE_INVALID" || projected != nil {
					t.Fatalf("projection refusal missed: projection=%q error=%v", projected, e)
				}
				if !bytes.Equal(raw, before) {
					t.Fatal("refusal mutated evidence bytes")
				}
			})
		}
	}
}
