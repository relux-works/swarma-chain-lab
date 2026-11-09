package smoke

import (
	"context"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	booking "github.com/relux-works/swarma-chain-lab/experiments/rental-booking"
)

// Request is public, immutable and canonical. SHA256 of its exact JSON bytes
// binds every response to this run, environment, stage, identity and deadline.
type Request struct {
	Version      int                       `json:"version"`
	RunID        string                    `json:"run_id"`
	Mode         string                    `json:"mode"`
	Scenario     string                    `json:"scenario"`
	Stage        string                    `json:"stage"`
	Sequence     int                       `json:"sequence"`
	ConfigSHA256 string                    `json:"config_sha256"`
	CreatedMS    int64                     `json:"created_ms"`
	DeadlineMS   int64                     `json:"deadline_ms"`
	Slot         string                    `json:"slot"`
	Contract     *booking.ContractV2       `json:"contract,omitempty"`
	Grant        *rental.GrantPresentation `json:"grant,omitempty"`
	Checks       []string                  `json:"checks"`
	Numbers      map[string]int64          `json:"numbers"`
	Hashes       map[string]string         `json:"hashes"`
}

func (q Request) SHA256() string { return rental.Hash(encode(q)) }

// Receipt has no free-form messages or raw command output. Hashes are evidence
// locators, not evidence verification. Numbers are selected public observations.
type Receipt struct {
	RequestSHA256 string            `json:"request_sha256"`
	ObservedMS    int64             `json:"observed_ms"`
	Checks        map[string]bool   `json:"checks"`
	Numbers       map[string]int64  `json:"numbers"`
	Hashes        map[string]string `json:"hashes"`
}
type Operator interface {
	Observe(context.Context, Request) (Receipt, error)
}
type OperatorFunc func(context.Context, Request) (Receipt, error)

func (f OperatorFunc) Observe(c context.Context, q Request) (Receipt, error) { return f(c, q) }

// ValidateReceipt checks the assertion set and fresh binding, not the truth of
// the operator's claim. Consumers must retain that distinction in every report.
func ValidateReceipt(q Request, r Receipt, previousMS, nowMS int64) error {
	if r.RequestSHA256 != q.SHA256() {
		return refuse("RECEIPT_BINDING")
	}
	if r.ObservedMS < q.CreatedMS || r.ObservedMS < previousMS || r.ObservedMS > nowMS || r.ObservedMS > q.DeadlineMS || nowMS > q.DeadlineMS {
		return refuse("RECEIPT_TIME")
	}
	if len(r.Checks) != len(q.Checks) || len(r.Numbers) != len(q.Numbers) || len(r.Hashes) != len(q.Hashes) {
		return refuse("RECEIPT_FIELDS")
	}
	for _, k := range q.Checks {
		if !r.Checks[k] {
			return refuse("CHECK_" + k)
		}
	}
	for k, want := range q.Numbers {
		got, ok := r.Numbers[k]
		if !ok || (want >= 0 && got != want) || (want == -1 && got < 0) || (want == -2 && got <= 0) || (want == -3 && got != 0 && got != 1) {
			return refuse("NUMBER_" + k)
		}
	}
	for k, want := range q.Hashes {
		got, ok := r.Hashes[k]
		if !ok || !digest(got) || (want != "" && got != want) {
			return refuse("HASH_" + k)
		}
	}
	return nil
}

func requirements(stage string, p profile, scenario string) ([]string, map[string]int64, map[string]string) {
	checks := map[string][]string{
		"preflight":           {"isolated_regtest", "public_configs", "coin_sets", "own_node_routes", "converged_selected_block", "fixture_responses_policy", "no_existing_slot"},
		"pregrant":            {"no_gateway_slot", "foreign_consent_unchanged"},
		"unconfirmed_payment": {"exact_payment", "payment_unconfirmed", "issuance_absent", "presentation_absent", "no_gateway_slot"},
		"issue":               {"payment_confirmed", "original_outbox", "native_signer", "unconfirmed_presentation_absent", "seal_confirmed", "own_node_ancestry", "converged_payment_seal"},
		"running":             {"started", "bootstrap_payload_bound", "payload_executable", "wrong_credential_auth", "wrong_pin_transport", "no_negative_upstream", "neighbor_valid"},
		"caps":                {"responses_shape", "no_pending", "private_closure_probe_retained"},
		"revoke":              {"native_v2_revoke", "seal_before_object", "seal_after_json_null", "converged_spend"},
		"close":               {"journal_ended", "channel_cleared", "model_revoked", "no_pending", "fresh_closed_auth", "closed_auth_no_text", "wrong_pin_transport", "no_new_delivery", "helper_owned_cleanup", "pid_ended"},
		"restart":             {"approved_restart", "no_journal_reset", "durable_accounting", "fresh_closed_auth", "closed_auth_no_text", "no_pending", "model_revoked", "no_new_delivery"},
	}[stage]
	checks = append([]string{}, checks...)
	if stage == "close" && scenario == "expiry" {
		checks = append(checks, "reason_not_after", "observed_after_not_after")
	}
	if p.mode == "host" {
		extra := map[string][]string{
			"preflight": {"release_signature", "exact_release_binaries", "linux_units_active", "real_helper_reviewed", "uid_separation", "ownership_modes", "egress_policy", "mtls_pins", "admin_valid_peer", "admin_wrong_uid_refused", "helper_valid_peer", "helper_wrong_uid_refused", "helper_wrong_policy_refused", "no_overlay_or_fake"},
			"issue":     {"running_signer_consumed", "mirror_hash_index_equal"},
			"revoke":    {"append_only_intake", "single_running_signer"},
			"running":   {"starting_then_started", "linux_admin_prepare_activate", "real_r4_create_start", "slot_linux_uid", "slot_cgroup", "bootstrap_0600", "slot_no_custody_access"},
			"close":     {"cgroup_ended", "slot_access_revoked", "storage_policy_completed", "physical_erasure_limits_recorded", "helper_independent_cleanup"},
		}[stage]
		checks = append(checks, extra...)
	}
	nums := map[string]int64{}
	hashes := map[string]string{}
	switch stage {
	case "preflight":
		hashes["selected_block"] = ""
		hashes["manifest"] = ""
	case "issue":
		hashes["original_outbox"] = ""
		hashes["payment_txid"] = ""
		hashes["selected_block"] = ""
		hashes["presentation"] = ""
	case "running":
		nums["upstream_calls"] = 1
		nums["payload_pid"] = -2
		hashes["payload_binary"] = ""
		hashes["bootstrap"] = ""
		if p.mode == "host" {
			nums["slot_uid"] = -2
			hashes["cgroup"] = ""
		}
	case "caps", "close", "restart":
		nums["upstream_calls"] = int64(p.requests)
		nums["requests"] = int64(p.requests)
		nums["input_tokens"] = int64(p.requests * 7)
		nums["output_tokens"] = int64(p.requests * 3)
		nums["pending"] = 0
		nums["seen_rumors"] = -1
		if stage == "close" {
			nums["gateway_destroyed"] = -3
		}
	case "revoke":
		hashes["revoke_item"] = ""
		hashes["spend_txid"] = ""
		hashes["selected_block"] = ""
	}
	return checks, nums, hashes
}
func (r *runner) observe(ctx context.Context, stage string, deadline time.Time) (Receipt, error) {
	checks, nums, hashes := requirements(stage, r.p, r.c.Scenario)
	if stage == "preflight" {
		hashes["manifest"] = r.c.EvidenceSHA256
	}
	if (stage == "close" || stage == "restart") && r.seenRumors >= 0 {
		nums["seen_rumors"] = r.seenRumors
	}
	q := Request{Version: 1, RunID: r.report.RunID, Mode: r.p.mode, Scenario: r.c.Scenario, Stage: stage, Sequence: len(r.report.Operator) + 1, ConfigSHA256: r.report.ConfigSHA256, CreatedMS: time.Now().UnixMilli(), DeadlineMS: deadline.UnixMilli(), Slot: r.p.slot, Checks: checks, Numbers: nums, Hashes: hashes}
	if r.contract != nil {
		c := *r.contract
		q.Contract = &c
	}
	if r.grant != nil {
		g := *r.grant
		q.Grant = &g
	}
	c, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	receipt, e := r.op.Observe(c, q)
	if e != nil {
		return receipt, refuse("OPERATOR_" + stage)
	}
	if e = ValidateReceipt(q, receipt, r.lastReceipt, time.Now().UnixMilli()); e != nil {
		return receipt, e
	}
	if stage == "caps" {
		r.seenRumors = receipt.Numbers["seen_rumors"]
	}
	r.lastReceipt = receipt.ObservedMS
	r.report.Operator = append(r.report.Operator, Attestation{q, receipt})
	return receipt, nil
}

// Propagate only fixed checker codes. Arbitrary operator/tool errors may contain
// private paths or credentials and must never enter a report.
func operatorFailure(q Request, e error) error {
	allowed := []string{"JSON_SIZE", "JSON_SHAPE", "JSON_TRAILING", "JSON_SCHEMA", "RECEIPT_BINDING", "RECEIPT_TIME", "RECEIPT_FIELDS", "RECEIPT_FILE", "RECEIPT_MISSING", "OUTPUT_CREATE", "OUTPUT_WRITE"}
	for _, k := range q.Checks {
		allowed = append(allowed, "CHECK_"+k)
	}
	for k := range q.Numbers {
		allowed = append(allowed, "NUMBER_"+k)
	}
	for k := range q.Hashes {
		allowed = append(allowed, "HASH_"+k)
	}
	if c, ok := e.(Code); ok {
		for _, name := range allowed {
			if string(c) == name {
				return refuse("OPERATOR_" + q.Stage + "_" + name)
			}
		}
	}
	return refuse("OPERATOR_" + q.Stage)
}
