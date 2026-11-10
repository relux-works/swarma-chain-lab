package rehearsal

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// CanonicalProjection compares the declared observable contract only. It keeps
// verdicts, counters, closure and ordered roles; random identifiers/paths/times
// stay in the input evidence. Missing or failed observations cannot normalize
// into success. This does not certify pending crash or action cases.
func CanonicalProjection(raw []byte) ([]byte, error) {
	var r struct {
		Head      string            `json:"product_base"`
		Outcome   string            `json:"outcome"`
		Scenario  string            `json:"scenario"`
		Scope     string            `json:"canonical_scope"`
		Order     []string          `json:"canonical_order"`
		Crashes   map[string]string `json:"crash_cases"`
		Names     bool              `json:"core_names_registered"`
		Clean     bool              `json:"known_secret_log_scan"`
		Processes []struct {
			Absent bool `json:"absent"`
		} `json:"direct_processes"`
		Nodes []struct {
			Role, Datadir, P2P, Tip string
			Port                    int `json:"rpc_port"`
			Paused                  bool
		} `json:"independent_nodes"`
		Check struct {
			Stale   string `json:"stale_reason"`
			Live    string `json:"converged_verdict"`
			Tip     string `json:"converged_tip"`
			ID      string `json:"grant_id"`
			Method  string `json:"failed_method"`
			Anchor  string `json:"missing_anchor"`
			NoState bool   `json:"stale_no_admission_state"`
		} `json:"independent_verifier"`
		Closure struct {
			Ended     bool   `json:"journal_ended"`
			Destroyed bool   `json:"journal_destroyed"`
			Reason    string `json:"reason"`
			Cleared   bool   `json:"channel_cleared"`
			Removed   bool   `json:"helper_bootstrap_removed"`
			Idle      int64  `json:"application_idle_milliseconds"`
			Deadline  int64  `json:"relay_read_deadline_milliseconds"`
		} `json:"closure"`
		Underquote map[string]any `json:"underquote"`
		Wrong      struct {
			Reason    string `json:"reason"`
			Calls     int    `json:"node_calls"`
			Unchanged bool   `json:"journal_unchanged"`
		} `json:"wrong_executor"`
		Closed struct {
			Verdict string `json:"verdict"`
			Reason  string `json:"reason"`
			Durable bool   `json:"durable_closed"`
		} `json:"independent_closed"`
		NonW struct {
			Reason     string `json:"reason"`
			NoState    bool   `json:"no_admission_state"`
			Positive   string `json:"native_w_neighbour"`
			T          string `json:"consensus_accepted_t"`
			A          string `json:"consensus_accepted_a"`
			Commitment string `json:"commitment"`
			ID         string `json:"hostile_grant_id"`
			TW         bool   `json:"seal_transaction_w"`
		} `json:"non_w_anchor"`
		Mirror struct {
			Original bool   `json:"original_bytes"`
			After    bool   `json:"published_after_independent_live"`
			Hash     string `json:"sha256"`
		} `json:"verified_presentation_mirror"`
		RelayBoundary map[string]any `json:"relay_boundary"`
		StoreBoundary map[string]any `json:"store_boundary"`
		ModelBoundary map[string]any `json:"model_auth_boundary"`
		IssuerCrash   struct {
			Before  bool   `json:"before_a_killed"`
			Ack     bool   `json:"lost_ack_killed"`
			Same    bool   `json:"same_durable_bytes"`
			Effects int    `json:"broadcast_effects"`
			One     bool   `json:"single_operation"`
			ID      string `json:"txid"`
			Hash    string `json:"raw_sha256"`
			Outcome string `json:"outcome"`
		} `json:"issuer_crash"`
		BookingCrash struct {
			Seen     bool   `json:"confirmed_payment_seen"`
			Killed   bool   `json:"killed_before_record"`
			Same     bool   `json:"same_consent"`
			Receipts int    `json:"payment_receipts"`
			ID       string `json:"selected_payment"`
			Outcome  string `json:"outcome"`
		} `json:"booking_crash"`
		Accounting json.RawMessage `json:"model_accounting"`
		Calls      int             `json:"upstream_calls"`
	}
	bad := func() ([]byte, error) { return nil, fmt.Errorf("CANONICAL_EVIDENCE_INVALID") }
	if json.Unmarshal(raw, &r) != nil {
		return bad()
	}
	validHex := func(s string, n int) bool {
		b, e := hex.DecodeString(s)
		return e == nil && len(b) == n && hex.EncodeToString(b) == s
	}
	if !validHex(r.Head, 20) || r.Outcome != "PASS_INTERIM" || (r.Scenario != "revoke" && r.Scenario != "expiry") || r.Scope != "implemented V2 order, not a spec-adopted profile" || !r.Names || !r.Clean || len(r.Processes) == 0 || len(r.Nodes) != 4 || len(r.Accounting) == 0 {
		return bad()
	}
	for _, p := range r.Processes {
		if !p.Absent {
			return bad()
		}
	}
	roles := []string{"booking", "issuer", "gateway", "verifier"}
	dirs := map[string]bool{}
	ports := map[int]bool{}
	peers := map[string]bool{}
	for i, n := range r.Nodes {
		if n.Role != roles[i] || n.Datadir == "" || dirs[n.Datadir] || n.Port <= 0 || ports[n.Port] || n.P2P == "" || peers[n.P2P] || n.Paused || n.Tip != r.Check.Tip {
			return bad()
		}
		dirs[n.Datadir] = true
		ports[n.Port] = true
		peers[n.P2P] = true
	}
	if r.Check.Stale != "NODE_UNAVAILABLE" || r.Check.Live != "live" || !r.Check.NoState || r.Check.Method != "getrawtransaction" || !validHex(r.Check.Tip, 32) || !validHex(r.Check.ID, 32) || !validHex(r.Check.Anchor, 32) {
		return bad()
	}
	wantOrder := []string{"names", "booking/consent", "confirmed payment", "issuance", "independent verify", "gateway/station", "chat", "closure"}
	if len(r.Order) != len(wantOrder) {
		return bad()
	}
	for i, s := range wantOrder {
		if r.Order[i] != s {
			return bad()
		}
	}
	wantCrash := map[string]string{"gateway": "pending-DA1", "station": "pending-DA1", "issuer": "transport-barriers-pass", "booking": "transport-barrier-pass"}
	if len(r.Crashes) != len(wantCrash) {
		return bad()
	}
	for k, v := range wantCrash {
		if r.Crashes[k] != v {
			return bad()
		}
	}
	if !r.Closure.Ended || !r.Closure.Cleared || !r.Closure.Removed || r.Closure.Deadline != 90000 {
		return bad()
	}
	if r.Scenario == "expiry" && (r.Closure.Reason != "not_after" || r.Closure.Idle <= r.Closure.Deadline) {
		return bad()
	}
	if r.Scenario == "revoke" && r.Closure.Reason != "kernel_closed" {
		return bad()
	}
	if len(r.Underquote) != 5 || r.Underquote["disposition"] != "refund_review" {
		return bad()
	}
	for _, k := range []string{"issuance_absent", "selected_payment_absent", "package_unchanged", "slot_absent"} {
		if r.Underquote[k] != true {
			return bad()
		}
	}
	if r.Wrong.Reason != "GRANT_POLICY" || r.Wrong.Calls != 0 || !r.Wrong.Unchanged || r.Closed.Verdict != "refused" {
		return bad()
	}
	if r.Scenario == "revoke" && (r.Closed.Reason != "SEAL_SPENT" || !r.Closed.Durable) {
		return bad()
	}
	if r.Scenario == "expiry" && r.Closed.Reason != "EXPIRED" {
		return bad()
	}
	if !r.Mirror.Original || !r.Mirror.After || !validHex(r.Mirror.Hash, 32) {
		return bad()
	}
	if !r.NonW.TW || r.NonW.Reason != "W_WITNESS_REQUIRED" || !r.NonW.NoState || r.NonW.Positive != "LIVE" || !validHex(r.NonW.T, 32) || !validHex(r.NonW.A, 32) || !validHex(r.NonW.Commitment, 32) || !validHex(r.NonW.ID, 32) {
		return bad()
	}
	if !r.IssuerCrash.Before || !r.IssuerCrash.Ack || !r.IssuerCrash.Same || !r.IssuerCrash.One || r.IssuerCrash.Effects != 1 || !validHex(r.IssuerCrash.ID, 32) || !validHex(r.IssuerCrash.Hash, 32) || r.IssuerCrash.Outcome != "exact-bytes recovery" {
		return bad()
	}
	if !r.BookingCrash.Seen || !r.BookingCrash.Killed || !r.BookingCrash.Same || r.BookingCrash.Receipts != 1 || !validHex(r.BookingCrash.ID, 32) || r.BookingCrash.Outcome != "resume" {
		return bad()
	}
	if r.RelayBoundary["boundary"] != "signed-event-kind" || r.RelayBoundary["unsupported_kind"] != "invalid: event" || r.RelayBoundary["rejected_not_replayed"] != true || r.RelayBoundary["allowed_stored_and_replayed"] != true {
		return bad()
	}
	if r.StoreBoundary["boundary"] != "writer-reader-owner ACL" || r.StoreBoundary["outsider_upload_status"] != float64(403) || r.StoreBoundary["reader_delete_status"] != float64(403) {
		return bad()
	}
	for _, k := range []string{"refusal_replay_unchanged", "writer_upload_reader_get", "refused_delete_preserved_blob", "owner_delete"} {
		if r.StoreBoundary[k] != true {
			return bad()
		}
	}
	if r.ModelBoundary["boundary"] != "slot bearer" || r.ModelBoundary["wrong_credential"] != "AUTH" || r.ModelBoundary["upstream_unchanged"] != true {
		return bad()
	}
	var accounting any
	if json.Unmarshal(r.Accounting, &accounting) != nil {
		return bad()
	}
	return json.Marshal(map[string]any{"product_base": r.Head, "outcome": r.Outcome, "scenario": r.Scenario, "order": r.Order, "node_roles": roles, "verifier": map[string]any{"stale": r.Check.Stale, "live": r.Check.Live, "grant": "grant:rental", "anchor": "tx:issuance", "tip": "tip:converged", "no_admission_state": true}, "closure": map[string]any{"ended": r.Closure.Ended, "destroyed": r.Closure.Destroyed, "reason": r.Closure.Reason, "channel_cleared": r.Closure.Cleared, "helper_removed": r.Closure.Removed}, "accounting": accounting, "upstream_calls": r.Calls, "verified_presentation_mirror": "original SG1 bytes after independent live", "non_w_anchor": map[string]any{"reason": r.NonW.Reason, "no_admission_state": true, "native_w_neighbour": r.NonW.Positive, "t": "tx:control-native-seal", "seal_transaction_w": true, "a": "tx:nonw-anchor"}, "underquote": r.Underquote, "wrong_executor": r.Wrong, "independent_closed": r.Closed, "relay_boundary": r.RelayBoundary, "store_boundary": r.StoreBoundary, "model_auth_boundary": r.ModelBoundary, "issuer_crash": "before-A/lost-ACK; one broadcast, exact durable bytes", "booking_crash": "confirmed payment before record; resume, one receipt, same consent", "crash_cases": r.Crashes, "known_secret_log_scan": r.Clean, "all_recorded_processes_absent": true})
}
