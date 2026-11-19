package wire

import "encoding/json"

type Request struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
	ID     string          `json:"request_id"`
}
type Error struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details"`
}

func (e *Error) Error() string { return e.Code }
func Refuse(code string) *Error {
	switch code {
	case "grant_malformed", "grant_id_mismatch", "grant_signature_invalid", "grant_chain_malformed", "grant_chain_broken", "grant_not_narrowing", "grant_root_unknown", "grant_subject_invalid", "grant_unsupported", "grant_revoked", "grant_expired", "grant_not_yet_valid":
	case "secret_free_lease_required", "request_malformed", "bind_target_invalid", "service_operation_conflict", "service_binding_unknown", "service_binding_mismatch", "account_hold_active", "hold_reason_unknown", "account_hold_unknown", "account_hold_not_found", "principal_ledger_mismatch", "lease_unbound", "lease_grant_revoked", "lease_caller_revoked", "revocation_state_unavailable":
	case "allowlist_not_authorised", "allowlist_generation_mismatch", "allowlist_tuple_mismatch", "allowlist_unavailable":
	case "peer_identity_unavailable", "server_identity_mismatch", "role_not_permitted", "frame_too_large", "version_unsupported", "request_deadline_exceeded", "account_exists", "account_unknown", "account_duplicate", "account_store_keyring_refused", "enrol_material_invalid", "lease_not_authorised", "lease_account_unknown", "lease_harness_mismatch", "lease_account_revoked", "lease_reauth_required", "lease_owner_unavailable", "lease_channel_unsupported", "lease_harness_unqualified", "lease_binding_mismatch", "lease_network_enforcement_unavailable", "lease_not_owner", "lease_not_active", "renew_not_current", "renew_timeout", "renew_failed", "external_token_init_failed", "credential_source_conflict", "credential_injection_unavailable":
	default:
		code = "lease_owner_unavailable"
	}
	return &Error{code, "request refused", map[string]any{}}
}

type Hello struct {
	Versions []int  `json:"versions"`
	Profile  string `json:"profile"`
}

// AllowlistRequest asks only about the exact served static policy, not a lease.
type AllowlistRequest struct {
	TargetUID          uint32  `json:"target_uid"`
	Account            string  `json:"account"`
	Profile            string  `json:"profile"`
	Harness            string  `json:"harness"`
	Channel            string  `json:"channel"`
	Binding            Binding `json:"credential_binding"`
	ExpectedGeneration uint64  `json:"expected_policy_generation"`
}

type AllowlistResult struct {
	Tuple      AllowlistRequest `json:"tuple"`
	Generation uint64           `json:"policy_generation"`
	Decision   string           `json:"decision"`
}
type Binding struct {
	Digest           string `json:"digest"`
	Harness          string `json:"harness"`
	Profile          string `json:"profile"`
	Account          string `json:"account"`
	Channel          string `json:"channel"`
	Endpoint         string `json:"endpoint"`
	ExecutableSHA256 string `json:"executable_sha256"`
	PolicyGeneration uint64 `json:"policy_generation"`
}
type Executor struct {
	Capabilities []string `json:"capabilities"`
	Version      string   `json:"version"`
}
type LeaseRequest struct {
	Harness  string          `json:"harness"`
	Profile  string          `json:"profile"`
	Account  string          `json:"account"`
	Channel  string          `json:"channel"`
	Binding  Binding         `json:"credential_binding"`
	Network  json.RawMessage `json:"network"`
	LaunchID string          `json:"launch_id"`
	Executor Executor        `json:"executor"`
}
type Renew struct {
	LeaseID        string `json:"lease_id"`
	RejectedSHA256 string `json:"rejected_sha256"`
}
type Release struct {
	LeaseID string `json:"lease_id"`
}
type Payload struct {
	Channel     string `json:"channel"`
	AccessToken string `json:"access_token"`
	AccountID   string `json:"chatgpt_account_id"`
	PlanType    string `json:"plan_type,omitempty"`
}
type LeaseResult struct {
	LeaseID         string  `json:"lease_id"`
	Account         string  `json:"account"`
	Harness         string  `json:"harness"`
	Channel         string  `json:"channel"`
	Payload         Payload `json:"payload"`
	TokenExpiresAt  string  `json:"token_expires_at"`
	AuthorizedUntil string  `json:"authorized_until"`
	Renewable       bool    `json:"renewable"`
}
type ReleaseResult struct {
	LeaseID string `json:"lease_id"`
	State   string `json:"state"`
}
type AccountStatus struct {
	Account        string  `json:"account"`
	State          string  `json:"state"`
	SingleOwner    bool    `json:"single_owner"`
	TokenExpiresAt *string `json:"token_expires_at"`
	LastRefusal    *string `json:"last_refusal"`
}
type Status struct {
	Generation uint64          `json:"policy_generation"`
	Accounts   []AccountStatus `json:"accounts"`
}
