//go:build linux

package service

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/model-proxy/service/internal/wire"
)

var brokerRefusalCases = []struct {
	code       Code
	connection bool
}{
	{"grant_malformed", false},
	{"grant_id_mismatch", false},
	{"grant_signature_invalid", false},
	{"grant_chain_malformed", false},
	{"grant_chain_broken", false},
	{"grant_not_narrowing", false},
	{"grant_root_unknown", false},
	{"grant_subject_invalid", false},
	{"grant_unsupported", false},
	{"grant_revoked", false},
	{"grant_expired", false},
	{"grant_not_yet_valid", false},
	{"secret_free_lease_required", false},
	{"request_malformed", false},
	{"bind_target_invalid", false},
	{"service_operation_conflict", false},
	{"service_binding_unknown", false},
	{"service_binding_mismatch", false},
	{"account_hold_active", false},
	{"hold_reason_unknown", false},
	{"account_hold_unknown", false},
	{"account_hold_not_found", false},
	{"principal_ledger_mismatch", true},
	{"lease_unbound", false},
	{"lease_grant_revoked", false},
	{"lease_caller_revoked", false},
	{"revocation_state_unavailable", false},
	{"allowlist_not_authorised", false},
	{"allowlist_generation_mismatch", false},
	{"allowlist_tuple_mismatch", false},
	{"allowlist_unavailable", false},
	{"peer_identity_unavailable", false},
	{"server_identity_mismatch", false},
	{"role_not_permitted", true},
	{"frame_too_large", false},
	{"version_unsupported", false},
	{"request_deadline_exceeded", false},
	{"account_exists", false},
	{"account_unknown", false},
	{"account_duplicate", false},
	{"account_store_keyring_refused", false},
	{"enrol_material_invalid", false},
	{"lease_not_authorised", false},
	{"lease_account_unknown", false},
	{"lease_harness_mismatch", false},
	{"lease_account_revoked", false},
	{"lease_reauth_required", false},
	{"lease_owner_unavailable", false},
	{"lease_channel_unsupported", false},
	{"lease_harness_unqualified", false},
	{"lease_binding_mismatch", false},
	{"lease_network_enforcement_unavailable", false},
	{"lease_not_owner", true},
	{"lease_not_active", false},
	{"renew_not_current", false},
	{"renew_timeout", false},
	{"renew_failed", false},
	{"external_token_init_failed", false},
	{"credential_source_conflict", false},
	{"credential_injection_unavailable", false},
}

func pinnedBrokerCodes(t *testing.T) map[Code]bool {
	t.Helper()
	source, err := parser.ParseFile(token.NewFileSet(), "internal/wire/types.go", nil, 0)
	if err != nil {
		t.Fatal("pinned wire source unavailable")
	}
	codes := make(map[Code]bool)
	for _, declaration := range source.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "Refuse" {
			continue
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			clause, ok := node.(*ast.CaseClause)
			if !ok {
				return true
			}
			for _, expression := range clause.List {
				literal, ok := expression.(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					t.Fatal("wire refusal set is not a literal closed set")
				}
				value, err := strconv.Unquote(literal.Value)
				if err != nil || codes[Code(value)] {
					t.Fatal("wire refusal code invalid or duplicated")
				}
				codes[Code(value)] = true
			}
			return true
		})
	}
	if len(codes) == 0 {
		t.Fatal("wire refusal set missing")
	}
	return codes
}

// Claim: every pinned wire refusal has exactly one reviewed socket policy;
// added, missing or duplicate codes fail independently of runtime dispatch.
// Each code is exercised on every client method with same/other-account controls.
// Renew/Check stop their target on error; Release/Hold stop use before sending.
func TestBrokerRefusalTable(t *testing.T) {
	codes := pinnedBrokerCodes(t)
	seen := make(map[Code]bool)
	for _, test := range brokerRefusalCases {
		if seen[test.code] || !codes[test.code] || wire.Refuse(string(test.code)).Code != string(test.code) {
			t.Fatal("refusal table contains a duplicate or non-wire code")
		}
		seen[test.code] = true
	}
	if len(seen) != len(codes) {
		t.Fatal("refusal table does not enumerate every wire code")
	}
	if codes[Code(fixtureMaterial)] {
		t.Fatal("unknown-code fixture is inside the pinned refusal set")
	}
	for _, test := range brokerRefusalCases {
		for _, method := range []string{"request", "renew", "check", "release", "hold"} {
			t.Run(string(test.code)+"/"+method, func(t *testing.T) {
				if refusal(string(test.code)) != test.code || sanitized(test.code) != test.code {
					t.Fatal("known broker diagnostic changed")
				}
				fixture := startFake(t)
				client := connect(t, fixture)
				target := lease(t, client)
				fixture.mu.Lock()
				fixture.leaseID = "lease-peer"
				fixture.mu.Unlock()
				peer, err := client.Request(context.Background(), "table-peer", caller)
				if err != nil {
					t.Fatal("same-account control refused")
				}
				otherCaller := caller
				otherCaller.Account, otherCaller.LaunchID = "account-b", "launch-b"
				fixture.mu.Lock()
				fixture.account, fixture.leaseID = otherCaller.Account, "lease-other"
				fixture.mu.Unlock()
				other, err := client.Request(context.Background(), "table-other", otherCaller)
				if err != nil || client.Check(context.Background(), target) != nil || client.Check(context.Background(), peer) != nil || client.Check(context.Background(), other) != nil {
					t.Fatal("live lease controls refused")
				}
				client.mu.Lock()
				epoch := client.epoch
				client.mu.Unlock()
				fixture.mu.Lock()
				fixture.account = caller.Account
				switch method {
				case "request":
					fixture.requestError = string(test.code)
				case "renew":
					fixture.renewError = string(test.code)
				case "check":
					fixture.checkError = string(test.code)
				case "release":
					fixture.releaseError = string(test.code)
				case "hold":
					fixture.holdError = string(test.code)
				}
				fixture.mu.Unlock()
				switch method {
				case "request":
					var result *Lease
					result, err = client.Request(context.Background(), "table-refused", caller)
					if result != nil {
						t.Fatal("refusal returned material")
					}
				case "renew":
					err = client.Renew(context.Background(), "table-refused", target)
				case "check":
					err = client.Check(context.Background(), target)
				case "release":
					err = client.Release(context.Background(), target)
				case "hold":
					err = client.Hold(context.Background(), "table-refused", target)
				}
				want := test.code
				if method == "hold" {
					want = ErrUnknown
				}
				if err != want {
					t.Fatal("refusal diagnostic changed")
				}
				client.mu.Lock()
				failed, changed := client.failed, client.epoch != epoch
				blocked := client.blocked[caller.Account]
				client.mu.Unlock()
				if failed != test.connection || changed != test.connection {
					t.Fatal("refusal changed connection scope")
				}
				accountClosed := method == "hold" || (method == "request" || method == "renew") && (test.code == "account_hold_active" || test.code == "account_hold_unknown")
				if blocked != accountClosed {
					t.Fatal("refusal changed account-block scope")
				}
				for _, check := range []struct {
					lease  *Lease
					closed bool
				}{
					{target, test.connection || accountClosed || method != "request"},
					{peer, test.connection || accountClosed},
					{other, test.connection},
				} {
					check.lease.mu.Lock()
					closed := check.lease.closed
					cleared := len(check.lease.value) == 0
					material := string(check.lease.value) == fixtureMaterial
					check.lease.mu.Unlock()
					if closed != check.closed || check.closed && !cleared || !check.closed && !material {
						t.Fatal("refusal changed cached lease scope")
					}
				}
				if test.connection {
					select {
					case <-fixture.done:
					case <-time.After(time.Second):
						t.Fatal("retired principal socket remained open")
					}
					if result, err := client.Request(context.Background(), "table-after-loss", otherCaller); result != nil || err != ErrInactive {
						t.Fatal("retired principal reopened")
					}
					return
				}
				fixture.mu.Lock()
				fixture.requestError, fixture.renewError, fixture.checkError, fixture.releaseError, fixture.holdError = "", "", "", "", ""
				fixture.account, fixture.leaseID = otherCaller.Account, "lease-fresh"
				fixture.mu.Unlock()
				if client.Check(context.Background(), other) != nil {
					t.Fatal("ordinary refusal invalidated another account")
				}
				if !accountClosed && client.Check(context.Background(), peer) != nil {
					t.Fatal("ordinary refusal invalidated a peer lease")
				}
				if method == "request" && !accountClosed && client.Check(context.Background(), target) != nil {
					t.Fatal("ordinary request refusal invalidated an existing lease")
				}
				if result, err := client.Request(context.Background(), "table-after-refusal", otherCaller); err != nil || result == nil {
					t.Fatal("ordinary refusal retired usable socket")
				}
			})
		}
	}
}
