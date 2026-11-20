//go:build linux && gateway_lab

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"github.com/relux-works/swarma-chain-lab/experiments/model-proxy/service"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/model-proxy/service/labtest"
)

func attemptRunResponse(harness *commandHarness, body string) {
	harness.responseHeader = http.Header{"Content-Type": {"text/event-stream"}, "Request-Id": {"control-request"}}
	harness.responseBody = func() io.ReadCloser { return io.NopCloser(strings.NewReader(body)) }
}
func attemptRunLedger(test *testing.T, harness *commandHarness) map[string]any {
	test.Helper()
	head, err := os.ReadFile(filepath.Join(harness.attempts.Root, "accounting", "head"))
	if err != nil {
		test.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(harness.attempts.Root, "accounting", "*.json"))
	if err != nil {
		test.Fatal(err)
	}
	for _, name := range files {
		raw, err := os.ReadFile(name)
		if err != nil {
			test.Fatal(err)
		}
		if labtest.Digest(raw) == string(head) {
			var ledger map[string]any
			decoder := json.NewDecoder(strings.NewReader(string(raw)))
			decoder.UseNumber()
			if decoder.Decode(&ledger) != nil {
				test.Fatal("ledger decode")
			}
			return ledger
		}
	}
	test.Fatal("protected head has no complete snapshot")
	return nil
}
func attemptRunRead(test *testing.T, harness *commandHarness, conn net.Conn) (int, string) {
	test.Helper()
	harness.request(test, conn)
	if conn.SetReadDeadline(time.Now().Add(time.Second)) != nil {
		test.Fatal("deadline")
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return 0, ""
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(response.Body)
	return response.StatusCode, string(raw)
}

// TestLabAttemptRunBounds proves run's real HTTP path settles complete usage, admits an exact-fit reservation, and refuses retries at cost/count bounds without extra forwards.
func TestLabAttemptRunBounds(test *testing.T) {
	for _, mode := range []string{"control", "count", "cost", "fits"} {
		test.Run(mode, func(test *testing.T) {
			harness := commandFixture(test)
			switch mode {
			case "count":
				harness.attempts.Plan["max_invocations"] = int64(1)
			case "cost":
				harness.attempts.Plan["max_total_cost_usd"] = "10.559999"
			case "fits":
				harness.attempts.Plan["max_total_cost_usd"] = "10.560000"
			}
			attemptRunResponse(harness, labtest.AttemptSSE())
			harness.start(test, false)
			conn := harness.dial(test)
			defer conn.Close()
			status, body := attemptRunRead(test, harness, conn)
			if mode == "cost" {
				if status < 400 || harness.calls.Load() != 0 {
					test.Fatal("unreserved command forward")
				}
				return
			}
			if status != 200 || body != labtest.AttemptSSE() || harness.calls.Load() != 1 {
				test.Fatal("bounded command control", status)
			}
			ledger := attemptRunLedger(test, harness)
			attempt := labtest.Object(ledger["attempts"].([]any)[0])
			if attempt["state"] != "settled" || attempt["settled_micro_usd"] != json.Number("3720") || attempt["reservation_cost_usd"] != "10.560000" {
				test.Fatal("run failed authoritative settlement")
			}
			status, _ = attemptRunRead(test, harness, conn)
			if mode == "control" {
				if status != 200 || harness.calls.Load() != 2 {
					test.Fatal("new attempt control refused")
				}
			} else if status < 400 || harness.calls.Load() != 1 {
				test.Fatal("run retried past a bound")
			}
		})
	}
}

// TestLabAttemptRunUnknown proves missing/inconsistent usage closes the real listener and every downstream connection, retaining a full-reservation sticky UNKNOWN instead of retrying.
func TestLabAttemptRunUnknown(test *testing.T) {
	for _, mode := range []string{"control", "missing", "partial", "model", "cache", "regression"} {
		test.Run(mode, func(test *testing.T) {
			harness := commandFixture(test)
			body := labtest.AttemptSSE()
			switch mode {
			case "missing":
				body = "data: genuine error\n\n"
			case "partial":
				body = strings.ReplaceAll(body, "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n", "")
			case "model":
				body = strings.ReplaceAll(body, "claude-opus-5-5", "unapproved-model")
			case "cache":
				body = strings.ReplaceAll(body, `"cache_creation_input_tokens":400`, `"cache_creation_input_tokens":0`)
			case "regression":
				body = strings.ReplaceAll(body, `"output_tokens":16`, `"output_tokens":9`)
			}
			attemptRunResponse(harness, body)
			harness.start(test, false)
			conn := harness.dial(test)
			idle := harness.dial(test)
			started := time.Now()
			status, _ := attemptRunRead(test, harness, conn)
			if mode == "control" {
				defer conn.Close()
				defer idle.Close()
				if status != 200 || harness.returned.Load() {
					test.Fatal("complete command control stopped")
				}
				return
			}
			harness.closed(test, []net.Conn{conn, idle}, started)
			attemptRunStopped(test, harness, started.Add(time.Second))
			ledger := attemptRunLedger(test, harness)
			attempt := labtest.Object(ledger["attempts"].([]any)[0])
			if ledger["status"] != "unknown" || attempt["state"] != "unknown" || attempt["settled_micro_usd"] != json.Number("10560000") || harness.calls.Load() != 1 {
				test.Fatal("uncertainty refunded or retried")
			}
		})
	}
}

// TestLabAttemptRunDeadlines proves both independently selected wall bounds cancel an in-flight upstream and close all downstream sockets within the existing one-second teardown bound.
func TestLabAttemptRunDeadlines(test *testing.T) {
	for _, mode := range []string{"per-attempt", "whole-group", "approval"} {
		test.Run(mode, func(test *testing.T) {
			harness := commandFixture(test)
			if mode == "approval" {
				labtest.Object(harness.attempts.Approval["approval"])["expires_at"] = time.Now().Add(1500 * time.Millisecond).UTC().Format(time.RFC3339Nano)
			} else if mode == "per-attempt" {
				harness.attempts.Plan["max_wall_time_per_invocation_ms"] = int64(200)
			} else {
				harness.attempts.Plan["max_wall_time_per_invocation_ms"] = int64(1500)
				harness.attempts.Plan["max_wall_time_total_ms"] = int64(1500)
			}
			harness.start(test, false)
			conn := harness.dial(test)
			idle := harness.dial(test)
			partial := harness.dial(test)
			_, _ = partial.Write([]byte("POST /v1/messages?beta=true HTTP/1.1\r\n"))
			started := time.Now()
			harness.request(test, conn)
			var upstreamDone <-chan struct{}
			select {
			case call := <-harness.entered:
				upstreamDone = call.Done()
			case <-time.After(time.Second):
				test.Fatal("no active command control")
			}
			if mode == "whole-group" {
				raw, err := os.ReadFile(filepath.Join(harness.attempts.Root, "accounting", "group.json"))
				if err != nil {
					test.Fatal(err)
				}
				var group struct {
					Started int64 `json:"group_started_monotonic_ms"`
				}
				if json.Unmarshal(raw, &group) != nil {
					test.Fatal("group clock")
				}
				started = time.Now().Add(time.Duration(group.Started+1500-labtest.AttemptClock(test)) * time.Millisecond)
			}
			if mode == "approval" {
				started, _ = time.Parse(time.RFC3339Nano, labtest.Object(harness.attempts.Approval["approval"])["expires_at"].(string))
			}
			harness.closed(test, []net.Conn{conn, idle, partial}, started)
			attemptRunStopped(test, harness, started.Add(time.Second))
			select {
			case <-upstreamDone:
			default:
				test.Fatal("bound left upstream active")
			}
			ledger := attemptRunLedger(test, harness)
			if ledger["status"] != "unknown" || len(ledger["attempts"].([]any)) != 1 {
				test.Fatal("deadline lost consumed ordinal")
			}
		})
	}
}

// TestLabAttemptRunAdmission proves protected approval, price, launch and accepted-native joins are independently required before run can open its generation listener.
func TestLabAttemptRunAdmission(test *testing.T) {
	cases := []struct {
		name   string
		change func(*labtest.AttemptFixture)
	}{
		{"control", func(*labtest.AttemptFixture) {}},
		{"unapproved-plan", func(fixture *labtest.AttemptFixture) {
			fixture.Put("approved-plan.sha256", []byte("sha256:"+strings.Repeat("0", 64)))
		}},
		{"unapproved-release", func(fixture *labtest.AttemptFixture) {
			fixture.Put("approved-release.sha256", []byte("sha256:"+strings.Repeat("0", 64)))
		}},
		{"unapproved-access", func(fixture *labtest.AttemptFixture) {
			fixture.Put("approved-access.sha256", []byte("sha256:"+strings.Repeat("0", 64)))
		}},
		{"missing-native-acceptance", func(fixture *labtest.AttemptFixture) {
			fixture.Put("accepted-start.sha256", []byte("sha256:"+strings.Repeat("0", 64)))
		}},
		{"unapproved-budget", func(fixture *labtest.AttemptFixture) { fixture.Plan["live_budget_approved"] = false; fixture.Rebind() }},
		{"output-profile", func(fixture *labtest.AttemptFixture) {
			fixture.Plan["max_output_tokens_per_invocation"] = int64(127999)
			fixture.Rebind()
		}},
		{"model-profile", func(fixture *labtest.AttemptFixture) { fixture.Plan["model"] = "other-model"; fixture.Rebind() }},
		{"wall-order", func(fixture *labtest.AttemptFixture) {
			fixture.Plan["max_wall_time_per_invocation_ms"] = int64(30001)
			fixture.Rebind()
		}},
		{"client-profile", func(fixture *labtest.AttemptFixture) {
			fixture.Plan["client_profile_sha256"] = "sha256:" + strings.Repeat("0", 64)
			fixture.Rebind()
		}},
		{"wire-profile", func(fixture *labtest.AttemptFixture) {
			fixture.Plan["wire_profile_sha256"] = "sha256:" + strings.Repeat("0", 64)
			fixture.Rebind()
		}},
		{"pinned-price", func(fixture *labtest.AttemptFixture) {
			labtest.Object(fixture.Price["rates"])["output_usd_per_million"] = "19.000000"
			labtest.Object(labtest.Object(fixture.Release["assets"].([]any)[1])["members"].([]any)[0])["sha256"] = labtest.Digest(labtest.Encode(test, fixture.Price))
			fixture.Rebind()
		}},
		{"price-member-missing", func(fixture *labtest.AttemptFixture) {
			fixture.Release["assets"] = fixture.Release["assets"].([]any)[:1]
			fixture.Rebind()
		}},
		{"price-member-duplicate", func(fixture *labtest.AttemptFixture) {
			fixture.Release["assets"] = append(fixture.Release["assets"].([]any), labtest.Clone(test, labtest.Object(fixture.Release["assets"].([]any)[1])))
			fixture.Rebind()
		}},
		{"price-member-product", func(fixture *labtest.AttemptFixture) {
			labtest.Object(fixture.Release["assets"].([]any)[1])["product"] = "broker"
			fixture.Rebind()
		}},
		{"price-member-mode", func(fixture *labtest.AttemptFixture) {
			labtest.Object(labtest.Object(fixture.Release["assets"].([]any)[1])["members"].([]any)[0])["mode"] = "0755"
			fixture.Rebind()
		}},
		{"price-member-digest", func(fixture *labtest.AttemptFixture) {
			labtest.Object(labtest.Object(fixture.Release["assets"].([]any)[1])["members"].([]any)[0])["sha256"] = "sha256:" + strings.Repeat("0", 64)
			fixture.Rebind()
		}},
		{"executor-release", func(fixture *labtest.AttemptFixture) {
			fixture.Plan["executor_sha256"] = "sha256:" + strings.Repeat("0", 64)
			fixture.Rebind()
		}},
		{"second-build", func(fixture *labtest.AttemptFixture) {
			labtest.Object(fixture.Release["assets"].([]any)[0])["second_build_equal"] = false
			fixture.Rebind()
		}},
		{"release-expired", func(fixture *labtest.AttemptFixture) {
			labtest.Object(fixture.Release["owner_approval"])["expires_at"] = time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)
			fixture.Rebind()
		}},
		{"approval-expired", func(fixture *labtest.AttemptFixture) {
			labtest.Object(fixture.Approval["approval"])["expires_at"] = time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)
			fixture.Rebind()
		}},
		{"access-expired", func(fixture *labtest.AttemptFixture) {
			fixture.Access["valid_until"] = time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)
			fixture.Rebind()
		}},
		{"access-principal", func(fixture *labtest.AttemptFixture) {
			labtest.Object(fixture.Access["guest_and_control_plane"].([]any)[0])["controller"] = "agent"
			fixture.Rebind()
		}},
		{"access-endpoint", func(fixture *labtest.AttemptFixture) {
			labtest.Object(fixture.Access["endpoint"])["no_agent_process"] = false
			fixture.Rebind()
		}},
		{"access-vendor", func(fixture *labtest.AttemptFixture) {
			labtest.Object(fixture.Access["vendor"])["roster_unchanged"] = false
			fixture.Rebind()
		}},
		{"available-cap", func(fixture *labtest.AttemptFixture) { fixture.Put("available-cap-micro-usd", []byte("49999999")) }},
		{"launch-operation", func(fixture *labtest.AttemptFixture) {
			fixture.Launch["operation_id"] = strings.Repeat("0", 32)
			fixture.Write()
		}},
		{"launch-generation", func(fixture *labtest.AttemptFixture) {
			fixture.Launch["target_generation"] = strings.Repeat("0", 32)
			fixture.Write()
		}},
		{"launch-context", func(fixture *labtest.AttemptFixture) {
			fixture.Launch["context"] = labtest.Clone(test, labtest.Object(fixture.Launch["context"]))
			labtest.Object(fixture.Launch["context"])["account"] = "other-account"
			fixture.Write()
		}},
		{"launch-input-duplicate", func(fixture *labtest.AttemptFixture) {
			fixture.Launch["input_pins"] = append(fixture.Launch["input_pins"].([]any), fixture.Launch["input_pins"].([]any)[0])
			fixture.Write()
		}},
		{"launch-input-digest", func(fixture *labtest.AttemptFixture) {
			labtest.Object(fixture.Launch["input_pins"].([]any)[0])["sha256"] = "sha256:" + strings.Repeat("0", 64)
			fixture.Write()
		}},
		{"native-caller-execution", func(fixture *labtest.AttemptFixture) {
			labtest.Object(fixture.Source.Objects["swarma-broker-lab-authority/1"]["worker"])["execution_id"] = "other-native-start"
			fixture.Rebind()
		}},
		{"native-uid-overflow", func(fixture *labtest.AttemptFixture) {
			labtest.Object(fixture.Observation["start"])["uid"] = int64(4294967295)
			fixture.Write()
		}},
		{"native-pid-overflow", func(fixture *labtest.AttemptFixture) {
			labtest.Object(fixture.Observation["receipts"].([]any)[0])["pid"] = int64(4194305)
			labtest.Object(fixture.Observation["debits"].([]any)[0])["pid"] = int64(4194305)
			fixture.Write()
		}},
		{"native-session-overflow", func(fixture *labtest.AttemptFixture) {
			labtest.Object(fixture.Observation["receipts"].([]any)[0])["session_id"] = int64(4194305)
			fixture.Write()
		}},
		{"native-phase", func(fixture *labtest.AttemptFixture) {
			labtest.Object(fixture.Observation["start"])["phase"] = "terminal"
			fixture.Write()
		}},
		{"native-incomplete", func(fixture *labtest.AttemptFixture) { fixture.Observation["complete"] = false; fixture.Write() }},
		{"native-generation-current", func(fixture *labtest.AttemptFixture) {
			labtest.Object(fixture.Observation["store"])["generation_current"] = false
			fixture.Write()
		}},
		{"native-start", func(fixture *labtest.AttemptFixture) {
			labtest.Object(fixture.Observation["start"])["start_id"] = "other-start"
			fixture.Write()
		}},
		{"native-receipt", func(fixture *labtest.AttemptFixture) {
			labtest.Object(fixture.Observation["receipts"].([]any)[0])["execution_id"] = "other-start"
			fixture.Write()
		}},
		{"native-debit", func(fixture *labtest.AttemptFixture) {
			labtest.Object(fixture.Observation["debits"].([]any)[0])["generation"] = strings.Repeat("0", 32)
			fixture.Write()
		}},
	}

	for _, name := range []string{"plan-extra", "plan-count-zero", "plan-count-over", "plan-wall-zero", "plan-wall-over", "plan-usd-zero", "plan-usd-fraction", "second-build-digest", "approval-context", "release-context", "approval-seal", "release-seal", "off-vm-future", "approval-after-off", "release-after-off", "access-seal", "access-context", "access-observed-future", "access-approved-after-observed", "access-window-future", "access-window-expired", "access-seal-expired", "access-vendor-audit", "access-vendor-principal", "access-empty-principal", "cap-over-hard", "cap-noncanonical", "launch-heads", "launch-approval-pin", "launch-release-pin", "launch-access-pin", "launch-target-pin", "manager-receipt-id", "manager-receipt-digest", "manager-uncommitted", "native-operation", "native-start-operation", "native-response-start", "native-plan", "native-generation", "native-boot", "native-receipt-boot", "native-debit-boot", "native-receipt-epoch", "native-debit-epoch", "native-debit-execution", "native-pid", "native-start-time", "native-time-future", "native-debit-time-future", "native-empty-receipts", "native-empty-debits", "native-extra-receipt", "native-invalidations", "native-stops"} {
		cases = append(cases, struct {
			name   string
			change func(*labtest.AttemptFixture)
		}{name, func(fixture *labtest.AttemptFixture) {
			zero := "sha256:" + strings.Repeat("0", 64)
			future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
			past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
			start := labtest.Object(fixture.Observation["start"])
			receipt := labtest.Object(fixture.Observation["receipts"].([]any)[0])
			debit := labtest.Object(fixture.Observation["debits"].([]any)[0])
			switch name {
			case "plan-extra":
				fixture.Plan["unexpected_field"] = true
			case "plan-count-zero":
				fixture.Plan["max_invocations"] = int64(0)
			case "plan-count-over":
				fixture.Plan["max_invocations"] = int64(257)
			case "plan-wall-zero":
				fixture.Plan["max_wall_time_per_invocation_ms"] = int64(0)
			case "plan-wall-over":
				fixture.Plan["max_wall_time_total_ms"] = int64(900001)
			case "plan-usd-zero":
				fixture.Plan["max_total_cost_usd"] = "0.000000"
			case "plan-usd-fraction":
				fixture.Plan["max_total_cost_usd"] = "50.00000"
			case "release-index":
				fixture.Release["contract_index_sha256"] = zero
			case "second-build-digest":
				labtest.Object(fixture.Release["assets"].([]any)[0])["second_build_sha256"] = zero
			case "approval-context":
				fixture.Approval["context"] = labtest.Clone(test, labtest.Object(fixture.Approval["context"]))
				labtest.Object(fixture.Approval["context"])["account"] = "different-account"
			case "release-context":
				fixture.Release["context"] = labtest.Clone(test, labtest.Object(fixture.Release["context"]))
				labtest.Object(fixture.Release["context"])["account"] = "different-account"
			case "off-vm-future":
				fixture.Approval["off_vm_now"] = future
			case "approval-after-off":
				labtest.Object(fixture.Approval["approval"])["approved_at"] = time.Now().UTC().Format(time.RFC3339Nano)
			case "release-after-off":
				labtest.Object(fixture.Release["owner_approval"])["approved_at"] = time.Now().UTC().Format(time.RFC3339Nano)
			case "access-context":
				fixture.Access["context"] = labtest.Clone(test, labtest.Object(fixture.Access["context"]))
				labtest.Object(fixture.Access["context"])["account"] = "different-account"
			case "access-observed-future":
				fixture.Access["observed_at"] = future
			case "access-approved-after-observed":
				labtest.Object(fixture.Access["owner_approval"])["approved_at"] = future
			case "access-window-future":
				fixture.Access["window_start"] = future
			case "access-window-expired":
				fixture.Access["window_end"] = past
			case "access-seal-expired":
				labtest.Object(fixture.Access["owner_approval"])["expires_at"] = past
			case "access-vendor-audit":
				labtest.Object(fixture.Access["vendor"])["audit_complete"] = false
			case "access-vendor-principal":
				labtest.Object(fixture.Access["vendor_principals"].([]any)[0])["controller"] = "agent"
			case "access-empty-principal":
				fixture.Access["guest_and_control_plane"] = []any{}
			case "cap-over-hard":
				labtest.Object(fixture.Access["vendor"])["hard_limit_minor_units"] = int64(1)
			}
			if !strings.HasPrefix(name, "native-") && !strings.HasPrefix(name, "launch-") && !strings.HasPrefix(name, "manager-") {
				fixture.Rebind()
			}
			pins := labtest.Object(fixture.Launch["pins"])
			join := labtest.Object(fixture.Launch["manager_join"])
			managerReceipt := labtest.Object(join["receipt"])
			switch name {
			case "approval-seal":
				labtest.Object(fixture.Approval["approval"])["approved_sha256"] = zero
				fixture.Plan["approval_record_sha256"] = labtest.Digest(labtest.Encode(test, fixture.Approval))
			case "release-seal":
				labtest.Object(fixture.Release["owner_approval"])["approved_sha256"] = zero
			case "access-seal":
				labtest.Object(fixture.Access["owner_approval"])["approved_sha256"] = zero
			case "launch-heads":
				fixture.Launch["predecessor_heads"] = labtest.Clone(test, labtest.Object(fixture.Launch["predecessor_heads"]))
				labtest.Object(labtest.Object(fixture.Launch["predecessor_heads"])["authority"])["sequence"] = int64(9)
			case "launch-approval-pin":
				pins["off_vm_approval_sha256"] = zero
			case "launch-release-pin":
				pins["release_set_sha256"] = zero
			case "launch-access-pin":
				pins["access_attestation_sha256"] = zero
			case "launch-target-pin":
				pins["invocation_sha256"] = zero
			case "manager-receipt-id":
				managerReceipt["request_id"] = strings.Repeat("0", 32)
			case "manager-receipt-digest":
				managerReceipt["request_sha256"] = zero
			case "manager-uncommitted":
				managerReceipt["result"] = "unknown"
			case "native-operation":
				fixture.Observation["operation_id"] = "other-operation"
			case "native-start-operation":
				start["operation_id"] = "other-operation"
			case "native-response-start":
				fixture.Observation["start_id"] = "other-start"
			case "native-plan":
				start["plan_sha256"] = zero
			case "native-generation":
				start["generation"] = strings.Repeat("0", 32)
			case "native-boot":
				labtest.Object(fixture.Observation["manager"])["boot_id"] = "00000000-0000-4000-8000-000000000000"
			case "native-receipt-boot":
				receipt["boot_id"] = "00000000-0000-4000-8000-000000000000"
			case "native-debit-boot":
				debit["boot_id"] = "00000000-0000-4000-8000-000000000000"
			case "native-receipt-epoch":
				receipt["epoch"] = int64(2)
			case "native-debit-epoch":
				debit["epoch"] = int64(2)
			case "native-debit-execution":
				debit["execution_id"] = "other-start"
			case "native-pid":
				debit["pid"] = int64(2)
			case "native-start-time":
				debit["start_time"] = int64(2)
			case "native-time-future":
				fixture.Observation["observed_monotonic_ms"] = int64(9007199254740991)
			case "native-debit-time-future":
				debit["committed_ms"] = int64(9007199254740991)
			case "native-empty-receipts":
				fixture.Observation["receipts"] = []any{}
			case "native-empty-debits":
				fixture.Observation["debits"] = []any{}
			case "native-extra-receipt":
				fixture.Observation["receipts"] = append(fixture.Observation["receipts"].([]any), receipt)
			case "native-invalidations":
				fixture.Observation["invalidations"] = []any{map[string]any{"unexpected_field": true}}
			case "native-stops":
				fixture.Observation["stops"] = []any{map[string]any{"unexpected_field": true}}
			}
			if strings.HasSuffix(name, "-seal") {
				fixture.Rebind(strings.TrimSuffix(name, "-seal"))
			}
			fixture.Write()
			if name == "cap-noncanonical" {
				fixture.Put("available-cap-micro-usd", []byte("0100000000"))
			}
		}})
	}

	for _, name := range []string{"plan-approval-chain", "approval-release-chain", "approval-invocation-chain", "release-invocation-chain", "release-index"} {
		cases = append(cases, struct {
			name   string
			change func(*labtest.AttemptFixture)
		}{name, func(fixture *labtest.AttemptFixture) {
			zero := "sha256:" + strings.Repeat("0", 64)
			if name == "release-index" {
				fixture.Release["contract_index_sha256"] = "sha256:4f9a81562d391153764b5ae75d7914cf83f03c1bb3d956461211d8eb36f6e7d8"
				fixture.Source.ReleaseIndex = fixture.Release["contract_index_sha256"].(string)
			}
			if name == "release-invocation-chain" {
				fixture.Release["invocation_sha256"] = zero
			}
			seal := func(record map[string]any, member string) {
				target := labtest.Clone(test, record)
				delete(target, member)
				labtest.Object(record[member])["approved_sha256"] = labtest.Digest(labtest.Encode(test, map[string]any{"domain": "swarma-broker-lab-approval-target/1", "record": target}))
			}
			seal(fixture.Release, "owner_approval")
			fixture.Approval["release_set_sha256"] = labtest.Digest(labtest.Encode(test, fixture.Release))
			if name == "approval-release-chain" {
				fixture.Approval["release_set_sha256"] = zero
			}
			if name == "approval-invocation-chain" {
				fixture.Approval["invocation_sha256"] = zero
			}
			seal(fixture.Approval, "approval")
			fixture.Plan["approval_record_sha256"] = labtest.Digest(labtest.Encode(test, fixture.Approval))
			if name == "plan-approval-chain" {
				fixture.Plan["approval_record_sha256"] = zero
			}
			pins := labtest.Object(fixture.Launch["pins"])
			pins["off_vm_approval_sha256"] = labtest.Digest(labtest.Encode(test, fixture.Approval))
			pins["release_set_sha256"] = labtest.Digest(labtest.Encode(test, fixture.Release))
			for _, value := range fixture.Launch["input_pins"].([]any) {
				pin := labtest.Object(value)
				if pin["name"] == "bounded-invocation" {
					pin["sha256"] = labtest.Digest(labtest.Encode(test, fixture.Plan))
				}
			}
			fixture.Write()
		}})
	}
	for _, entry := range cases {
		test.Run(entry.name, func(test *testing.T) {
			harness := commandFixture(test)
			attemptRunResponse(harness, labtest.AttemptSSE())
			harness.afterPrepare = func() {
				entry.change(harness.attempts)
				labtest.Object(harness.attempts.Observation["start"])["plan_sha256"] = labtest.Digest(labtest.Encode(test, harness.attempts.Launch))
				harness.attempts.Write()
				switch entry.name {
				case "unapproved-plan", "unapproved-release", "unapproved-access", "missing-native-acceptance", "available-cap", "cap-noncanonical", "native-plan":
					entry.change(harness.attempts)
				}
				harness.attempts.RewriteGroup()
			}
			harness.start(test, false)
			if entry.name == "control" {
				conn := harness.dial(test)
				defer conn.Close()
				if status, _ := attemptRunRead(test, harness, conn); status != 200 || harness.calls.Load() != 1 {
					test.Fatal("admission control")
				}
				return
			}
			select {
			case err := <-harness.result:
				if err == nil {
					test.Fatal("invalid admission succeeded")
				}
			case <-time.After(time.Second):
				test.Fatal("invalid admission opened or retained listener")
			}
			harness.result <- io.EOF
			if harness.calls.Load() != 0 {
				test.Fatal("invalid approval/native join forwarded")
			}
			if _, err := net.DialTimeout("unix", harness.socket, 50*time.Millisecond); err == nil {
				test.Fatal("invalid admission listener opened")
			}
		})
	}
}

// TestLabAttemptRunCurrent proves byte-only approval/access changes on the same immutable-mode inode cancel real idle/in-flight use, without transient permission or replacement errors masking the current-proof comparison.
func TestLabAttemptRunCurrent(test *testing.T) {
	for _, mode := range []string{"idle-plan", "active-plan", "idle-access", "active-access"} {
		test.Run(mode, func(test *testing.T) {
			harness := commandFixture(test)
			active := strings.HasPrefix(mode, "active")
			if !active {
				attemptRunResponse(harness, labtest.AttemptSSE())
			}
			name := "approved-plan.sha256"
			if strings.HasSuffix(mode, "access") {
				name = "approved-access.sha256"
			}
			path := filepath.Join(harness.attempts.Root, name)
			if os.Chmod(path, 0600) != nil {
				test.Fatal("trusted fixture write preparation")
			}
			writer, err := os.OpenFile(path, os.O_WRONLY, 0)
			if err != nil {
				test.Fatal(err)
			}
			defer writer.Close()
			if os.Chmod(path, 0400) != nil {
				test.Fatal("restore protected mode before command")
			}
			harness.start(test, false)
			conn := harness.dial(test)
			idle := harness.dial(test)
			var upstreamDone <-chan struct{}
			if active {
				harness.request(test, conn)
				select {
				case call := <-harness.entered:
					upstreamDone = call.Done()
				case <-time.After(time.Second):
					test.Fatal("missing active control")
				}
			} else {
				if status, _ := attemptRunRead(test, harness, conn); status != 200 {
					test.Fatal("valid current control")
				}
			}
			started := time.Now()
			changed := []byte("sha256:" + strings.Repeat("0", 64))
			if count, err := writer.WriteAt(changed, 0); err != nil || count != len(changed) {
				test.Fatal("byte-only proof change")
			}
			harness.closed(test, []net.Conn{conn, idle}, started)
			attemptRunStopped(test, harness, started.Add(time.Second))
			if active {
				select {
				case <-upstreamDone:
				default:
					test.Fatal("changed approval left upstream active")
				}
			}
			ledger := attemptRunLedger(test, harness)
			if ledger["status"] != "unknown" || harness.calls.Load() != 1 {
				test.Fatal("changed authority was not sticky UNKNOWN", ledger["status"], harness.calls.Load())
			}
		})
	}
}

func attemptRunStopped(test *testing.T, harness *commandHarness, deadline time.Time) {
	test.Helper()
	select {
	case err := <-harness.result:
		harness.result <- err
		if !errors.Is(err, service.ErrUnknown) {
			test.Fatal("uncertain command exit did not retain UNKNOWN", err)
		}
	case <-time.After(time.Until(deadline)):
		test.Fatal("UNKNOWN settlement exceeded teardown budget")
	}
}

// TestLabAttemptRunReplay proves restart is status-only and missing, rewound, malformed, retargeted or contradictory durable history is UNKNOWN without a listener or another upstream attempt.
func TestLabAttemptRunReplay(test *testing.T) {
	for _, mode := range []string{"control", "missing-head", "rewound-head", "orphan", "previous", "sequence", "release-join", "ordinal", "reservation-output", "reservation-cost", "settled-cost", "complete", "usage-digest", "usage-extra", "usage-cache", "prefix", "noncanonical", "duplicate", "null"} {
		test.Run(mode, func(test *testing.T) {
			harness := commandFixture(test)
			harness.attempts.Plan["max_invocations"] = int64(1)
			attemptRunResponse(harness, labtest.AttemptSSE())
			harness.start(test, false)
			conn := harness.dial(test)
			if status, _ := attemptRunRead(test, harness, conn); status != 200 {
				test.Fatal("replay control")
			}
			conn.Close()
			harness.cancel()
			select {
			case <-harness.result:
			case <-time.After(time.Second):
				test.Fatal("control did not stop")
			}
			harness.result <- io.EOF
			ledger := labtest.Clone(test, attemptRunLedger(test, harness))
			attempt := labtest.Object(ledger["attempts"].([]any)[0])
			accounting := filepath.Join(harness.attempts.Root, "accounting")
			switch mode {
			case "missing-head":
				if os.Remove(filepath.Join(accounting, "head")) != nil {
					test.Fatal("head fault")
				}
			case "rewound-head":
				raw, err := os.ReadFile(filepath.Join(accounting, "000000001.json"))
				if err != nil {
					test.Fatal(err)
				}
				harness.attempts.Put("accounting/head", []byte(labtest.Digest(raw)))
			case "orphan":
				harness.attempts.Put("accounting/000000004.json", labtest.Encode(test, ledger))
			case "previous":
				ledger["previous_sha256"] = "sha256:" + strings.Repeat("0", 64)
			case "sequence":
				ledger["sequence"] = int64(2)
			case "release-join":
				ledger["release_set_sha256"] = "sha256:" + strings.Repeat("0", 64)
			case "ordinal":
				attempt["ordinal"] = int64(2)
			case "reservation-output":
				attempt["reservation_output_tokens"] = int64(127999)
			case "reservation-cost":
				attempt["reservation_cost_usd"] = "10.559999"
			case "settled-cost":
				attempt["settled_micro_usd"] = int64(0)
			case "complete":
				attempt["usage_complete"] = false
			case "usage-digest":
				attempt["usage_sha256"] = "sha256:" + strings.Repeat("0", 64)
			case "usage-extra":
				labtest.Object(attempt["usage"])["unexpected_field"] = true
				attempt["usage_sha256"] = labtest.Digest(labtest.Encode(test, attempt["usage"]))
			case "usage-cache":
				labtest.Object(attempt["usage"])["cache_creation_input_tokens"] = int64(399)
				attempt["usage_sha256"] = labtest.Digest(labtest.Encode(test, attempt["usage"]))
			case "prefix":
				attempt["started_monotonic_ms"] = attempt["started_monotonic_ms"].(int64) + 1
			}

			if mode == "ordinal" || mode == "reservation-cost" {
				raw, err := os.ReadFile(filepath.Join(accounting, "000000002.json"))
				if err != nil {
					test.Fatal(err)
				}
				var reserved map[string]any
				decoder := json.NewDecoder(strings.NewReader(string(raw)))
				decoder.UseNumber()
				if decoder.Decode(&reserved) != nil {
					test.Fatal("reserved decode")
				}
				prior := labtest.Object(reserved["attempts"].([]any)[0])
				field := "ordinal"
				if mode == "reservation-cost" {
					field = "reservation_cost_usd"
				}
				prior[field] = attempt[field]
				raw = labtest.Encode(test, reserved)
				harness.attempts.Put("accounting/000000002.json", raw)
				ledger["previous_sha256"] = labtest.Digest(raw)
			}
			switch mode {
			case "control", "missing-head", "rewound-head", "orphan":
			default:
				raw := labtest.Encode(test, ledger)
				if mode == "noncanonical" {
					raw = append(raw, '\n')
				}
				if mode == "duplicate" {
					raw = append([]byte(`{"status":"open",`), raw[1:]...)
				}
				if mode == "null" {
					raw = []byte(strings.Replace(string(raw), `"usage_complete":true`, `"usage_complete":null`, 1))
				}
				harness.attempts.Put("accounting/000000003.json", raw)
				harness.attempts.Put("accounting/head", []byte(labtest.Digest(raw)))
			}
			var mapping brokerMapping
			if json.Unmarshal(harness.mapping, &mapping) != nil {
				test.Fatal("mapping")
			}
			manifest := attemptCrashManifest{Config: harness.config, Mapping: mapping, Socket: harness.socket, Root: harness.attempts.Root}
			for _, path := range harness.paths {
				manifest.Paths = append(manifest.Paths, *path)
			}
			calls := 0
			err := run(context.Background(), "config", "mapping", harness.socket, harness.paths, attemptCrashInputs(manifest, commandTransport(func(*http.Request) (*http.Response, error) { calls++; return nil, io.ErrUnexpectedEOF })))
			if mode == "control" {
				if !errors.Is(err, service.ErrInactive) {
					test.Fatal("repeated start was not status-only", err)
				}
			} else if !errors.Is(err, service.ErrUnknown) {
				test.Fatal("replay did not fail UNKNOWN", err)
			}
			if calls != 0 || harness.calls.Load() != 1 {
				test.Fatal("replay forwarded")
			}
			if listener, err := net.DialTimeout("unix", harness.socket, 25*time.Millisecond); err == nil {
				listener.Close()
				test.Fatal("replay opened listener")
			}
		})
	}
}

// TestLabAttemptRunPreauthorization proves protected paths/group identity and the preauthorization total-clock latch are checked before the real run can open a listener, beside an admitted control.
func TestLabAttemptRunPreauthorization(test *testing.T) {
	for _, mode := range []string{"control", "root-mode", "record-mode", "record-link", "accounting-link", "missing-group", "stale-group", "group-boot", "group-plan"} {
		test.Run(mode, func(test *testing.T) {
			harness := commandFixture(test)
			attemptRunResponse(harness, labtest.AttemptSSE())
			harness.afterPrepare = func() {
				groupPath := filepath.Join(harness.attempts.Root, "accounting", "group.json")
				switch mode {
				case "root-mode":
					if os.Chmod(harness.attempts.Root, 0750) != nil {
						test.Fatal("mode")
					}
				case "record-mode":
					if os.Chmod(filepath.Join(harness.attempts.Root, "plan.json"), 0600) != nil {
						test.Fatal("mode")
					}
				case "record-link":
					if os.Link(filepath.Join(harness.attempts.Root, "plan.json"), filepath.Join(harness.attempts.Root, "alias")) != nil {
						test.Fatal("link")
					}
				case "accounting-link":
					from := filepath.Join(harness.attempts.Root, "accounting")
					to := filepath.Join(harness.attempts.Root, "relocated")
					if os.Rename(from, to) != nil || os.Symlink("relocated", from) != nil {
						test.Fatal("link")
					}
				case "missing-group":
					if os.Remove(groupPath) != nil {
						test.Fatal("remove group")
					}
				case "stale-group", "group-boot", "group-plan":
					raw, err := os.ReadFile(groupPath)
					if err != nil {
						test.Fatal(err)
					}
					var group map[string]any
					decoder := json.NewDecoder(strings.NewReader(string(raw)))
					decoder.UseNumber()
					if decoder.Decode(&group) != nil {
						test.Fatal("group")
					}
					if mode == "stale-group" {
						group["group_started_monotonic_ms"] = labtest.AttemptClock(test) - harness.attempts.Plan["max_wall_time_total_ms"].(int64) - 1
					}
					if mode == "group-boot" {
						group["boot_id"] = "00000000-0000-4000-8000-000000000000"
					}
					if mode == "group-plan" {
						group["plan_sha256"] = "sha256:" + strings.Repeat("0", 64)
					}
					harness.attempts.Put("accounting/group.json", labtest.Encode(test, group))
				}
			}
			harness.start(test, false)
			if mode == "control" {
				conn := harness.dial(test)
				defer conn.Close()
				if status, _ := attemptRunRead(test, harness, conn); status != 200 {
					test.Fatal("preauthorization control")
				}
				return
			}
			select {
			case err := <-harness.result:
				if err == nil {
					test.Fatal("invalid preauthorization succeeded")
				}
				harness.result <- err
			case <-time.After(time.Second):
				test.Fatal("invalid preauthorization opened or retained run")
			}
			if harness.listener != nil || harness.calls.Load() != 0 {
				test.Fatal("preauthorization gate was late")
			}
		})
	}
}

// TestLabAttemptStatusChild executes the actual read-only command flags in an owned subprocess; the parent observes the real exit code and exact stdout bytes.
func TestLabAttemptStatusChild(test *testing.T) {
	root := os.Getenv("LAB_ATTEMPT_STATUS_ROOT")
	if root == "" {
		test.Skip("subprocess fixture only")
	}
	flag.CommandLine = flag.NewFlagSet("lab", flag.ContinueOnError)
	os.Args = []string{"lab", "--attempt-status", "--attempt-root", root, "--operation", os.Getenv("LAB_ATTEMPT_STATUS_OPERATION"), "--plan-sha256", os.Getenv("LAB_ATTEMPT_STATUS_PLAN"), "--ordinal", os.Getenv("LAB_ATTEMPT_STATUS_ORDINAL")}
	main()
	os.Exit(0)
}

// TestLabAttemptRunStatus proves the shipped command reconciles exact IDs without a lease/forward/write, distinguishes bounded settled status from sticky UNKNOWN, and rejects wrong operation/plan/ordinal beside the valid control.
func TestLabAttemptRunStatus(test *testing.T) {
	for _, unknown := range []bool{false, true} {
		test.Run(map[bool]string{false: "settled", true: "unknown"}[unknown], func(test *testing.T) {
			harness := commandFixture(test)
			harness.attempts.Plan["max_invocations"] = int64(1)
			body := labtest.AttemptSSE()
			if unknown {
				body = "data: genuine error\n\n"
			}
			attemptRunResponse(harness, body)
			harness.start(test, false)
			conn := harness.dial(test)
			started := time.Now()
			attemptRunRead(test, harness, conn)
			conn.Close()
			if unknown {
				attemptRunStopped(test, harness, started.Add(time.Second))
			}
			head, err := os.ReadFile(filepath.Join(harness.attempts.Root, "accounting", "head"))
			if err != nil {
				test.Fatal(err)
			}
			for _, mode := range []string{"control", "operation", "plan", "ordinal"} {
				test.Run(mode, func(test *testing.T) {
					operation := harness.attempts.Plan["operation_id"].(string)
					plan := labtest.Digest(labtest.Encode(test, harness.attempts.Plan))
					ordinal := "1"
					if mode == "operation" {
						operation = strings.Repeat("0", 32)
					}
					if mode == "plan" {
						plan = "sha256:" + strings.Repeat("0", 64)
					}
					if mode == "ordinal" {
						ordinal = "2"
					}
					child := exec.Command(os.Args[0], "-test.run=^TestLabAttemptStatusChild$")
					child.Env = append(os.Environ(), "LAB_ATTEMPT_STATUS_ROOT="+harness.attempts.Root, "LAB_ATTEMPT_STATUS_OPERATION="+operation, "LAB_ATTEMPT_STATUS_PLAN="+plan, "LAB_ATTEMPT_STATUS_ORDINAL="+ordinal)
					raw, err := child.Output()
					code := 0
					if err != nil {
						exit, ok := err.(*exec.ExitError)
						if !ok {
							test.Fatal(err)
						}
						code = exit.ExitCode()
					}
					expected := 0
					if unknown {
						expected = 2
					}
					if mode != "control" {
						expected = 1
					}
					if code != expected {
						test.Fatal("read-only command exit", code, expected)
					}
					if mode == "control" {
						if labtest.Digest(raw) != string(head) {
							test.Fatal("status changed or wrapped current snapshot")
						}
					} else if len(raw) != 0 {
						test.Fatal("wrong tuple returned evidence")
					}
					current, err := os.ReadFile(filepath.Join(harness.attempts.Root, "accounting", "head"))
					if err != nil || string(current) != string(head) || harness.calls.Load() != 1 {
						test.Fatal("reconciliation wrote/forwarded")
					}
				})
			}
		})
	}
}

// TestLabAttemptRunStatusBoot proves a fully rejoined foreign-boot history is UNKNOWN at the real status command, not merely a stale-digest refusal; its actual-boot control returns exact settled bytes without a forward.
func TestLabAttemptRunStatusBoot(test *testing.T) {
	harness := commandFixture(test)
	harness.attempts.Plan["max_invocations"] = int64(1)
	attemptRunResponse(harness, labtest.AttemptSSE())
	harness.start(test, false)
	conn := harness.dial(test)
	if status, _ := attemptRunRead(test, harness, conn); status != 200 {
		test.Fatal("boot control")
	}
	conn.Close()
	harness.cancel()
	select {
	case <-harness.result:
	case <-time.After(time.Second):
		test.Fatal("control did not stop")
	}
	harness.result <- io.EOF
	statusCommand := func(expected int) {
		test.Helper()
		child := exec.Command(os.Args[0], "-test.run=^TestLabAttemptStatusChild$")
		child.Env = append(os.Environ(), "LAB_ATTEMPT_STATUS_ROOT="+harness.attempts.Root, "LAB_ATTEMPT_STATUS_OPERATION="+harness.attempts.Plan["operation_id"].(string), "LAB_ATTEMPT_STATUS_PLAN="+labtest.Digest(labtest.Encode(test, harness.attempts.Plan)), "LAB_ATTEMPT_STATUS_ORDINAL=1")
		raw, err := child.Output()
		code := 0
		if err != nil {
			exit, ok := err.(*exec.ExitError)
			if !ok {
				test.Fatal(err)
			}
			code = exit.ExitCode()
		}
		if code != expected {
			test.Fatal("status boot exit", code, expected)
		}
		if expected == 0 && len(raw) == 0 {
			test.Fatal("missing status control")
		}
		if expected != 0 && len(raw) != 0 {
			test.Fatal("foreign boot returned conclusive evidence")
		}
	}
	statusCommand(0)
	foreign := "00000000-0000-4000-8000-000000000000"
	observation := harness.attempts.Observation
	labtest.Object(observation["manager"])["boot_id"] = foreign
	for _, key := range []string{"receipts", "debits"} {
		for _, value := range observation[key].([]any) {
			labtest.Object(value)["boot_id"] = foreign
		}
	}
	harness.attempts.Write()
	read := func(name string) map[string]any {
		raw, err := os.ReadFile(filepath.Join(harness.attempts.Root, "accounting", name))
		if err != nil {
			test.Fatal(err)
		}
		var record map[string]any
		decoder := json.NewDecoder(strings.NewReader(string(raw)))
		decoder.UseNumber()
		if decoder.Decode(&record) != nil {
			test.Fatal("disk record")
		}
		return record
	}
	group := read("group.json")
	group["boot_id"] = foreign
	harness.attempts.Put("accounting/group.json", labtest.Encode(test, group))
	previous := ""
	for _, name := range []string{"000000001.json", "000000002.json", "000000003.json"} {
		ledger := read(name)
		ledger["boot_id"] = foreign
		ledger["group_sha256"] = labtest.Digest(labtest.Encode(test, group))
		ledger["start_observation_sha256"] = labtest.Digest(labtest.Encode(test, observation))
		ledger["start_receipt"] = observation["receipts"].([]any)[0]
		ledger["start_debit"] = observation["debits"].([]any)[0]
		if previous != "" {
			ledger["previous_sha256"] = previous
		}
		raw := labtest.Encode(test, ledger)
		harness.attempts.Put("accounting/"+name, raw)
		previous = labtest.Digest(raw)
	}
	harness.attempts.Put("accounting/head", []byte(previous))
	statusCommand(2)
	if harness.calls.Load() != 1 {
		test.Fatal("status boot check forwarded")
	}
}

// TestLabAttemptRunStalledFsync proves wall cancellation never waits behind a blocked durable reservation or startup commit, with no unreserved forward and no lost ordinal after release.
func TestLabAttemptRunStalledFsync(test *testing.T) {
	for _, mode := range []string{"per-attempt", "whole-group", "startup"} {
		test.Run(mode, func(test *testing.T) {
			harness := commandFixture(test)
			if mode == "per-attempt" {
				harness.attempts.Plan["max_wall_time_per_invocation_ms"] = int64(200)
			} else {
				harness.attempts.Plan["max_wall_time_per_invocation_ms"] = int64(1500)
				harness.attempts.Plan["max_wall_time_total_ms"] = int64(1500)
			}
			entered := make(chan time.Time, 1)
			release := make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			defer unblock()
			blocked := false
			harness.attemptIO.SyncFile = func(file *os.File) error {
				if err := file.Sync(); err != nil {
					return err
				}
				if filepath.Base(file.Name()) != "head.next" || blocked {
					return nil
				}
				_, err := os.Stat(filepath.Join(harness.attempts.Root, "accounting", "head"))
				if (mode == "startup") != os.IsNotExist(err) {
					return nil
				}
				blocked = true
				entered <- time.Now()
				<-release
				return nil
			}
			harness.start(test, false)
			var connections []net.Conn
			if mode != "startup" {
				live := harness.dial(test)
				idle := harness.dial(test)
				partial := harness.dial(test)
				_, _ = partial.Write([]byte("POST /v1/messages?beta=true HTTP/1.1\r\n"))
				connections = []net.Conn{live, idle, partial}
				harness.request(test, live)
			}
			var started time.Time
			select {
			case started = <-entered:
			case <-time.After(time.Second):
				test.Fatal("no durable commit checkpoint")
			}
			if harness.calls.Load() != 0 || harness.broker.Active.Load() == 0 {
				test.Fatal("invalid pre-forward cancellation control")
			}
			if mode != "per-attempt" {
				raw, err := os.ReadFile(filepath.Join(harness.attempts.Root, "accounting", "group.json"))
				if err != nil {
					test.Fatal(err)
				}
				var group struct {
					Started int64 `json:"group_started_monotonic_ms"`
				}
				if json.Unmarshal(raw, &group) != nil {
					test.Fatal("group clock")
				}
				started = time.Now().Add(time.Duration(group.Started+1500-labtest.AttemptClock(test)) * time.Millisecond)
			}
			harness.closed(test, connections, started)
			deadline := started.Add(time.Second)
			for harness.broker.Active.Load() != 0 && time.Now().Before(deadline) {
				runtime.Gosched()
			}
			if harness.broker.Active.Load() != 0 || harness.calls.Load() != 0 {
				test.Fatal("deadline waited behind ledger fsync")
			}
			unblock()
			attemptRunStopped(test, harness, time.Now().Add(time.Second))
			if mode != "startup" {
				ledger := attemptRunLedger(test, harness)
				records := ledger["attempts"].([]any)
				if ledger["status"] != "unknown" || len(records) != 1 || labtest.Object(records[0])["settled_micro_usd"] != json.Number("10560000") {
					test.Fatal("pre-forward timeout refunded or lost durable reservation")
				}
			}
		})
	}
}

// TestLabAttemptRunIdleBound proves the group wall bound closes idle/partial sockets without another request and leaves a fully observed settlement cleanly stopped rather than UNKNOWN.
func TestLabAttemptRunIdleBound(test *testing.T) {
	harness := commandFixture(test)
	harness.attempts.Plan["max_wall_time_per_invocation_ms"] = int64(1500)
	harness.attempts.Plan["max_wall_time_total_ms"] = int64(1500)
	attemptRunResponse(harness, labtest.AttemptSSE())
	harness.start(test, false)
	conn := harness.dial(test)
	idle := harness.dial(test)
	partial := harness.dial(test)
	_, _ = partial.Write([]byte("POST /v1/messages?beta=true HTTP/1.1\r\n"))
	status, body := attemptRunRead(test, harness, conn)
	if status != 200 || body != labtest.AttemptSSE() || harness.returned.Load() {
		test.Fatal("idle bound control did not settle")
	}
	raw, err := os.ReadFile(filepath.Join(harness.attempts.Root, "accounting", "group.json"))
	if err != nil {
		test.Fatal(err)
	}
	var group struct {
		Started int64 `json:"group_started_monotonic_ms"`
	}
	if json.Unmarshal(raw, &group) != nil {
		test.Fatal("group clock")
	}
	started := time.Now().Add(time.Duration(group.Started+1500-labtest.AttemptClock(test)) * time.Millisecond)
	harness.closed(test, []net.Conn{conn, idle, partial}, started)
	select {
	case err := <-harness.result:
		harness.result <- err
		if err != nil {
			test.Fatal("fully observed wall exhaustion is not UNKNOWN", err)
		}
	case <-time.After(time.Until(started.Add(time.Second))):
		test.Fatal("idle bounded command did not return")
	}
	ledger := attemptRunLedger(test, harness)
	if ledger["status"] != "stopped" || len(ledger["attempts"].([]any)) != 1 || harness.calls.Load() != 1 {
		test.Fatal("idle wall bound reopened or refunded")
	}
}

// TestLabAttemptRunStatusStore proves the real read-only command refuses symlinked or nonprivate stores without repair/forward, beside the byte-identical settled control.
func TestLabAttemptRunStatusStore(test *testing.T) {
	for _, mode := range []string{"control", "link", "mode"} {
		test.Run(mode, func(test *testing.T) {
			harness := commandFixture(test)
			harness.attempts.Plan["max_invocations"] = int64(1)
			attemptRunResponse(harness, labtest.AttemptSSE())
			harness.start(test, false)
			conn := harness.dial(test)
			if status, _ := attemptRunRead(test, harness, conn); status != 200 {
				test.Fatal("store control")
			}
			conn.Close()
			harness.cancel()
			select {
			case <-harness.result:
			case <-time.After(time.Second):
				test.Fatal("control did not stop")
			}
			harness.result <- io.EOF
			store := filepath.Join(harness.attempts.Root, "accounting")
			head, err := os.ReadFile(filepath.Join(store, "head"))
			if err != nil {
				test.Fatal(err)
			}
			if mode == "link" {
				relocated := filepath.Join(harness.attempts.Root, "relocated")
				if os.Rename(store, relocated) != nil || os.Symlink("relocated", store) != nil {
					test.Fatal("store alias")
				}
			}
			if mode == "mode" && os.Chmod(store, 0750) != nil {
				test.Fatal("store mode")
			}
			child := exec.Command(os.Args[0], "-test.run=^TestLabAttemptStatusChild$")
			child.Env = append(os.Environ(), "LAB_ATTEMPT_STATUS_ROOT="+harness.attempts.Root, "LAB_ATTEMPT_STATUS_OPERATION="+harness.attempts.Plan["operation_id"].(string), "LAB_ATTEMPT_STATUS_PLAN="+labtest.Digest(labtest.Encode(test, harness.attempts.Plan)), "LAB_ATTEMPT_STATUS_ORDINAL=1")
			raw, err := child.Output()
			code := 0
			if err != nil {
				exit, ok := err.(*exec.ExitError)
				if !ok {
					test.Fatal(err)
				}
				code = exit.ExitCode()
			}
			expected := 0
			if mode != "control" {
				expected = 2
			}
			if code != expected {
				test.Fatal("unsafe read-only store accepted", code, expected)
			}
			if mode == "control" && labtest.Digest(raw) != string(head) || mode != "control" && len(raw) != 0 {
				test.Fatal("unprotected status bytes")
			}
			current, err := os.ReadFile(filepath.Join(store, "head"))
			if err != nil || string(current) != string(head) || harness.calls.Load() != 1 {
				test.Fatal("status repaired or forwarded")
			}
		})
	}
}
