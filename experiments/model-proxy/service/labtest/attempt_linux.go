//go:build linux && gateway_lab

package labtest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

type AttemptFixture struct {
	Test                                                        *testing.T
	Root                                                        string
	Plan, Approval, Release, Launch, Price, Access, Observation map[string]any
	Client, Wire, Index                                         []byte
	Source                                                      *Fixture
}

func NewAttemptFixture(test *testing.T, path string, source *Fixture) *AttemptFixture {
	test.Helper()
	fixture := &AttemptFixture{Test: test, Root: ShortDir(test), Source: source}
	raw, err := os.ReadFile(filepath.Join(path, "fixtures.json"))
	if err != nil {
		test.Fatal(err)
	}
	var data struct {
		Cases []struct {
			Surface string
			Valid   json.RawMessage
		}
	}
	if json.Unmarshal(raw, &data) != nil {
		test.Fatal("attempt fixtures")
	}
	for _, row := range data.Cases {
		var object map[string]any
		decoder := json.NewDecoder(strings.NewReader(string(row.Valid)))
		decoder.UseNumber()
		if decoder.Decode(&object) != nil {
			test.Fatal("fixture decode")
		}
		object = normalizeAttempt(test, object)
		switch row.Surface {
		case "swarma-broker-lab-bounded-invocation/1":
			fixture.Plan = object
		case "swarma-broker-lab-off-vm-approval/1":
			fixture.Approval = object
		case "swarma-lab-release-set/1":
			fixture.Release = object
		case "swarma-broker-lab-launch-plan/1":
			fixture.Launch = object
		case "swarma-broker-lab-model-price/1":
			fixture.Price = object
		case "swarma-broker-lab-access-attestation/1":
			fixture.Access = object
		case "swarma-broker-lab-observation-response/1":
			fixture.Observation = object
		}
	}
	for name, target := range map[string]*[]byte{"client.json": &fixture.Client, "wire-fixtures.json": &fixture.Wire, "index.json": &fixture.Index} {
		*target, err = os.ReadFile(filepath.Join(path, name))
		if err != nil {
			test.Fatal(err)
		}
	}
	worker := Object(source.Objects["swarma-broker-lab-authority/1"]["worker"])
	worker["generation"] = strings.Repeat("a", 32)
	worker["execution_id"] = fixture.Observation["start_id"]
	fixture.Plan["max_invocations"] = int64(3)
	fixture.Plan["max_total_cost_usd"] = "50.000000"
	fixture.Plan["max_wall_time_per_invocation_ms"] = int64(8000)
	fixture.Plan["max_wall_time_total_ms"] = int64(30000)
	fixture.Plan["target_generation"] = worker["generation"]
	fixture.Plan["live_budget_approved"] = true
	now := time.Now()
	context := source.Objects["swarma-broker-lab-authority/1"]["context"]
	for _, record := range []map[string]any{fixture.Plan, fixture.Approval, fixture.Release, fixture.Launch, fixture.Access} {
		record["context"] = context
	}
	for _, seal := range []map[string]any{Object(fixture.Approval["approval"]), Object(fixture.Release["owner_approval"]), Object(fixture.Access["owner_approval"])} {
		seal["approved_at"] = now.Add(-time.Minute).UTC().Format(time.RFC3339Nano)
		seal["expires_at"] = now.Add(time.Minute).UTC().Format(time.RFC3339Nano)
	}
	fixture.Approval["off_vm_now"] = now.Add(-time.Second).UTC().Format(time.RFC3339Nano)
	fixture.Access["observed_at"], fixture.Access["window_start"] = now.Add(-time.Second).UTC().Format(time.RFC3339Nano), now.Add(-time.Minute).UTC().Format(time.RFC3339Nano)
	fixture.Access["window_end"], fixture.Access["valid_until"] = now.Add(time.Minute).UTC().Format(time.RFC3339Nano), now.Add(time.Minute).UTC().Format(time.RFC3339Nano)
	Object(fixture.Access["vendor"])["hard_limit_minor_units"] = int64(10000)
	fixture.Release["contract_index_sha256"] = Digest(fixture.Index)
	base := Clone(test, Object(fixture.Release["assets"].([]any)[0]))
	base["product"] = "manager"
	base["sha256"] = fixture.Plan["executor_sha256"]
	base["second_build_sha256"] = fixture.Plan["executor_sha256"]
	priceAsset := Clone(test, base)
	priceAsset["product"] = "gateway"
	priceAsset["members"] = []any{map[string]any{"path": "contracts/lab-v0/model-price.json", "mode": "0644", "sha256": Digest(Encode(test, fixture.Price))}}
	fixture.Release["assets"] = []any{base, priceAsset}
	fixture.Observation["stops"], fixture.Observation["invalidations"] = []any{}, []any{}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		test.Fatal(err)
	}
	bootID := strings.TrimSpace(string(boot))
	Object(fixture.Observation["manager"])["boot_id"] = bootID
	start := Object(fixture.Observation["start"])
	start["generation"] = worker["generation"]
	start["uid"] = worker["uid"]
	Object(fixture.Observation["receipts"].([]any)[0])["boot_id"] = bootID
	debit := Object(fixture.Observation["debits"].([]any)[0])
	debit["boot_id"] = bootID
	debit["generation"] = Object(fixture.Observation["store"])["generation"]
	fixture.Rebind()
	return fixture
}
func normalizeAttempt(test *testing.T, value map[string]any) map[string]any {
	test.Helper()
	var visit func(any) any
	visit = func(value any) any {
		switch typed := value.(type) {
		case map[string]any:
			for name, child := range typed {
				typed[name] = visit(child)
			}
			return typed
		case []any:
			for index, child := range typed {
				typed[index] = visit(child)
			}
			return typed
		case json.Number:
			integer, err := typed.Int64()
			if err != nil {
				test.Fatal(err)
			}
			return integer
		default:
			return value
		}
	}
	return visit(value).(map[string]any)
}
func attemptTarget(test *testing.T, record map[string]any, member, domain string) string {
	copy := Clone(test, record)
	delete(copy, member)
	return Digest(Encode(test, map[string]any{"domain": domain, "record": copy}))
}
func (fixture *AttemptFixture) Rebind(excludeSeals ...string) {
	excluded := func(name string) bool {
		for _, value := range excludeSeals {
			if name == value {
				return true
			}
		}
		return false
	}
	test := fixture.Test
	test.Helper()
	if !excluded("access") {
		Object(fixture.Access["owner_approval"])["approved_sha256"] = attemptTarget(test, fixture.Access, "owner_approval", "swarma-broker-lab-approval-target/1")
	}
	fixture.Approval["access_attestation_sha256"] = Digest(Encode(test, fixture.Access))
	target := attemptTarget(test, fixture.Plan, "approval_record_sha256", "swarma-broker-lab-bounded-invocation-target/1")
	fixture.Release["invocation_sha256"] = target
	if !excluded("release") {
		Object(fixture.Release["owner_approval"])["approved_sha256"] = attemptTarget(test, fixture.Release, "owner_approval", "swarma-broker-lab-approval-target/1")
	}
	fixture.Approval["invocation_sha256"] = target
	fixture.Approval["release_set_sha256"] = Digest(Encode(test, fixture.Release))
	if !excluded("approval") {
		Object(fixture.Approval["approval"])["approved_sha256"] = attemptTarget(test, fixture.Approval, "approval", "swarma-broker-lab-approval-target/1")
	}
	fixture.Plan["approval_record_sha256"] = Digest(Encode(test, fixture.Approval))
	fixture.Launch["context"], fixture.Launch["operation_id"], fixture.Launch["target_generation"] = fixture.Plan["context"], fixture.Plan["operation_id"], fixture.Plan["target_generation"]
	fixture.Launch["predecessor_heads"] = fixture.Approval["heads"]
	pins := Object(fixture.Launch["pins"])
	pins["invocation_sha256"] = target
	pins["off_vm_approval_sha256"] = fixture.Plan["approval_record_sha256"]
	pins["release_set_sha256"] = fixture.Approval["release_set_sha256"]
	pins["access_attestation_sha256"] = fixture.Approval["access_attestation_sha256"]
	fixture.Launch["input_pins"] = []any{}
	for name, value := range map[string]any{"bounded-invocation": Digest(Encode(test, fixture.Plan)), "client-profile": fixture.Plan["client_profile_sha256"], "wire-profile": fixture.Plan["wire_profile_sha256"], "bounded-executor": fixture.Plan["executor_sha256"]} {
		fixture.Launch["input_pins"] = append(fixture.Launch["input_pins"].([]any), map[string]any{"name": name, "sha256": value})
	}
	start := Object(fixture.Observation["start"])
	start["plan_sha256"] = Digest(Encode(test, fixture.Launch))
	start["operation_id"] = fixture.Observation["operation_id"]
	fixture.Source.ReleaseIndex = Digest(fixture.Index)
	fixture.Source.Objects["swarma-lab-release-set/1"] = fixture.Release
	fixture.Source.Rebuild()
	fixture.Write()
}
func (fixture *AttemptFixture) Write() {
	test := fixture.Test
	test.Helper()
	for name, record := range map[string]map[string]any{"plan": fixture.Plan, "approval": fixture.Approval, "release": fixture.Release, "launch": fixture.Launch, "price": fixture.Price, "access": fixture.Access, "start-observation": fixture.Observation} {
		fixture.Put(name+".json", Encode(test, record))
	}
	for name, raw := range map[string][]byte{"approved-plan.sha256": []byte(Digest(Encode(test, fixture.Plan))), "approved-release.sha256": []byte(Digest(Encode(test, fixture.Release))), "approved-access.sha256": []byte(Digest(Encode(test, fixture.Access))), "accepted-start.sha256": []byte(Digest(Encode(test, fixture.Observation))), "start-operation-id": []byte(fixture.Observation["operation_id"].(string)), "start-id": []byte(fixture.Observation["start_id"].(string)), "client-profile.json": fixture.Client, "wire-profile.json": fixture.Wire, "available-cap-micro-usd": []byte("100000000")} {
		fixture.Put(name, raw)
	}
}
func (fixture *AttemptFixture) Put(name string, raw []byte) {
	fixture.Test.Helper()
	path := filepath.Join(fixture.Root, name)
	if _, err := os.Stat(path); err == nil {
		if os.Chmod(path, 0600) != nil {
			fixture.Test.Fatal("fixture chmod")
		}
	}
	if os.WriteFile(path, raw, 0400) != nil || os.Chmod(path, 0400) != nil {
		fixture.Test.Fatal("fixture write")
	}
}
func AttemptSSE() string {
	return "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-opus-5-5\",\"service_tier\":\"standard\",\"usage\":{\"input_tokens\":100,\"output_tokens\":0,\"cache_creation_input_tokens\":400,\"cache_creation_5m_input_tokens\":100,\"cache_creation_1h_input_tokens\":300,\"cache_read_input_tokens\":500}}}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":10}}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":16}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
}
func (fixture *AttemptFixture) RewriteGroup() {
	test := fixture.Test
	test.Helper()
	path := filepath.Join(fixture.Root, "accounting", "group.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		test.Fatal(err)
	}
	var group map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	if decoder.Decode(&group) != nil {
		test.Fatal("group decode")
	}
	group = normalizeAttempt(test, group)
	for name, value := range map[string]any{"context": fixture.Plan["context"], "operation_id": fixture.Plan["operation_id"], "plan_sha256": Digest(Encode(test, fixture.Plan)), "approval_record_sha256": Digest(Encode(test, fixture.Approval)), "release_set_sha256": Digest(Encode(test, fixture.Release)), "launch_plan_sha256": Digest(Encode(test, fixture.Launch)), "model_price_sha256": Digest(Encode(test, fixture.Price)), "start_operation_id": fixture.Observation["operation_id"], "start_id": fixture.Observation["start_id"]} {
		group[name] = value
	}
	fixture.Put("accounting/group.json", Encode(test, group))
}

func AttemptClock(test *testing.T) int64 {
	test.Helper()
	var stamp syscall.Timespec
	_, _, failure := syscall.Syscall(syscall.SYS_CLOCK_GETTIME, 7, uintptr(unsafe.Pointer(&stamp)), 0)
	if failure != 0 {
		test.Fatal("fixture boot clock")
	}
	return stamp.Sec*1000 + stamp.Nsec/1000000
}
func (fixture *AttemptFixture) PublishStart() {
	now := AttemptClock(fixture.Test)
	fixture.Observation["observed_monotonic_ms"] = now
	Object(fixture.Observation["debits"].([]any)[0])["committed_ms"] = now
	fixture.Write()
}
