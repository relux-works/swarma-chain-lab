//go:build linux && gateway_lab

package service

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

type labAttemptAdmission struct {
	root                                                *os.Root
	records                                             map[string][]byte
	plan, approval, release, launch, price, observation map[string]any
	group                                               map[string]any
	deadline                                            time.Time
	monotonicDeadline                                   time.Time
	source                                              *LabSource
	readOnly                                            bool
}

func labBootClock() (string, int64, error) {
	raw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", 0, ErrUnknown
	}
	boot := strings.TrimSuffix(string(raw), "\n")
	var stamp syscall.Timespec
	_, _, failure := syscall.Syscall(syscall.SYS_CLOCK_GETTIME, 7, uintptr(unsafe.Pointer(&stamp)), 0)
	if failure != 0 || stamp.Sec < 0 || stamp.Sec > labSafeInteger/1000 || labValue(boot, "uuid") != nil {
		return "", 0, ErrUnknown
	}
	return boot, stamp.Sec*1000 + stamp.Nsec/1000000, nil
}
func labAttemptRoot(path string) (*os.Root, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrInput
	}
	physical, err := filepath.EvalSymlinks(path)
	if err != nil || physical != path {
		return nil, ErrInactive
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, ErrInactive
	}
	info, err := root.Stat(".")
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		root.Close()
		return nil, ErrInactive
	}
	return root, nil
}
func labAttemptRead(root *os.Root, name string, mode os.FileMode, limit int64) ([]byte, error) {
	info, err := root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != mode || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) || info.Sys().(*syscall.Stat_t).Nlink != 1 || info.Size() > limit {
		return nil, ErrInactive
	}
	file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrInactive
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, ErrUnknown
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, ErrInactive
	}
	return raw, nil
}
func labLoadAttemptAdmission(path string, readOnly ...bool) (*labAttemptAdmission, error) {
	root, err := labAttemptRoot(path)
	if err != nil {
		return nil, err
	}
	admission := &labAttemptAdmission{root: root, records: map[string][]byte{}}
	if len(readOnly) == 1 {
		admission.readOnly = readOnly[0]
	}
	failed := true
	defer func() {
		if failed {
			root.Close()
		}
	}()
	for name, format := range map[string]string{"plan": "swarma-broker-lab-bounded-invocation/1", "approval": "swarma-broker-lab-off-vm-approval/1", "release": "swarma-lab-release-set/1", "launch": "swarma-broker-lab-launch-plan/1", "price": "swarma-broker-lab-model-price/1", "access": "swarma-broker-lab-access-attestation/1"} {
		raw, readErr := labAttemptRead(root, name+".json", 0400, 262144)
		if readErr != nil {
			return nil, readErr
		}
		object, parseErr := labAttemptRecord(raw, format)
		if parseErr != nil {
			return nil, parseErr
		}
		admission.records[name+".json"] = raw
		switch name {
		case "plan":
			admission.plan = object
		case "approval":
			admission.approval = object
		case "release":
			admission.release = object
		case "launch":
			admission.launch = object
		case "price":
			admission.price = object
		}
	}
	for _, name := range []string{"approved-plan.sha256", "approved-release.sha256", "approved-access.sha256", "start-operation-id", "start-id", "client-profile.json", "wire-profile.json", "available-cap-micro-usd"} {
		raw, readErr := labAttemptRead(root, name, 0400, 262144)
		if readErr != nil {
			return nil, readErr
		}
		admission.records[name] = raw
	}
	if err := admission.validate(); err != nil {
		return nil, err
	}
	now := time.Now()
	admission.monotonicDeadline = now.Add(admission.deadline.Sub(now))
	failed = false
	return admission, nil
}
func (admission *labAttemptAdmission) validate() error {
	plan, approval, release, launch, price := admission.plan, admission.approval, admission.release, admission.launch, admission.price
	if string(admission.records["approved-plan.sha256"]) != labAttemptHash(plan) || string(admission.records["approved-release.sha256"]) != labAttemptHash(release) || string(admission.records["approved-access.sha256"]) != labDigest(admission.records["access.json"]) {
		return ErrIdentity
	}
	if !bytes.Equal(admission.records["client-profile.json"], labAttemptClient) || !bytes.Equal(admission.records["wire-profile.json"], labWireFixtures) || !bytes.Equal(admission.records["price.json"], labAttemptPrice) || release["contract_index_sha256"] != labDigest(labAttemptIndex) {
		return ErrIdentity
	}
	if plan["client_profile_sha256"] != labDigest(labAttemptClient) || plan["wire_profile_sha256"] != labDigest(labWireFixtures) || plan["model"] != "claude-opus-5-5" || plan["max_output_tokens_per_invocation"] != int64(128000) || plan["live_budget_approved"] != true || plan["max_wall_time_per_invocation_ms"].(int64) > plan["max_wall_time_total_ms"].(int64) {
		return ErrInactive
	}
	target := labApprovalTarget(plan, "approval_record_sha256", "swarma-broker-lab-bounded-invocation-target/1")
	if plan["approval_record_sha256"] != labAttemptHash(approval) || approval["release_set_sha256"] != labAttemptHash(release) || approval["invocation_sha256"] != target || release["invocation_sha256"] != target {
		return ErrIdentity
	}
	for _, record := range []map[string]any{approval, release, launch} {
		if !labEqual(record["context"], plan["context"]) {
			return ErrIdentity
		}
	}
	if launch["operation_id"] != plan["operation_id"] || launch["target_generation"] != plan["target_generation"] || !labEqual(launch["predecessor_heads"], approval["heads"]) {
		return ErrIdentity
	}
	pins := labObject(launch["pins"])
	if pins["invocation_sha256"] != target || pins["off_vm_approval_sha256"] != labAttemptHash(approval) || pins["release_set_sha256"] != labAttemptHash(release) || pins["access_attestation_sha256"] != approval["access_attestation_sha256"] || approval["access_attestation_sha256"] != labDigest(admission.records["access.json"]) {
		return ErrIdentity
	}
	names := map[string]any{}
	for _, value := range launch["input_pins"].([]any) {
		pin := labObject(value)
		name := pin["name"].(string)
		if _, exists := names[name]; exists {
			return ErrIdentity
		}
		names[name] = pin["sha256"]
	}
	for name, value := range map[string]any{"bounded-invocation": labAttemptHash(plan), "client-profile": plan["client_profile_sha256"], "wire-profile": plan["wire_profile_sha256"], "bounded-executor": plan["executor_sha256"]} {
		if names[name] != value {
			return ErrIdentity
		}
	}
	priceMembers, executorMembers := 0, 0
	for _, value := range release["assets"].([]any) {
		asset := labObject(value)
		if asset["second_build_equal"] != true || asset["sha256"] != asset["second_build_sha256"] {
			return ErrIdentity
		}
		if asset["product"] == "manager" && asset["sha256"] == plan["executor_sha256"] {
			executorMembers++
		}
		for _, child := range asset["members"].([]any) {
			member := labObject(child)
			if member["path"] == "contracts/lab-v0/model-price.json" {
				priceMembers++
				if asset["product"] != "gateway" || member["mode"] != "0644" || member["sha256"] != labAttemptHash(price) {
					return ErrIdentity
				}
			}
		}
	}
	if priceMembers != 1 || executorMembers != 1 {
		return ErrIdentity
	}
	for _, item := range []struct {
		record map[string]any
		field  string
	}{{approval, "approval"}, {release, "owner_approval"}} {
		seal := labObject(item.record[item.field])
		if seal["approved_sha256"] != labApprovalTarget(item.record, item.field, "swarma-broker-lab-approval-target/1") {
			return ErrIdentity
		}
		approved, expiry := labTime(seal["approved_at"]), labTime(seal["expires_at"])
		now := time.Now()
		off := labTime(approval["off_vm_now"])
		if approved.After(off) || !admission.readOnly && (off.After(now) || !now.Before(expiry)) {
			return ErrInactive
		}
		if admission.deadline.IsZero() || expiry.Before(admission.deadline) {
			admission.deadline = expiry
		}
	}
	qualification := labTime(labObject(plan["context"])["qualification_expires_at"])
	if !admission.readOnly && !time.Now().Before(qualification) {
		return ErrInactive
	}
	if qualification.Before(admission.deadline) {
		admission.deadline = qualification
	}
	if admission.accessValid() != nil {
		return ErrIdentity
	}
	join := labObject(launch["manager_join"])
	receipt := labObject(join["receipt"])
	if join["request_id"] != receipt["request_id"] || join["request_sha256"] != receipt["request_sha256"] || receipt["result"] != "committed" {
		return ErrIdentity
	}
	if labAttemptValue(string(admission.records["start-operation-id"]), "native-id") != nil || labAttemptValue(string(admission.records["start-id"]), "native-id") != nil {
		return ErrIdentity
	}
	return nil
}
func (admission *labAttemptAdmission) current(ctx context.Context) error {
	now := time.Now()
	if ctx.Err() != nil || !now.Before(admission.deadline) || !now.Before(admission.monotonicDeadline) {
		return ErrInactive
	}
	if admission.source != nil && admission.source.ctx.Err() != nil {
		return ErrInactive
	}
	for name, expected := range admission.records {
		raw, err := labAttemptRead(admission.root, name, 0400, 262144)
		if err != nil || !bytes.Equal(raw, expected) {
			return ErrUnknown
		}
	}
	return nil
}
func labAttemptGroup(admission *labAttemptAdmission, boot string, started int64) map[string]any {
	return map[string]any{"format": labAttemptGroupFormat, "context": admission.plan["context"], "operation_id": admission.plan["operation_id"], "plan_sha256": labAttemptHash(admission.plan), "approval_record_sha256": labAttemptHash(admission.approval), "release_set_sha256": labAttemptHash(admission.release), "launch_plan_sha256": labAttemptHash(admission.launch), "model_price_sha256": labAttemptHash(admission.price), "start_operation_id": string(admission.records["start-operation-id"]), "start_id": string(admission.records["start-id"]), "boot_id": boot, "group_started_monotonic_ms": started}
}
func (admission *labAttemptAdmission) acceptStart(source *LabSource) error {
	raw, err := labAttemptRead(admission.root, "start-observation.json", 0400, 65536)
	if err != nil {
		return err
	}
	observation, err := labAttemptRecord(raw, "swarma-broker-lab-observation-response/1")
	if err != nil {
		return err
	}
	accepted, err := labAttemptRead(admission.root, "accepted-start.sha256", 0400, 128)
	if err != nil || string(accepted) != labDigest(raw) {
		return ErrIdentity
	}
	group := admission.group
	boot, clock, clockErr := labBootClock()
	if clockErr != nil || boot != group["boot_id"] || observation["observed_monotonic_ms"].(int64) < group["group_started_monotonic_ms"].(int64) || observation["observed_monotonic_ms"].(int64) > clock {
		return ErrIdentity
	}
	start, store, manager := labObject(observation["start"]), labObject(observation["store"]), labObject(observation["manager"])
	if observation["complete"] != true || store["generation_current"] != true || start["phase"] != "admitted" || len(observation["stops"].([]any)) != 0 || len(observation["invalidations"].([]any)) != 0 || len(observation["receipts"].([]any)) != 1 || len(observation["debits"].([]any)) != 1 {
		return ErrInactive
	}
	receipt, debit := labObject(observation["receipts"].([]any)[0]), labObject(observation["debits"].([]any)[0])
	if observation["operation_id"] != group["start_operation_id"] || start["operation_id"] != group["start_operation_id"] || start["start_id"] != group["start_id"] || observation["start_id"] != group["start_id"] || start["plan_sha256"] != group["launch_plan_sha256"] || start["generation"] != admission.plan["target_generation"] || manager["boot_id"] != group["boot_id"] {
		return ErrIdentity
	}
	for _, record := range []map[string]any{receipt, debit} {
		if record["boot_id"] != group["boot_id"] || record["execution_id"] != group["start_id"] || record["epoch"] != start["epoch"] {
			return ErrIdentity
		}
	}
	for _, name := range []string{"pid", "start_time"} {
		if !reflect.DeepEqual(receipt[name], debit[name]) {
			return ErrIdentity
		}
	}
	if debit["committed_ms"].(int64) < group["group_started_monotonic_ms"].(int64) || debit["committed_ms"].(int64) > observation["observed_monotonic_ms"].(int64) {
		return ErrIdentity
	}
	if start["uid"].(int64) > 4294967294 || receipt["pid"].(int64) > 4194304 || debit["pid"].(int64) > 4194304 || receipt["session_id"].(int64) > 4194304 {
		return ErrIdentity
	}
	if debit["generation"] != store["generation"] {
		return ErrIdentity
	}
	if source == nil && !admission.readOnly || source != nil && (source.pins.release != labAttemptHash(admission.release) || !labEqual(source.pins.context, admission.plan["context"]) || source.pins.worker["generation"] != admission.plan["target_generation"] || source.pins.worker["uid"] != start["uid"] || source.pins.worker["execution_id"] != group["start_id"]) {
		return ErrIdentity
	}
	admission.source = source
	admission.observation = observation
	admission.records["start-observation.json"] = raw
	admission.records["accepted-start.sha256"] = accepted
	return nil
}

func (admission *labAttemptAdmission) accessValid() error {
	access, err := labAttemptRecord(admission.records["access.json"], "swarma-broker-lab-access-attestation/1")
	if err != nil || !labEqual(access["context"], admission.plan["context"]) {
		return ErrIdentity
	}
	seal := labObject(access["owner_approval"])
	if seal["approved_sha256"] != labApprovalTarget(access, "owner_approval", "swarma-broker-lab-approval-target/1") {
		return ErrIdentity
	}
	now := time.Now()
	observed := labTime(access["observed_at"])
	if labTime(seal["approved_at"]).After(observed) || !admission.readOnly && (observed.After(now) || labTime(access["window_start"]).After(now)) {
		return ErrInactive
	}
	for _, expiry := range []time.Time{labTime(seal["expires_at"]), labTime(access["valid_until"]), labTime(access["window_end"])} {
		if !admission.readOnly && !now.Before(expiry) {
			return ErrInactive
		}
		if expiry.Before(admission.deadline) {
			admission.deadline = expiry
		}
	}
	for _, value := range labObject(access["endpoint"]) {
		if value != true {
			return ErrInactive
		}
	}
	for _, name := range []string{"guest_and_control_plane", "vendor_principals"} {
		principals := access[name].([]any)
		if len(principals) == 0 {
			return ErrInactive
		}
		for _, value := range principals {
			if labObject(value)["controller"] != "human" {
				return ErrInactive
			}
		}
	}
	vendor := labObject(access["vendor"])
	if vendor["audit_complete"] != true || vendor["roster_unchanged"] != true {
		return ErrInactive
	}
	capText := string(admission.records["available-cap-micro-usd"])
	cap, parseErr := strconv.ParseInt(capText, 10, 64)
	approved, _ := labMicroUSD(admission.plan["max_total_cost_usd"])
	minor := vendor["hard_limit_minor_units"].(int64)
	if parseErr != nil || capText != strconv.FormatInt(cap, 10) || cap < approved || cap > labSafeInteger || minor > labSafeInteger/10000 || cap > minor*10000 {
		return ErrInactive
	}
	return nil
}
