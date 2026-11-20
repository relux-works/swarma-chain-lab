//go:build linux && gateway_lab

package service

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/model-proxy/service/internal/wire"
)

const LabPollInterval = 250 * time.Millisecond
const LabRPCTimeout = 200 * time.Millisecond
const LabWatchdog = 500 * time.Millisecond
const labContractIndex = "sha256:4f9a81562d391153764b5ae75d7914cf83f03c1bb3d956461211d8eb36f6e7d8"

type LabPins struct {
	context, gateway, worker, floor map[string]any
	activation, authority, fence    string
	lifetime                        time.Duration
	deadline                        time.Time
}

func NewLabPins(activationRaw, authorityRaw, fenceRaw, floorRaw, releaseRaw []byte) (*LabPins, error) {
	activation, err := labRecord(activationRaw, "swarma-broker-lab-activation/1")
	if err != nil {
		return nil, err
	}
	authority, err := labRecord(authorityRaw, "swarma-broker-lab-authority/1")
	if err != nil {
		return nil, err
	}
	fence, err := labRecord(fenceRaw, "swarma-broker-lab-start-fence/1")
	if err != nil {
		return nil, err
	}
	floor, err := labRecord(floorRaw, "swarma-broker-lab-consumer-high-water/1")
	if err != nil {
		return nil, err
	}
	release, err := labRecord(releaseRaw, "swarma-lab-release-set/1")
	if err != nil {
		return nil, err
	}
	scope := labObject(authority["context"])
	for key, value := range scope {
		if activation[key] != value {
			return nil, ErrIdentity
		}
	}
	for _, record := range []map[string]any{fence, floor, release} {
		if !labEqual(record["context"], scope) {
			return nil, ErrIdentity
		}
	}
	gateway, worker := labObject(authority["gateway"]), labObject(authority["worker"])
	if gateway["uid"].(int64) > 4294967295 || worker["uid"].(int64) > 4294967295 || gateway["kind"] != "service" || gateway["service_name"] != "credential-gateway" || worker["kind"] != "worker" || gateway["uid"] == worker["uid"] || gateway["generation"] == worker["generation"] || gateway["execution_id"] == worker["execution_id"] {
		return nil, ErrRole
	}
	if activation["enabled"] != true || activation["test_api_key"] != true || authority["test_api_key"] != true || floor["persisted_before_release"] != true || len(floor["hold_ids"].([]any)) != 0 || activation["authority_sha256"] != labDigest(authorityRaw) || activation["fence_sha256"] != labDigest(fenceRaw) || activation["release_set_sha256"] != labDigest(releaseRaw) || release["contract_index_sha256"] != labContractIndex || !labEqual(authority["manager_head"], floor["manager_prefix"]) || !labEqual(labObject(fence["heads"])["manager"], floor["manager_prefix"]) {
		return nil, ErrInactive
	}
	deadline := labTime(scope["qualification_expires_at"])
	if bound := labTime(authority["per_use_expires_at"]); bound.Before(deadline) {
		deadline = bound
	}
	if !time.Now().Before(deadline) {
		return nil, ErrInactive
	}
	return &LabPins{scope, gateway, worker, labObject(floor["manager_prefix"]), labDigest(activationRaw), labDigest(authorityRaw), labDigest(fenceRaw), time.Duration(activation["service_lease_max_lifetime_seconds"].(int64)) * time.Second, deadline}, nil
}

type LabSource struct{ *labSourceState }

type labSourceState struct {
	mu            sync.Mutex
	pins          *LabPins
	cfg           Config
	client        *Client
	lease         *Lease
	version       string
	revocation    int64
	values        [][]byte
	ctx           context.Context
	cancel        context.CancelFunc
	once          sync.Once
	onClose       func()
	watchdog      *time.Timer
	timerMu       sync.Mutex
	renewAt       time.Time
	leak          atomic.Bool
	holdOnce      sync.Once
	holdID        string
	holdLease     string
	holdCommitted bool
	holdDone      chan struct{}
	recovery      context.Context
	stopRecovery  context.CancelFunc
}

func (*labSourceState) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("<lab-managed-source>"))
}

func OpenLabSource(ctx context.Context, cfg Config, pins *LabPins, onClose func()) (*LabSource, error) {
	if ctx == nil || pins == nil || cfg.MaxLifetime != pins.lifetime || cfg.ServiceUID != uint32(pins.gateway["uid"].(int64)) || cfg.Generation != pins.gateway["generation"] || onClose == nil || !time.Now().Before(pins.deadline) {
		return nil, ErrInput
	}
	bounded, cancel := context.WithTimeout(ctx, LabRPCTimeout)
	defer cancel()
	client, err := Dial(bounded, cfg)
	if err != nil {
		return nil, err
	}
	lifetime, stop := context.WithCancel(context.Background())
	recovery, stopRecovery := context.WithCancel(context.Background())
	source := &LabSource{&labSourceState{recovery: recovery, stopRecovery: stopRecovery, pins: pins, cfg: cfg, client: client, ctx: lifetime, cancel: stop, onClose: onClose, holdDone: make(chan struct{})}}
	go source.supervise()
	return source, nil
}

func (source *LabSource) GatewayBinding() (Caller, string) {
	worker := source.pins.worker
	return Caller{source.pins.context["account"].(string), uint32(worker["uid"].(int64)), worker["generation"].(string), worker["execution_id"].(string)}, source.cfg.Generation
}

func (source *LabSource) end() {
	source.once.Do(func() {
		source.cancel()
		_ = source.client.Close()
		source.timerMu.Lock()
		if source.watchdog != nil {
			source.watchdog.Stop()
		}
		source.timerMu.Unlock()
		source.onClose()
	})
}
func (source *LabSource) Close() {
	source.end()
	source.stopRecovery()
	source.mu.Lock()
	for _, value := range source.values {
		clear(value)
	}
	source.values = nil
	source.mu.Unlock()
}

func (source *LabSource) checked(started time.Time) bool {
	source.timerMu.Lock()
	defer source.timerMu.Unlock()
	remaining := time.Until(started.Add(LabWatchdog))
	if source.ctx.Err() != nil || remaining <= 0 {
		return false
	}
	if source.watchdog == nil {
		source.watchdog = time.AfterFunc(remaining, source.end)
	} else {
		source.watchdog.Reset(remaining)
	}
	return true
}

func (source *LabSource) accept(raw []byte, operation string, started time.Time, oldID string) error {
	record, err := labRecord(raw, "anthropic-api-key-lab/1")
	if err != nil {
		return err
	}
	pins := source.pins
	if !labEqual(record["context"], pins.context) || !labEqual(record["gateway"], pins.gateway) || !labEqual(record["caller"], pins.worker) || !labEqual(record["manager_floor"], pins.floor) || record["activation_sha256"] != pins.activation || record["authority_sha256"] != pins.authority || record["fence_sha256"] != pins.fence || record["request_id"] != operation || oldID != "" && record["lease_id"] != oldID {
		return ErrIdentity
	}
	bounds := labObject(record["bounds"])
	issued, until := labTime(bounds["issued_at"]), labTime(bounds["authorized_until"])
	lifetime := time.Duration(bounds["lifetime_seconds"].(int64)) * time.Second
	if lifetime != pins.lifetime || issued.After(time.Now()) || !until.After(issued) || !time.Now().Before(until) || until.After(issued.Add(lifetime)) || until.After(pins.deadline) {
		return ErrInactive
	}
	for _, name := range []string{"authority_until", "caller_until", "qualification_until", "time_until"} {
		if until.After(labTime(bounds[name])) {
			return ErrInactive
		}
	}
	if bound := started.Add(lifetime); until.After(bound) {
		until = bound
	}
	if source.ctx.Err() != nil {
		return ErrInactive
	}
	if oldID != "" {
		source.lease.mu.Lock()
		live := source.lease.live()
		source.lease.mu.Unlock()
		if !live {
			return ErrInactive
		}
	}
	caller, _ := source.GatewayBinding()
	lease := &Lease{leaseState: &leaseState{owner: source.client, caller: caller, id: record["lease_id"].(string), kind: "anthropic-api-key-lab/1", harness: "claude_code", until: until, localUntil: time.Now().Add(time.Until(until)), value: []byte(record["material"].(string))}}
	version := operation
	sequence := record["revocation_sequence"].(int64)
	if sequence < source.revocation {
		lease.close()
		return ErrInactive
	}
	source.revocation = sequence
	source.client.mu.Lock()
	if source.client.failed || source.ctx.Err() != nil {
		source.client.mu.Unlock()
		lease.close()
		return ErrInactive
	}
	source.client.leases[lease] = true
	source.client.mu.Unlock()
	if source.lease != nil {
		source.lease.close()
	}
	source.lease, source.version = lease, version
	source.renewAt = time.Now().Add(time.Until(until) * 2 / 3)
	value := []byte(record["material"].(string))
	record["material"] = ""
	found := false
	for _, previous := range source.values {
		if string(previous) == string(value) {
			found = true
		}
	}
	if !found {
		if len(source.values) >= 256 {
			clear(value)
			return ErrInactive
		}
		source.values = append(source.values, value)
	} else {
		clear(value)
	}
	return nil
}

func (source *LabSource) operation(renew bool) error {
	operation, err := OperationID()
	if err != nil {
		return err
	}
	method := "service.lease.request"
	caller, _ := source.GatewayBinding()
	params := map[string]any{"operation_id": operation, "account": caller.Account, "agent_uid": caller.UID, "agent_generation": caller.Generation, "launch_id": caller.LaunchID}
	oldID := ""
	if renew {
		oldID = source.lease.id
		method = "service.lease.renew"
		params = map[string]any{"operation_id": operation, "service_lease_id": oldID}
	}
	started := time.Now()
	bounded, cancel := context.WithTimeout(source.ctx, LabRPCTimeout)
	defer cancel()
	var raw json.RawMessage
	if err = source.client.call(bounded, method, params, &raw); err != nil {
		clear(raw)
		return err
	}
	defer clear(raw)
	return source.accept(raw, operation, started, oldID)
}

func (source *LabSource) check() error {
	if source.ctx.Err() != nil || !time.Now().Before(source.pins.deadline) {
		return ErrInactive
	}
	bounded, cancel := context.WithTimeout(source.ctx, LabRPCTimeout)
	defer cancel()
	source.lease.mu.Lock()
	live := source.lease.live()
	source.lease.mu.Unlock()
	if !live {
		return ErrInactive
	}
	var result struct {
		Verdict  string  `json:"verdict"`
		Sequence *uint64 `json:"revocation_sequence"`
	}
	started := time.Now()
	if err := source.client.call(bounded, "service.revocation.check", map[string]any{"service_lease_id": source.lease.id}, &result); err != nil {
		return err
	}
	if result.Verdict != "not_revoked" || result.Sequence == nil || *result.Sequence > 9007199254740991 || int64(*result.Sequence) < source.revocation {
		return ErrRevoked
	}
	source.revocation = int64(*result.Sequence)
	source.lease.mu.Lock()
	live = source.lease.live()
	source.lease.mu.Unlock()
	if !live {
		return ErrInactive
	}
	if !source.checked(started) {
		return ErrInactive
	}
	return nil
}

func (source *LabSource) CredentialValue(ctx context.Context) (string, []byte, string, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	if ctx == nil || ctx.Err() != nil || source.ctx.Err() != nil || !time.Now().Before(source.pins.deadline) {
		return "", nil, "", ErrInactive
	}
	if source.lease == nil {
		if err := source.operation(false); err != nil {
			source.end()
			return "", nil, "", sanitized(err)
		}
	}
	if err := source.check(); err != nil {
		source.end()
		return "", nil, "", sanitized(err)
	}
	source.lease.mu.Lock()
	live := source.lease.live()
	material := append([]byte(nil), source.lease.value...)
	source.lease.mu.Unlock()
	if !live {
		clear(material)
		source.end()
		return "", nil, "", ErrInactive
	}
	return "api-key", material, source.version, nil
}

func (source *LabSource) CredentialContext(ctx context.Context, version string) (context.Context, context.CancelFunc) {
	source.mu.Lock()
	valid := version == source.version && source.ctx.Err() == nil
	deadline := time.Now()
	if source.lease != nil {
		deadline = source.lease.localUntil
	}
	source.mu.Unlock()
	call, cancel := context.WithDeadline(ctx, deadline)
	stop := context.AfterFunc(source.ctx, cancel)
	if !valid {
		cancel()
	}
	return call, func() { stop(); cancel() }
}

func (source *LabSource) Inventory() [][]byte {
	source.mu.Lock()
	defer source.mu.Unlock()
	values := make([][]byte, len(source.values))
	for index, value := range source.values {
		values[index] = append([]byte(nil), value...)
	}
	return values
}

func (source *LabSource) supervise() {
	ticker := time.NewTicker(LabPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-source.ctx.Done():
			return
		case <-ticker.C:
		}
		source.mu.Lock()
		if source.lease == nil {
			source.mu.Unlock()
			continue
		}
		err := source.check()
		if err == nil && !time.Now().Before(source.renewAt) {
			err = source.operation(true)
		}
		source.mu.Unlock()
		if err != nil {
			source.end()
			return
		}
	}
}

func (source *LabSource) ReportLeak() {
	source.leak.Store(true)
	source.cancel()
	source.holdOnce.Do(func() {
		source.mu.Lock()
		operation, err := OperationID()
		if err != nil || source.lease == nil {
			source.mu.Unlock()
			source.end()
			close(source.holdDone)
			return
		}
		source.holdID, source.holdLease = operation, source.lease.id
		source.mu.Unlock()
		source.end()
		go source.reconcileHold()
	})
}

func (source *LabSource) AwaitHold(ctx context.Context) error {
	if !source.leak.Load() {
		return nil
	}
	select {
	case <-ctx.Done():
		return ErrUnknown
	case <-source.holdDone:
	}
	source.mu.Lock()
	committed := source.holdCommitted
	source.mu.Unlock()
	if !committed {
		return ErrUnknown
	}
	return nil
}

func (source *LabSource) reconcileHold() {
	defer close(source.holdDone)
	caller, _ := source.GatewayBinding()
	params := map[string]any{"operation_id": source.holdID, "service_lease_id": source.holdLease, "account": caller.Account, "reason_code": "leak_match"}
	encoded, _ := wire.Encode(params)
	digest := labDigest(encoded)
	for {
		if source.recovery.Err() != nil {
			return
		}
		ctx, cancel := context.WithTimeout(source.recovery, LabRPCTimeout)
		client, err := Dial(ctx, source.cfg)
		if err == nil {
			var raw json.RawMessage
			err = client.call(ctx, "account.hold", params, &raw)
			if err == nil {
				record, parseErr := labRecord(raw, "swarma-broker-lab-hold/1")
				if parseErr == nil && record["result"] == "committed" && record["operation_id"] == source.holdID && record["request_sha256"] == digest && labEqual(record["context"], source.pins.context) && labEqual(record["caller"], source.pins.worker) {
					source.mu.Lock()
					source.holdCommitted = true
					source.mu.Unlock()
					clear(raw)
					client.Close()
					cancel()
					return
				}
			}
			clear(raw)
			client.Close()
		}
		cancel()
		select {
		case <-source.recovery.Done():
			return
		case <-time.After(LabPollInterval):
		}
	}
}

func (source *LabSource) RenewValue(ctx context.Context, rejected string) (string, []byte, string, error) {
	return "", nil, "", ErrInactive
}
