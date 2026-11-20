//go:build linux && gateway_lab

package service

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type LabAttemptIO struct {
	SyncFile  func(*os.File) error
	CloseFile func(*os.File) error
}

func labAttemptIO(collaborators []LabAttemptIO) LabAttemptIO {
	selected := LabAttemptIO{}
	if len(collaborators) == 1 {
		selected = collaborators[0]
	}
	if selected.SyncFile == nil {
		selected.SyncFile = func(file *os.File) error { return file.Sync() }
	}
	if selected.CloseFile == nil {
		selected.CloseFile = func(file *os.File) error { return file.Close() }
	}
	return selected
}

type LabAttemptGate struct {
	mu             sync.Mutex
	admission      *labAttemptAdmission
	store          *os.Root
	lock           *os.File
	ledger         map[string]any
	head           string
	lastClock      int64
	closed         bool
	active         *labAttempt
	stopped        chan struct{}
	io             LabAttemptIO
	deadlineCancel context.CancelFunc
	boundary       atomic.Bool
	busy           atomic.Bool
}
type labAttempt struct {
	gate    *LabAttemptGate
	ordinal int64
	ctx     context.Context
	cancel  context.CancelFunc
	done    chan struct{}
	once    sync.Once
}

func labSyncDirectory(root *os.Root, collaborators ...LabAttemptIO) error {
	selected := labAttemptIO(collaborators)
	file, err := root.Open(".")
	if err != nil {
		return ErrUnknown
	}
	defer file.Close()
	if selected.SyncFile(file) != nil {
		return ErrUnknown
	}
	return nil
}
func labWriteImmutable(root *os.Root, name string, raw []byte, collaborators ...LabAttemptIO) error {
	selected := labAttemptIO(collaborators)
	if len(raw) == 0 {
		return ErrUnknown
	}
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0400)
	if err != nil {
		return ErrUnknown
	}
	_, writeErr := file.Write(raw)
	syncErr := selected.SyncFile(file)
	closeErr := selected.CloseFile(file)
	if writeErr != nil || syncErr != nil || closeErr != nil || labSyncDirectory(root, selected) != nil {
		return ErrUnknown
	}
	return nil
}
func labOpenAttemptStore(root *os.Root) (*os.Root, error) {
	accountingInfo, err := root.Lstat("accounting")
	if err != nil || !accountingInfo.IsDir() || accountingInfo.Mode()&os.ModeSymlink != 0 {
		return nil, ErrInactive
	}
	store, err := root.OpenRoot("accounting")
	if err != nil {
		return nil, ErrInactive
	}
	info, err := store.Stat(".")
	if err != nil || !os.SameFile(accountingInfo, info) || info.Mode().Perm() != 0700 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		store.Close()
		return nil, ErrInactive
	}
	return store, nil
}
func PrepareLabAttemptGroup(path string) error {
	admission, err := labLoadAttemptAdmission(path)
	if err != nil {
		return err
	}
	defer admission.root.Close()
	boot, now, err := labBootClock()
	if err != nil {
		return err
	}
	if err := admission.root.Mkdir("accounting", 0700); err != nil {
		return ErrInactive
	}
	if labSyncDirectory(admission.root) != nil {
		return ErrUnknown
	}
	store, err := labOpenAttemptStore(admission.root)
	if err != nil {
		return ErrUnknown
	}
	defer store.Close()
	group := labAttemptGroup(admission, boot, now)
	if _, err := labAttemptRecord(labAttemptEncode(group), labAttemptGroupFormat); err != nil {
		return err
	}
	return labWriteImmutable(store, "group.json", labAttemptEncode(group))
}
func OpenLabAttempts(ctx context.Context, path string, source *LabSource, collaborators ...LabAttemptIO) (*LabAttemptGate, error) {
	if len(collaborators) > 1 {
		return nil, ErrInput
	}
	if source == nil || source.labSourceState == nil || source.pins == nil {
		return nil, ErrInput
	}
	admission, err := labLoadAttemptAdmission(path)
	if err != nil {
		return nil, err
	}
	gate := &LabAttemptGate{admission: admission, stopped: make(chan struct{}), io: labAttemptIO(collaborators)}
	failed := true
	defer func() {
		if failed {
			gate.release()
		}
	}()
	store, err := labOpenAttemptStore(admission.root)
	if err != nil {
		return nil, err
	}
	gate.store = store
	lock, err := store.OpenFile("lock", os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, ErrUnknown
	}
	gate.lock = lock
	if syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return nil, ErrInactive
	}
	raw, err := labAttemptRead(store, "group.json", 0400, 65536)
	if err != nil {
		return nil, err
	}
	group, err := labAttemptRecord(raw, labAttemptGroupFormat)
	if err != nil {
		return nil, err
	}
	admission.group = group
	boot, now, err := labBootClock()
	if err != nil || boot != group["boot_id"] || !labEqual(group, labAttemptGroup(admission, boot, group["group_started_monotonic_ms"].(int64))) {
		return nil, ErrUnknown
	}
	if now < group["group_started_monotonic_ms"].(int64) || now-group["group_started_monotonic_ms"].(int64) >= admission.plan["max_wall_time_total_ms"].(int64) {
		return nil, ErrUnknown
	}
	if admission.acceptStart(source) != nil || admission.current(ctx) != nil {
		return nil, ErrIdentity
	}
	gate.lastClock = now
	ledger := admission.initialLedger(raw)
	gate.ledger = ledger
	gate.head = ledger["previous_sha256"].(string)
	totalRemaining := group["group_started_monotonic_ms"].(int64) + admission.plan["max_wall_time_total_ms"].(int64) - now
	groupDeadline := time.Now().Add(time.Duration(totalRemaining) * time.Millisecond)
	wallBoundary := !admission.monotonicDeadline.Before(groupDeadline)
	if !wallBoundary {
		groupDeadline = admission.monotonicDeadline
	}
	deadlineContext, deadlineCancel := context.WithDeadline(ctx, groupDeadline)
	gate.deadlineCancel = deadlineCancel
	go labWatchAttemptDeadline(deadlineContext, boot, group["group_started_monotonic_ms"].(int64)+admission.plan["max_wall_time_total_ms"].(int64), func(wall bool) {
		if wall || wallBoundary && deadlineContext.Err() == context.DeadlineExceeded {
			gate.boundary.Store(true)
		}
		admission.source.end()
	})
	if _, statErr := store.Lstat("claimed"); !os.IsNotExist(statErr) {
		if gate.reload() != nil {
			return nil, ErrUnknown
		}
		if gate.ledger["status"] == "open" {
			attempts := gate.ledger["attempts"].([]any)
			if len(attempts) > 0 && labObject(attempts[len(attempts)-1])["state"] == "reserved" {
				attempt := labObject(attempts[len(attempts)-1])
				gate.unknown(attempt, now)
			} else {
				gate.ledger["status"] = "stopped"
			}
			if gate.commit() != nil {
				return nil, ErrUnknown
			}
		}
		failed = false
		return gate, nil
	}
	if labWriteImmutable(store, "claimed", []byte(labAttemptHash(group))) != nil || gate.commit() != nil {
		return nil, ErrUnknown
	}
	after, clockErr := gate.clock()
	if clockErr != nil || after-group["group_started_monotonic_ms"].(int64) >= admission.plan["max_wall_time_total_ms"].(int64) || admission.current(ctx) != nil {
		return nil, ErrUnknown
	}
	failed = false
	go gate.supervise(ctx)
	return gate, nil
}
func labWatchAttemptDeadline(ctx context.Context, boot string, until int64, retire func(bool)) {
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			if ctx.Err() == context.DeadlineExceeded {
				retire(false)
			}
			return
		case <-ticker.C:
			currentBoot, now, err := labBootClock()
			if err != nil || currentBoot != boot {
				retire(false)
				return
			}
			if now >= until {
				retire(true)
				return
			}
		}
	}
}
func (gate *LabAttemptGate) release() {
	if gate.deadlineCancel != nil {
		gate.deadlineCancel()
	}
	if gate.lock != nil {
		gate.lock.Close()
	}
	if gate.store != nil {
		gate.store.Close()
	}
	if gate.admission != nil {
		gate.admission.root.Close()
	}
}
func (gate *LabAttemptGate) Close() error {
	gate.mu.Lock()
	defer gate.mu.Unlock()
	if gate.closed {
		return nil
	}
	gate.closed = true
	close(gate.stopped)
	if gate.active != nil {
		gate.active.cancel()
		_, now, err := labBootClock()
		if err != nil {
			now = gate.lastClock
		}
		attempts := gate.ledger["attempts"].([]any)
		gate.unknown(labObject(attempts[len(attempts)-1]), now)
		_ = gate.commit()
	}
	gate.release()
	return nil
}
func (gate *LabAttemptGate) commit() error {
	prior := gate.head
	if gate.ledger["sequence"].(int64) > 0 {
		raw, err := labAttemptRead(gate.store, "head", 0400, 128)
		if err != nil || string(raw) != prior {
			return ErrUnknown
		}
	}
	gate.ledger["sequence"] = gate.ledger["sequence"].(int64) + 1
	gate.ledger["previous_sha256"] = prior
	raw := labAttemptEncode(gate.ledger)
	if _, err := labAttemptRecord(raw, labAttemptLedgerFormat); err != nil {
		return ErrUnknown
	}
	name := fmt.Sprintf("%09d.json", gate.ledger["sequence"].(int64))
	if labWriteImmutable(gate.store, name, raw, gate.io) != nil {
		return ErrUnknown
	}
	next := labDigest(raw)
	if labWriteImmutable(gate.store, "head.next", []byte(next), gate.io) != nil {
		return ErrUnknown
	}
	if gate.ledger["sequence"].(int64) > 1 {
		current, err := labAttemptRead(gate.store, "head", 0400, 128)
		if err != nil || string(current) != prior {
			return ErrUnknown
		}
	}
	if gate.store.Rename("head.next", "head") != nil || labSyncDirectory(gate.store, gate.io) != nil {
		return ErrUnknown
	}
	gate.head = next
	return nil
}
func (gate *LabAttemptGate) reload() error {
	head, err := labAttemptRead(gate.store, "head", 0400, 128)
	if err != nil {
		return ErrUnknown
	}
	directory, err := gate.store.Open(".")
	if err != nil {
		return ErrUnknown
	}
	names, err := directory.Readdirnames(-1)
	directory.Close()
	if err != nil {
		return ErrUnknown
	}
	count := 0
	for _, name := range names {
		switch name {
		case "group.json", "claimed", "lock", "head":
			continue
		}
		if len(name) != 14 || name[9:] != ".json" {
			return ErrUnknown
		}
		count++
	}
	if count < 1 || count > 514 {
		return ErrUnknown
	}
	previous := labAttemptHash(map[string]any{"domain": "swarma-broker-lab-attempt-ledger-genesis/1", "operation_id": gate.ledger["operation_id"]})
	immutable := gate.ledger
	var last map[string]any
	for sequence := 1; sequence <= count; sequence++ {
		raw, err := labAttemptRead(gate.store, fmt.Sprintf("%09d.json", sequence), 0400, 262144)
		if err != nil {
			return ErrUnknown
		}
		record, err := labAttemptRecord(raw, labAttemptLedgerFormat)
		if err != nil || record["sequence"] != int64(sequence) || record["previous_sha256"] != previous {
			return ErrUnknown
		}
		for name, value := range immutable {
			switch name {
			case "sequence", "previous_sha256", "status", "attempts":
				continue
			}
			if !labEqual(record[name], value) {
				return ErrUnknown
			}
		}
		if gate.history(last, record) != nil {
			return ErrUnknown
		}
		previous = labDigest(raw)
		last = record
	}
	if string(head) != previous {
		return ErrUnknown
	}
	gate.ledger = last
	gate.head = previous
	return nil
}
func (gate *LabAttemptGate) history(before, after map[string]any) error {
	attempts := after["attempts"].([]any)
	if len(attempts) > int(gate.admission.plan["max_invocations"].(int64)) {
		return ErrUnknown
	}
	spent := int64(0)
	lastSettled := after["group_started_monotonic_ms"].(int64)
	limit, _ := labMicroUSD(gate.admission.plan["max_total_cost_usd"])
	for index, value := range attempts {
		attempt := labObject(value)
		if attempt["ordinal"] != int64(index+1) || attempt["reservation_output_tokens"] != gate.admission.plan["max_output_tokens_per_invocation"] {
			return ErrUnknown
		}
		worst, err := labWorstReservation(gate.admission.price, attempt["reservation_output_tokens"].(int64))
		if err != nil || attempt["reservation_cost_usd"] != labUSD(worst) {
			return ErrUnknown
		}
		started, settled := attempt["started_monotonic_ms"].(int64), attempt["settled_monotonic_ms"].(int64)
		if started < lastSettled || started-after["group_started_monotonic_ms"].(int64) >= gate.admission.plan["max_wall_time_total_ms"].(int64) || spent >= limit || worst > limit-spent {
			return ErrUnknown
		}
		switch attempt["state"] {
		case "reserved":
			if index != len(attempts)-1 || attempt["usage_complete"] != false || attempt["settled_micro_usd"] != int64(0) || settled != 0 || attempt["upstream_request_id"] != "not-observed" || attempt["usage_sha256"] != labUsageUnavailable || !labEqual(attempt["usage"], labUsageZero()) {
				return ErrUnknown
			}
		case "unknown":
			if after["status"] != "unknown" || attempt["settled_micro_usd"] != worst || attempt["usage_complete"] != false || settled < started || attempt["upstream_request_id"] != "not-observed" || attempt["usage_sha256"] != labUsageUnavailable || !labEqual(attempt["usage"], labUsageZero()) {
				return ErrUnknown
			}
		case "settled":
			if settled-started >= gate.admission.plan["max_wall_time_per_invocation_ms"].(int64) || settled-after["group_started_monotonic_ms"].(int64) >= gate.admission.plan["max_wall_time_total_ms"].(int64) {
				return ErrUnknown
			}
			cost, err := labPriceCharge(gate.admission.price, labObject(attempt["usage"]))
			if err != nil || attempt["settled_micro_usd"] != cost || attempt["usage_complete"] != true || settled < started || attempt["upstream_request_id"] == "not-observed" || attempt["usage_sha256"] != labAttemptHash(attempt["usage"]) {
				return ErrUnknown
			}
		}
		cost := attempt["settled_micro_usd"].(int64)
		if cost > labSafeInteger-spent {
			return ErrUnknown
		}
		spent += cost
		if attempt["state"] != "reserved" {
			lastSettled = settled
		}
		if index < len(attempts)-1 && (attempt["state"] != "settled" || spent >= limit || labObject(attempt["usage"])["output_tokens"] == gate.admission.plan["max_output_tokens_per_invocation"]) {
			return ErrUnknown
		}
	}
	if after["status"] == "open" && len(attempts) > 0 && (spent >= limit || len(attempts) == int(gate.admission.plan["max_invocations"].(int64)) && labObject(attempts[len(attempts)-1])["state"] == "settled") {
		return ErrUnknown
	}
	if before == nil {
		if len(attempts) != 0 || after["status"] != "open" {
			return ErrUnknown
		}
		return nil
	}
	old := before["attempts"].([]any)
	if before["status"] != "open" {
		return ErrUnknown
	}
	if len(attempts) < len(old) || len(attempts) > len(old)+1 {
		return ErrUnknown
	}
	for index, value := range old {
		prior := labObject(value)
		if prior["state"] != "reserved" {
			if !labEqual(value, attempts[index]) {
				return ErrUnknown
			}
			continue
		}
		next := labObject(attempts[index])
		if len(attempts) != len(old) || next["state"] == "reserved" {
			return ErrUnknown
		}
		for _, name := range []string{"ordinal", "started_monotonic_ms", "reservation_output_tokens", "reservation_cost_usd"} {
			if prior[name] != next[name] {
				return ErrUnknown
			}
		}
	}
	if len(attempts) == len(old)+1 {
		if len(old) > 0 && labObject(old[len(old)-1])["state"] != "settled" || after["status"] != "open" || labObject(attempts[len(old)])["state"] != "reserved" {
			return ErrUnknown
		}
	}
	return nil
}
func (gate *LabAttemptGate) unknown(attempt map[string]any, now int64) {
	cost, _ := labMicroUSD(attempt["reservation_cost_usd"])
	attempt["state"] = "unknown"
	attempt["settled_micro_usd"] = cost
	attempt["settled_monotonic_ms"] = now
	attempt["usage_complete"] = false
	attempt["usage"] = labUsageZero()
	attempt["usage_sha256"] = labUsageUnavailable
	attempt["upstream_request_id"] = "not-observed"
	gate.ledger["status"] = "unknown"
}
func (gate *LabAttemptGate) clock() (int64, error) {
	boot, now, err := labBootClock()
	if err != nil || boot != gate.ledger["boot_id"] || now < gate.lastClock {
		return 0, ErrUnknown
	}
	gate.lastClock = now
	return now, nil
}
func (gate *LabAttemptGate) begin(ctx context.Context) (*labAttempt, error) {
	if !gate.busy.CompareAndSwap(false, true) {
		return nil, ErrInactive
	}
	forwarded := false
	defer func() {
		if !forwarded {
			gate.busy.Store(false)
		}
	}()
	gate.mu.Lock()
	defer gate.mu.Unlock()
	defer func() {
		if gate.ledger["status"] == "unknown" {
			gate.admission.source.end()
		}
	}()
	if gate.closed || gate.active != nil || gate.ledger["status"] != "open" {
		return nil, ErrInactive
	}
	savedHead := gate.head
	if gate.reload() != nil || gate.head != savedHead {
		gate.ledger["status"] = "unknown"
		return nil, ErrUnknown
	}
	now, err := gate.clock()
	if err != nil || gate.admission.current(ctx) != nil {
		gate.ledger["status"] = "unknown"
		_ = gate.commit()
		return nil, ErrUnknown
	}
	attempts := gate.ledger["attempts"].([]any)
	plan := gate.admission.plan
	limit, _ := labMicroUSD(plan["max_total_cost_usd"])
	reserved, err := labWorstReservation(gate.admission.price, plan["max_output_tokens_per_invocation"].(int64))
	spent := int64(0)
	for _, value := range attempts {
		prior := labObject(value)
		if prior["state"] != "settled" {
			return nil, ErrUnknown
		}
		cost := prior["settled_micro_usd"].(int64)
		if cost > labSafeInteger-spent {
			return nil, ErrUnknown
		}
		spent += cost
	}
	elapsed := now - gate.ledger["group_started_monotonic_ms"].(int64)
	if err != nil || elapsed < 0 || elapsed >= plan["max_wall_time_total_ms"].(int64) || len(attempts) >= int(plan["max_invocations"].(int64)) || spent >= limit || reserved > limit-spent {
		gate.ledger["status"] = "stopped"
		if gate.commit() != nil {
			return nil, ErrUnknown
		}
		return nil, ErrInactive
	}
	attemptRecord := map[string]any{"ordinal": int64(len(attempts) + 1), "state": "reserved", "reservation_output_tokens": plan["max_output_tokens_per_invocation"], "reservation_cost_usd": labUSD(reserved), "settled_micro_usd": int64(0), "usage_complete": false, "usage": labUsageZero(), "upstream_request_id": "not-observed", "usage_sha256": labUsageUnavailable, "started_monotonic_ms": now, "settled_monotonic_ms": int64(0)}
	remaining := min(plan["max_wall_time_per_invocation_ms"].(int64), plan["max_wall_time_total_ms"].(int64)-elapsed)
	deadline := time.Now().Add(time.Duration(remaining) * time.Millisecond)
	if gate.admission.monotonicDeadline.Before(deadline) {
		deadline = gate.admission.monotonicDeadline
	}
	call, cancel := context.WithDeadline(ctx, deadline)
	go labWatchAttemptDeadline(call, gate.ledger["boot_id"].(string), now+plan["max_wall_time_per_invocation_ms"].(int64), func(bool) {
		gate.admission.source.end()
	})
	defer func() {
		if !forwarded {
			cancel()
		}
	}()
	gate.ledger["attempts"] = append(attempts, attemptRecord)
	if gate.commit() != nil {
		gate.ledger["status"] = "unknown"
		return nil, ErrUnknown
	}
	after, clockErr := gate.clock()
	elapsed = after - gate.ledger["group_started_monotonic_ms"].(int64)
	activeElapsed := after - now
	if clockErr != nil || gate.admission.current(call) != nil || activeElapsed >= plan["max_wall_time_per_invocation_ms"].(int64) || elapsed >= plan["max_wall_time_total_ms"].(int64) {
		gate.unknown(attemptRecord, gate.lastClock)
		_ = gate.commit()
		return nil, ErrUnknown
	}
	attempt := &labAttempt{gate: gate, ordinal: attemptRecord["ordinal"].(int64), ctx: call, cancel: cancel, done: make(chan struct{})}
	gate.active = attempt
	forwarded = true
	go attempt.monitor()
	return attempt, nil
}
func (attempt *labAttempt) monitor() {
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-attempt.done:
			return
		case <-attempt.ctx.Done():
			return
		case <-ticker.C:
			if attempt.gate.admission.current(attempt.ctx) != nil {
				attempt.cancel()
				return
			}
			attempt.gate.mu.Lock()
			now, err := attempt.gate.clock()
			total := attempt.gate.ledger["group_started_monotonic_ms"].(int64) + attempt.gate.admission.plan["max_wall_time_total_ms"].(int64)
			attempt.gate.mu.Unlock()
			if err != nil || now >= total {
				attempt.cancel()
				return
			}
		}
	}
}
func (attempt *labAttempt) finish(usage map[string]any, requestID string, complete bool) error {
	result := error(ErrUnknown)
	attempt.once.Do(func() {
		defer attempt.gate.busy.Store(false)
		defer close(attempt.done)
		defer attempt.cancel()
		defer func() {
			if result != nil {
				attempt.gate.admission.source.end()
			}
		}()
		gate := attempt.gate
		gate.mu.Lock()
		defer gate.mu.Unlock()
		if gate.closed {
			return
		}
		records := gate.ledger["attempts"].([]any)
		record := labObject(records[len(records)-1])
		now, err := gate.clock()
		if err != nil {
			now = gate.lastClock
			complete = false
		}
		cost, chargeErr := labPriceCharge(gate.admission.price, usage)
		reservation, _ := labMicroUSD(record["reservation_cost_usd"])
		if !complete || now-record["started_monotonic_ms"].(int64) >= gate.admission.plan["max_wall_time_per_invocation_ms"].(int64) || now-gate.ledger["group_started_monotonic_ms"].(int64) >= gate.admission.plan["max_wall_time_total_ms"].(int64) || attempt.ctx.Err() != nil || gate.admission.current(attempt.ctx) != nil || chargeErr != nil || cost > reservation || requestID == "not-observed" || labValue(requestID, "id") != nil {
			gate.unknown(record, now)
		} else {
			record["state"] = "settled"
			record["settled_micro_usd"] = cost
			record["settled_monotonic_ms"] = now
			record["usage_complete"] = true
			record["usage"] = usage
			record["usage_sha256"] = labAttemptHash(usage)
			record["upstream_request_id"] = requestID
			if int64(len(records)) >= gate.admission.plan["max_invocations"].(int64) {
				gate.ledger["status"] = "stopped"
			}
			total := int64(0)
			for _, value := range records {
				total += labObject(value)["settled_micro_usd"].(int64)
			}
			limit, _ := labMicroUSD(gate.admission.plan["max_total_cost_usd"])
			if total >= limit || usage["output_tokens"] == gate.admission.plan["max_output_tokens_per_invocation"] {
				gate.ledger["status"] = "stopped"
			}
			result = nil
		}
		gate.active = nil
		if gate.commit() != nil {
			gate.ledger["status"] = "unknown"
			result = ErrUnknown
		}
	})
	return result
}
func (gate *LabAttemptGate) Status(operation, plan string, ordinal int64) ([]byte, error) {
	gate.mu.Lock()
	defer gate.mu.Unlock()
	if gate.closed || gate.ledger["operation_id"] != operation || gate.ledger["plan_sha256"] != plan || ordinal < 1 || ordinal > int64(len(gate.ledger["attempts"].([]any))) {
		return nil, ErrIdentity
	}
	head, err := labAttemptRead(gate.store, "head", 0400, 128)
	raw, readErr := labAttemptRead(gate.store, fmt.Sprintf("%09d.json", gate.ledger["sequence"].(int64)), 0400, 262144)
	if err != nil || readErr != nil || string(head) != gate.head || labDigest(raw) != gate.head || !bytes.Equal(raw, labAttemptEncode(gate.ledger)) {
		return nil, ErrUnknown
	}
	return raw, nil
}
func (gate *LabAttemptGate) supervise(ctx context.Context) {
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-gate.stopped:
			return
		case <-ticker.C:
			gate.mu.Lock()
			if gate.closed {
				gate.mu.Unlock()
				return
			}
			now, err := gate.clock()
			fresh := gate.admission.current(ctx)
			expired := now-gate.ledger["group_started_monotonic_ms"].(int64) >= gate.admission.plan["max_wall_time_total_ms"].(int64)
			if err == nil && fresh == nil && !expired {
				gate.mu.Unlock()
				continue
			}
			if gate.active != nil {
				gate.active.cancel()
			} else if gate.ledger["status"] == "open" {
				gate.ledger["status"] = "unknown"
				if expired && (gate.boundary.Load() || fresh == nil) {
					gate.boundary.Store(true)
					gate.ledger["status"] = "stopped"
				}
				_ = gate.commit()
			}
			gate.mu.Unlock()
			gate.admission.source.end()
			return
		}
	}
}
func (gate *LabAttemptGate) FinalizeBoundary() error {
	gate.mu.Lock()
	defer gate.mu.Unlock()
	if !gate.closed && gate.boundary.Load() && gate.active == nil && gate.ledger["status"] == "open" {
		gate.ledger["status"] = "stopped"
		if gate.commit() != nil {
			gate.ledger["status"] = "unknown"
			return ErrUnknown
		}
	}
	return nil
}
func (gate *LabAttemptGate) Err() error {
	gate.mu.Lock()
	defer gate.mu.Unlock()
	if gate.ledger["status"] == "unknown" {
		return ErrUnknown
	}
	if gate.closed || gate.ledger["status"] != "open" {
		return ErrInactive
	}
	return nil
}

func (admission *labAttemptAdmission) initialLedger(groupRaw []byte) map[string]any {
	group := admission.group
	observation := admission.observation
	ledger := map[string]any{}
	for name, value := range group {
		ledger[name] = value
	}
	ledger["format"] = labAttemptLedgerFormat
	ledger["group_sha256"] = labDigest(groupRaw)
	ledger["start_observation_sha256"] = labAttemptHash(observation)
	ledger["manager_instance_id"] = labObject(observation["manager"])["instance_id"]
	ledger["store_generation"] = labObject(observation["store"])["generation"]
	ledger["start_receipt"] = observation["receipts"].([]any)[0]
	ledger["start_debit"] = observation["debits"].([]any)[0]
	ledger["sequence"] = int64(0)
	ledger["previous_sha256"] = labAttemptHash(map[string]any{"domain": "swarma-broker-lab-attempt-ledger-genesis/1", "operation_id": group["operation_id"]})
	ledger["attempts"] = []any{}
	ledger["status"] = "open"
	return ledger
}

func ReadLabAttemptStatus(path, operation, plan string, ordinal int64) ([]byte, error) {
	admission, err := labLoadAttemptAdmission(path, true)
	if err != nil {
		return nil, ErrUnknown
	}
	defer admission.root.Close()
	if admission.plan["operation_id"] != operation || labAttemptHash(admission.plan) != plan {
		return nil, ErrIdentity
	}
	store, err := labOpenAttemptStore(admission.root)
	if err != nil {
		return nil, ErrUnknown
	}
	defer store.Close()
	groupRaw, err := labAttemptRead(store, "group.json", 0400, 65536)
	if err != nil {
		return nil, ErrUnknown
	}
	group, err := labAttemptRecord(groupRaw, labAttemptGroupFormat)
	if err != nil {
		return nil, ErrUnknown
	}
	admission.group = group
	if !labEqual(group, labAttemptGroup(admission, group["boot_id"].(string), group["group_started_monotonic_ms"].(int64))) || admission.acceptStart(nil) != nil {
		return nil, ErrUnknown
	}
	gate := &LabAttemptGate{admission: admission, store: store, ledger: admission.initialLedger(groupRaw)}
	if gate.reload() != nil {
		return nil, ErrUnknown
	}
	return gate.Status(operation, plan, ordinal)
}
