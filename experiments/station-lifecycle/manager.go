package lifecycle

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/single-use/durable"
)

type record struct {
	ID             string       `json:"id"`
	StartAttempted bool         `json:"start_attempted"`
	CreateFence    *CreateFence `json:"create_fence,omitempty"`
	Slot           *Slot        `json:"slot"`
	BootstrapHash  string       `json:"bootstrap_hash"`
	Binding        string       `json:"binding"`
	Phase          string       `json:"phase"`
	Reason         string       `json:"reason"`
}
type state struct {
	Version int               `json:"version"`
	Policy  string            `json:"policy"`
	High    int64             `json:"high"`
	Records map[string]record `json:"records"`
}
type Manager struct {
	mu       sync.Mutex
	cfg      Config
	disk     *durable.Store
	state    state
	poisoned bool
	closed   bool
}

func publicBinding(s Slot, secretHash string) string {
	s.Bootstrap = NewPrivateBytes(nil)
	return hash(privateCanonical([]any{slotPrivateValue(s), secretHash}))
}
func recordStatus(r record) Status {
	s := Status{SlotID: r.ID, Binding: r.Binding, Phase: r.Phase, Reason: r.Reason}
	if r.Slot != nil {
		s.NotAfter = r.Slot.NotAfter
	}
	return s
}
func New(c Config) (*Manager, error) {
	if !c.Range.valid() || !label(c.Payload.ID) || !digest(c.Payload.SHA256) || c.Host == nil || c.Now == nil {
		return nil, fail("CONFIG")
	}
	if c.StepTimeout == 0 {
		c.StepTimeout = 2 * time.Second
	}
	if c.TickInterval == 0 {
		c.TickInterval = 100 * time.Millisecond
	}
	if c.StepTimeout < time.Millisecond || c.StepTimeout > 5*time.Second || c.TickInterval < time.Millisecond || c.TickInterval > time.Second {
		return nil, fail("CONFIG")
	}
	d, e := durable.Open(c.StateDir, "lifecycle.lock")
	if e != nil {
		return nil, fail("STATE_OPEN")
	}
	m := &Manager{cfg: c, disk: d, state: state{Version: 1, Policy: hash(privateCanonical([]any{c.Range, c.Payload})), Records: map[string]record{}}}
	raw, e := d.Read("state.json", MaxBody)
	if e != nil {
		d.Close()
		return nil, fail("STATE_READ")
	}
	if raw != nil {
		var s state
		if strict(raw, &s) != nil || s.Version != 1 || s.Policy != m.state.Policy || s.High < 0 || s.Records == nil || len(s.Records) > MaxRetained {
			d.Close()
			return nil, fail("STATE_BINDING")
		}
		for id, r := range s.Records {
			if !c.Range.contains(id) || r.ID != id {
				d.Close()
				return nil, fail("STATE_RECORD")
			}
			if r.CreateFence != nil && (!r.StartAttempted || !r.CreateFence.Valid()) {
				d.Close()
				return nil, fail("STATE_RECORD")
			}
			if (r.Phase == "starting" || r.Phase == "running") && !r.StartAttempted {
				d.Close()
				return nil, fail("STATE_RECORD")
			}
			switch r.Phase {
			case "starting", "running", "stopping", "stopped":
			default:
				d.Close()
				return nil, fail("STATE_RECORD")
			}
			switch r.Reason {
			case "", "HOST_START", "HOST_CLEANUP", "EXPIRED", "STOPPED", "RECOVERY", "CLOCK_ROLLBACK":
			default:
				d.Close()
				return nil, fail("STATE_RECORD")
			}
			if r.Slot == nil {
				d.Close()
				return nil, fail("STATE_RECORD")
			} else {
				v := *r.Slot
				if r.Phase == "stopped" {
					if len(v.Bootstrap.Reveal()) != 0 {
						d.Close()
						return nil, fail("STATE_RECORD")
					}
					v.Bootstrap = NewPrivateBytes(make(Secret, 32))
				} else if hash(v.Bootstrap.Reveal()) != r.BootstrapHash {
					d.Close()
					return nil, fail("STATE_RECORD")
				}
				if !digest(r.BootstrapHash) || c.Range.validateSlot(v) != nil || v.ID != id || v.PayloadID != c.Payload.ID || v.PayloadSHA256 != c.Payload.SHA256 || publicBinding(*r.Slot, r.BootstrapHash) != r.Binding {
					d.Close()
					return nil, fail("STATE_RECORD")
				}
			}
		}
		m.state = s
	}
	return m, nil
}
func (m *Manager) save() error {
	raw := privateCanonical(m.state)
	if len(raw) > MaxBody {
		m.poisoned = true
		return fail("STATE_CAPACITY")
	}
	if m.disk.Write("state.json", raw) != nil {
		m.poisoned = true
		return fail("STATE_WRITE")
	}
	return nil
}
func (m *Manager) clock() (int64, error) {
	if m.closed {
		return 0, fail("CLOSED")
	}
	now := m.cfg.Now().Unix()
	if now < 1 || now > 1<<50 {
		return 0, fail("CLOCK")
	}
	if now < m.state.High {
		return now, fail("CLOCK_ROLLBACK")
	}
	if m.poisoned {
		return now, fail("STATE_WRITE")
	}
	if now > m.state.High {
		m.state.High = now
		if e := m.save(); e != nil {
			return now, e
		}
	}
	return now, nil
}
func (m *Manager) Start(ctx context.Context, s Slot) (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e := m.cfg.Range.validateSlot(s); e != nil {
		return Status{}, e
	}
	now, e := m.clock()
	if e != nil {
		return Status{}, e
	}
	if ctx.Err() != nil {
		return Status{}, fail("CANCELLED")
	}
	if s.PayloadID != m.cfg.Payload.ID || s.PayloadSHA256 != m.cfg.Payload.SHA256 {
		return Status{}, fail("HOST_POLICY")
	}
	incoming := publicBinding(s, hash(s.Bootstrap.Reveal()))
	if old, ok := m.state.Records[s.ID]; ok {
		if old.Binding != incoming {
			return recordStatus(old), fail("SLOT_CONFLICT")
		}
		if old.Phase == "stopped" {
			return recordStatus(old), fail("SLOT_TERMINAL")
		}
		if old.Phase != "running" {
			return m.stop(ctx, s.ID, "RECOVERY")
		}
		if now >= old.Slot.NotAfter {
			return m.stop(ctx, s.ID, "EXPIRED")
		}
		return recordStatus(old), nil
	}
	if now < s.NotBefore || s.NotAfter-now <= 60 {
		return Status{}, fail("SLOT_WINDOW")
	}
	if len(m.state.Records) >= MaxRetained {
		return Status{}, fail("CAPACITY")
	}
	live := 0
	for _, r := range m.state.Records {
		if r.Phase != "stopped" {
			live++
		}
	}
	if live >= MaxLive {
		return Status{}, fail("CAPACITY")
	}
	// Opaque immutable holders make a value copy independent of caller buffers.
	copied := s
	r := record{ID: s.ID, StartAttempted: true, Slot: &copied, BootstrapHash: hash(s.Bootstrap.Reveal()), Binding: incoming, Phase: "starting"}
	// Capacity is checked before any map write or host operation.
	before := privateCanonical(m.state)
	m.state.Records[s.ID] = r
	if len(privateCanonical(m.state)) > MaxBody {
		_ = strict(before, &m.state)
		return Status{}, fail("CAPACITY")
	}
	if e := m.save(); e != nil {
		return recordStatus(r), e
	}
	budget := m.cfg.StepTimeout
	if left := time.Duration(s.NotAfter-now) * time.Second; left < budget {
		budget = left
	}
	call, cancel := context.WithTimeout(ctx, budget)
	err := m.cfg.Host.Start(call, copied, func(f CreateFence) error {
		if !f.Valid() || r.CreateFence != nil {
			return fail("CREATE_FENCE")
		}
		r.CreateFence = &f
		m.state.Records[s.ID] = r
		return m.save()
	})
	cancel()
	if err != nil {
		status, cleanup := m.stop(context.WithoutCancel(ctx), s.ID, "HOST_START")
		if cleanup != nil {
			return status, cleanup
		}
		return status, fail("HOST_START")
	}
	if m.cfg.Now().Unix() >= s.NotAfter {
		return m.stop(context.WithoutCancel(ctx), s.ID, "EXPIRED")
	}
	if m.cfg.Now().Unix() < m.state.High {
		return m.stop(context.WithoutCancel(ctx), s.ID, "CLOCK_ROLLBACK")
	}
	r.Phase = "running"
	m.state.Records[s.ID] = r
	if e := m.save(); e != nil {
		_, _ = m.stop(context.WithoutCancel(ctx), s.ID, "RECOVERY")
		return recordStatus(m.state.Records[s.ID]), e
	}
	return recordStatus(r), nil
}
func (m *Manager) stop(ctx context.Context, id, reason string) (Status, error) {
	r, ok := m.state.Records[id]
	if !ok {
		return Status{}, fail("NOT_FOUND")
	}
	if r.Phase == "stopped" {
		return recordStatus(r), nil
	}
	r.Phase = "stopping"
	r.Reason = reason
	m.state.Records[id] = r
	saved := m.save()
	call, cancel := context.WithTimeout(ctx, m.cfg.StepTimeout)
	e := m.cfg.Host.Stop(call, *r.Slot, !r.StartAttempted, r.CreateFence)
	cancel()
	if e != nil {
		r.Reason = "HOST_CLEANUP"
		m.state.Records[id] = r
		_ = m.save()
		return recordStatus(r), fail("HOST_CLEANUP")
	}
	if saved != nil {
		return recordStatus(r), saved
	}
	r.Phase = "stopped"
	r.Slot.Bootstrap = NewPrivateBytes(nil)
	m.state.Records[id] = r
	if e := m.save(); e != nil {
		return recordStatus(r), e
	}
	return recordStatus(r), nil
}
func (m *Manager) Stop(ctx context.Context, id string) (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return Status{}, fail("CLOSED")
	}
	if !m.cfg.Range.contains(id) {
		return Status{}, fail("SLOT_ID")
	}
	return m.stop(ctx, id, "STOPPED")
}
func (m *Manager) Status(ctx context.Context, id string) (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return Status{}, fail("CLOSED")
	}
	r, ok := m.state.Records[id]
	if !ok {
		return Status{}, fail("NOT_FOUND")
	}
	if r.Phase == "running" {
		call, cancel := context.WithTimeout(ctx, m.cfg.StepTimeout)
		phase, e := m.cfg.Host.Status(call, *r.Slot)
		cancel()
		if e != nil || phase != "running" {
			return recordStatus(r), fail("HOST_STATUS")
		}
	}
	return recordStatus(r), nil
}

// Tick is independent of the network client. Storage failure still permits
// cleanup attempts, but never a claimed durable success or a new start.
func (m *Manager) Tick(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now, clockErr := m.clock()
	if m.closed {
		return clockErr
	}
	var result error
	for id, r := range m.state.Records {
		if r.Phase == "stopped" {
			continue
		}
		reason := ""
		if r.Phase == "starting" || r.Phase == "stopping" {
			reason = "RECOVERY"
		} else if clockErr != nil {
			reason = "RECOVERY"
			if clockErr.Error() == "CLOCK_ROLLBACK" {
				reason = "CLOCK_ROLLBACK"
			}
		} else if now >= r.Slot.NotAfter {
			reason = "EXPIRED"
		}
		if reason == "" && r.Phase == "running" {
			call, cancel := context.WithTimeout(ctx, m.cfg.StepTimeout)
			phase, e := m.cfg.Host.Status(call, *r.Slot)
			cancel()
			if e != nil || phase != "running" {
				reason = "RECOVERY"
			}
		}
		if reason != "" {
			if _, e := m.stop(ctx, id, reason); e != nil {
				result = e
			}
		}
	}
	if result != nil {
		return result
	}
	return clockErr
}
func (m *Manager) Run(ctx context.Context) error {
	// A failed cleanup stays pending and is retried; it must not kill the
	// independent expiry worker while the network loop remains connected.
	_ = m.Tick(ctx)
	tick := time.NewTicker(m.cfg.TickInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
			_ = m.Tick(ctx)
		}
	}
}
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	m.disk.Close()
	return nil
}

// Apply binds authenticated broker commands to one immutable slot. A Stop that
// arrives before Start still asks the helper to prove absence/cleanup, rather
// than assuming an empty adapter journal means no OS state exists.
func (m *Manager) Apply(ctx context.Context, c Command) (Status, error) {
	if m.cfg.Range.validateSlot(c.Slot) != nil || c.Binding != publicBinding(c.Slot, hash(c.Slot.Bootstrap.Reveal())) {
		return Status{}, fail("COMMAND_BINDING")
	}
	if c.Slot.PayloadID != m.cfg.Payload.ID || c.Slot.PayloadSHA256 != m.cfg.Payload.SHA256 {
		return Status{}, fail("HOST_POLICY")
	}
	switch c.Op {
	case "start":
		return m.Start(ctx, c.Slot)
	case "stop":
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.closed {
			return Status{}, fail("CLOSED")
		}
		r, ok := m.state.Records[c.Slot.ID]
		if ok && r.Binding != c.Binding {
			return recordStatus(r), fail("SLOT_CONFLICT")
		}
		if !ok {
			if len(m.state.Records) >= MaxRetained {
				return Status{}, fail("CAPACITY")
			}
			s := copySlot(c.Slot)
			r = record{ID: s.ID, Slot: &s, BootstrapHash: hash(s.Bootstrap.Reveal()), Binding: c.Binding, Phase: "stopping", Reason: "STOPPED"}
			m.state.Records[s.ID] = r
			if e := m.save(); e != nil {
				return recordStatus(r), e
			}
		}
		return m.stop(ctx, c.Slot.ID, "STOPPED")
	default:
		return Status{}, fail("COMMAND_OP")
	}
}
func (m *Manager) Results() []Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Status, 0, len(m.state.Records))
	for _, r := range m.state.Records {
		if r.Binding != "" {
			out = append(out, recordStatus(r))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SlotID < out[j].SlotID })
	return out
}
