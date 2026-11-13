package lifecycle

import (
	"context"
	"crypto/rand"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/single-use/durable"
)

type BrokerConfig struct {
	StateDir     string
	Range        Range
	Payload      Payload
	Now          func() time.Time
	StartTimeout time.Duration
	// BootstrapProfile binds the encoder's version to durable state. Empty means
	// raw-v1. The trusted gateway adapter may wrap the fresh 32-byte credential in
	// an opaque, bounded payload document; managers never parse it.
	BootstrapProfile string
	EncodeBootstrap  func(key string, credential Secret) (Secret, error)
}
type brokerRecord struct {
	Key           string       `json:"key"`
	Credential    PrivateBytes `json:"credential"`
	Slot          Slot         `json:"slot"`
	BootstrapHash string       `json:"bootstrap_hash"`
	Binding       string       `json:"binding"`
	Desired       string       `json:"desired"`
	Result        Status       `json:"result"`
}
type brokerState struct {
	Version int                     `json:"version"`
	Config  string                  `json:"config"`
	High    int64                   `json:"high"`
	Records map[string]brokerRecord `json:"records"`
}
type Broker struct {
	mu               sync.Mutex
	cfg              BrokerConfig
	disk             *durable.Store
	state            brokerState
	notify           chan struct{}
	closed, poisoned bool
	waiting          int
	fresh            map[string]bool
}
type Command struct {
	Op      string `json:"op"`
	Slot    Slot   `json:"slot"`
	Binding string `json:"binding"`
}
type PollRequest struct {
	Version int      `json:"version"`
	Results []Status `json:"results"`
}
type PollResponse struct {
	Version  int       `json:"version"`
	Commands []Command `json:"commands"`
}

func NewBroker(c BrokerConfig) (*Broker, error) {
	if !c.Range.valid() || !label(c.Payload.ID) || !digest(c.Payload.SHA256) || c.Now == nil {
		return nil, fail("BROKER_CONFIG")
	}
	if c.BootstrapProfile == "" {
		c.BootstrapProfile = "raw-v1"
	}
	if !label(c.BootstrapProfile) || (c.EncodeBootstrap != nil && c.BootstrapProfile == "raw-v1") {
		return nil, fail("BROKER_CONFIG")
	}
	if c.StartTimeout == 0 {
		c.StartTimeout = 2 * time.Second
	}
	if c.StartTimeout < time.Millisecond || c.StartTimeout > 5*time.Second {
		return nil, fail("BROKER_CONFIG")
	}
	disk, e := durable.Open(c.StateDir, "broker.lock")
	if e != nil {
		return nil, fail("BROKER_OPEN")
	}
	b := &Broker{cfg: c, disk: disk, notify: make(chan struct{}), fresh: map[string]bool{}, state: brokerState{Version: 1, Config: hash(privateCanonical([]any{c.Range, c.Payload, c.BootstrapProfile})), Records: map[string]brokerRecord{}}}
	raw, e := disk.Read("broker.json", MaxBody)
	if e != nil {
		disk.Close()
		return nil, fail("BROKER_READ")
	}
	if raw != nil {
		var s brokerState
		if strict(raw, &s) != nil || s.Version != 1 || s.Config != b.state.Config || s.High < 0 || s.Records == nil || len(s.Records) > MaxRetained {
			disk.Close()
			return nil, fail("BROKER_STATE")
		}
		ids := map[string]bool{}
		for key, r := range s.Records {
			v := r.Slot
			if r.Desired == "stopped" {
				if len(v.Bootstrap.Reveal()) != 0 || len(r.Credential.Reveal()) != 0 {
					disk.Close()
					return nil, fail("BROKER_STATE")
				}
				v.Bootstrap = NewPrivateBytes(make(Secret, 32))
			} else if hash(v.Bootstrap.Reveal()) != r.BootstrapHash || len(r.Credential.Reveal()) != 32 {
				disk.Close()
				return nil, fail("BROKER_STATE")
			}
			if !digest(key) || r.Key != key || ids[v.ID] || c.Range.validateSlot(v) != nil || v.PayloadID != c.Payload.ID || v.PayloadSHA256 != c.Payload.SHA256 || !digest(r.BootstrapHash) || publicBinding(r.Slot, r.BootstrapHash) != r.Binding {
				disk.Close()
				return nil, fail("BROKER_STATE")
			}
			ids[v.ID] = true
			switch r.Desired {
			case "allocated", "start", "stop", "stopped":
			default:
				disk.Close()
				return nil, fail("BROKER_STATE")
			}
			if r.Result.SlotID != "" && (r.Result.SlotID != v.ID || r.Result.Binding != r.Binding || r.Result.NotAfter != v.NotAfter || !validStatus(r.Result)) {
				disk.Close()
				return nil, fail("BROKER_STATE")
			}
		}
		b.state = s
	}
	return b, nil
}
func validStatus(s Status) bool {
	switch s.Phase {
	case "starting", "running", "stopping", "stopped":
	default:
		return false
	}
	switch s.Reason {
	case "", "HOST_START", "HOST_CLEANUP", "EXPIRED", "STOPPED", "RECOVERY", "CLOCK_ROLLBACK":
	default:
		return false
	}
	return true
}
func (b *Broker) save() error {
	raw := privateCanonical(b.state)
	if len(raw) > MaxBody {
		b.poisoned = true
		return fail("BROKER_CAPACITY")
	}
	if b.disk.Write("broker.json", raw) != nil {
		b.poisoned = true
		return fail("BROKER_WRITE")
	}
	close(b.notify)
	b.notify = make(chan struct{})
	return nil
}
func (b *Broker) clock() (int64, error) {
	if b.closed {
		return 0, fail("CLOSED")
	}
	if b.poisoned {
		return 0, fail("BROKER_WRITE")
	}
	now := b.cfg.Now().Unix()
	if now < 1 || now > 1<<50 || now < b.state.High {
		return now, fail("CLOCK_ROLLBACK")
	}
	if now > b.state.High {
		b.state.High = now
		if e := b.save(); e != nil {
			return now, e
		}
	}
	return now, nil
}
func copySlot(s Slot) Slot { return s }
func (b *Broker) Allocate(key, grant string, before, after int64) (Slot, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now, e := b.clock()
	if e != nil {
		return Slot{}, e
	}
	if !digest(key) || !digest(grant) || before < 1 || after <= before || after-before > 3600 {
		return Slot{}, fail("SLOT_POLICY")
	}
	if r, ok := b.state.Records[key]; ok {
		if r.Slot.GrantID != grant || r.Slot.NotBefore != before || r.Slot.NotAfter != after {
			return Slot{}, fail("SLOT_CONFLICT")
		}
		if r.Desired == "stop" || r.Desired == "stopped" {
			return Slot{}, fail("SLOT_TERMINAL")
		}
		return copySlot(r.Slot), nil
	}
	if now < before || after-now <= 60 {
		return Slot{}, fail("SLOT_WINDOW")
	}
	if len(b.state.Records) >= MaxRetained {
		return Slot{}, fail("CAPACITY")
	}
	live := 0
	used := map[string]bool{}
	for _, r := range b.state.Records {
		used[r.Slot.ID] = true
		if r.Desired != "stopped" {
			live++
		}
	}
	if live >= MaxLive {
		return Slot{}, fail("CAPACITY")
	}
	id := ""
	for n := int(b.cfg.Range.First); n <= int(b.cfg.Range.Last); n++ {
		v := strconv.Itoa(n)
		if !used[v] {
			id = v
			break
		}
	}
	if id == "" {
		return Slot{}, fail("CAPACITY")
	}
	secret := make(Secret, 32)
	if _, e := rand.Read(secret); e != nil {
		return Slot{}, fail("RANDOM")
	}
	bootstrap := append(Secret(nil), secret...)
	if b.cfg.EncodeBootstrap != nil {
		var err error
		bootstrap, err = b.cfg.EncodeBootstrap(key, append(Secret(nil), secret...))
		if err != nil || len(bootstrap) < 1 || len(bootstrap) > 4096 {
			return Slot{}, fail("BOOTSTRAP")
		}
		bootstrap = append(Secret(nil), bootstrap...)
	}
	s := Slot{Version: 1, ID: id, GrantID: grant, NotBefore: before, NotAfter: after, PayloadID: b.cfg.Payload.ID, PayloadSHA256: b.cfg.Payload.SHA256, Bootstrap: NewPrivateBytes(bootstrap)}
	r := brokerRecord{Key: key, Credential: NewPrivateBytes(secret), Slot: s, BootstrapHash: hash(bootstrap), Binding: publicBinding(s, hash(bootstrap)), Desired: "allocated"}
	b.state.Records[key] = r
	if e := b.save(); e != nil {
		return Slot{}, e
	}
	return copySlot(s), nil
}

// Lookup recovers a retained booking mapping without allocating or restarting it.
// Terminal mappings remain available for idempotent cleanup, with no secret.
func (b *Broker) Lookup(key string) (Slot, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return Slot{}, fail("CLOSED")
	}
	if b.poisoned {
		return Slot{}, fail("BROKER_WRITE")
	}
	r, ok := b.state.Records[key]
	if !ok {
		return Slot{}, fail("NOT_FOUND")
	}
	return copySlot(r.Slot), nil
}

// Credential is private gateway custody; it is never returned in poll results.
func (b *Broker) Credential(key string) (Secret, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || b.poisoned {
		return nil, fail("BROKER_UNAVAILABLE")
	}
	r, ok := b.state.Records[key]
	if !ok || len(r.Credential.Reveal()) != 32 {
		return nil, fail("NOT_FOUND")
	}
	return append(Secret(nil), r.Credential.Reveal()...), nil
}

func (b *Broker) SetStart(key string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	now, e := b.clock()
	if e != nil {
		return e
	}
	r, ok := b.state.Records[key]
	if !ok {
		return fail("NOT_FOUND")
	}
	if r.Desired == "stop" || r.Desired == "stopped" {
		return fail("SLOT_TERMINAL")
	}
	if now < r.Slot.NotBefore || r.Slot.NotAfter-now <= 60 {
		return fail("SLOT_WINDOW")
	}
	b.fresh[key] = false
	r.Desired = "start"
	b.state.Records[key] = r
	return b.save()
}
func (b *Broker) SetStop(key string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return fail("CLOSED")
	}
	r, ok := b.state.Records[key]
	if !ok {
		return fail("NOT_FOUND")
	}
	if r.Desired == "stopped" {
		return nil
	}
	r.Desired = "stop"
	b.state.Records[key] = r
	return b.save()
}
func (b *Broker) Wait(ctx context.Context, key, phase string) (Status, error) {
	ctx, cancel := context.WithTimeout(ctx, b.cfg.StartTimeout)
	defer cancel()
	b.mu.Lock()
	if b.waiting >= MaxLive {
		b.mu.Unlock()
		return Status{}, fail("BUSY")
	}
	b.waiting++
	b.mu.Unlock()
	defer func() { b.mu.Lock(); b.waiting--; b.mu.Unlock() }()
	for {
		b.mu.Lock()
		if b.closed {
			b.mu.Unlock()
			return Status{}, fail("CLOSED")
		}
		r, ok := b.state.Records[key]
		fresh := b.fresh[key]
		now := b.cfg.Now().Unix()
		healthy := !b.poisoned && now >= b.state.High && now >= r.Slot.NotBefore && now < r.Slot.NotAfter
		ch := b.notify
		b.mu.Unlock()
		if !ok {
			return Status{}, fail("NOT_FOUND")
		}
		if phase == "running" && !healthy {
			return r.Result, fail("NOT_READY")
		}
		if r.Result.Phase == phase && (phase != "running" || (r.Desired == "start" && fresh)) {
			return r.Result, nil
		}
		if phase == "running" && (r.Desired == "stop" || r.Desired == "stopped" || r.Result.Reason != "") {
			return r.Result, fail("NOT_READY")
		}
		select {
		case <-ctx.Done():
			return r.Result, fail("NOT_READY")
		case <-ch:
		}
	}
}

// Poll is called only after mTLS authentication. Stop always wins over a late
// running report; retries return the same immutable command bytes and binding.
func (b *Broker) Poll(p PollRequest) (PollResponse, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := PollResponse{Version: 1, Commands: []Command{}}
	if p.Version != 1 || len(p.Results) > MaxRetained {
		return out, fail("POLL_REQUEST")
	}
	now, e := b.clock()
	if e != nil {
		return out, e
	}
	byID := map[string]string{}
	for key, r := range b.state.Records {
		byID[r.Slot.ID] = key
	}
	seen := map[string]bool{}
	for _, s := range p.Results {
		key, ok := byID[s.SlotID]
		if !ok || seen[s.SlotID] || !validStatus(s) {
			return out, fail("POLL_RESULT")
		}
		seen[s.SlotID] = true
		r := b.state.Records[key]
		if s.Binding != r.Binding || s.NotAfter != r.Slot.NotAfter {
			return out, fail("POLL_BINDING")
		}
	}
	for _, s := range p.Results {
		key := byID[s.SlotID]
		r := b.state.Records[key]
		if r.Desired == "stopped" {
			continue
		}
		if s.Phase == "stopped" {
			r.Desired = "stopped"
			r.Slot.Bootstrap = NewPrivateBytes(nil)
			r.Credential = NewPrivateBytes(nil)
		}
		b.fresh[key] = s.Phase == "running"
		r.Result = s
		b.state.Records[key] = r
	}
	// An allocated but never submitted slot also expires into a stop tombstone.
	for key, r := range b.state.Records {
		if r.Desired != "stopped" && now >= r.Slot.NotAfter {
			r.Desired = "stop"
			b.state.Records[key] = r
		}
	}
	if e := b.save(); e != nil {
		return out, e
	}
	keys := make([]string, 0, len(b.state.Records))
	for key := range b.state.Records {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		r := b.state.Records[key]
		if len(out.Commands) >= MaxLive {
			break
		}
		if r.Desired == "stop" {
			out.Commands = append(out.Commands, Command{Op: "stop", Slot: copySlot(r.Slot), Binding: r.Binding})
		} else if r.Desired == "start" && r.Result.Phase != "running" {
			out.Commands = append(out.Commands, Command{Op: "start", Slot: copySlot(r.Slot), Binding: r.Binding})
		}
	}
	return out, nil
}
func (b *Broker) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.closed {
		b.closed = true
		close(b.notify)
		b.disk.Close()
	}
	return nil
}
