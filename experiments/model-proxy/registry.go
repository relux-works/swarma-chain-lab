package modelproxy

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"sync"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/single-use/durable"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/payloadbootstrap/codec"
)

type reservation struct {
	Model string `json:"model"`
	Usage Usage  `json:"usage"`
	Cost  uint64 `json:"cost"`
}
type record struct {
	Binding  Binding              `json:"binding"`
	Bearer   codec.Secret[Secret] `json:"bearer"`
	Phase    string               `json:"phase"`
	Exposure Counts               `json:"exposure"`
	Observed Usage                `json:"observed"`
	Pending  *reservation         `json:"pending"`
}
type ledger struct {
	Version int               `json:"version"`
	Config  string            `json:"config"`
	High    int64             `json:"high"`
	Records map[string]record `json:"records"`
}
type Service struct {
	mu               sync.Mutex
	cfg              Config
	disk             *durable.Store
	state            ledger
	closed, poisoned bool
	cancel           map[string]context.CancelFunc
}

func New(c Config) (*Service, error) {
	if c.Now == nil || !validOrigin(c.Endpoint.URL) || !digest(c.Endpoint.CertSHA256) || !validURL(c.Upstream) || len(c.APIKey.Reveal()) < 1 || len(c.APIKey.Reveal()) > 4096 || len(c.Models) < 1 || len(c.Models) > 16 {
		return nil, fail("CONFIG")
	}
	for _, v := range []byte(c.APIKey.Reveal()) {
		if v < 33 || v > 126 {
			return nil, fail("CONFIG")
		}
	}
	models := map[string]Model{}
	for k, m := range c.Models {
		if len(k) < 1 || len(k) > 128 || m.ContextTokens < 1 || m.ContextTokens > 1<<32 || m.InputNanoUSD == 0 || m.OutputNanoUSD == 0 || len(m.Source) < 1 || len(m.Source) > 1024 {
			return nil, fail("CONFIG")
		}
		for _, v := range k {
			if !(v >= 'a' && v <= 'z' || v >= '0' && v <= '9' || v == '-' || v == '.') {
				return nil, fail("CONFIG")
			}
		}
		if _, ok := price(m, Usage{m.ContextTokens, m.ContextTokens}); !ok {
			return nil, fail("CONFIG")
		}
		models[k] = m
	}
	c.Models = models
	if c.Timeout == 0 {
		c.Timeout = 30 * time.Second
	}
	if c.Timeout < time.Millisecond || c.Timeout > time.Minute {
		return nil, fail("CONFIG")
	}
	if c.Dialect == nil {
		c.Dialect = Messages{}
	}
	profiles, e := validateProfiles(c)
	if e != nil {
		return nil, e
	}
	c.ModelProfiles = profiles
	fingerprint := []any{c.Endpoint, c.Upstream, c.Models, c.Dialect.Profile()}
	if len(profiles) != 0 {
		fingerprint = append(fingerprint, profiles)
	}
	d, e := durable.Open(c.StateDir, "proxy.lock")
	if e != nil {
		return nil, fail("STATE_OPEN")
	}
	s := &Service{cfg: c, disk: d, cancel: map[string]context.CancelFunc{}, state: ledger{Version: 1, Config: sum(privateCanonical(fingerprint)), Records: map[string]record{}}}
	raw, e := d.Read("registry.json", MaxBody)
	if e != nil {
		d.Close()
		return nil, fail("STATE_READ")
	}
	if raw != nil {
		var v ledger
		if unique(raw) != nil || json.Unmarshal(raw, &v) != nil || string(privateCanonical(v)) != string(raw) || v.Version != 1 || v.Config != s.state.Config || v.High < 0 || len(v.Records) > MaxRecords || v.Records == nil {
			d.Close()
			return nil, fail("STATE")
		}
		seen := map[Secret]bool{}
		for id, r := range v.Records {
			b, e := base64.RawURLEncoding.DecodeString(string(r.Bearer.Reveal()))
			if !r.Binding.Valid() || id != r.Binding.SlotID || e != nil || len(b) != 32 || base64.RawURLEncoding.EncodeToString(b) != string(r.Bearer.Reveal()) || seen[r.Bearer.Reveal()] || !validRecord(r, c.Models) {
				d.Close()
				return nil, fail("STATE")
			}
			seen[r.Bearer.Reveal()] = true
			// An interrupted attempt remains charged at its entire worst-case exposure.
			r.Pending = nil
			v.Records[id] = r
		}
		s.state = v
		if e = s.save(); e != nil {
			d.Close()
			return nil, e
		}
	}
	return s, nil
}
func validRecord(r record, models map[string]Model) bool {
	if r.Phase != "prepared" && r.Phase != "active" && r.Phase != "revoked" && r.Phase != "frozen" {
		return false
	}
	c, x := r.Binding.Caps, r.Exposure
	if x.Input > c.InputTokens || x.Output > c.OutputTokens || x.Requests > c.Requests || x.Cost > c.CostNanoUSD || r.Observed.Input > x.Input || r.Observed.Output > x.Output {
		return false
	}
	if p := r.Pending; p != nil {
		m, ok := models[p.Model]
		cost, priced := price(m, p.Usage)
		if !ok || !priced || cost != p.Cost || p.Usage.Input != m.ContextTokens || p.Usage.Output == 0 || p.Usage.Output > c.MaxTokens || p.Cost > x.Cost || p.Usage.Input > x.Input || p.Usage.Output > x.Output || x.Requests == 0 {
			return false
		}
	}
	return true
}
func (s *Service) save() error {
	if s.closed || s.poisoned {
		return fail("STATE_WRITE")
	}
	raw := privateCanonical(s.state)
	if len(raw) > MaxBody || s.disk.Write("registry.json", raw) != nil {
		s.poisoned = true
		return fail("STATE_WRITE")
	}
	return nil
}
func (s *Service) clock() (int64, error) {
	if s.closed || s.poisoned {
		return 0, fail("UNAVAILABLE")
	}
	now := s.cfg.Now().Unix()
	if now < 1 || now > 1<<50 || now < s.state.High {
		return now, fail("CLOCK")
	}
	if now > s.state.High {
		s.state.High = now
		if e := s.save(); e != nil {
			return now, e
		}
	}
	return now, nil
}
func (s *Service) Prepare(b Binding) (Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now, e := s.clock()
	if e != nil {
		return Credential{}, e
	}
	if !b.Valid() || now < b.NotBefore || now >= b.NotAfter {
		return Credential{}, fail("BINDING")
	}
	if r, ok := s.state.Records[b.SlotID]; ok {
		if r.Binding != b {
			return Credential{}, fail("CONFLICT")
		}
		if r.Phase == "revoked" || r.Phase == "frozen" {
			return Credential{}, fail("TERMINAL")
		}
		return s.credential(r), nil
	}
	if len(s.state.Records) >= MaxRecords {
		return Credential{}, fail("CAPACITY")
	}
	live := 0
	for _, r := range s.state.Records {
		if (r.Phase == "prepared" || r.Phase == "active") && now < r.Binding.NotAfter {
			live++
		}
	}
	if live >= MaxLive {
		return Credential{}, fail("CAPACITY")
	}
	bfr := make([]byte, 32)
	if _, e = rand.Read(bfr); e != nil {
		return Credential{}, fail("RANDOM")
	}
	r := record{Binding: b, Bearer: NewBearer(Secret(base64.RawURLEncoding.EncodeToString(bfr))), Phase: "prepared"}
	s.state.Records[b.SlotID] = r
	if e = s.save(); e != nil {
		return Credential{}, e
	}
	return s.credential(r), nil
}
func (s *Service) credential(r record) Credential {
	ep := s.cfg.Endpoint
	return Credential{r.Bearer, ep}
}
func (s *Service) Activate(b Binding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now, e := s.clock()
	if e != nil {
		return e
	}
	r, ok := s.state.Records[b.SlotID]
	if !ok || r.Binding != b {
		return fail("BINDING")
	}
	if now < b.NotBefore || now >= b.NotAfter || r.Phase == "revoked" || r.Phase == "frozen" {
		return fail("TERMINAL")
	}
	r.Phase = "active"
	s.state.Records[b.SlotID] = r
	return s.save()
}
func (s *Service) Revoke(b Binding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.poisoned {
		return fail("UNAVAILABLE")
	}
	r, ok := s.state.Records[b.SlotID]
	if !ok || r.Binding != b {
		return fail("BINDING")
	}
	r.Phase = "revoked"
	s.state.Records[b.SlotID] = r
	e := s.save()
	if cancel := s.cancel[b.SlotID]; cancel != nil {
		cancel()
	}
	return e
}
func (s *Service) Status(id string) (Status, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.poisoned {
		return Status{}, fail("UNAVAILABLE")
	}
	r, ok := s.state.Records[id]
	if !ok {
		return Status{}, fail("NOT_FOUND")
	}
	return Status{r.Binding, r.Phase, r.Exposure, r.Observed, r.Pending != nil}, nil
}
func (s *Service) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		for _, cancel := range s.cancel {
			cancel()
		}
		s.disk.Close()
	}
	return nil
}
func (s *Service) authorize(id string, bearer Secret) (record, error) {
	now, e := s.clock()
	if e != nil {
		return record{}, e
	}
	r, ok := s.state.Records[id]
	if !ok || subtle.ConstantTimeCompare([]byte(r.Bearer.Reveal()), []byte(bearer)) != 1 || r.Phase != "active" || now < r.Binding.NotBefore || now >= r.Binding.NotAfter {
		return record{}, fail("AUTH")
	}
	return r, nil
}
func (s *Service) reserve(ctx context.Context, id string, bearer Secret, p Prepared) (context.Context, context.CancelFunc, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, e := s.authorize(id, bearer)
	if e != nil {
		return nil, nil, e
	}
	if r.Pending != nil || len(s.cancel) >= MaxLive {
		return nil, nil, fail("BUSY")
	}
	m, ok := s.cfg.Models[p.Model]
	if !ok {
		return nil, nil, fail("MODEL")
	}
	c := r.Binding.Caps
	if p.MaxTokens == 0 || p.MaxTokens > c.MaxTokens {
		return nil, nil, fail("CAP")
	}
	u := Usage{m.ContextTokens, p.MaxTokens}
	cost, ok := price(m, u)
	if !ok {
		return nil, nil, fail("CAP")
	}
	next := r.Exposure
	var a, b, d, f bool
	next.Input, a = add(next.Input, u.Input)
	next.Output, b = add(next.Output, u.Output)
	next.Requests, d = add(next.Requests, 1)
	next.Cost, f = add(next.Cost, cost)
	if !a || !b || !d || !f || next.Input > c.InputTokens || next.Output > c.OutputTokens || next.Requests > c.Requests || next.Cost > c.CostNanoUSD {
		return nil, nil, fail("CAP")
	}
	r.Exposure = next
	r.Pending = &reservation{p.Model, u, cost}
	s.state.Records[id] = r
	if e = s.save(); e != nil {
		return nil, nil, e
	}
	budget := s.cfg.Timeout
	left := time.Duration(r.Binding.NotAfter-s.cfg.Now().Unix()) * time.Second
	if left < budget {
		budget = left
	}
	call, cancel := context.WithTimeout(ctx, budget)
	s.cancel[id] = cancel
	return call, cancel, nil
}
func (s *Service) alive(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now, e := s.clock()
	r, ok := s.state.Records[id]
	return e == nil && ok && r.Phase == "active" && now >= r.Binding.NotBefore && now < r.Binding.NotAfter
}
func (s *Service) settle(id string, u *Usage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.cancel, id)
	if s.closed || s.poisoned {
		return fail("STATE_WRITE")
	}
	r := s.state.Records[id]
	p := r.Pending
	if p == nil {
		return fail("STATE_WRITE")
	}
	var verdict error
	if u != nil {
		cost, ok := price(s.cfg.Models[p.Model], *u)
		if !ok || u.Input > p.Usage.Input || u.Output > p.Usage.Output || cost > p.Cost {
			r.Phase = "frozen"
			verdict = fail("USAGE")
		} else {
			r.Exposure.Input = r.Exposure.Input - p.Usage.Input + u.Input
			r.Exposure.Output = r.Exposure.Output - p.Usage.Output + u.Output
			r.Exposure.Cost = r.Exposure.Cost - p.Cost + cost
			r.Observed.Input += u.Input
			r.Observed.Output += u.Output
		}
	}
	r.Pending = nil
	s.state.Records[id] = r
	if e := s.save(); e != nil {
		return e
	}
	return verdict
}
