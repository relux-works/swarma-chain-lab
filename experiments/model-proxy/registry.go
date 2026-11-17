package modelproxy

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"os"
	"sync"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/single-use/durable"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/payloadbootstrap/codec"
)

type reservation struct {
	Model string `json:"model"`
	Usage Usage  `json:"usage"`
	Cost  uint64 `json:"cost"`
	Day   int64  `json:"day"`
}
type record struct {
	Binding  Binding              `json:"binding"`
	Bearer   codec.Secret[Secret] `json:"bearer"`
	Phase    string               `json:"phase"`
	Exposure Counts               `json:"exposure"`
	Observed Usage                `json:"observed"`
	Pending  *reservation         `json:"pending"`
}
type dailyAccounting struct {
	Day       int64  `json:"day"`
	Committed uint64 `json:"committed"`
	Checksum  string `json:"checksum"`
}

func (d *dailyAccounting) checksum() string { return sum(privateCanonical([]any{d.Day, d.Committed})) }

func newDaily(day int64) *dailyAccounting {
	d := &dailyAccounting{Day: day}
	d.Checksum = d.checksum()
	return d
}

type ledger struct {
	Version int               `json:"version"`
	Config  string            `json:"config"`
	High    int64             `json:"high"`
	Records map[string]record `json:"records"`
	Daily   *dailyAccounting  `json:"daily,omitempty"`
	// Blocked maps a run account digest to the tripwire verdict that blocked
	// it. Only the explicit owner clear removes an entry.
	Blocked map[string]string `json:"blocked,omitempty"`
}
type Service struct {
	mu                sync.Mutex
	cfg               Config
	source            CredentialSource
	tripwire          *tripwire
	disk              *durable.Store
	state             ledger
	persisted         string
	accountingFailure string
	closed, poisoned  bool
	cancel            map[string]context.CancelFunc
}

// InitializeAccounting is an explicit provisioning operation, never a startup
// fallback. The CLI admits its configuration through the signed static boundary.
// An existing lock, ledger or any other entry prevents reinitialization.
func InitializeAccounting(c Config) error {
	entries, e := os.ReadDir(c.StateDir)
	if e != nil || len(entries) != 0 {
		return fail("DAILY_ACCOUNTING_INIT_REFUSED")
	}
	s, e := newService(c, true)
	if e != nil {
		return e
	}
	return s.Close()
}

func New(c Config) (*Service, error) { return newService(c, false) }

func newService(c Config, initialize bool) (*Service, error) {
	if c.Now == nil || !validOrigin(c.Endpoint.URL) || !digest(c.Endpoint.CertSHA256) || !validURL(c.Upstream) || len(c.Models) < 1 || len(c.Models) > 16 {
		return nil, fail("CONFIG")
	}
	// Exactly one credential origin: the static key or a per-use source.
	static := len(c.APIKey.Reveal()) > 0
	if static == (c.Source != nil) {
		return nil, fail("CONFIG_CREDENTIAL")
	}
	source := c.Source
	if static {
		if !printable(c.APIKey.Reveal(), 4096) {
			return nil, fail("CONFIG")
		}
		source = &staticSource{value: c.APIKey}
	}
	switch c.Mode {
	case "", ModeDevelopment:
	case ModeManaged:
		// Managed mode allow-lists the broker adapter: the proxy must never be
		// able to read a provider token from this host. A static key is the
		// wrong origin for the mode; any other source, wrapped or not, is not
		// the broker. The structural seam receives this same private marker
		// only through AdaptManagedSource.
		if static {
			return nil, fail("CONFIG_MODE")
		}
		if _, broker := c.Source.(brokerSource); !broker {
			return nil, fail("CONFIG_MODE_NO_BROKER")
		}
	default:
		return nil, fail("CONFIG_MODE")
	}
	if c.RunMaxWindowSeconds > MaxRunWindow {
		return nil, fail("CONFIG_RUN_WINDOW")
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
	fingerprint = append(fingerprint, c.DailyCostCeilingNanoUSD)
	d, e := durable.Open(c.StateDir, "proxy.lock")
	if e != nil {
		return nil, fail("STATE_OPEN")
	}
	s := &Service{cfg: c, source: source, tripwire: newTripwire(), disk: d, cancel: map[string]context.CancelFunc{}, state: ledger{Version: 1, Config: sum(privateCanonical(fingerprint)), Records: map[string]record{}}}
	if static {
		// The static key is issued at construction, so the tripwire sees it
		// before the first request rather than after the first fetch.
		s.tripwire.add(c.APIKey.Reveal())
	}
	raw, e := d.Read("registry.json", MaxBody)
	if e != nil {
		d.Close()
		return nil, fail("DAILY_ACCOUNTING_CORRUPT")
	}
	if raw == nil {
		if !initialize {
			d.Close()
			return nil, fail("DAILY_ACCOUNTING_MISSING")
		}
		now := c.Now().Unix()
		if now < 1 || now > 1<<50 {
			d.Close()
			return nil, fail("CLOCK")
		}
		s.state.High = now
		s.state.Daily = newDaily(now / 86400)
		raw = privateCanonical(s.state)
		if d.Write("registry.json", raw) != nil {
			d.Close()
			return nil, fail("STATE_WRITE")
		}
		s.persisted = sum(raw)
		return s, nil
	}
	if initialize {
		d.Close()
		return nil, fail("DAILY_ACCOUNTING_INIT_REFUSED")
	}
	s.persisted = sum(raw)
	if raw != nil {
		var v ledger
		if unique(raw) != nil || json.Unmarshal(raw, &v) != nil || string(privateCanonical(v)) != string(raw) || v.Version != 1 || v.High < 0 || len(v.Records) > MaxRecords || v.Records == nil {
			d.Close()
			return nil, fail("DAILY_ACCOUNTING_CORRUPT")
		}
		if v.Daily == nil || v.Daily.Checksum != v.Daily.checksum() || v.Daily.Day < 0 || v.Daily.Day != v.High/86400 || v.Daily.Committed > c.DailyCostCeilingNanoUSD {
			d.Close()
			return nil, fail("DAILY_ACCOUNTING_CORRUPT")
		}
		if v.Config != s.state.Config {
			d.Close()
			return nil, fail("STATE")
		}
		for account, code := range v.Blocked {
			if !digest(account) || !blockCode(code) {
				d.Close()
				return nil, fail("STATE")
			}
		}
		var pendingCost uint64
		seen := map[Secret]bool{}
		for id, r := range v.Records {
			b, e := base64.RawURLEncoding.DecodeString(string(r.Bearer.Reveal()))
			if !r.Binding.Valid() || id != r.Binding.SlotID || e != nil || len(b) != 32 || base64.RawURLEncoding.EncodeToString(b) != string(r.Bearer.Reveal()) || seen[r.Bearer.Reveal()] || !validRecord(r, c.Models) {
				d.Close()
				return nil, fail("STATE")
			}
			seen[r.Bearer.Reveal()] = true
			if p := r.Pending; p != nil {
				if p.Day < 0 || p.Day > v.Daily.Day {
					d.Close()
					return nil, fail("DAILY_ACCOUNTING_CORRUPT")
				}
				if p.Day == v.Daily.Day {
					var ok bool
					pendingCost, ok = add(pendingCost, p.Cost)
					if !ok || pendingCost > v.Daily.Committed {
						d.Close()
						return nil, fail("DAILY_ACCOUNTING_CORRUPT")
					}
				}
			}
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
	if e := s.accountingIntegrity(); e != nil {
		return e
	}
	s.state.Daily.Checksum = s.state.Daily.checksum()
	raw := privateCanonical(s.state)
	if len(raw) > MaxBody || s.disk.Write("registry.json", raw) != nil {
		s.poisoned = true
		return fail("STATE_WRITE")
	}
	s.persisted = sum(raw)
	return nil
}

// The process must not recreate deleted state or overwrite corrupted accounting.
// All calls hold mu; the filesystem lock excludes a second cooperating process.
func (s *Service) accountingIntegrity() error {
	raw, e := s.disk.Read("registry.json", MaxBody)
	code := ""
	if e != nil {
		code = "DAILY_ACCOUNTING_CORRUPT"
	} else if raw == nil {
		code = "DAILY_ACCOUNTING_MISSING"
	} else if sum(raw) != s.persisted {
		code = "DAILY_ACCOUNTING_CORRUPT"
	}
	if code != "" {
		s.poisoned = true
		s.accountingFailure = code
		return fail(code)
	}
	return nil
}

func (s *Service) clock() (int64, error) {
	if s.accountingFailure != "" {
		return 0, fail(s.accountingFailure)
	}
	if s.closed || s.poisoned {
		return 0, fail("UNAVAILABLE")
	}
	if e := s.accountingIntegrity(); e != nil {
		return 0, e
	}
	now := s.cfg.Now().Unix()
	if now < 1 || now > 1<<50 || now < s.state.High {
		return now, fail("CLOCK")
	}
	if now > s.state.High {
		s.state.High = now
		if day := now / 86400; day > s.state.Daily.Day {
			s.state.Daily = newDaily(day)
		}
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
	if b.Kind() == KindRun {
		if e := s.runRefusal(b); e != nil {
			return Credential{}, e
		}
		if s.isBlocked(b) {
			return Credential{}, fail("ACCOUNT_BLOCKED")
		}
		// One live binding per (generation, run_id, account): another slot for
		// the tuple conflicts while that binding is prepared or active, and a
		// revoked, frozen or expired tuple is terminal and never re-prepared.
		// The exact retry of the same slot keeps its existing rule below.
		for other, r := range s.state.Records {
			if other == b.SlotID || r.Binding.Run != b.Run {
				continue
			}
			if r.Phase == "revoked" || r.Phase == "frozen" || r.Binding.NotAfter <= now {
				return Credential{}, fail("TERMINAL")
			}
			return Credential{}, fail("CONFLICT")
		}
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
	if e := s.runRefusal(b); e != nil {
		return e
	}
	if s.isBlocked(b) {
		return fail("ACCOUNT_BLOCKED")
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
	if e := s.runRefusal(r.Binding); e != nil {
		return record{}, e
	}
	if s.isBlocked(r.Binding) {
		return record{}, fail("ACCOUNT_BLOCKED")
	}
	return r, nil
}

// runRefusal is the run-kind admission that Prepare, Activate and every use
// share: a run
// binding exists only behind the broker-backed managed mode, and only while its
// window fits the CURRENT sealed maximum, where zero admits none. Re-checking
// at use is what lets an operator lower the maximum, or reopen the state in
// development mode, and have it take effect on the next request; neither Mode
// nor the maximum enters the ledger fingerprint for that reason.
func (s *Service) runRefusal(b Binding) error {
	if b.Kind() != KindRun {
		return nil
	}
	if _, broker := s.source.(brokerSource); s.cfg.Mode != ModeManaged || !broker {
		return fail("RUN_REQUIRES_MANAGED")
	}
	if s.cfg.RunMaxWindowSeconds == 0 || b.NotAfter-b.NotBefore > int64(s.cfg.RunMaxWindowSeconds) {
		return fail("RUN_WINDOW")
	}
	return nil
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
	dailyNext, ok := add(s.state.Daily.Committed, cost)
	if !ok || dailyNext > s.cfg.DailyCostCeilingNanoUSD {
		return nil, nil, fail("DAILY_COST_CEILING")
	}
	// Both reservations commit in one fsync/rename/directory-sync transaction
	// under mu, before any provider call. Pending/uncertain cost stays charged.
	s.state.Daily.Committed = dailyNext
	r.Exposure = next
	r.Pending = &reservation{Model: p.Model, Usage: u, Cost: cost, Day: s.state.Daily.Day}
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
	return e == nil && ok && r.Phase == "active" && now >= r.Binding.NotBefore && now < r.Binding.NotAfter && s.runRefusal(r.Binding) == nil && !s.isBlocked(r.Binding)
}
func (s *Service) settle(id string, u *Usage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.cancel, id)
	if s.closed || s.poisoned {
		return fail("STATE_WRITE")
	}
	if _, e := s.clock(); e != nil {
		return e
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
			// Settlement belongs to the admission day, never a later day's budget.
			if p.Day == s.state.Daily.Day {
				s.state.Daily.Committed -= p.Cost - cost
			}
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
