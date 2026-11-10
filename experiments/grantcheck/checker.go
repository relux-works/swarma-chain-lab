package grantcheck

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernel"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernelbind"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/durable"
)

const MaxPresentationBytes = 16384
const maxUnix = 253402300799
const stateName = "grantcheck.json"

var (
	ErrConfig = errors.New("grantcheck: invalid configuration")
	ErrState  = errors.New("grantcheck: state unavailable")
)

// Config is resolved by the authenticated a2a daemon (a2ad), never from a message.
// StateDir must already exist, be canonical/absolute/private, and belong to this
// identity alone. Node must honor cancellation; no worker goroutine is detached.
type Config struct {
	Identity     string
	AgentName    string
	LandlordName string
	IssuerPubkey string
	StateDir     string
	Node         su.Node
	Now          func() time.Time
	CheckTimeout time.Duration
}

type backend interface {
	kernel.Checker
	kernel.Presenter
}

// Checker cannot be copied or constructed as a useful zero value. Only New
// installs a backend, always the landed kernelbind adapter; no public injection
// point can substitute a replayed/fake verdict for a chain observation.
type Checker struct {
	mu       sync.Mutex
	config   Config
	binding  string
	backend  backend
	poisoned bool
}

type state struct {
	Version int    `json:"version"`
	Binding string `json:"binding"`
	High    int64  `json:"high"`
}

func validLabel(s string, max int) bool {
	if len(s) == 0 || len(s) > max {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}
func validName(s string) bool {
	return strings.HasPrefix(s, "id/") && validLabel(strings.TrimPrefix(s, "id/"), 252)
}
func validKey(s string) bool {
	if len(s) != 64 {
		return false
	}
	b, e := hex.DecodeString(s)
	if e != nil || len(b) != 32 || hex.EncodeToString(b) != s {
		return false
	}
	_, e = schnorr.ParsePubKey(b)
	return e == nil
}

func New(config Config) (*Checker, error) {
	if !validLabel(config.Identity, 128) || !validName(config.AgentName) || !validName(config.LandlordName) ||
		config.AgentName == config.LandlordName || !validKey(config.IssuerPubkey) || config.Node == nil ||
		config.CheckTimeout < 0 || config.CheckTimeout > 5*time.Second {
		return nil, ErrConfig
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.CheckTimeout == 0 {
		config.CheckTimeout = 5 * time.Second
	}
	if !canonicalRoot(config.StateDir) {
		return nil, ErrState
	}
	a, err := kernelbind.New(config.Node, config.StateDir, config.AgentName, config.LandlordName, config.IssuerPubkey)
	if err != nil {
		return nil, ErrConfig
	}
	pins, _ := json.Marshal(struct{ Identity, Agent, Landlord, Issuer, Network, Genesis string }{
		config.Identity, config.AgentName, config.LandlordName, config.IssuerPubkey, "regtest", su.RegtestGenesis,
	})
	c := &Checker{config: config, binding: rental.Hash(pins), backend: a}
	s, err := durable.Open(config.StateDir, "grantcheck.lock")
	if err != nil {
		return nil, ErrState
	}
	defer s.Close()
	raw, err := s.Read(stateName, 4096)
	if err != nil {
		return nil, ErrState
	}
	if raw == nil {
		// Never adopt an old K1 cache or closure journal as a new identity.
		entries, e := os.ReadDir(config.StateDir)
		if e != nil {
			return nil, ErrState
		}
		for _, entry := range entries {
			if entry.Name() != "grantcheck.lock" {
				return nil, ErrState
			}
		}
		now := config.Now().Unix()
		if now < 0 || now > maxUnix {
			return nil, ErrConfig
		}
		b, _ := json.Marshal(state{Version: 1, Binding: c.binding, High: now})
		if s.Write(stateName, b) != nil {
			return nil, ErrState
		}
	} else if _, err = c.load(s); err != nil {
		return nil, ErrState
	}
	return c, nil
}

func canonicalRoot(path string) bool {
	actual, err := filepath.EvalSymlinks(path)
	return err == nil && filepath.IsAbs(path) && filepath.Clean(path) == path && actual == path
}
func (c *Checker) load(s *durable.Store) (state, error) {
	var m state
	raw, err := s.Read(stateName, 4096)
	if err != nil || raw == nil || json.Unmarshal(raw, &m) != nil {
		return m, ErrState
	}
	b, _ := json.Marshal(m)
	if !bytes.Equal(raw, b) || m.Version != 1 || m.Binding != c.binding || m.High < 0 || m.High > maxUnix {
		return m, ErrState
	}
	return m, nil
}

// stamp persists the clock high-water before any possible live return. A failed
// fsync poisons this instance; it cannot assume which state became durable.
func (c *Checker) stamp(s *durable.Store, m *state) (int64, Code) {
	now := c.config.Now().Unix()
	if now < m.High || now < 0 || now > maxUnix {
		return 0, CodeClockInvalid
	}
	if now != m.High {
		m.High = now
		b, _ := json.Marshal(m)
		if s.Write(stateName, b) != nil {
			c.poisoned = true
			return 0, CodeStateUnavailable
		}
	}
	return now, CodeLive
}

func (c *Checker) parse(p Presentation, peer string) (rental.Grant, Code) {
	var empty rental.Grant
	if len(p.Bytes) > MaxPresentationBytes {
		return empty, CodeOversize
	}
	id, err := kernel.PresentationID(p.Bytes)
	if err != nil || id != p.GrantID {
		return empty, CodeInvalidPresentation
	}
	proof, err := rental.ParseGrantPresentation(p.Bytes)
	if err != nil {
		return empty, CodeInvalidPresentation
	}
	g := proof.SignedGrant.Grant
	if g.GranteeKey != peer || g.AgentName != c.config.AgentName || g.LandlordName != c.config.LandlordName ||
		g.IssuerKey != c.config.IssuerPubkey || g.Network != "regtest" || g.Genesis != su.RegtestGenesis {
		return empty, CodeBindingMismatch
	}
	return g, CodeLive
}

// Inbound requires the authenticated NIP-17 inner seal signer. nil presentation
// uses previously admitted proof; explicit invalid proof never falls back.
func (c *Checker) Inbound(ctx context.Context, sender string, p *Presentation) Verdict {
	return c.check(ctx, sender, p, true)
}

// Outbound freshly checks the exact recipient using this identity's admitted
// public proof cache. It never routes agent replies through the exchange.
func (c *Checker) Outbound(ctx context.Context, recipient string) Verdict {
	return c.check(ctx, recipient, nil, false)
}

func (c *Checker) check(ctx context.Context, peer string, supplied *Presentation, inbound bool) Verdict {
	fail := func(code Code) Verdict { return route(code, inbound, false) }
	if ctx == nil || ctx.Err() != nil {
		return fail(CodeCancelled)
	}
	if c == nil || c.backend == nil {
		return fail(CodeCheckFailed)
	}
	if !validKey(peer) {
		return fail(CodeInvalidPeer)
	}
	var p Presentation
	var g rental.Grant
	if supplied != nil {
		// Bounds precede allocation, parser, state access and kernel/node calls.
		if len(supplied.Bytes) > MaxPresentationBytes {
			return fail(CodeOversize)
		}
		p = Presentation{GrantID: supplied.GrantID, Bytes: bytes.Clone(supplied.Bytes)}
		var code Code
		g, code = c.parse(p, peer)
		if code != CodeLive {
			return fail(code)
		}
	}
	if !c.mu.TryLock() {
		return fail(CodeBusy)
	}
	defer c.mu.Unlock()
	if c.poisoned || !canonicalRoot(c.config.StateDir) {
		return fail(CodeStateUnavailable)
	}
	ctx, cancel := context.WithTimeout(ctx, c.config.CheckTimeout)
	defer cancel()
	s, err := durable.Open(c.config.StateDir, "grantcheck.lock")
	if err != nil {
		return fail(CodeStateUnavailable)
	}
	defer s.Close()
	m, err := c.load(s)
	if err != nil {
		return fail(CodeStateUnavailable)
	}
	now, code := c.stamp(s, &m)
	if code != CodeLive {
		return fail(code)
	}
	if ctx.Err() != nil {
		return fail(CodeCancelled)
	}
	if supplied == nil {
		raw, err := c.backend.CachedGrant(peer)
		if errors.Is(err, kernel.ErrNoPresentation) {
			v := fail(CodeNoGrant)
			v.CheckedAt = now
			return v
		}
		if err != nil {
			return fail(CodeStateUnavailable)
		}
		id, err := kernel.PresentationID(raw)
		if err != nil {
			return fail(CodeStateUnavailable)
		}
		p = Presentation{GrantID: id, Bytes: raw}
		g, code = c.parse(p, peer)
		if code != CodeLive {
			return fail(CodeStateUnavailable)
		}
	}
	var r kernel.Receipt
	if supplied != nil {
		r, err = c.backend.Present(ctx, p.Bytes, p.GrantID, c.config.AgentName, peer, now)
	} else {
		r, err = c.backend.Check(ctx, p.Bytes, c.config.AgentName, peer, now)
	}
	if ctx.Err() != nil {
		return fail(CodeCancelled)
	}
	if err != nil {
		return fail(CodeCheckFailed)
	}
	if r.GrantID != p.GrantID || r.AgentName != g.AgentName || r.LandlordName != g.LandlordName || r.CheckedAt != now {
		return fail(CodeCheckFailed)
	}
	v := mapReceipt(r, inbound)
	// An unexpected scope on a live result cannot become executor metadata.
	if v.Decision == Live && !slices.Equal(r.Scope, g.Scope) {
		return fail(CodeCheckFailed)
	}
	v.GrantID, v.NotBefore, v.NotAfter, v.CheckedAt = p.GrantID, g.NotBefore, g.NotAfter, now
	if v.Decision != Live {
		return v
	}
	// Repeat the clock check after kernel cache/journal writes, and after our
	// own persistence. Bounded retries cover a second boundary during fsync.
	for range 3 {
		end, code := c.stamp(s, &m)
		if code != CodeLive {
			return fail(code)
		}
		if end < g.NotBefore {
			return fail(CodeClockInvalid)
		}
		if end >= g.NotAfter {
			v = fail(CodeExpired)
			v.Decision = Refused
			return v
		}
		if ctx.Err() != nil {
			return fail(CodeCancelled)
		}
		last := c.config.Now().Unix()
		if last < end {
			return fail(CodeClockInvalid)
		}
		if last == end {
			v.CheckedAt = end
			v.Scope = slices.Clone(g.Scope)
			return v
		}
	}
	return fail(CodeClockInvalid)
}
