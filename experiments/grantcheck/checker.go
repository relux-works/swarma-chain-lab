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
	ConstructionProfile string
	Identity            string
	AgentName           string
	LandlordName        string
	IssuerPubkey        string
	// ExecutorKey is required for pay and must be empty for trust.
	ExecutorKey string
	Freshness   *FreshnessPolicy
	// Terms is a bounded, nonblocking lookup of canonical terms by contract hash.
	// It must not perform I/O; transport adapters resolve objects before checking.
	Terms        func(string) ([]byte, error)
	StateDir     string
	Node         su.Node
	Now          func() time.Time
	CheckTimeout time.Duration

	// ContractProfile selects how the contract behind contract_sha256 is read:
	// ContractProfilePay (also selected by the empty string) or
	// ContractProfileTrust. It is never inferred from a grant or a contract.
	ContractProfile string
	// Network and Genesis are the configured chain binding: "regtest" with the
	// regtest genesis, or "main" with MainGenesis. The trust profile has no
	// default and refuses construction unless both name one such pair. The
	// pay profile keeps its fixed regtest pin when both are empty.
	Network string
	Genesis string
}

type backend interface {
	kernel.Checker
}

// Checker cannot be copied or constructed as a useful zero value. Only New
// installs a backend, always the landed kernelbind adapter; no public injection
// point can substitute a replayed/fake verdict for a chain observation.
type Checker struct {
	mu           sync.Mutex
	config       Config
	transport    Transport
	binding      string
	backend      backend
	poisoned     bool
	node         *policyNode
	observedTime time.Time

	// profile, network and genesis are the resolved Config values.
	profile string
	network string
	genesis string
}

type state struct {
	Version      int               `json:"version"`
	Binding      string            `json:"binding"`
	High         int64             `json:"high"`
	Provisioning []ProvisionRecord `json:"provisioning,omitempty"`
	Cache        []cachedProof     `json:"cache,omitempty"`
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
	return NewForTransport(config, NostrNIP17Seal)
}

// NewForTransport requires a supported, authenticated provenance pin. It never
// infers transport from message fields or adopts differently bound state.
func NewForTransport(config Config, transport Transport) (*Checker, error) {
	if !transport.valid() {
		return nil, ErrConfig
	}
	if e := su.RequireWitnessProfile(config.ConstructionProfile); e != nil {
		return nil, e
	}
	profile, network, genesis, bound := resolveBinding(config)
	if !bound {
		return nil, ErrConfig
	}
	if (profile == ContractProfilePay && !validKey(config.ExecutorKey)) ||
		(profile == ContractProfileTrust && config.ExecutorKey != "") || config.Terms == nil || !validFreshness(config.Freshness) {
		return nil, ErrConfig
	}
	config.Freshness = cloneFreshness(config.Freshness)
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
	node := &policyNode{Node: config.Node, policy: *config.Freshness, chain: network}
	if profile == ContractProfileTrust {
		// The trust profile admits legacy landlord values only (LIP-0010 section 10).
		node.legacyLandlord = config.LandlordName
	}
	a, err := kernelbind.NewForNetwork(node, config.StateDir, config.AgentName, config.LandlordName, config.IssuerPubkey, network, genesis, config.ConstructionProfile)
	if err != nil {
		return nil, ErrConfig
	}
	pinned := struct {
		Identity, Agent, Landlord, Issuer, Network, Genesis, Construction string
		Transport                                                         Transport
		Executor                                                          string
		Age, Skew                                                         int64
		Floor                                                             int64
	}{
		config.Identity, config.AgentName, config.LandlordName, config.IssuerPubkey, network, genesis, config.ConstructionProfile, transport, config.ExecutorKey, int64(config.Freshness.MaxTipAge), int64(*config.Freshness.MaxFutureSkew), *config.Freshness.MinimumHeight,
	}
	// The pay binding keeps its earlier bytes. The trust binding wraps the same
	// pins with its profile name, so no state root serves both profiles.
	pins, _ := json.Marshal(pinned)
	if profile == ContractProfileTrust {
		pins, _ = json.Marshal(struct {
			Contract string
			Pins     any
		}{ContractProfileTrust, pinned})
	}
	c := &Checker{config: config, profile: profile, network: network, genesis: genesis, transport: transport, binding: rental.Hash(pins), backend: a, node: node}
	s, err := durable.Open(config.StateDir, "grantcheck.lock")
	if err != nil {
		return nil, ErrState
	}
	defer s.Close()
	raw, err := s.Read(stateName, int64(maxStateBytes))
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
		if s.WriteBounded(stateName, b, maxStateBytes) != nil {
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
	raw, err := s.Read(stateName, int64(maxStateBytes))
	if err != nil || raw == nil || json.Unmarshal(raw, &m) != nil {
		return m, ErrState
	}
	b, _ := json.Marshal(m)
	if !bytes.Equal(raw, b) || m.Version != 1 || m.Binding != c.binding || m.High < 0 || m.High > maxUnix || !validProvisioning(m.Provisioning) || !c.validCache(m.Cache) {
		return m, ErrState
	}
	return m, nil
}

// stamp advances the candidate clock high-water. The operation commits it only
// after final cancellation and capacity checks, before any possible live return.
func (c *Checker) stamp(ctx context.Context, m *state) (int64, Code) {
	if ctx.Err() != nil {
		return 0, CodeCancelled
	}
	sample := c.config.Now()
	if ctx.Err() != nil {
		return 0, CodeCancelled
	}
	now := sample.Unix()
	if now < m.High || now < 0 || now > maxUnix {
		return 0, CodeClockInvalid
	}
	m.High = now
	c.observedTime = sample
	return now, CodeLive
}

// commit refuses predictable capacity failures without attempting a write or
// poisoning the checker. Only uncertain filesystem failures poison the instance.
func (c *Checker) commit(ctx context.Context, s *durable.Store, m state) Code {
	if ctx.Err() != nil {
		return CodeCancelled
	}
	raw, code := encodeState(m)
	if code != CodeLive {
		return code
	}
	if ctx.Err() != nil {
		return CodeCancelled
	}
	if s.WriteBounded(stateName, raw, maxStateBytes) != nil {
		c.poisoned = true
		return CodeStateUnavailable
	}
	return CodeLive
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
		g.IssuerKey != c.config.IssuerPubkey || g.Network != c.network || g.Genesis != c.genesis {
		return empty, CodeBindingMismatch
	}
	terms, err := c.config.Terms(g.ContractSHA256)
	if c.profile == ContractProfileTrust {
		if code := trustTerms(g, terms, err); code != CodeLive {
			return empty, code
		}
		return g, CodeLive
	}
	if err != nil || len(terms) == 0 || len(terms) > MaxPresentationBytes || rental.Hash(terms) != g.ContractSHA256 {
		return empty, CodeTermsInvalid
	}
	var pay rental.PayTermsV2
	if json.Unmarshal(terms, &pay) != nil {
		return empty, CodeTermsInvalid
	}
	canonical, err := rental.EncodePayTermsV2(pay)
	if err != nil || !bytes.Equal(canonical, terms) || pay.Network != g.Network || pay.Genesis != g.Genesis {
		return empty, CodeTermsInvalid
	}
	if pay.ExecutorKey != c.config.ExecutorKey {
		return empty, CodeExecutorMismatch
	}
	return g, CodeLive
}

// Inbound requires the authenticated NIP-17 inner seal signer. nil presentation
// uses previously admitted proof; explicit invalid proof never falls back.
func (c *Checker) Inbound(ctx context.Context, sender string, p *Presentation) Verdict {
	return c.InboundFrom(ctx, SenderProof{Transport: NostrNIP17Seal, Key: sender}, p)
}

// Outbound freshly checks the exact recipient using this identity's admitted
// public proof cache. It never routes agent replies through the exchange.
func (c *Checker) Outbound(ctx context.Context, recipient string) Verdict {
	if c != nil && c.backend != nil && c.transport != NostrNIP17Seal {
		return route(CodeBindingMismatch, false, false)
	}
	return c.check(ctx, recipient, nil, false)
}

func (c *Checker) check(ctx context.Context, peer string, supplied *Presentation, inbound bool) Verdict {
	return c.checkOperation(ctx, peer, supplied, inbound, false)
}

// checkTransaction is owned under both the checker mutex and durable store lock.
// No candidate state reaches disk until the owning operation decides to commit.
type checkTransaction struct {
	m state
}

func (c *Checker) checkOperation(ctx context.Context, peer string, supplied *Presentation, inbound, provision bool) Verdict {
	return c.checkStaged(ctx, peer, supplied, inbound, provision, nil)
}

func (c *Checker) checkStaged(ctx context.Context, peer string, supplied *Presentation, inbound, provision bool, pending *checkTransaction) (out Verdict) {
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
			if provision {
				return c.auditRefusal(ctx, *supplied, fail(code))
			}
			return fail(code)
		}
	}
	var s *durable.Store
	var m state
	if pending == nil {
		if !c.mu.TryLock() {
			return fail(CodeBusy)
		}
		defer c.mu.Unlock()
		if c.poisoned || !canonicalRoot(c.config.StateDir) {
			return fail(CodeStateUnavailable)
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.config.CheckTimeout)
		defer cancel()
		var err error
		s, err = durable.Open(c.config.StateDir, "grantcheck.lock")
		if err != nil {
			return fail(CodeStateUnavailable)
		}
		defer s.Close()
		m, err = c.load(s)
		if err != nil {
			return fail(CodeStateUnavailable)
		}
	} else {
		m = pending.m
	}
	// Cancellation and predictable capacity refusal commit nothing, including
	// audit and clock high-water. A successful cache/audit update is atomic.
	originalHigh := m.High
	discard := false
	defer func() {
		if discard {
			return
		}
		if ctx.Err() != nil {
			out = fail(CodeCancelled)
			return
		}
		changed := m.High != originalHigh
		if out.Decision == Live && supplied != nil {
			if code := putCached(&m, peer, p); code != CodeLive {
				out = fail(code)
				return
			}
			changed = true
		}
		if provision {
			appendProvision(&m, p, out, m.High)
			changed = true
		}
		if changed {
			if pending != nil {
				pending.m = m
				return
			}
			if code := c.commit(ctx, s, m); code != CodeLive {
				out = fail(code)
			}
		}
	}()

	now, code := c.stamp(ctx, &m)
	if code != CodeLive {
		return fail(code)
	}
	if ctx.Err() != nil {
		return fail(CodeCancelled)
	}
	if supplied == nil {
		raw, err := cachedGrant(m, peer)
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
	c.node.reset(c.observedTime)
	var r kernel.Receipt
	var err error
	r, err = c.backend.Check(ctx, p.Bytes, c.config.AgentName, peer, now)
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
	if c.node.code != "" {
		return fail(c.node.code)
	}
	// An unexpected scope on a live result cannot become executor metadata.
	if v.Decision == Live && !slices.Equal(r.Scope, g.Scope) {
		return fail(CodeCheckFailed)
	}
	v.GrantID, v.NotBefore, v.NotAfter, v.CheckedAt = p.GrantID, g.NotBefore, g.NotAfter, now
	if v.Decision != Live {
		return v
	}
	// Repeat the clock check after kernel journal writes and before our deferred
	// proof-cache persistence. Bounded retries cover a second boundary between samples.
	for range 3 {
		end, code := c.stamp(ctx, &m)
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
		lastTime := c.config.Now()
		if ctx.Err() != nil {
			return fail(CodeCancelled)
		}
		last := lastTime.Unix()
		if last < end || lastTime.Before(c.observedTime) {
			return fail(CodeClockInvalid)
		}
		if last == end {
			if c.node.seen {
				if code := c.node.freshAt(lastTime); code != CodeLive {
					discard = true
					return fail(code)
				}
			}
			v.checked = &liveCheck{node: *c.node, at: lastTime}
			v.CheckedAt = end
			v.Scope = slices.Clone(g.Scope)
			return v
		}
	}
	return fail(CodeClockInvalid)
}
