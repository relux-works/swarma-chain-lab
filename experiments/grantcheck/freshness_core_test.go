package grantcheck

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernel"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// recordedNode captures every public RPC answer from a genuine live check.
// Frozen mode replays that consistent old observation after a real newer block
// is mined. Missing reads fail; this is a declared stale-observer test seam.
type recordedNode struct {
	real    su.Node
	frozen  bool
	answers map[string]json.RawMessage
}

func (n *recordedNode) Call(ctx context.Context, method string, args ...any) (json.RawMessage, error) {
	key, _ := json.Marshal([]any{method, args})
	if n.frozen {
		raw, ok := n.answers[string(key)]
		if !ok {
			return nil, fmt.Errorf("unrecorded public RPC")
		}
		return bytes.Clone(raw), nil
	}
	raw, err := n.real.Call(ctx, method, args...)
	if err == nil {
		n.answers[string(key)] = bytes.Clone(raw)
	}
	return raw, err
}

func corePresentation(t *testing.T, raw []byte) Presentation {
	t.Helper()
	id, err := kernel.PresentationID(raw)
	if err != nil {
		t.Fatal(err)
	}
	return Presentation{GrantID: id, Bytes: raw}
}
func coreTip(t *testing.T, l *coreLab) (su.ChainInfo, int64) {
	t.Helper()
	var info su.ChainInfo
	if err := json.Unmarshal(l.rpc("", "getblockchaininfo"), &info); err != nil {
		t.Fatal(err)
	}
	var h struct {
		Time int64 `json:"time"`
	}
	if err := json.Unmarshal(l.rpc("", "getblockheader", info.Best), &h); err != nil {
		t.Fatal(err)
	}
	return info, h.Time
}
func freshCoreChecker(t *testing.T, l *coreLab, node su.Node, now int64, policy *FreshnessPolicy, executor string) *Checker {
	t.Helper()
	root, err := os.MkdirTemp(l.private, "checker-")
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewForTransport(Config{ConstructionProfile: "W", Identity: "fresh-test", AgentName: e2eAgentName, LandlordName: e2eLandlordName, IssuerPubkey: l.issuerPub, ExecutorKey: executor, Terms: unitTermsLookup, Freshness: policy, StateDir: root, Node: node, Now: func() time.Time { return time.Unix(now, 0) }}, SwarmEnvelopeV2)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func coreInbound(c *Checker, p Presentation) Verdict {
	proof, _ := rental.ParseGrantPresentation(p.Bytes)
	return c.InboundFrom(context.Background(), SenderProof{SwarmEnvelopeV2, proof.SignedGrant.Grant.GranteeKey}, &p)
}

// Claim: the real checker refuses each policy violation beside a live Core
// control; only the frozen observer and header-count seam replace RPC answers.
func TestCoreFreshness(t *testing.T) {
	agent, err := nostr.GeneratePrivKey()
	if err != nil {
		t.Fatal(err)
	}
	l := newCoreLab(t, agent.PubKeyHex())
	peer, err := nostr.GeneratePrivKey()
	if err != nil {
		t.Fatal(err)
	}
	p := corePresentation(t, l.grant(peer, "freshness", l.seal(), true))
	info, now := coreTip(t, l)
	policy := func(floor int64) *FreshnessPolicy { return testFreshness(60*time.Second, 120*time.Second, floor) }
	live := func(t *testing.T, node su.Node, at int64, floor int64) {
		t.Helper()
		c := freshCoreChecker(t, l, node, at, policy(floor), xonly(9))
		assertVerdict(t, coreInbound(c, p), Live, CodeLive, false, false)
	}
	t.Run("ExecutorPin", func(t *testing.T) {
		// Claim: a different configured executor refuses before any durable state change.
		live(t, l.observer, now, info.Blocks)
		c := freshCoreChecker(t, l, l.observer, now, policy(info.Blocks), xonly(8))
		before, err := os.ReadFile(filepath.Join(c.config.StateDir, stateName))
		if err != nil {
			t.Fatal(err)
		}
		assertVerdict(t, coreInbound(c, p), Refused, CodeExecutorMismatch, false, false)
		after, err := os.ReadFile(filepath.Join(c.config.StateDir, stateName))
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("executor mismatch wrote state")
		}
	})
	t.Run("HeadersEqualBlocks", func(t *testing.T) {
		// Claim: headers ahead and headers behind both refuse as retryable not-synced; equal is live.
		live(t, l.observer, now, info.Blocks)
		for _, delta := range []int64{1, -1} {
			node := nodeFunc(func(ctx context.Context, method string, args ...any) (json.RawMessage, error) {
				raw, err := l.observer.Call(ctx, method, args...)
				if err != nil || method != "getblockchaininfo" {
					return raw, err
				}
				var fields map[string]json.RawMessage
				if err = json.Unmarshal(raw, &fields); err != nil {
					return nil, err
				}
				fields["headers"] = jsonBytes(t, info.Blocks+delta)
				return json.Marshal(fields)
			})
			c := freshCoreChecker(t, l, node, now, policy(info.Blocks), xonly(9))
			assertVerdict(t, coreInbound(c, p), Refused, CodeNodeNotSynced, false, true)
		}
	})
	t.Run("HeightFloor", func(t *testing.T) {
		// Claim: the observed height is live at the floor and retryably stale one below it.
		live(t, l.observer, now, info.Blocks)
		c := freshCoreChecker(t, l, l.observer, now, policy(info.Blocks+1), xonly(9))
		assertVerdict(t, coreInbound(c, p), Refused, CodeTipBelowFloor, false, true)
	})
	t.Run("FrozenOldView", func(t *testing.T) {
		// Claim: a complete old Core view stays live at age A, then refuses at A+1 despite consistent RPCs.
		frozen := &recordedNode{real: l.observer, answers: map[string]json.RawMessage{}}
		live(t, frozen, now, info.Blocks)
		l.mine(1)
		newInfo, _ := coreTip(t, l)
		if newInfo.Blocks != info.Blocks+1 || newInfo.Best == info.Best {
			t.Fatal("newer Core block witness missing")
		}
		frozen.frozen = true
		live(t, frozen, now+60, info.Blocks)
		c := freshCoreChecker(t, l, frozen, now+61, policy(info.Blocks), xonly(9))
		assertVerdict(t, coreInbound(c, p), Refused, CodeTipStale, false, true)
		// Claim: cached inbound and outbound checks cannot reuse a formerly live stale view.
		c = freshCoreChecker(t, l, frozen, now, policy(info.Blocks), xonly(9))
		assertVerdict(t, coreInbound(c, p), Live, CodeLive, false, false)
		c.config.Now = func() time.Time { return time.Unix(now+61, 0) }
		assertVerdict(t, c.InboundFrom(context.Background(), SenderProof{SwarmEnvelopeV2, peer.PubKeyHex()}, nil), Refused, CodeTipStale, false, true)
		assertVerdict(t, c.OutboundFrom(context.Background(), RecipientProof{SwarmEnvelopeV2, []string{peer.PubKeyHex()}}), Refused, CodeTipStale, false, true)
	})
	t.Run("LateAge", func(t *testing.T) {
		// Claim: crossing A while a genuine check runs refuses before cache persistence.
		current, at := coreTip(t, l)
		c := freshCoreChecker(t, l, l.observer, at, policy(current.Blocks), xonly(9))
		calls := 0
		c.config.Now = func() time.Time {
			calls++
			if calls > 1 {
				return time.Unix(at+61, 0)
			}
			return time.Unix(at, 0)
		}
		assertVerdict(t, coreInbound(c, p), Refused, CodeTipStale, false, true)
		if _, err := c.cachedGrant(peer.PubKeyHex()); err != kernel.ErrNoPresentation {
			t.Fatal("late stale refusal cached proof", err)
		}
	})
	t.Run("FutureSkew", func(t *testing.T) {
		// Claim: actual Core tip headers at F are live; F+1 and two hours ahead refuse non-retryably.
		for _, tc := range []struct {
			skew int64
			code Code
		}{{120, CodeLive}, {121, CodeTipFuture}, {7200, CodeTipFuture}} {
			l.rpc("", "setmocktime", now+tc.skew)
			l.mine(1)
			current, at := coreTip(t, l)
			if at != now+tc.skew {
				t.Fatal("future header witness timestamp", at-now)
			}
			c := freshCoreChecker(t, l, l.observer, now, policy(current.Blocks), xonly(9))
			decision := Refused
			if tc.code == CodeLive {
				decision = Live
			}
			assertVerdict(t, coreInbound(c, p), decision, tc.code, false, false)
		}
	})
}

// Claim: protected provisioning bootstraps cached admissions without an inbound
// message; every invalid replacement preserves already admitted bytes and logs its result.
func TestCoreProvisioning(t *testing.T) {
	agent, err := nostr.GeneratePrivKey()
	if err != nil {
		t.Fatal(err)
	}
	l := newCoreLab(t, agent.PubKeyHex())
	peer, err := nostr.GeneratePrivKey()
	if err != nil {
		t.Fatal(err)
	}
	seal := l.seal()
	p := corePresentation(t, l.grant(peer, "provision-one", seal, true))
	other := corePresentation(t, l.grant(peer, "provision-two", l.seal(), true))
	wrong := corePresentation(t, l.grant(peer, "provision-wrong-executor", l.seal(), true, xonly(8)))
	var wrongTerms rental.PayTermsV2
	if err := json.Unmarshal(unitTerms(t), &wrongTerms); err != nil {
		t.Fatal(err)
	}
	wrongTerms.ExecutorKey = xonly(8)
	wrongBytes, err := rental.EncodePayTermsV2(wrongTerms)
	if err != nil {
		t.Fatal(err)
	}

	info, now := coreTip(t, l)
	ctx := context.Background()
	makeChecker := func(t *testing.T, executor string) *Checker {
		c := freshCoreChecker(t, l, l.observer, now, testFreshness(60*time.Second, 120*time.Second, info.Blocks), executor)
		c.config.Terms = func(hash string) ([]byte, error) {
			if hash == rental.Hash(wrongBytes) {
				return bytes.Clone(wrongBytes), nil
			}
			return unitTermsLookup(hash)
		}
		return c
	}
	cache := func(t *testing.T, c *Checker) []byte {
		t.Helper()
		raw, err := c.cachedGrant(peer.PubKeyHex())
		if err != nil && err != kernel.ErrNoPresentation {
			t.Fatal(err)
		}
		return raw
	}
	logResult := func(t *testing.T, c *Checker, p Presentation, code Code) {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(c.config.StateDir, stateName))
		var m state
		if err != nil || json.Unmarshal(raw, &m) != nil || len(m.Provisioning) == 0 {
			t.Fatal("provision audit missing")
		}
		r := m.Provisioning[len(m.Provisioning)-1]
		if r.GrantID != p.GrantID || r.Hash != rental.Hash(p.Bytes) || r.Result != code || r.At != c.config.Now().Unix() {
			t.Fatalf("provision audit mismatch: %+v", r)
		}
	}
	t.Run("Bootstrap", func(t *testing.T) {
		// Claim: provisioning alone enables a first outbound send and cached inbound admission, including after reopen.
		c := makeChecker(t, xonly(9))
		if len(cache(t, c)) != 0 {
			t.Fatal("unexpected initial cache")
		}
		assertVerdict(t, c.Provision(ctx, p), Live, CodeLive, false, false)
		logResult(t, c, p, CodeLive)
		assertVerdict(t, c.OutboundFrom(ctx, RecipientProof{SwarmEnvelopeV2, []string{peer.PubKeyHex()}}), Live, CodeLive, false, false)
		reopened, err := NewForTransport(c.config, SwarmEnvelopeV2)
		if err != nil {
			t.Fatal(err)
		}
		assertVerdict(t, reopened.InboundFrom(ctx, SenderProof{SwarmEnvelopeV2, peer.PubKeyHex()}, nil), Live, CodeLive, false, false)
	})
	for _, name := range []string{"Tampered", "UncommittedHash", "WrongExecutor", "StaleNode", "SpentSeal"} {
		t.Run(name, func(t *testing.T) {
			// Claim: each named refusal leaves the proof cache byte-for-byte unchanged beside live provisioning.
			c := makeChecker(t, xonly(9))
			assertVerdict(t, c.Provision(ctx, other), Live, CodeLive, false, false)
			bad := Presentation{GrantID: p.GrantID, Bytes: bytes.Clone(p.Bytes)}
			code := CodeInvalidPresentation
			closed, retry := false, false
			switch name {
			case "Tampered":
				bad.Bytes[len(bad.Bytes)-2] ^= 1
			case "UncommittedHash":
				// A valid, issuer-signed hash with the genuine locator and seal but no matching issuance commitment.
				proof, err := rental.ParseGrantPresentation(p.Bytes)
				if err != nil {
					t.Fatal(err)
				}
				budget := int64(999999)
				proof.SignedGrant.Grant.Budget = &budget
				digest, err := proof.SignedGrant.Grant.SigningHash()
				if err != nil {
					t.Fatal(err)
				}
				proof.SignedGrant.Signature = signHash(t, l.issuer, digest)
				bad = corePresentation(t, jsonBytes(t, proof))
				code = CodeIssuanceMismatch
			case "WrongExecutor":
				bad = wrong
				code = CodeExecutorMismatch
			case "StaleNode":
				c.config.Now = func() time.Time { return time.Unix(now+61, 0) }
				code = CodeTipStale
				retry = true
			case "SpentSeal":
				l.revoke(seal)
				code = CodeSealSpent
				closed = true
			}
			before := bytes.Clone(cache(t, c))
			assertVerdict(t, c.Provision(ctx, bad), Refused, code, closed, retry)
			logResult(t, c, bad, code)
			if !bytes.Equal(before, cache(t, c)) {
				t.Fatal("refused provisioning replaced cache")
			}
		})
	}
}
