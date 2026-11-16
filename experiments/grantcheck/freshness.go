package grantcheck

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/sealwatch"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// MaxFutureSkew is an interim test-bench configuration bound, not a production
// recommendation. No policy field defaults; subsecond ages and skews are
// supported within the same bounds.
const MaxFutureSkew = 10 * time.Minute

// FreshnessPolicy is the interim v3 test-bench rule, superseded by LIP-0022 once
// accepted. Pointer fields distinguish an explicit zero from an absent input.
// The hidden age of an admitted view is at most MaxTipAge + MaxFutureSkew.
type FreshnessPolicy struct {
	MaxTipAge     time.Duration
	MaxFutureSkew *time.Duration
	MinimumHeight *int64
}

func validFreshness(p *FreshnessPolicy) bool {
	return p != nil && p.MaxTipAge > 0 &&
		p.MaxFutureSkew != nil && *p.MaxFutureSkew >= 0 && *p.MaxFutureSkew <= MaxFutureSkew &&
		p.MinimumHeight != nil && *p.MinimumHeight >= 0 && *p.MinimumHeight <= 2147483647
}

func cloneFreshness(p *FreshnessPolicy) *FreshnessPolicy {
	skew, floor := *p.MaxFutureSkew, *p.MinimumHeight
	return &FreshnessPolicy{p.MaxTipAge, &skew, &floor}
}

// policyNode checks the actual getblockchaininfo observations consumed by K1,
// including its stability reads. It never takes time from the node. Checker.mu
// serializes use; reset supplies this operation's trusted Config.Now input.
// K1 also checks active headers, membership, genesis and observation stability.
type policyNode struct {
	su.Node
	policy  FreshnessPolicy
	now     time.Time
	code    Code
	info    su.ChainInfo
	tipTime time.Time
	seen    bool

	// chain is the configured network name that getblockchaininfo must report.
	chain string
	// legacyLandlord is set under the trust profile only: the landlord name
	// whose value must not carry a holders member (LIP-0010 section 10).
	legacyLandlord string
}

func (n *policyNode) reset(now time.Time) { n.now, n.code, n.seen = now, "", false }

func (n *policyNode) Call(ctx context.Context, method string, args ...any) (json.RawMessage, error) {
	raw, err := n.Node.Call(ctx, method, args...)
	refuse := func(code Code) (json.RawMessage, error) {
		n.code = code
		return nil, errors.New("grantcheck node observation refused")
	}
	if err == nil && method == "name_show" && n.legacyLandlord != "" && len(args) > 0 && args[0] == n.legacyLandlord && landlordHolders(raw) {
		return refuse(CodeBindingMismatch)
	}
	if err != nil || method != "getblockchaininfo" {
		return raw, err
	}
	var info su.ChainInfo
	if len(raw) > 1<<20 || json.Unmarshal(raw, &info) != nil || info.Chain != n.chain || info.Blocks < 0 || info.Blocks > 2147483647 || info.Headers < 0 || info.Headers > 2147483647 {
		return refuse(CodeVerifierUnavailable)
	}
	n.info = info
	if code := n.synced(); code != CodeLive {
		return refuse(code)
	}
	header, err := n.Node.Call(ctx, "getblockheader", info.Best)
	if err != nil {
		return refuse(CodeVerifierUnavailable)
	}
	var hash string
	var height, confirmations, at int64
	if len(header) > 1<<20 || sealwatch.ProjectJSON(header, map[string]any{"hash": &hash, "height": &height, "confirmations": &confirmations, "time": &at}, nil) != nil ||
		hash != info.Best || len(hash) != 64 || height != info.Blocks || confirmations != 1 || at < 0 || at > maxUnix {
		return refuse(CodeVerifierUnavailable)
	}
	n.tipTime, n.seen = time.Unix(at, 0), true
	if code := n.freshAt(n.now); code != CodeLive {
		return refuse(code)
	}
	return raw, nil
}

func (n *policyNode) synced() Code {
	info := n.info
	if info.IBD || info.Headers != info.Blocks {
		return CodeNodeNotSynced
	}
	if info.Blocks < *n.policy.MinimumHeight {
		return CodeTipBelowFloor
	}
	return CodeLive
}

func (n *policyNode) freshAt(now time.Time) Code {
	if code := n.synced(); code != CodeLive {
		return code
	}
	if n.tipTime.Before(now.Add(-n.policy.MaxTipAge)) {
		return CodeTipStale
	}
	if n.tipTime.After(now.Add(*n.policy.MaxFutureSkew)) {
		return CodeTipFuture
	}
	return CodeLive
}

// liveCheck retains this decision's own observation, never a subsequent caller's
// mutable node state. Aggregate checks compare every recipient at one final time.
type liveCheck struct {
	node policyNode
	at   time.Time
}
