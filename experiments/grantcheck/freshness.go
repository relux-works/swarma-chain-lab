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
	tipTime time.Time
	seen    bool
}

func (n *policyNode) reset(now time.Time) { n.now, n.code, n.seen = now, "", false }

func (n *policyNode) Call(ctx context.Context, method string, args ...any) (json.RawMessage, error) {
	raw, err := n.Node.Call(ctx, method, args...)
	if err != nil || method != "getblockchaininfo" {
		return raw, err
	}
	refuse := func(code Code) (json.RawMessage, error) {
		n.code = code
		return nil, errors.New("grantcheck node observation refused")
	}
	var info su.ChainInfo
	if len(raw) > 1<<20 || json.Unmarshal(raw, &info) != nil || info.Chain != "regtest" || info.Blocks < 0 || info.Blocks > 2147483647 || info.Headers < 0 || info.Headers > 2147483647 {
		return refuse(CodeVerifierUnavailable)
	}
	if info.IBD || info.Headers != info.Blocks {
		return refuse(CodeNodeNotSynced)
	}
	if info.Blocks < *n.policy.MinimumHeight {
		return refuse(CodeTipBelowFloor)
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

func (n *policyNode) freshAt(now time.Time) Code {
	if n.tipTime.Before(now.Add(-n.policy.MaxTipAge)) {
		return CodeTipStale
	}
	if n.tipTime.After(now.Add(*n.policy.MaxFutureSkew)) {
		return CodeTipFuture
	}
	return CodeLive
}
