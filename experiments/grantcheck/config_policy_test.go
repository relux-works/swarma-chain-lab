package grantcheck

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Claim: every required executor/freshness input fails construction when absent
// or invalid, before state opens; explicit F=0 and FLOOR=0 are valid controls.
func TestRequiredPolicyConfig(t *testing.T) {
	for _, name := range []string{"pin-missing", "pin-invalid", "policy-missing", "age-missing", "age-negative", "age-fractional", "skew-missing", "skew-negative", "skew-excess", "skew-fractional", "floor-missing", "floor-negative", "floor-excess", "terms-missing"} {
		t.Run(name, func(t *testing.T) {
			good := unitConfig(t)
			good.Freshness = testFreshness(time.Second, 0, 0)
			if c, err := New(good); err != nil || c == nil {
				t.Fatal("explicit zero neighbour", err)
			}
			bad := unitConfig(t)
			switch name {
			case "pin-missing":
				bad.ExecutorKey = ""
			case "pin-invalid":
				bad.ExecutorKey = "invalid"
			case "policy-missing":
				bad.Freshness = nil
			case "age-missing":
				bad.Freshness.MaxTipAge = 0
			case "age-negative":
				bad.Freshness.MaxTipAge = -time.Second
			case "age-fractional":
				bad.Freshness.MaxTipAge = time.Nanosecond
			case "skew-missing":
				bad.Freshness.MaxFutureSkew = nil
			case "skew-negative":
				v := -time.Second
				bad.Freshness.MaxFutureSkew = &v
			case "skew-excess":
				v := MaxFutureSkew + time.Second
				bad.Freshness.MaxFutureSkew = &v
			case "skew-fractional":
				v := time.Nanosecond
				bad.Freshness.MaxFutureSkew = &v
			case "floor-missing":
				bad.Freshness.MinimumHeight = nil
			case "floor-negative":
				v := int64(-1)
				bad.Freshness.MinimumHeight = &v
			case "floor-excess":
				v := int64(2147483648)
				bad.Freshness.MinimumHeight = &v
			case "terms-missing":
				bad.Terms = nil
			}
			if c, err := New(bad); c != nil || !errors.Is(err, ErrConfig) {
				t.Fatal("required config did not refuse", err)
			}
			entries, err := os.ReadDir(bad.StateDir)
			if err != nil || len(entries) != 0 {
				t.Fatal("invalid config opened state")
			}
		})
	}
}

// Claim: executor/policy pins survive restart and caller pointer mutation cannot
// alter a constructed checker's policy; a changed pin cannot adopt its state.
func TestPolicyBinding(t *testing.T) {
	cfg := unitConfig(t)
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	*cfg.Freshness.MinimumHeight = 99
	*cfg.Freshness.MaxFutureSkew = 0
	if *c.config.Freshness.MinimumHeight != 0 || *c.config.Freshness.MaxFutureSkew != 120*time.Second {
		t.Fatal("policy pointer aliases escaped")
	}
	if _, err = New(c.config); err != nil {
		t.Fatal("same policy reopen", err)
	}
	for _, name := range []string{"executor", "age", "skew", "floor"} {
		t.Run(name, func(t *testing.T) {
			bad := c.config
			bad.Freshness = cloneFreshness(c.config.Freshness)
			switch name {
			case "executor":
				bad.ExecutorKey = xonly(8)
			case "age":
				bad.Freshness.MaxTipAge += time.Second
			case "skew":
				*bad.Freshness.MaxFutureSkew += time.Second
			case "floor":
				*bad.Freshness.MinimumHeight++
			}
			if other, err := New(bad); other != nil || !errors.Is(err, ErrState) {
				t.Fatal("policy state relabeled", err)
			}
		})
	}
}

// Claim: missing, oversized, malformed, noncanonical or hash-mismatched terms
// refuse before node/backend/state changes, beside the exact live canonical terms.
func TestTermsBinding(t *testing.T) {
	for _, name := range []string{"missing", "oversize", "malformed", "noncanonical", "wrong-hash"} {
		t.Run(name, func(t *testing.T) {
			c, b, p := unitChecker(t)
			assertVerdict(t, c.Inbound(context.Background(), xonly(2), &p), Live, CodeLive, false, false)
			before, err := os.ReadFile(filepath.Join(c.config.StateDir, stateName))
			if err != nil {
				t.Fatal(err)
			}
			calls := b.Calls
			c.config.Terms = func(string) ([]byte, error) {
				switch name {
				case "missing":
					return nil, errors.New("missing")
				case "oversize":
					return make([]byte, MaxPresentationBytes+1), nil
				case "malformed":
					return []byte("{"), nil
				case "noncanonical":
					return append(unitTerms(t), ' '), nil
				default:
					return []byte("{}"), nil
				}
			}
			assertVerdict(t, c.Inbound(context.Background(), xonly(2), &p), Refused, CodeTermsInvalid, false, false)
			after, err := os.ReadFile(filepath.Join(c.config.StateDir, stateName))
			if err != nil || !bytes.Equal(before, after) || b.Calls != calls {
				t.Fatal("invalid terms changed state or called backend")
			}
		})
	}
}
