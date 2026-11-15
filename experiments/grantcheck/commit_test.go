package grantcheck

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernel"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/durable"
)

func readCheckerState(t *testing.T, c *Checker) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(c.config.StateDir, stateName))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Claim: cancellation during any trusted-clock sample refuses every admission
// entry point without changing cache, audit or high-water; a live control writes.
// The unit backend isolates wrapper ordering; genuine Core controls run separately.
func TestFinalSampleCancellation(t *testing.T) {
	for _, operation := range []string{"Provision", "Inbound", "Outbound", "OutboundFrom", "RefusalAudit"} {
		t.Run(operation, func(t *testing.T) {
			for _, sample := range []int{0, 1, 2, 3, 4, -1} {
				if (operation != "OutboundFrom" && sample == 4) || (operation == "RefusalAudit" && sample > 1) {
					continue
				}
				t.Run(fmt.Sprintf("Sample%d", sample), func(t *testing.T) {
					c, _, p := unitChecker(t)
					assertVerdict(t, c.Provision(context.Background(), p), Live, CodeLive, false, false)
					before := readCheckerState(t, c)
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					if sample == -1 {
						cancel()
					}
					reads := 0
					c.config.Now = func() time.Time {
						reads++
						if reads == sample {
							cancel()
						}
						// Advance high-water too, so outbound tests require a write guard.
						return time.Unix(501, 0)
					}
					var v Verdict
					switch operation {
					case "Provision":
						v = c.Provision(ctx, p)
					case "Inbound":
						v = c.Inbound(ctx, xonly(2), &p)
					case "Outbound":
						v = c.Outbound(ctx, xonly(2))
					case "OutboundFrom":
						v = c.OutboundFrom(ctx, RecipientProof{NostrNIP17Seal, []string{xonly(2)}})
					case "RefusalAudit":
						v = c.Provision(ctx, Presentation{Bytes: []byte("invalid")})
					}
					if sample != 0 {
						assertVerdict(t, v, Refused, CodeCancelled, false, true)
						after := readCheckerState(t, c)
						if !bytes.Equal(before, after) {
							t.Fatal("cancelled call changed cache, audit or high-water")
						}
					} else {
						if operation == "RefusalAudit" {
							assertVerdict(t, v, Refused, CodeInvalidPresentation, false, false)
						} else {
							assertVerdict(t, v, Live, CodeLive, false, false)
						}
						if bytes.Equal(before, readCheckerState(t, c)) {
							t.Fatal("live/control operation failed to commit")
						}
					}
				})
			}
		})
	}
}

// Claim: the maximum JSON envelope, 60000-byte cache and 64 longest audit
// records fit the explicit durable budget together. This is an encoding fixture,
// not a valid grant/chain fixture; public-path tests below cover admission.
func TestCombinedStateBudget(t *testing.T) {
	c, _, _ := unitChecker(t)
	digest := strings.Repeat("f", 64)
	m := state{Version: 1, Binding: digest, High: maxUnix}
	for range MaxRecipients {
		m.Cache = append(m.Cache, cachedProof{digest, digest, json.RawMessage(`""`)})
	}
	remaining := maxCacheBytes - len(jsonBytes(t, m.Cache))
	for i := range m.Cache {
		n := min(remaining, MaxPresentationBytes-2)
		m.Cache[i].Bytes = json.RawMessage(`"` + strings.Repeat("x", n) + `"`)
		remaining -= n
	}
	if remaining != 0 || len(jsonBytes(t, m.Cache)) != maxCacheBytes {
		t.Fatal("fixture did not fill cache byte/count budgets")
	}
	for range MaxProvisionRecords {
		m.Provisioning = append(m.Provisioning, ProvisionRecord{digest, digest, maxUnix, CodeInvalidPresentation})
	}
	raw, code := encodeState(m)
	if code != CodeLive || len(raw) != maxStateBytes || len(raw) >= durable.MaxWriteBytes || len(raw) <= 65536 {
		t.Fatalf("combined budget: code=%s bytes=%d maximum=%d writer=%d", code, len(raw), maxStateBytes, durable.MaxWriteBytes)
	}
	s, err := durable.Open(c.config.StateDir, "grantcheck.lock")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if code := c.commit(context.Background(), s, m); code != CodeLive {
		t.Fatal("full combined state did not commit", code)
	}
	before := readCheckerState(t, c)
	// Overflow only the combined envelope, keeping cache and audit capacities
	// fixed. The preflight must reject the writer can reject and poison the checker.
	oversize := m
	oversize.Binding += "x"
	if code := c.commit(context.Background(), s, oversize); code != CodeCapacityExceeded || c.poisoned {
		t.Fatal("combined overflow was not a non-poisoning preflight refusal", code)
	}
	oversize = m
	oversize.Cache = append(append([]cachedProof(nil), m.Cache...), cachedProof{digest, digest, json.RawMessage(`{}`)})
	if code := c.commit(context.Background(), s, oversize); code != CodeCapacityExceeded || c.poisoned {
		t.Fatal("extra cache entry was not a named capacity refusal", code)
	}
	if !bytes.Equal(before, readCheckerState(t, c)) {
		t.Fatal("capacity refusal changed durable state")
	}
	if code := c.commit(context.Background(), s, m); code != CodeLive {
		t.Fatal("valid commit after refusal failed", code)
	}
	t.Logf("combined maximum=%d cache=%d audit=%d writer=%d", len(raw), maxCacheBytes, MaxProvisionRecords, durable.MaxWriteBytes)
}

// Claim: the last persistence boundary independently rejects an already
// cancelled candidate, preserving bytes without poisoning, beside a live write.
func TestCommitCancellationGuard(t *testing.T) {
	c, _, _ := unitChecker(t)
	var m state
	before := readCheckerState(t, c)
	if err := json.Unmarshal(before, &m); err != nil {
		t.Fatal(err)
	}
	m.High++
	s, err := durable.Open(c.config.StateDir, "grantcheck.lock")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if code := c.commit(ctx, s, m); code != CodeCancelled || c.poisoned {
		t.Fatal("cancelled candidate reached writer", code)
	}
	if !bytes.Equal(before, readCheckerState(t, c)) {
		t.Fatal("cancelled candidate changed state")
	}
	if code := c.commit(context.Background(), s, m); code != CodeLive {
		t.Fatal("valid commit after cancellation", code)
	}
}

// Claim: after one live recipient, a missing or refused later recipient and
// cancellation at every clock sample preserve all checker bytes; a concurrent
// same-checker call refuses busy and cannot interfere with a live aggregate.
// The unit backend isolates transaction ordering; Core tests verify real grants.
func TestAggregateRecipientTransaction(t *testing.T) {
	for _, mode := range []string{"Live", "Missing", "Refused", "Cancelled"} {
		for sample := range 8 {
			if mode != "Cancelled" && sample != 0 {
				continue
			}
			t.Run(fmt.Sprintf("%s/Sample%d", mode, sample), func(t *testing.T) {
				c, b, p := unitChecker(t)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				assertVerdict(t, c.Provision(ctx, p), Live, CodeLive, false, false)
				other := unitGrantForPeer(t, xonly(3))
				id, err := kernel.PresentationID(other)
				if err != nil {
					t.Fatal(err)
				}
				if mode != "Missing" {
					assertVerdict(t, c.Provision(ctx, Presentation{GrantID: id, Bytes: other}), Live, CodeLive, false, false)
				}
				if mode == "Refused" {
					old := b.Handler
					b.Handler = func(ctx context.Context, raw []byte, a, peer string, now int64) (kernel.Receipt, error) {
						r, err := old(ctx, raw, a, peer, now)
						if peer == xonly(3) {
							r.Verdict, r.Reason = kernel.Refused, "RPC_UNAVAILABLE"
						}
						return r, err
					}
				}
				before := readCheckerState(t, c)
				reads := 0
				c.config.Now = func() time.Time {
					reads++
					if mode == "Cancelled" && reads == sample {
						cancel()
					}
					if mode == "Live" && reads == 7 {
						assertVerdict(t, c.Outbound(context.Background(), xonly(2)), Refused, CodeBusy, false, true)
					}
					return time.Unix(501, 0)
				}
				v := c.OutboundFrom(ctx, RecipientProof{NostrNIP17Seal, []string{xonly(2), xonly(3)}})
				if mode == "Live" || mode == "Cancelled" && sample == 0 {
					assertVerdict(t, v, Live, CodeLive, false, false)
					if bytes.Equal(before, readCheckerState(t, c)) {
						t.Fatal("live aggregate did not commit")
					}
				} else {
					code := CodeCancelled
					if mode == "Missing" {
						code = CodeNoGrant
					}
					if mode == "Refused" {
						code = CodeVerifierUnavailable
					}
					assertVerdict(t, v, Refused, code, false, code != CodeNoGrant)
					if !bytes.Equal(before, readCheckerState(t, c)) {
						t.Fatal("recipient refusal changed checker state")
					}
				}
			})
		}
	}
}
