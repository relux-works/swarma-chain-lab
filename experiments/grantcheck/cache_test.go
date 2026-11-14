package grantcheck

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernel"
)

// Claim: the private cache builder enforces capacity/byte limits without partial
// mutation. Small JSON stand-ins isolate storage bounds, not grant verification.
func TestCacheBuilderBounds(t *testing.T) {
	m := state{}
	for i := 0; i < MaxRecipients; i++ {
		if code := putCached(&m, fmt.Sprint(i), Presentation{GrantID: "id", Bytes: []byte("{}")}); code != CodeLive {
			t.Fatal("capacity neighbour", code)
		}
	}
	before, _ := json.Marshal(m)
	if code := putCached(&m, "overflow", Presentation{GrantID: "id", Bytes: []byte("{}")}); code != CodeStateUnavailable {
		t.Fatal("capacity overflow", code)
	}
	after, _ := json.Marshal(m)
	if !bytes.Equal(before, after) {
		t.Fatal("capacity refusal changed cache")
	}
	if code := putCached(&m, "0", Presentation{GrantID: "replacement", Bytes: []byte("{}")}); code != CodeLive {
		t.Fatal("at-capacity replacement", code)
	}
	before, _ = json.Marshal(m)
	large, _ := json.Marshal(string(bytes.Repeat([]byte("x"), maxCacheBytes)))
	if code := putCached(&m, "0", Presentation{GrantID: "id", Bytes: large}); code != CodeStateUnavailable {
		t.Fatal("byte overflow", code)
	}
	after, _ = json.Marshal(m)
	if !bytes.Equal(before, after) {
		t.Fatal("byte refusal changed cache")
	}
}

// Claim: persisted duplicate senders, altered IDs and peer bindings are refused
// on load beside the genuine admitted cache, rather than adopted after restart.
func TestCacheCorruption(t *testing.T) {
	for _, name := range []string{"duplicate", "id", "peer", "oversize"} {
		t.Run(name, func(t *testing.T) {
			c, _, p := unitChecker(t)
			assertVerdict(t, c.Inbound(context.Background(), xonly(2), &p), Live, CodeLive, false, false)
			path := filepath.Join(c.config.StateDir, stateName)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var m state
			if err = json.Unmarshal(raw, &m); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "duplicate":
				m.Cache = append(m.Cache, m.Cache[0])
			case "id":
				m.Cache[0].GrantID = "invalid"
			case "peer":
				m.Cache[0].Peer = xonly(3)
			case "oversize":
				m.Cache[0].Bytes = json.RawMessage(`"` + string(bytes.Repeat([]byte("x"), MaxPresentationBytes)) + `"`)
			}
			bad, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(path, bad, 0600); err != nil {
				t.Fatal(err)
			}
			assertVerdict(t, c.Inbound(context.Background(), xonly(2), nil), Refused, CodeStateUnavailable, false, true)
			if reopened, err := New(c.config); reopened != nil || err != ErrState {
				t.Fatal("corrupt cache reopened", err)
			}
		})
	}
}

// Claim: the durable provision audit retains exactly the newest bounded records;
// malformed attempts cannot replace proof, and the ring survives restart.
func TestProvisionAuditRing(t *testing.T) {
	c, _, p := unitChecker(t)
	ctx := context.Background()
	assertVerdict(t, c.Provision(ctx, p), Live, CodeLive, false, false)
	for i := 0; i < MaxProvisionRecords+1; i++ {
		bad := Presentation{Bytes: []byte(fmt.Sprintf("invalid-%d", i))}
		assertVerdict(t, c.Provision(ctx, bad), Refused, CodeInvalidPresentation, false, false)
	}
	if !bytes.Equal(cachedBytes(t, c, xonly(2)), p.Bytes) {
		t.Fatal("audit churn replaced proof")
	}
	if _, err := New(c.config); err != nil {
		t.Fatal("audit reopen", err)
	}
	raw, err := os.ReadFile(filepath.Join(c.config.StateDir, stateName))
	var m state
	if err != nil || json.Unmarshal(raw, &m) != nil || len(m.Provisioning) != MaxProvisionRecords {
		t.Fatal("audit ring bound")
	}
	if _, err := c.cachedGrant(xonly(3)); err != kernel.ErrNoPresentation {
		t.Fatal("audit introduced peer", err)
	}
}
