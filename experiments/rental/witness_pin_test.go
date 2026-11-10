package rental

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Policy pin refusal precedes parsing, RPC and cache access even with a
// malformed presentation. The valid W policy itself validates; genuine live
// admission and existing cache preservation are covered by the Core suite.
func TestGrantWitnessPolicyPin(t *testing.T) {
	g := testGrant(t)
	script, _ := GrantSealScript(g.IssuerKey)
	p := Policy{ConstructionProfile: "W", Network: g.Network, Genesis: g.Genesis, AgentName: g.AgentName, LandlordName: g.LandlordName, SealScript: script, StateDir: t.TempDir()}
	if e := p.validateGrant(); e != nil {
		t.Fatal("W policy neighbor", e)
	}
	marker := filepath.Join(p.StateDir, "existing-cache")
	if e := os.WriteFile(marker, []byte("preserve"), 0600); e != nil {
		t.Fatal(e)
	}
	for _, pin := range []string{"", "L", "future"} {
		p.ConstructionProfile = pin
		got := Check(context.Background(), nil, p, []byte("malformed"), g.AgentName, g.GranteeKey, 100)
		if got.Verdict != "refused" || got.Reason != "W_PROFILE_REQUIRED" || got.Calls != 0 || got.Closed {
			t.Fatal("rental W pin refusal", got)
		}
		entries, e := os.ReadDir(p.StateDir)
		if e != nil || len(entries) != 1 {
			t.Fatal("pin refusal created state", e)
		}
		raw, e := os.ReadFile(marker)
		if e != nil || string(raw) != "preserve" {
			t.Fatal("pin refusal changed cache", e)
		}
	}
}
