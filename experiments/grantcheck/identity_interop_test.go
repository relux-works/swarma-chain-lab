package grantcheck

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

func identityChecker(t *testing.T, n *identityNode, now int64) (*Checker, Presentation, string) {
	t.Helper()
	raw := identityRead(t, "presentation.json")
	p, e := rental.ParseGrantPresentation(raw)
	if e != nil {
		t.Fatal(e)
	}
	g := p.SignedGrant.Grant
	cfg := unitConfig(t)
	cfg.ContractProfile = ContractProfileTrust
	cfg.ExecutorKey = ""
	cfg.Network = "regtest"
	cfg.Genesis = su.RegtestGenesis
	cfg.Node = n
	cfg.AgentName = g.AgentName
	cfg.LandlordName = g.LandlordName
	cfg.IssuerPubkey = g.IssuerKey
	cfg.Terms = termsOf(identityRead(t, "contract.json"), identityRead(t, "expired-contract.json"), identityRead(t, "wrong-profile-contract.json"))
	cfg.Now = func() time.Time { return time.Unix(now, 0) }
	cfg.Freshness = testFreshness(10*time.Minute, 0, 0)
	c, e := New(cfg)
	if e != nil {
		t.Fatal(e)
	}
	return c, Presentation{GrantID: p.SignedGrant.ID(), Bytes: raw}, g.GranteeKey
}

// Claim: exact pinned-issuer bytes admit through CG1 trust and the real kernel,
// with cached inbound and outbound rechecking this read-only offline graph.
// Limit: synthetic headers/name generations are not consensus or Core evidence.
func TestIdentityInteropLegacy(t *testing.T) {
	n := newIdentityNode(t)
	c, p, peer := identityChecker(t, n, 1795000000)

	assertVerdict(t, c.Inbound(context.Background(), peer, &p), Live, CodeLive, false, false)
	before := n.calls
	assertVerdict(t, c.Inbound(context.Background(), peer, nil), Live, CodeLive, false, false)
	assertVerdict(t, c.Outbound(context.Background(), peer), Live, CodeLive, false, false)
	if n.calls <= before {
		t.Fatal("cached routes skipped node")
	}
}

// Claim: every mutation has a live issuer-byte control, refuses with its exact
// public code, and never inserts a proof into CG1's cache. The holders cases
// read the issuer's exact exported values through CG1's actual policyNode.
// A spent seal legitimately records terminal closure in the kernel journal.
func TestIdentityInteropRefusals(t *testing.T) {
	cases := []struct {
		name, file, landlord string
		spent                bool
		want                 Code
		closed               bool
	}{
		{name: "wrong-consent", file: "wrong-consent.json", want: CodeInvalidPresentation},
		{name: "wrong-grantee", file: "wrong-grantee.json", want: CodeInvalidPresentation},
		{name: "wrong-profile", file: "wrong-profile.json", want: CodeTermsInvalid},
		{name: "wrong-version", file: "wrong-version.json", want: CodeInvalidPresentation},
		{name: "tampered-byte", file: "tampered-byte.json", want: CodeInvalidPresentation},
		{name: "expired-window", file: "expired-window.json", want: CodeExpired},
		{name: "wrong-seal", file: "wrong-seal.json", want: CodeIssuanceMismatch},
		{name: "wrong-locator", file: "wrong-locator.json", want: CodeIssuanceMismatch},
		{name: "spent-seal", spent: true, want: CodeSealSpent, closed: true},
		{name: "holders-empty", landlord: "landlord-holders-empty.json", want: CodeBindingMismatch},
		{name: "holders-populated", landlord: "landlord-holders-populated.json", want: CodeBindingMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			control := newIdentityNode(t)
			good, p, peer := identityChecker(t, control, 1795000000)
			assertVerdict(t, good.Inbound(context.Background(), peer, &p), Live, CodeLive, false, false)
			n := newIdentityNode(t)
			c, bad, peer := identityChecker(t, n, 1795000000)
			if tc.landlord != "" {
				n.names[c.config.LandlordName]["value"] = string(identityRead(t, tc.landlord))
			}
			n.spent = tc.spent
			if tc.file != "" {
				bad.Bytes = identityRead(t, tc.file)
				var decoded rental.GrantPresentation
				if err := json.Unmarshal(bad.Bytes, &decoded); err != nil {
					t.Fatal(err)
				}
				signed, _ := json.Marshal(decoded.SignedGrant)
				bad.GrantID = rental.Hash(signed)
			}
			v := c.Inbound(context.Background(), peer, &bad)
			decision := Refused
			if tc.want == CodeExpired || tc.want == CodeSealSpent {
				decision = Exchange
			}
			assertVerdict(t, v, decision, tc.want, tc.closed, false)
			t.Logf("CG1-trust %s: %s/%s closed=%v", tc.name, v.Decision, v.Code, v.Closed)
			if _, err := c.cachedGrant(peer); err == nil {
				t.Fatal("refused bytes entered cache")
			}
			assertVerdict(t, c.Outbound(context.Background(), peer), Refused, CodeNoGrant, false, false)
		})
	}
}

// Claim: wrong authenticated sender and changed contract octets refuse beside
// exact-byte acceptance, without replacing a previously admitted cached grant.
func TestIdentityInteropCachePreserved(t *testing.T) {
	n := newIdentityNode(t)
	c, p, peer := identityChecker(t, n, 1795000000)
	assertVerdict(t, c.Inbound(context.Background(), peer, &p), Live, CodeLive, false, false)
	assertVerdict(t, c.Inbound(context.Background(), xonly(7), &p), Refused, CodeBindingMismatch, false, false)
	original := c.config.Terms
	c.config.Terms = func(h string) ([]byte, error) { b, e := original(h); return append(b, ' '), e }
	assertVerdict(t, c.Inbound(context.Background(), peer, &p), Refused, CodeTermsInvalid, false, false)
	if !bytes.Equal(cachedBytes(t, c, peer), p.Bytes) {
		t.Fatal("mutation replaced cache")
	}
	c.config.Terms = original
	assertVerdict(t, c.Outbound(context.Background(), peer), Live, CodeLive, false, false)
}

// Claim: the corpus preserves every listed JSON octet, omits no JSON file,
// and its admitted control remains the owner's exact G1.0 shape. This is
// byte-integrity/shape evidence, not a signature of fixture provenance.
func TestIdentityInteropCorpus(t *testing.T) {
	sums := strings.Split(strings.TrimSpace(string(identityRead(t, "SHA256SUMS"))), "\n")
	seen := map[string]bool{}
	for _, line := range sums {
		fields := strings.Fields(line)
		if len(fields) != 2 || seen[fields[1]] || strings.ContainsAny(fields[1], "/\\") {
			t.Fatal("bad manifest line")
		}
		seen[fields[1]] = true
		if rental.Hash(identityRead(t, fields[1])) != fields[0] {
			t.Fatalf("fixture digest: %s", fields[1])
		}
	}
	entries, err := os.ReadDir("testdata/identity-interop")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") && !seen[e.Name()] {
			t.Fatalf("unsealed JSON fixture: %s", e.Name())
		}
	}
	var c struct {
		Profile, Network string
		Actions          []string
		Repos            []string
		SpendBudget      int64 `json:"spend_budget"`
	}
	if err := json.Unmarshal(identityRead(t, "contract.json"), &c); err != nil {
		t.Fatal(err)
	}
	if c.Profile != "swarma-trust-contract/1" || c.Network != "regtest" || !slices.Equal(c.Actions, []string{"instruct", "review"}) || c.Repos == nil || len(c.Repos) != 0 || c.SpendBudget != 0 {
		t.Fatal("not the G1.0 contract shape")
	}
	p, err := rental.ParseGrantPresentation(identityRead(t, "presentation.json"))
	if err != nil {
		t.Fatal(err)
	}
	g := p.SignedGrant.Grant
	if g.Version != 3 || g.Network != "regtest" || g.Genesis != su.RegtestGenesis || g.Scope == nil || len(g.Scope) != 0 || g.Budget != nil {
		t.Fatal("not the G1.0 v3 grant shape")
	}
	var outcomes map[string]struct {
		Code string
		Exit int
	}
	identityDecode(t, "issuer-outcomes.json", &outcomes)
	for _, name := range []string{"holders-empty", "holders-populated"} {
		got := outcomes[name]
		if got.Code != "LANDLORD_NOT_V3" || got.Exit != 3 {
			t.Fatalf("issuer holders pair: %s %+v", name, got)
		}
	}
}
