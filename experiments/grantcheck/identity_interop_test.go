package grantcheck

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// Deployment encodings: ASCII name strings and lowercase 32-byte x-only hex.
// These constants are independent of all corpus bytes and exporter output.
const (
	identityAgent    = "id/landlord-a-agent"
	identityLandlord = "id/landlord-a"
	identityIssuer   = "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659"
	identityGrantee  = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
)

func identityChecker(t *testing.T, n *identityNode, now int64) (*Checker, Presentation, string) {
	t.Helper()
	raw := identityRead(t, "presentation.json")
	p, e := rental.ParseGrantPresentation(raw)
	if e != nil {
		t.Fatal(e)
	}
	cfg := unitConfig(t)
	cfg.ContractProfile = ContractProfileTrust
	cfg.ExecutorKey = ""
	cfg.Network = "regtest"
	cfg.Genesis = su.RegtestGenesis
	cfg.Node = n
	cfg.AgentName = identityAgent
	cfg.LandlordName = identityLandlord
	cfg.IssuerPubkey = identityIssuer
	cfg.Terms = termsOf(identityRead(t, "contract.json"), identityRead(t, "expired-contract.json"), identityRead(t, "wrong-profile-contract.json"))
	cfg.Now = func() time.Time { return time.Unix(now, 0) }
	cfg.Freshness = testFreshness(10*time.Minute, 0, 0)
	c, e := New(cfg)
	if e != nil {
		t.Fatal(e)
	}
	return c, Presentation{GrantID: p.SignedGrant.ID(), Bytes: raw}, identityGrantee
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
	if n.calls <= before {
		t.Fatal("cached inbound skipped node")
	}
	before = n.calls
	assertVerdict(t, c.Outbound(context.Background(), peer), Live, CodeLive, false, false)
	if n.calls <= before {
		t.Fatal("cached outbound skipped node")
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
				n.setLandlordValue(t, string(identityRead(t, tc.landlord)))
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
	if len(sums) != 37 {
		t.Fatalf("manifest count=%d, want 37", len(sums))
	}
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
	// An independent filename set prevents a manifest edit from deleting a fixture.
	expectedFiles := []string{
		"agent-value.json",
		"anchor-request.json",
		"anchor-result.json",
		"consent-result.json",
		"contract.json",
		"draft-request.json",
		"draft-result.json",
		"expired-contract.json",
		"expired-signed-grant.json",
		"expired-window.json",
		"issuer-holders-empty.json",
		"issuer-holders-populated.json",
		"issuer-outcomes.json",
		"issuer-seal-missing.json",
		"issuer-seal-spent.json",
		"issuer-tampered-contract.json",
		"issuer-wrong-consent.json",
		"issuer-wrong-grantee.json",
		"issuer-wrong-profile.json",
		"issuer-wrong-seal.json",
		"issuer-wrong-version.json",
		"landlord-holders-empty.json",
		"landlord-holders-populated.json",
		"landlord-legacy.json",
		"presentation.json",
		"seal-request.json",
		"seal-result.json",
		"sign-result.json",
		"signed-grant.json",
		"tampered-byte.json",
		"wrong-consent.json",
		"wrong-grantee.json",
		"wrong-locator.json",
		"wrong-profile-contract.json",
		"wrong-profile.json",
		"wrong-seal.json",
		"wrong-version.json",
	}
	actualFiles := make([]string, 0, len(seen))
	for name := range seen {
		actualFiles = append(actualFiles, name)
	}
	sort.Strings(actualFiles)
	if !slices.Equal(actualFiles, expectedFiles) {
		t.Fatalf("manifest filenames=%v", actualFiles)
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
	if g.AgentName != identityAgent || g.LandlordName != identityLandlord || g.IssuerKey != identityIssuer || g.GranteeKey != identityGrantee {
		t.Fatal("corpus identity differs from deployment literals")
	}
	if g.Version != 3 || g.Network != "regtest" || g.Genesis != su.RegtestGenesis || g.Scope == nil || len(g.Scope) != 0 || g.Budget != nil {
		t.Fatal("not the G1.0 v3 grant shape")
	}
	t.Run("issuer-outcomes", TestIdentityInteropIssuerOutcomes)
}

// Claim: each configured binding independently rejects otherwise valid issuer
// bytes, beside a live control, with no cached proof or usable outbound grant.
func TestIdentityInteropConfiguredIdentity(t *testing.T) {
	for _, field := range []string{"agent", "landlord", "issuer-key", "grantee-key"} {
		t.Run(field, func(t *testing.T) {
			good, p, peer := identityChecker(t, newIdentityNode(t), 1795000000)
			assertVerdict(t, good.Inbound(context.Background(), peer, &p), Live, CodeLive, false, false)
			candidate, _, _ := identityChecker(t, newIdentityNode(t), 1795000000)
			cfg := candidate.config
			// A different deployment identity needs its own unbound state directory.
			cfg.StateDir = stateDir(t)
			switch field {
			case "agent":
				cfg.AgentName = "id/other-agent"
			case "landlord":
				cfg.LandlordName = "id/other-landlord"
			case "issuer-key":
				cfg.IssuerPubkey = xonly(7)
			case "grantee-key":
				peer = xonly(7)
			}
			c, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			assertVerdict(t, c.Inbound(context.Background(), peer, &p), Refused, CodeBindingMismatch, false, false)
			if _, err := c.cachedGrant(peer); err == nil {
				t.Fatal("mismatched identity entered cache")
			}
			assertVerdict(t, c.Outbound(context.Background(), peer), Refused, CodeNoGrant, false, false)
		})
	}
}

// Claim: all twelve recorded dispatcher outcomes match this independent matrix;
// every refusal envelope has the exact stage, code and fail-closed shape.
// This checks recorded data; the separate CI exporter remeasures issuer behavior.
func TestIdentityInteropIssuerOutcomes(t *testing.T) {
	type outcome struct {
		Code   string `json:"code"`
		Exit   int    `json:"exit"`
		Stage  string `json:"stage,omitempty"`
		Reason string `json:"reason,omitempty"`
	}
	expected := map[string]outcome{
		"legacy":            {Code: "OK", Exit: 0, Stage: "signed+anchor-plan"},
		"expired-window":    {Code: "OK", Exit: 0, Reason: "issuer has no ambient clock"},
		"holders-empty":     {Code: "LANDLORD_NOT_V3", Exit: 3},
		"holders-populated": {Code: "LANDLORD_NOT_V3", Exit: 3},
		"seal-missing":      {Code: "SEAL_MISSING_OR_SPENT", Exit: 3},
		"seal-spent":        {Code: "SEAL_MISSING_OR_SPENT", Exit: 3},
		"tampered-contract": {Code: "CONTRACT_HASH", Exit: 3},
		"wrong-consent":     {Code: "CONSENT_SIGNATURE", Exit: 3},
		"wrong-grantee":     {Code: "CONSENT_SIGNER", Exit: 3},
		"wrong-profile":     {Code: "CONTRACT_PROFILE", Exit: 3},
		"wrong-seal":        {Code: "SEAL_KEY_MISMATCH", Exit: 3},
		"wrong-version":     {Code: "BAD_INPUT", Exit: 2},
	}
	var got map[string]outcome
	decoder := json.NewDecoder(bytes.NewReader(identityRead(t, "issuer-outcomes.json")))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 12 || !reflect.DeepEqual(got, expected) {
		t.Fatalf("issuer outcomes differ: %+v", got)
	}
	for name, want := range expected {
		t.Run(name, func(t *testing.T) {
			if want.Exit == 0 {
				t.Logf("recorded dispatcher %s: %s exit=%d", name, want.Code, want.Exit)
				return
			}
			command := "grant anchor"
			switch name {
			case "holders-empty", "holders-populated", "wrong-version":
				command = "grant draft"
			case "wrong-consent", "wrong-grantee", "wrong-profile":
				command = "grant consent"
			}
			var envelope struct {
				Schema, Command, Network string
				OK                       *bool
				Result                   json.RawMessage
				Error                    *struct {
					Code, Message string
					Retryable     *bool
				}
			}
			identityDecode(t, "issuer-"+name+".json", &envelope)
			if envelope.Schema != "swarma-identity/result/1" || envelope.Command != command || envelope.Network != "regtest" || envelope.OK == nil || *envelope.OK || string(envelope.Result) != "null" || envelope.Error == nil {
				t.Fatalf("invalid refusal envelope: %+v", envelope)
			}
			message := "The grant input is refused by the trust-grant contract."
			if name == "wrong-version" {
				message = "The input does not satisfy the selected contract."
			}
			if envelope.Error.Code != want.Code || envelope.Error.Retryable == nil || *envelope.Error.Retryable || envelope.Error.Message != message {
				t.Fatalf("refusal error: %+v", envelope.Error)
			}
			t.Logf("recorded dispatcher %s: %s exit=%d", name, want.Code, want.Exit)
		})
	}
}

// Claim: each exported landlord VALUE is the same in name_show, the projected
// name_update and its raw transaction; changing it preserves the old generation.
// The model asserts consistency only, not name registration or consensus.
func TestIdentityInteropHolderGeneration(t *testing.T) {
	for _, file := range []string{"landlord-legacy.json", "landlord-holders-empty.json", "landlord-holders-populated.json"} {
		t.Run(file, func(t *testing.T) {
			n := newIdentityNode(t)
			oldID := n.names[identityLandlord]["txid"].(string)
			oldBytes := append([]byte(nil), n.tx[oldID].Body.Bytes()...)
			value := string(identityRead(t, file))
			n.setLandlordValue(t, value)
			projection, err := n.Call(context.Background(), "name_show", identityLandlord)
			if err != nil {
				t.Fatal(err)
			}
			var name struct{ Value, TxID string }
			if err := json.Unmarshal(projection, &name); err != nil {
				t.Fatal(err)
			}
			transaction, err := n.Call(context.Background(), "getrawtransaction", name.TxID, true)
			if err != nil {
				t.Fatal(err)
			}
			var tx struct {
				Hex, TxID string
				Vout      []struct {
					ScriptPubKey struct {
						Hex    string
						NameOp struct{ Name, Value string }
					}
				}
			}
			if err := json.Unmarshal(transaction, &tx); err != nil {
				t.Fatal(err)
			}
			raw, err := hex.DecodeString(tx.Hex)
			if err != nil {
				t.Fatal(err)
			}
			body, err := su.DecodePaymentTransaction(raw)
			if err != nil {
				t.Fatal(err)
			}
			if len(tx.Vout) != 1 || len(body.Outputs) != 1 {
				t.Fatal("name output shape")
			}
			script := tx.Vout[0].ScriptPubKey
			expectedScript := su.NameUpdateScript(identityLandlord, value, []byte{0x51})
			if name.Value != value || tx.TxID != name.TxID || body.ID() != name.TxID || script.NameOp.Name != identityLandlord || script.NameOp.Value != value || script.Hex != hex.EncodeToString(expectedScript) || !bytes.Equal(body.Outputs[0].Script, expectedScript) {
				t.Fatal("landlord generation script/value mismatch")
			}
			if !bytes.Equal(n.tx[oldID].Body.Bytes(), oldBytes) {
				t.Fatal("old name generation overwritten")
			}
		})
	}
}
