package rental

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
)

// Each certificate profile accepts its own valid bytes and refuses out-of-range
// scalars before state access or node calls; these are boundary cases, not a
// claimed verifying (s+n) neighbour of an ordinary 256-bit fixture scalar.
func TestBIP340CertificateBoundaries(t *testing.T) {
	g := testGrant(t)
	script, e := GrantSealScript(g.IssuerKey)
	if e != nil {
		t.Fatal(e)
	}
	legacy := testCertificate()
	cases := []struct {
		name  string
		raw   []byte
		parse func([]byte) error
		check func([]byte, string) Receipt
	}{
		{"v1", signTest(t, legacy, 1), func(b []byte) error { _, e := ParseEnvelope(b); return e }, func(b []byte, dir string) Receipt {
			return CheckLegacy(context.Background(), nil, Policy{Network: legacy.Network, Genesis: legacy.Genesis, IssuerPubkey: legacy.IssuerPubkey, AgentPubkey: legacy.AgentPubkey, StationName: legacy.StationName, StationScript: "76a914" + strings.Repeat("00", 20) + "88ac", StateDir: dir}, b, legacy.StationName, legacy.GranteePubkey, 500)
		}},
		{"v2", signDetachedTest(t, testDetached(), 1), func(b []byte) error { _, e := ParseDetachedEnvelope(b); return e }, func(b []byte, dir string) Receipt {
			return CheckV2(context.Background(), nil, Policy{Network: g.Network, Genesis: g.Genesis, AgentName: g.AgentName, SealScript: script, StateDir: dir}, b, g.AgentName, g.GranteeKey, 500)
		}},
		{"v3", signGrantTest(t, g, 1), func(b []byte) error { _, e := ParseSignedGrant(b); return e }, func(b []byte, dir string) Receipt {
			presentation, _ := json.Marshal(GrantPresentation{SignedGrant: decodeSignedBoundary(t, b), Issuance: IssuanceProof{TxID: strings.Repeat("e", 64)}})
			return Check(context.Background(), nil, Policy{ConstructionProfile: "W", Network: g.Network, Genesis: g.Genesis, AgentName: g.AgentName, LandlordName: g.LandlordName, SealScript: script, StateDir: dir}, presentation, g.AgentName, g.GranteeKey, 500)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if e := c.parse(c.raw); e != nil {
				t.Fatal("valid control", e)
			}
			var object map[string]json.RawMessage
			if e := json.Unmarshal(c.raw, &object); e != nil {
				t.Fatal(e)
			}
			var sig string
			if e := json.Unmarshal(object["signature"], &sig); e != nil {
				t.Fatal(e)
			}
			b, _ := hex.DecodeString(sig)
			btcec.S256().N.FillBytes(b[32:])
			// Preserve the original canonical field order.
			bad := []byte(strings.Replace(string(c.raw), sig, hex.EncodeToString(b), 1))
			if e := c.parse(bad); e == nil {
				t.Fatal("non-canonical scalar accepted")
			}
			dir := filepath.Join(t.TempDir(), "must-not-open")
			r := c.check(bad, dir)
			if r.Verdict != "refused" || r.Calls != 0 || r.Reason == "" || (c.name == "v3" && r.GrantID != "") {
				t.Fatalf("invalid certificate reached authority: %+v", r)
			}
			if _, e := os.Stat(dir); !os.IsNotExist(e) {
				t.Fatalf("invalid certificate accessed state: %v", e)
			}
			if e := c.parse(c.raw); e != nil {
				t.Fatal("valid neighbour", e)
			}
		})
	}
}

func decodeSignedBoundary(t *testing.T, b []byte) SignedGrant {
	t.Helper()
	var s SignedGrant
	if e := json.Unmarshal(b, &s); e != nil {
		t.Fatal(e)
	}
	return s
}
