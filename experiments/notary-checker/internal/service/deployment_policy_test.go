package service

import (
	"encoding/json"
	"path/filepath"
	"sync/atomic"
	"testing"

	check "github.com/relux-works/swarma-chain-lab/experiments/notary-checker"
)

// Claim: a correctly signed non-regtest bundle reaches the post-Check network
// guard, which refuses NODE_NETWORK with no signer invocation or signed output.
// Its regtest counterpart attests; all RPC here is synthetic loopback data.
func TestServiceAttestationNetworkGuard(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		signs      int32
	}{
		{"positive-same-owner", "ATTEST", 1}, {"positive-main-network-bundle", "NODE_NETWORK", 0},
	} {
		s, req, _ := setupForVector(t, fixtureNamed(t, tc.name))
		n := rev374Counted(s)
		_, r, _ := submit(t, s, encode(t, req))
		if r.Decision != tc.want || atomic.LoadInt32(n) != tc.signs || (tc.signs == 0 && (len(r.SignedAttestation) != 0 || r.AnchorFrame != "")) {
			t.Fatalf("%s decision=%s signs=%d", tc.name, r.Decision, atomic.LoadInt32(n))
		}
	}
}

// Claim: the loaded default config cannot infer MVP from owner relations,
// agreements or available chain names. An omitted/zero deployment policy mode
// retains strict D8 and refuses a pair-owned notary. Only that local policy's
// explicit MVP field enables its bilateral-approval path for the same bundle.
func TestDeploymentPolicyStrictDefaultAndExplicitMVP(t *testing.T) {
	for _, mode := range []string{"omitted", "zero", "explicit-mvp"} {
		t.Run(mode, func(t *testing.T) {
			v := fixtureNamed(t, "positive-mvp-issuer-owner")
			var p check.Policy
			if err := json.Unmarshal([]byte(v.Policy), &p); err != nil {
				t.Fatal(err)
			}
			if mode != "explicit-mvp" {
				p.Mode = ""
				p.ModeApprovals = nil
			}
			if mode == "omitted" {
				var fields map[string]json.RawMessage
				if err := json.Unmarshal(encode(t, p), &fields); err != nil {
					t.Fatal(err)
				}
				if _, exists := fields["mode"]; exists {
					t.Fatal("zero policy mode was serialized")
				}
			}
			v.Policy = string(encode(t, p))
			s, req, _ := setupForVector(t, v)
			// Load again through the default config to cover the actual deployment file,
			// rather than supplying a policy directly to the checker or request.
			path := filepath.Join(t.TempDir(), "config")
			put(t, path, encode(t, s.config))
			loaded, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(loaded.Close)
			loaded.now = s.now
			n := rev374Counted(loaded)
			_, r, _ := submit(t, loaded, encode(t, req))
			want := "NOTARY_OWNER_RELATION"
			signs := int32(0)
			if mode == "explicit-mvp" {
				want = "ATTEST"
				signs = 1
			}
			if r.Decision != want || atomic.LoadInt32(n) != signs || (signs == 0 && (len(r.SignedAttestation) != 0 || r.AnchorFrame != "")) {
				t.Fatalf("decision=%s signs=%d", r.Decision, atomic.LoadInt32(n))
			}
		})
	}
}

// Claim: a one-owner issuer/delegator pair still requires its own notary in
// strict D8. MVP cannot relax this rule; a one-owner MVP pair is refused.
func TestDeploymentPolicyOneOwnerStaysStrict(t *testing.T) {
	for _, tc := range []struct{ name, want string }{
		{"positive-same-owner", "ATTEST"},
		{"negative-owner-relation", "NOTARY_OWNER_RELATION"},
		{"negative-mvp-one-owner-pair", "MVP_MODE_PAIR_REQUIRED"},
	} {
		s, req, _ := setupForVector(t, fixtureNamed(t, tc.name))
		n := rev374Counted(s)
		_, r, _ := submit(t, s, encode(t, req))
		wantSigns := int32(0)
		if tc.want == "ATTEST" {
			wantSigns = 1
		}
		if r.Decision != tc.want || atomic.LoadInt32(n) != wantSigns {
			t.Fatalf("%s decision=%s signs=%d", tc.name, r.Decision, atomic.LoadInt32(n))
		}
	}
}
