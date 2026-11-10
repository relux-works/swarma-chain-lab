package rental

import (
	"bytes"
	"encoding/hex"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"testing"
)

func locatorFixture(t *testing.T) (Policy, PlanSpec, []byte) {
	t.Helper()
	g := testGrant(t)
	raw := signGrantTest(t, g, 1)
	seal, _ := GrantSealScript(g.IssuerKey)
	p := Policy{ConstructionProfile: "W", Network: g.Network, Genesis: g.Genesis, AgentName: g.AgentName, LandlordName: g.LandlordName, SealScript: seal, FundingScript: testFundingScript(), StateDir: t.TempDir()}
	spec := PlanSpec{Kind: "grant-issue", Inputs: []su.PlanInput{{Point: su.Point{TxID: Hash([]byte("funding"))}, ValueSat: 1000000, Script: p.FundingScript, Role: "funding"}}, ChangeScript: p.FundingScript}
	return p, spec, raw
}
func framedGrantScript(t *testing.T, raw []byte) []byte {
	t.Helper()
	s, e := ParseSignedGrant(raw)
	if e != nil {
		t.Fatal(e)
	}
	commit, e := IssuanceCommitment(s)
	if e != nil {
		t.Fatal(e)
	}
	b, e := hex.DecodeString("6a03534c014201" + commit + "01" + s.ID())
	if e != nil {
		t.Fatal(e)
	}
	return b
}

// The kernel's script gate accepts independent framed/bare fixtures only when
// the bound commitment matches, and frames also bind issuance/blob/grant ID.
func TestIssuanceLocatorBinding(t *testing.T) {
	_, _, raw := locatorFixture(t)
	s, _ := ParseSignedGrant(raw)
	commit, _ := IssuanceCommitment(s)
	good := framedGrantScript(t, raw)
	legacy := append([]byte{0x6a, 32}, mustDecodeKey(commit)...)
	for _, script := range [][]byte{good, legacy} {
		if !issuanceScriptMatches(script, commit, s.ID()) {
			t.Fatal("valid issuance form refused")
		}
	}
	for _, kind := range []string{"commitment", "pointer", "batch", "torrent_v2", "swarm", "none", "memo", "legacy_commitment"} {
		t.Run(kind, func(t *testing.T) {
			script := bytes.Clone(good)
			switch kind {
			case "commitment":
				script[7] ^= 1
			case "pointer":
				script[40] ^= 1
			case "batch":
				script[4] = 2
			case "torrent_v2":
				script[39] = 2
			case "swarm":
				script[39] = 4
			case "none":
				script = script[:40]
				script[5] = 34
				script[39] = 0
			case "memo":
				script = []byte{0x6a, 2, 0x6d, 2, 1, 'x'}
			case "legacy_commitment":
				script = bytes.Clone(legacy)
				script[2] ^= 1
			}
			if issuanceScriptMatches(script, commit, s.ID()) {
				t.Fatal("invalid issuance locator admitted")
			}
			if !issuanceScriptMatches(good, commit, s.ID()) {
				t.Fatal("valid issuance neighbor refused")
			}
		})
	}
}

// The pre-sign funding projection must include 72 script bytes. A budget enough
// for the old 34-byte output but short for the frame refuses before planning.
func TestFramedFundingProjection(t *testing.T) {
	p, s, raw := locatorFixture(t)
	plan, e := MakeGrantIssuancePlan(p, s, raw)
	if e != nil {
		t.Fatal(e)
	}
	g, _ := ParseSignedGrant(raw)
	s.Inputs[0].ValueSat = plan.FeeSat - 38*200 + 1000
	if _, _, e = grantFunding(p, s, g.Grant.Seal); e == nil || e.Error() != "FUNDING_OR_DUST_RESERVE" {
		t.Fatal("framed pre-sign fee undercount")
	}
	if got, e := MakeGrantIssuancePlan(p, s, raw); e == nil || got.GrantID != "" || len(got.Outputs) != 0 {
		t.Fatal("insufficient framed funding yielded plan")
	}
	s.Inputs[0].ValueSat += 38 * 200
	if _, _, e = grantFunding(p, s, g.Grant.Seal); e != nil {
		t.Fatal("valid framed fee boundary refused")
	}
	got, e := MakeGrantIssuancePlan(p, s, raw)
	if e != nil || got.Outputs[1].ValueSat != 1000 || got.FeeSat != plan.FeeSat {
		t.Fatal("framed fee boundary changed")
	}
}
func oldBarePlan(t *testing.T, framed Plan, raw []byte) Plan {
	t.Helper()
	old := framed
	old.Outputs = append([]su.PlanOutput{}, framed.Outputs...)
	s, e := ParseSignedGrant(raw)
	if e != nil {
		t.Fatal(e)
	}
	commit, e := IssuanceCommitment(s)
	if e != nil {
		t.Fatal(e)
	}
	old.Outputs[0].Script = "6a20" + commit
	old.MaxSignedVBytes -= 38
	old.FeeSat -= 38 * 200
	old.Outputs[1].ValueSat += 38 * 200
	return old
}

// A completed-record comparator checks the complete old/new plan, including
// byte-specific fee and change. Mutating either shape cannot launder a record.
func TestCompletedPlanShapes(t *testing.T) {
	p, s, raw := locatorFixture(t)
	framed, e := MakeGrantIssuancePlan(p, s, raw)
	if e != nil {
		t.Fatal(e)
	}
	bare := oldBarePlan(t, framed, raw)
	for _, plan := range []Plan{framed, bare} {
		if !matchesIssuedGrantPlan(p, s, raw, &plan) {
			t.Fatal("exact completed plan refused")
		}
	}
	if matchesIssuedGrantPlan(p, s, raw, nil) {
		t.Fatal("nil completed plan accepted")
	}
	for _, kind := range []string{"pointer", "extra", "bare_with_new_fee", "frame_with_old_fee", "fee", "change", "size", "grant_id", "version"} {
		t.Run(kind, func(t *testing.T) {
			bad := framed
			bad.Outputs = append([]su.PlanOutput{}, framed.Outputs...)
			switch kind {
			case "pointer":
				b := mustDecodeKey(bad.Outputs[0].Script)
				b[40] ^= 1
				bad.Outputs[0].Script = hex.EncodeToString(b)
			case "extra":
				bad.Outputs = append(bad.Outputs, su.PlanOutput{Script: "6a00"})
			case "bare_with_new_fee":
				bad.Outputs[0].Script = bare.Outputs[0].Script
			case "frame_with_old_fee":
				bad = bare
				bad.Outputs = append([]su.PlanOutput{}, bare.Outputs...)
				bad.Outputs[0].Script = framed.Outputs[0].Script
			case "fee":
				bad.FeeSat++
			case "change":
				bad.Outputs[1].ValueSat--
			case "size":
				bad.MaxSignedVBytes--
			case "grant_id":
				bad.GrantID = Hash([]byte("other"))
			case "version":
				bad.Version = 2
			}
			if matchesIssuedGrantPlan(p, s, raw, &bad) {
				t.Fatal("corrupt completed plan admitted")
			}
			if !matchesIssuedGrantPlan(p, s, raw, &bare) {
				t.Fatal("bare completed neighbor refused")
			}
		})
	}
}
