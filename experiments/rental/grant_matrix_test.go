package rental

import (
	"bytes"
	"context"
	"encoding/json"
	su "relux.works/swarma-chain-lab/experiments/single-use"
	"strings"
	"testing"
)

// All rows use genuine confirmed Core identities, seals and issuance. Wire/key
// controls fail before node use by design; explicit transport mutations are
// labelled. Every denial retains a live neighbor and never falsely closes it.
func TestCoreGrantMatrix(t *testing.T) {
	l := newCore(t)
	l.grantIdentity()
	seal := l.detachedPool(1, true)
	base, g, raw := l.grantFixture("base", seal, 2)
	proof := l.grantProof(base, raw, true)
	var presentation GrantPresentation
	if e := json.Unmarshal(proof, &presentation); e != nil {
		t.Fatal(e)
	}
	passed := []string{}
	run := func(name string, fn func()) {
		t.Run(name, func(tt *testing.T) {
			old := l.t
			l.t = tt
			defer func() { l.t = old }()
			fn()
			passed = append(passed, name)
		})
	}
	for _, mode := range []string{"foreign-agent", "foreign-landlord", "wrong-landlord-key", "foreign-network", "wrong-sender", "wrong-grantee", "not-yet", "expired", "consent-future", "consent-foreign-key", "landlord-sig-missing", "consent-other-contract", "v2-wire", "extra-field", "seal-pin", "missing-commitment"} {
		run(mode, func() {
			p := base
			p.StateDir = l.policy(mode).StateDir
			cg := testGrant(l.t)
			cg.AgentName = g.AgentName
			cg.LandlordName = g.LandlordName
			cg.Seal = g.Seal
			sender := g.GranteeKey
			at := int64(500)
			want := ""
			verdict := "refused"
			signer := byte(1)
			locator := presentation.Issuance.TxID
			switch mode {
			case "foreign-agent":
				cg.AgentName = "id/foreign"
				want = "GRANT_POLICY"
			case "foreign-landlord":
				cg.LandlordName = "id/foreign"
				want = "GRANT_POLICY"
			case "wrong-landlord-key":
				_, cg.IssuerKey = testKey(5)
				cg.Consent.LandlordSig = signature(l.t, cg.ContractSHA256, 5)
				p.SealScript, _ = GrantSealScript(cg.IssuerKey)
				signer = 5
				want = "LANDLORD_KEY_MISMATCH"
			case "foreign-network":
				cg.Network = "main"
				cg.Genesis = su.MainGenesis
				want = "GRANT_POLICY"
			case "wrong-sender":
				_, sender = testKey(4)
				want = "GRANTEE_MISMATCH"
			case "wrong-grantee":
				_, cg.GranteeKey = testKey(4)
				cg.Consent.ConsentEvent = signedEvent(l.t, cg.Consent.ConsentEvent, 4)
				want = "GRANTEE_MISMATCH"
			case "not-yet":
				at = 99
				want = "NOT_YET_VALID"
				verdict = "pending"
			case "expired":
				at = 1000
				want = "EXPIRED"
			case "consent-future":
				cg.Consent.ConsentEvent.CreatedAt = 600
				cg.Consent.ConsentEvent = signedEvent(l.t, cg.Consent.ConsentEvent, 2)
				want = "CONSENT_FUTURE"
			case "consent-foreign-key":
				cg.Consent.ConsentEvent = signedEvent(l.t, cg.Consent.ConsentEvent, 4)
				want = "RENTER_CONSENT_EVENT"
			case "landlord-sig-missing":
				cg.Consent.LandlordSig = ""
				want = "LANDLORD_CONSENT_SIGNATURE"
			case "consent-other-contract":
				cg.Consent.ConsentEvent.Tags[1][1] = Hash([]byte("wrong"))
				cg.Consent.ConsentEvent = signedEvent(l.t, cg.Consent.ConsentEvent, 2)
				want = "RENTER_CONSENT_BINDING"
			case "v2-wire":
				want = "CANONICAL_ENCODING"
			case "extra-field":
				want = "CANONICAL_ENCODING"
			case "seal-pin":
				p.SealScript = l.script
				want = "SEAL_KEY_BINDING"
			case "missing-commitment":
				locator = Hash([]byte("not-present"))
				want = "NODE_UNAVAILABLE"
			}
			signedRaw := signGrantTest(l.t, cg, signer)
			var sg SignedGrant
			if e := json.Unmarshal(signedRaw, &sg); e != nil {
				l.t.Fatal(e)
			}
			badProof, _ := json.Marshal(GrantPresentation{sg, IssuanceProof{locator}})
			if mode == "v2-wire" {
				badProof = signDetachedTest(l.t, testDetached(), 1)
			}
			if mode == "extra-field" {
				badProof = bytes.Replace(badProof, []byte(`"version":3`), []byte(`"version":3,"extra":0`), 1)
			}
			r := Check(context.Background(), l.observer, p, badProof, p.AgentName, sender, at)
			l.save(mode+"-denied.json", r)
			if r.Verdict != verdict || r.Reason != want || r.Closed {
				l.t.Fatalf("want %s/%s unclosed got %+v", verdict, want, r)
			}
			// Refused checks may create the root/lock but not a grant or seen-seal record.
			assertNoIssuerBurn(l.t, p.StateDir)
			p.SealScript = base.SealScript
			l.checkGrant(mode+"-neighbor", p, g, proof, 500, "live", "LIVE", false)
		})
	}
	for _, mode := range []string{"agent-no-pointer", "agent-extra", "agent-alias", "landlord-no-key", "landlord-extra", "landlord-alias"} {
		run(mode, func() {
			p := base
			p.StateDir = l.policy(mode).StateDir
			l.checkGrant(mode+"-before", p, g, proof, 500, "live", "LIVE", false)
			name := l.station
			want := "AGENT_BINDING_VALUE"
			_, nostr := testKey(3)
			av, _ := AgentBindingValue(AgentBinding{nostr, labLandlord})
			lv, _ := LandlordValue(LandlordBinding{g.IssuerKey})
			value := av
			switch mode {
			case "agent-no-pointer":
				value = `{"swarma":{"agent":{"nostr":"` + nostr + `"}}}`
			case "agent-extra":
				value = strings.Replace(av, `"nostr":`, `"extra":0,"nostr":`, 1)
			case "agent-alias":
				value = strings.Replace(av, `"landlord":`, `"owner":`, 1)
			case "landlord-no-key":
				name = labLandlord
				value = `{"swarma":{"landlord":{}}}`
				want = "LANDLORD_VALUE"
			case "landlord-extra":
				name = labLandlord
				value = strings.Replace(lv, `"grant":`, `"extra":0,"grant":`, 1)
				want = "LANDLORD_VALUE"
			case "landlord-alias":
				name = labLandlord
				value = strings.Replace(lv, `"grant":`, `"issuer":`, 1)
				want = "LANDLORD_VALUE"
			}
			l.rpc("issuer", "name_update", name, value)
			l.mine(1)
			l.checkGrant(mode+"-denied", p, g, proof, 500, "refused", want, false)
			if name == labLandlord {
				l.landlordKey(1, true)
			} else {
				l.agentPointer(labLandlord, 3, true)
			}
			l.checkGrant(mode+"-neighbor", p, g, proof, 500, "live", "LIVE", false)
		})
	}
	for _, mode := range []string{"wrong-commitment", "two-opreturns", "nonzero-commitment"} {
		run(mode, func() {
			p := base
			p.StateDir = l.policy(mode).StateDir
			plan := l.grantPlan(p, raw)
			switch mode {
			case "wrong-commitment":
				plan.Outputs[0].Script = "6a20" + Hash([]byte("wrong"))
			case "two-opreturns":
				plan.Outputs = append(plan.Outputs, su.PlanOutput{ValueSat: 0, Script: "6a20" + Hash([]byte("extra")), Role: "forbidden-extra"})
			case "nonzero-commitment":
				plan.Outputs[0].ValueSat = 1
				plan.Outputs[1].ValueSat--
			}
			// Only this negative fixture permits a one-satoshi regtest burn.
			id := l.sendPlan(plan, true, plan.Outputs[0].ValueSat)
			badProof, e := PresentIssuedGrant(raw, id)
			if e != nil {
				l.t.Fatal(e)
			}
			l.checkGrant(mode+"-denied", p, g, badProof, 500, "refused", "ISSUANCE_COMMITMENT", false)
			assertNoIssuerBurn(l.t, p.StateDir)
			l.checkGrant(mode+"-neighbor", p, g, proof, 500, "live", "LIVE", false)
		})
	}
	run("commitment-reorg", func() {
		p, cg, signed := l.grantFixture("reorg", l.detachedPool(1, true), 2)
		pr := l.grantProof(p, signed, true)
		l.checkGrant("reorg-before", p, cg, pr, 500, "live", "LIVE", false)
		tip := text(l.t, l.rpc("", "getbestblockhash"))
		l.rpc("", "invalidateblock", tip)
		l.checkGrant("reorg-denied", p, cg, pr, 500, "pending", "ISSUANCE_UNCONFIRMED", false)
		l.rpc("", "reconsiderblock", tip)
		l.checkGrant("reorg-neighbor", p, cg, pr, 500, "live", "LIVE", false)
	})
	run("landlord-absent", func() {
		p := base
		p.StateDir = l.policy("absent").StateDir
		p.LandlordName = "id/absent-landlord"
		cg := g
		cg.LandlordName = p.LandlordName
		sr := signGrantTest(l.t, cg, 1)
		var s SignedGrant
		_ = json.Unmarshal(sr, &s)
		pr, _ := json.Marshal(GrantPresentation{s, presentation.Issuance})
		l.agentPointer(p.LandlordName, 3, true)
		l.checkGrant("landlord-absent", p, cg, pr, 500, "refused", "NODE_UNAVAILABLE", false)
		l.agentPointer(labLandlord, 3, true)
		p.LandlordName = labLandlord
		l.checkGrant("landlord-absent-neighbor", p, g, proof, 500, "live", "LIVE", false)
	})
	run("transport-failure", func() {
		p := base
		p.StateDir = l.policy("transport").StateDir
		r := Check(context.Background(), unavailableNode{}, p, proof, p.AgentName, g.GranteeKey, 500)
		if r.Reason != "NODE_UNAVAILABLE" || r.Closed {
			l.t.Fatal(r)
		}
		assertNoIssuerBurn(l.t, p.StateDir)
		l.checkGrant("transport-neighbor", p, g, proof, 500, "live", "LIVE", false)
	})
	run("seen-seal", func() {
		p := base
		p.StateDir = l.policy("seen").StateDir
		l.checkGrant("seen-first", p, g, proof, 500, "live", "LIVE", false)
		other := g
		_, other.GranteeKey = testKey(4)
		other.Consent.ConsentEvent = signedEvent(l.t, other.Consent.ConsentEvent, 4)
		sr := signGrantTest(l.t, other, 1)
		pr := l.grantProof(p, sr, true)
		l.checkGrant("seen-second", p, other, pr, 500, "refused", "SEAL_ALREADY_SEEN", false)
		l.checkGrant("seen-neighbor", p, g, proof, 500, "live", "LIVE", false)
	})
	for _, role := range []string{"agent", "landlord"} {
		run(role+"-expiry", func() {
			p := base
			p.StateDir = l.policy(role + "-expiry").StateDir
			name := labLandlord
			if role == "agent" {
				name = l.station
				l.landlordKey(1, true)
			} else {
				l.agentPointer(labLandlord, 3, true)
			}
			l.checkGrant(role+"-expiry-before", p, g, proof, 500, "live", "LIVE", false)
			var n su.NameView
			if e := json.Unmarshal(l.rpc("", "name_show", name), &n); e != nil {
				l.t.Fatal(e)
			}
			if n.ExpiresIn < 1 || n.ExpiresIn > 50000 {
				l.t.Fatal("expiry bound")
			}
			var height int64
			if e := json.Unmarshal(l.rpc("", "getblockcount"), &height); e != nil {
				l.t.Fatal(e)
			}
			l.mine(int(n.ExpiresIn))
			first := text(l.t, l.rpc("", "getblockhash", height+1))
			l.checkGrant(role+"-expiry-denied", p, g, proof, 500, "refused", "NODE_UNAVAILABLE", false)
			// Restore the entire empty-block interval, so renewal is not attempted
			// in the very block where the name expires again.
			l.rpc("", "invalidateblock", first)
			l.checkGrant(role+"-expiry-neighbor", p, g, proof, 500, "live", "LIVE", false)
			if role == "agent" {
				l.agentPointer(labLandlord, 3, true)
			} else {
				l.landlordKey(1, true)
			}
		})
	}
	l.save("matrix.json", passed)
	if len(passed) != 31 {
		t.Fatalf("matrix count %d", len(passed))
	}
}
