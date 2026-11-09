package rental

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	su "relux.works/swarma-chain-lab/experiments/single-use"
	"testing"
)

func (l *coreLab) grantIssueInputs(p Policy, label string, confirmed bool) (IssuerPolicy, []byte, []byte, string, PlanSpec) {
	l.t.Helper()
	fund := l.detachedPool(7, true)
	spec := PlanSpec{Kind: "grant-issue", Inputs: []su.PlanInput{{Point: su.Point{TxID: fund.TxID, Vout: fund.Vout}, ValueSat: 1000000, Script: p.FundingScript, Role: "funding"}}, ChangeScript: p.FundingScript}
	ip, req, event, key := l.detachedIssueInputs(p, label, confirmed)
	return ip, req, event, key, spec
}
func requirePrepared(t *testing.T, r GrantIssueResult) {
	t.Helper()
	if r.Verdict != "prepared" || r.GrantID != Hash(r.SignedGrant) || r.Plan == nil || r.Plan.GrantID != r.GrantID {
		t.Fatalf("prepare: %+v", r)
	}
}

// Genuine Core issuance prepares without broadcasting, then its exact plan is
// confirmed before live. Complete retries return identical grant/plan bytes;
// a distinct booking cannot reuse a burned seal, beside a valid fresh seal.
func TestCoreGrantIssuer(t *testing.T) {
	l := newCore(t)
	l.grantIdentity()
	seal := l.detachedPool(1, true)
	p, _, _ := l.grantFixture("issuer", seal, 2)
	ip, req, event, key, spec := l.grantIssueInputs(p, "one", true)
	tip := text(t, l.rpc("", "getbestblockhash"))
	r := IssueGrant(context.Background(), l.observer, ip, req, event, seal, spec, key, 500)
	requirePrepared(t, r)
	l.save("prepared.json", r)
	if text(t, l.rpc("", "getbestblockhash")) != tip {
		t.Fatal("issuer changed chain")
	}
	signed, e := ParseSignedGrant(r.SignedGrant)
	if e != nil {
		t.Fatal(e)
	}
	missing, e := PresentIssuedGrant(r.SignedGrant, Hash([]byte("missing")))
	if e != nil {
		t.Fatal(e)
	}
	l.checkGrant("before-broadcast", p, signed.Grant, missing, 500, "refused", "NODE_UNAVAILABLE", false)
	id := l.sendPlan(*r.Plan, false)
	proof, e := PresentIssuedGrant(r.SignedGrant, id)
	if e != nil {
		t.Fatal(e)
	}
	l.checkGrant("unconfirmed", p, signed.Grant, proof, 500, "pending", "ISSUANCE_UNCONFIRMED", false)
	l.mine(1)
	l.checkGrant("issued-live", p, signed.Grant, proof, 500, "live", "LIVE", false)
	replay := IssueGrant(context.Background(), nil, ip, req, event, seal, spec, "", 1001)
	requirePrepared(t, replay)
	if !replay.Replay || !bytes.Equal(r.SignedGrant, replay.SignedGrant) || !sameJSON(r.Plan, replay.Plan) {
		t.Fatal("exact replay changed")
	}
	other := l.detachedPool(1, true)
	changed := IssueGrant(context.Background(), l.observer, ip, req, event, other, spec, key, 500)
	if changed.Reason != "ISSUANCE_CONFLICT" || len(changed.SignedGrant) != 0 {
		t.Fatal("booking changed", changed)
	}
	_, req2, event2, key2, spec2 := l.grantIssueInputs(p, "two", true)
	reused := IssueGrant(context.Background(), l.observer, ip, req2, event2, seal, spec2, key2, 500)
	if reused.Reason != "POOL_ALREADY_RESERVED" || len(reused.SignedGrant) != 0 {
		t.Fatal("seal reuse", reused)
	}
	requirePrepared(t, IssueGrant(context.Background(), l.observer, ip, req2, event2, other, spec2, key2, 500))
	l.checkGrant("expiry-no-tx", p, signed.Grant, proof, 1000, "refused", "EXPIRED", false)
}

// Real node observations and invalid authenticated input paths refuse before
// any booking/pool burn. A repaired issuance succeeds after each denial.
func TestCoreGrantIssuerDenials(t *testing.T) {
	l := newCore(t)
	l.grantIdentity()
	for _, mode := range []string{"mempool-payment", "expired-hold", "bad-package", "key-mode", "wrong-key", "funding-value", "funding-role", "seal-as-input", "pool-unconfirmed", "funding-spent"} {
		t.Run(mode, func(t *testing.T) {
			// Regtest names expire after 30 blocks; renew unchanged bindings so
			// later rows still exercise their intended issuer guard.
			l.agentPointer(labLandlord, 3, true)
			l.landlordKey(1, true)
			seal := l.detachedPool(1, true)
			p, _, _ := l.grantFixture(mode, seal, 2)
			ip, req, event, key, spec := l.grantIssueInputs(p, mode, mode != "mempool-payment")
			at := int64(500)
			badSpec := spec
			badSpec.Inputs = append([]su.PlanInput(nil), spec.Inputs...)
			badEvent := event
			want := ""
			switch mode {
			case "mempool-payment":
				want = "payment_unconfirmed"
			case "expired-hold":
				at = 900
				want = "hold_expired_at_admission"
			case "bad-package":
				badEvent = []byte(`{}`)
				want = "PACKAGE_EVENT"
			case "key-mode":
				if e := os.Chmod(key, 0644); e != nil {
					t.Fatal(e)
				}
				want = "KEY_FILE"
			case "wrong-key":
				k, _ := testKey(3)
				if e := os.WriteFile(key, k.Serialize(), 0600); e != nil {
					t.Fatal(e)
				}
				want = "KEY_PIN"
			case "funding-value":
				badSpec.Inputs[0].ValueSat++
				want = "FUNDING_BINDING"
			case "funding-role":
				badSpec.Inputs[0].Role = "seal"
				want = "ISSUANCE_FUNDING"
			case "seal-as-input":
				badSpec.Inputs[0].Point = su.Point{TxID: seal.TxID, Vout: seal.Vout}
				want = "ISSUANCE_SPENDS_SEAL"
			case "pool-unconfirmed":
				seal = l.detachedPool(1, false)
				want = "POOL_UNCONFIRMED"
			case "funding-spent":
				in := spec.Inputs[0].Point
				l.revokeDetached(Point{in.TxID, in.Vout}, false)
				want = "FUNDING_SPENT"
			}
			r := IssueGrant(context.Background(), l.observer, ip, req, badEvent, seal, badSpec, key, at)
			l.save(mode+"-denied.json", r)
			if r.Verdict != "refused" || r.Reason != want || len(r.SignedGrant) != 0 || r.Plan != nil {
				t.Fatalf("want %s got %+v", want, r)
			}
			assertNoIssuerBurn(t, p.StateDir)
			k, _ := testKey(1)
			if e := os.Chmod(key, 0600); e != nil {
				t.Fatal(e)
			}
			if e := os.WriteFile(key, k.Serialize(), 0600); e != nil {
				t.Fatal(e)
			}
			if mode == "mempool-payment" || mode == "pool-unconfirmed" {
				l.mine(1)
			}
			if mode == "funding-spent" {
				fund := l.detachedPool(7, true)
				spec.Inputs[0].Point = su.Point{TxID: fund.TxID, Vout: fund.Vout}
			}
			requirePrepared(t, IssueGrant(context.Background(), l.observer, ip, req, event, seal, spec, key, 500))
		})
	}
}

// Child helper exits at a real persistence/signature boundary. It is invoked
// only by the isolated Core crash test and never handles production keys.
func TestGrantIssuerCrashChild(t *testing.T) {
	if os.Getenv("K1_ISSUER_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	root := os.Getenv("K1_ISSUER_INPUT")
	load := func(name string, v any) {
		b, e := os.ReadFile(filepath.Join(root, name))
		if e != nil {
			t.Fatal(e)
		}
		if e = json.Unmarshal(b, v); e != nil {
			t.Fatal(e)
		}
	}
	var p IssuerPolicy
	var route su.Route
	var seal Point
	var spec PlanSpec
	load("policy.json", &p)
	load("route.json", &route)
	load("seal.json", &seal)
	load("spec.json", &spec)
	req, e := os.ReadFile(filepath.Join(root, "request.json"))
	if e != nil {
		t.Fatal(e)
	}
	event, e := os.ReadFile(filepath.Join(root, "event.json"))
	if e != nil {
		t.Fatal(e)
	}
	node, e := su.NewRPC(route)
	if e != nil {
		t.Fatal(e)
	}
	r := issueGrant(context.Background(), node, p, req, event, seal, spec, filepath.Join(root, "grant-key"), 500, func(stage string) {
		if stage == os.Getenv("K1_ISSUER_STAGE") {
			os.Exit(73)
		}
	})
	t.Fatalf("boundary not reached: %s", r.Reason)
}

// Actual child exits after reservation, landlord countersignature and outer
// signature recover uncertain without a second signing attempt; completed
// state returns the exact stored grant/plan. Each has a fresh valid neighbor.
func TestCoreGrantIssuerCrash(t *testing.T) {
	l := newCore(t)
	l.grantIdentity()
	for _, stage := range []string{"reserved", "countersigned", "signed", "complete"} {
		t.Run(stage, func(t *testing.T) {
			seal := l.detachedPool(1, true)
			p, _, _ := l.grantFixture("crash-"+stage, seal, 2)
			ip, req, event, key, spec := l.grantIssueInputs(p, "crash-"+stage, true)
			inputs := filepath.Join(l.private, "crash-"+stage)
			if e := os.Mkdir(inputs, 0700); e != nil {
				t.Fatal(e)
			}
			for name, v := range map[string]any{"policy.json": ip, "route.json": l.route, "seal.json": seal, "spec.json": spec} {
				b, _ := json.Marshal(v)
				if e := os.WriteFile(filepath.Join(inputs, name), b, 0600); e != nil {
					t.Fatal(e)
				}
			}
			k, _ := testKey(1)
			for name, b := range map[string][]byte{"request.json": req, "event.json": event, "grant-key": k.Serialize()} {
				if e := os.WriteFile(filepath.Join(inputs, name), b, 0600); e != nil {
					t.Fatal(e)
				}
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestGrantIssuerCrashChild$")
			cmd.Env = append(os.Environ(), "K1_ISSUER_CHILD=1", "K1_ISSUER_INPUT="+inputs, "K1_ISSUER_STAGE="+stage)
			out, e := cmd.CombinedOutput()
			ee, ok := e.(*exec.ExitError)
			if !ok || ee.ExitCode() != 73 {
				t.Fatalf("child boundary: %v %s", e, out)
			}
			l.rows = append(l.rows, map[string]any{"crash_child_pid": cmd.ProcessState.Pid(), "stage": stage, "exit": 73})
			r := IssueGrant(context.Background(), nil, ip, req, event, seal, spec, key, 500)
			if stage == "complete" {
				requirePrepared(t, r)
				if !r.Replay {
					t.Fatal("missing replay")
				}
			} else if r.Reason != "ISSUANCE_UNCERTAIN" || len(r.SignedGrant) != 0 {
				t.Fatalf("reservation retried: %+v", r)
			}
			l.save(stage+"-recovery.json", r)
			fresh := l.detachedPool(1, true)
			np, _, _ := l.grantFixture("neighbor-"+stage, fresh, 2)
			nip, nreq, nevent, nkey, nspec := l.grantIssueInputs(np, "neighbor-"+stage, true)
			requirePrepared(t, IssueGrant(context.Background(), l.observer, nip, nreq, nevent, fresh, nspec, nkey, 500))
		})
	}
}
