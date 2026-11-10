package rental

import (
	"bytes"
	"context"
	"encoding/json"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func issuerFiles(t *testing.T, root string) map[string]string {
	t.Helper()
	entries, e := os.ReadDir(root)
	if e != nil {
		t.Fatal(e)
	}
	out := map[string]string{}
	for _, entry := range entries {
		if entry.Name() == "rental.lock" {
			continue
		}
		b, e := os.ReadFile(filepath.Join(root, entry.Name()))
		if e != nil {
			t.Fatal(e)
		}
		out[entry.Name()] = Hash(b)
	}
	return out
}
func testPoolFile(p Policy, point Point) string {
	b, _ := json.Marshal(struct {
		Network, Genesis string
		Point            Point
	}{p.Network, p.Genesis, point})
	return filepath.Join(p.StateDir, "pool-"+Hash(b)+".json")
}

// A genuinely live first grant's seal cannot fund a second grant, whether it is
// the first or a later input. Refusal emits no signed plan, changes no journal,
// and leaves the first grant live. Ordinary funds prepare beside each refusal.
// Any reservation bytes (including interrupted/corrupt state) deny funding.
func TestCoreGrantReservedFunding(t *testing.T) {
	l := newCore(t)
	l.grantIdentity()
	ctx := context.Background()
	sealA := l.witnessPool(1, true)
	p, _, _ := l.grantFixture("reserved-funding", sealA, 2)
	ip, reqA, eventA, key, specA := l.grantIssueInputs(p, "first", true)
	reqA, eventA = scopePackage(t, reqA, eventA, []string{"deliver", "names.register", "pay"}, []string{"publish", "repository.push", "secret.release"})
	first := IssueGrant(ctx, l.observer, ip, reqA, eventA, sealA, specA, key, 500)
	requirePrepared(t, first)
	id := l.sendPlan(*first.Plan, true)
	proof, e := PresentIssuedGrant(first.SignedGrant, id)
	if e != nil {
		t.Fatal(e)
	}
	signed, e := ParseSignedGrant(first.SignedGrant)
	if e != nil {
		t.Fatal(e)
	}
	l.checkGrant("first-live", p, signed.Grant, proof, 500, "live", "LIVE", false)
	sealB := l.witnessPool(1, true)
	_, reqB, eventB, _, specB := l.grantIssueInputs(p, "second", true)
	// A forged funding-script assertion must not hide a reserved outpoint.
	reserved := su.PlanInput{Point: su.Point{TxID: sealA.TxID, Vout: sealA.Vout}, ValueSat: 1000000, Script: p.FundingScript, Role: "funding"}
	for _, mode := range []string{"first-input", "later-input", "corrupt-reservation"} {
		t.Run(mode, func(t *testing.T) {
			badSpec := specB
			badSpec.Inputs = []su.PlanInput{reserved}
			if mode == "later-input" {
				badSpec.Inputs = append(append([]su.PlanInput{}, specB.Inputs...), reserved)
			}
			var original []byte
			path := testPoolFile(p, sealA)
			if mode == "corrupt-reservation" {
				original, e = os.ReadFile(path)
				if e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(path, []byte("{interrupted"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			before := issuerFiles(t, p.StateDir)
			r := IssueGrant(ctx, l.observer, ip, reqB, eventB, sealB, badSpec, key, 500)
			l.save(mode+"-reserved-refusal.json", r)
			if r.Verdict != "refused" || r.Reason != "FUNDING_RESERVED_POOL" || len(r.SignedGrant) != 0 || r.Plan != nil {
				t.Fatalf("reserved funding accepted: %+v", r)
			}
			if !reflect.DeepEqual(before, issuerFiles(t, p.StateDir)) {
				t.Fatal("reserved funding changed issuer journal")
			}
			if mode == "corrupt-reservation" {
				if e = os.WriteFile(path, original, 0600); e != nil {
					t.Fatal(e)
				}
			}
			l.checkGrant(mode+"-first-still-live", p, signed.Grant, proof, 500, "live", "LIVE", false)
		})
	}
	second := IssueGrant(ctx, l.observer, ip, reqB, eventB, sealB, specB, key, 500)
	requirePrepared(t, second)
	l.save("ordinary-funding-neighbor.json", second)
	// Defence in depth: even inconsistent recovered reservation bytes burn a
	// funding point. The separate-script rule prevents a legitimate new seal
	// from being created at this funding address, so inject only private state.
	fundB := Point{specB.Inputs[0].Point.TxID, specB.Inputs[0].Point.Vout}
	if e := os.WriteFile(testPoolFile(p, fundB), []byte("{interrupted"), 0600); e != nil {
		t.Fatal(e)
	}
	before := issuerFiles(t, p.StateDir)
	replay := IssueGrant(ctx, nil, ip, reqB, eventB, sealB, specB, "", 1001)
	l.save("reserved-funding-replay-refusal.json", replay)
	if replay.Verdict != "refused" || replay.Reason != "FUNDING_RESERVED_POOL" || len(replay.SignedGrant) != 0 || replay.Plan != nil {
		t.Fatalf("reserved replay accepted: %+v", replay)
	}
	if !reflect.DeepEqual(before, issuerFiles(t, p.StateDir)) {
		t.Fatal("reserved replay changed journal")
	}
	replayFirst := IssueGrant(ctx, nil, ip, reqA, eventA, sealA, specA, "", 1001)
	requirePrepared(t, replayFirst)
	if !replayFirst.Replay || !bytes.Equal(first.SignedGrant, replayFirst.SignedGrant) || !sameJSON(first.Plan, replayFirst.Plan) {
		t.Fatal("ordinary replay neighbor")
	}
	l.checkGrant("final-first-still-live", p, signed.Grant, proof, 500, "live", "LIVE", false)
}

// A fresh, unreserved output explicitly assigned to the trusted pool inventory
// is rejected even if its input spec lies about the script. No journal is
// created on refusal; a separate funding-key output prepares and replays.
func TestCoreGrantKnownPoolFunding(t *testing.T) {
	l := newCore(t)
	l.grantIdentity()
	seal := l.witnessPool(1, true)
	p, _, _ := l.grantFixture("known-pool", seal, 2)
	ip, req, event, key, spec := l.grantIssueInputs(p, "known-pool", true)
	known := l.witnessPool(1, true)
	ip.Policy.KnownPoolSeals = []Point{seal, known}
	badSpec := spec
	badSpec.Inputs = append([]su.PlanInput{}, spec.Inputs...)
	badSpec.Inputs[0].Point = su.Point{TxID: known.TxID, Vout: known.Vout}
	before := issuerFiles(t, p.StateDir)
	r := IssueGrant(context.Background(), l.observer, ip, req, event, seal, badSpec, key, 500)
	l.save("known-unreserved-refusal.json", r)
	if r.Verdict != "refused" || r.Reason != "FUNDING_KNOWN_POOL" || len(r.SignedGrant) != 0 || r.Plan != nil {
		t.Fatalf("known pool funding accepted: %s/%s", r.Verdict, r.Reason)
	}
	if !reflect.DeepEqual(before, issuerFiles(t, p.StateDir)) {
		t.Fatal("known pool refusal changed journal")
	}
	good := IssueGrant(context.Background(), l.observer, ip, req, event, seal, spec, key, 500)
	requirePrepared(t, good)
	if _, e := MakeGrantIssuancePlan(ip.Policy, badSpec, good.SignedGrant); e == nil || e.Error() != "FUNDING_KNOWN_POOL" {
		t.Fatal("offline known pool funding", e)
	}
	replay := IssueGrant(context.Background(), nil, ip, req, event, seal, spec, "", 1001)
	requirePrepared(t, replay)
	if !replay.Replay || !sameJSON(good.Plan, replay.Plan) {
		t.Fatal("known pool ordinary neighbor")
	}
	ip.Policy.KnownPoolSeals = append(ip.Policy.KnownPoolSeals, Point{spec.Inputs[0].Point.TxID, spec.Inputs[0].Point.Vout})
	before = issuerFiles(t, p.StateDir)
	replay = IssueGrant(context.Background(), nil, ip, req, event, seal, spec, "", 1001)
	if replay.Reason != "FUNDING_KNOWN_POOL" || replay.Plan != nil || len(replay.SignedGrant) != 0 {
		t.Fatal("new inventory ignored at replay")
	}
	if !reflect.DeepEqual(before, issuerFiles(t, p.StateDir)) {
		t.Fatal("known pool replay changed journal")
	}
}
