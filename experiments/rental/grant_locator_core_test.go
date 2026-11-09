package rental

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// Genuine isolated Core confirms the actual issuer's frame before live. Each
// malformed transaction is mined, refused without a closure, and followed by
// the same valid proof. Bare legacy and Memo are distinguished by script shape.
func TestCoreGrantLocator(t *testing.T) {
	l := newCore(t)
	l.grantIdentity()
	seal := l.detachedPool(1, true)
	p, _, _ := l.grantFixture("locator", seal, 2)
	ip, req, event, key, spec := l.grantIssueInputs(p, "locator", true)
	r := IssueGrant(context.Background(), l.observer, ip, req, event, seal, spec, key, 500)
	requirePrepared(t, r)
	good := framedGrantScript(t, r.SignedGrant)
	if r.Plan.Outputs[0].Script != hex.EncodeToString(good) || len(good) != 72 {
		t.Fatal("issuer did not emit exact frame")
	}
	l.save("prepared-frame.json", r)
	signed, _ := ParseSignedGrant(r.SignedGrant)
	proof, e := PresentIssuedGrant(r.SignedGrant, l.sendPlan(*r.Plan, false))
	if e != nil {
		t.Fatal(e)
	}
	l.checkGrant("frame-pending", p, signed.Grant, proof, 500, "pending", "ISSUANCE_UNCONFIRMED", false)
	l.mine(1)
	l.checkGrant("frame-live", p, signed.Grant, proof, 500, "live", "LIVE", false)
	for _, mode := range []string{"legacy", "header_pd1", "header_pd2", "header_pd4", "payload_pd1", "payload_pd2", "payload_pd4", "split_id", "op1", "op16", "extra_push", "trailing", "length", "short", "action", "version", "location", "pointer", "commitment", "memo", "two_returns"} {
		t.Run(mode, func(t *testing.T) {
			l.agentPointer(labLandlord, 3, true)
			l.landlordKey(1, true)
			plan := l.grantPlan(p, r.SignedGrant)
			b := bytes.Clone(good)
			switch mode {
			case "legacy":
				b = append([]byte{0x6a, 32}, good[7:39]...)
			case "header_pd1":
				b = append([]byte{0x6a, 0x4c, 3}, good[2:]...)
			case "header_pd2":
				b = append([]byte{0x6a, 0x4d, 3, 0}, good[2:]...)
			case "header_pd4":
				b = append([]byte{0x6a, 0x4e, 3, 0, 0, 0}, good[2:]...)
			case "payload_pd1":
				b = append(append(bytes.Clone(good[:5]), 0x4c, 66), good[6:]...)
			case "payload_pd2":
				b = append(append(bytes.Clone(good[:5]), 0x4d, 66, 0), good[6:]...)
			case "payload_pd4":
				b = append(append(bytes.Clone(good[:5]), 0x4e, 66, 0, 0, 0), good[6:]...)
			case "split_id":
				b = append([]byte{0x6a, 1, 0x53, 1, 0x4c, 1}, good[4:]...)
			case "op1":
				b[5] = 0x51
			case "op16":
				b[5] = 0x60
			case "extra_push":
				b = append(b, 1, 0)
			case "trailing":
				b = append(b, 0)
			case "length":
				b[5]--
			case "short":
				b = b[:len(b)-1]
				b[5]--
			case "action":
				b[4] = 3
			case "version":
				b[6] = 2
			case "location":
				b[39] = 5
			case "pointer":
				b[40] ^= 1
			case "commitment":
				b[7] ^= 1
			case "memo":
				b = []byte{0x6a, 2, 0x6d, 2, 1, 'x'}
			case "two_returns":
				plan.Outputs = append(plan.Outputs, su.PlanOutput{Script: "6a026d02", Role: "memo"})
			}
			plan.Outputs[0].Script = hex.EncodeToString(b)
			candidate, e := PresentIssuedGrant(r.SignedGrant, l.sendPlan(plan, true))
			if e != nil {
				t.Fatal(e)
			}
			fresh := p
			fresh.StateDir = l.policy("locator-" + mode).StateDir
			want, reason := "refused", "ISSUANCE_COMMITMENT"
			if mode == "legacy" {
				want, reason = "live", "LIVE"
			}
			l.checkGrant(mode, fresh, signed.Grant, candidate, 500, want, reason, false)
			l.checkGrant(mode+"-neighbor", fresh, signed.Grant, proof, 500, "live", "LIVE", false)
		})
	}
}

// The real pre-L5 issuer prepares an old completed record at the old minimum
// funding boundary. New code replays identical bytes with no node/key access;
// a corrupt plan refuses without writes. Fresh issuance rejects the old budget
// before any reservation/signature, beside a fully funded framed issuance.
func TestCoreGrantLocatorReplay(t *testing.T) {
	if os.Getenv("M1_REGTEST") != "1" {
		t.Skip("explicit genuine Core run required")
	}
	oldPath := os.Getenv("L5_OLD_ISSUER")
	oldBin, e := os.ReadFile(oldPath)
	if e != nil || Hash(oldBin) != "ec0ea6d732aaba05069ee35dc3ff70ff5c9f4a84e6980ef51bf92ba7f950f664" {
		t.Fatal("pinned pre-L5 issuer required")
	}
	l := newCore(t)
	l.grantIdentity()
	seal := l.detachedPool(1, true)
	p, _, raw := l.grantFixture("locator-replay", seal, 2)
	ip, req, event, key, spec := l.grantIssueInputs(p, "locator-replay", true)
	projection, e := MakeGrantIssuancePlan(p, spec, raw)
	if e != nil {
		t.Fatal(e)
	}
	value := projection.FeeSat - 38*200 + 1000
	// Split an actual confirmed funding output, retaining the same owner script.
	funding := Plan{TransactionVersion: 2, Inputs: spec.Inputs, Outputs: []su.PlanOutput{{ValueSat: value, Script: p.FundingScript}, {ValueSat: 1000000 - value - 100000, Script: p.FundingScript}}}
	txid := l.sendPlan(funding, true)
	spec.Inputs = append([]su.PlanInput{}, spec.Inputs...)
	spec.Inputs[0].Point = su.Point{TxID: txid, Vout: 0}
	spec.Inputs[0].ValueSat = value
	l.rpc("issuer", "lockunspent", false, []Point{{TxID: txid, Vout: 0}})
	write := func(name string, v any) string {
		t.Helper()
		b, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		path := filepath.Join(l.private, name)
		if e = os.WriteFile(path, b, 0600); e != nil {
			t.Fatal(e)
		}
		return path
	}
	args := []string{"--policy", write("old-policy.json", ip), "--route", write("old-route.json", l.route), "--request", write("old-request.json", json.RawMessage(req)), "--package-event", write("old-event.json", json.RawMessage(event)), "--seal", write("old-seal.json", seal), "--spec", write("old-spec.json", spec), "--grant-key-file", key, "--at", "500"}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, oldPath, args...)
	out, e := cmd.Output()
	if e != nil {
		t.Fatal("old issuer failed", e)
	}
	l.rows = append(l.rows, map[string]any{"old_issuer_pid": cmd.ProcessState.Pid(), "exit": cmd.ProcessState.ExitCode(), "binary_sha256": Hash(oldBin)})
	var old GrantIssueResult
	if json.Unmarshal(out, &old) != nil {
		t.Fatal("old issuer result")
	}
	requirePrepared(t, old)
	signed, e := ParseSignedGrant(old.SignedGrant)
	if e != nil {
		t.Fatal(e)
	}
	commit, _ := IssuanceCommitment(signed)
	if old.Plan.Outputs[0].Script != "6a20"+commit || old.Plan.Outputs[1].ValueSat != 1000 {
		t.Fatal("historical issuer boundary fixture")
	}
	l.save("old-prepared.json", old)
	before := issuerFiles(t, p.StateDir)
	replay := func() GrantIssueResult {
		return IssueGrant(context.Background(), nil, ip, req, event, seal, spec, "", 1001)
	}
	assertReplay := func() {
		t.Helper()
		r := replay()
		requirePrepared(t, r)
		if !r.Replay || r.Reason != "EXACT_GRANT_REPLAY" || !bytes.Equal(r.SignedGrant, old.SignedGrant) || !sameJSON(r.Plan, old.Plan) || !reflect.DeepEqual(before, issuerFiles(t, p.StateDir)) {
			t.Fatal("historical replay changed bytes or journal")
		}
		l.save("old-exact-replay.json", r)
	}
	assertReplay()
	files, e := filepath.Glob(filepath.Join(p.StateDir, "issued-grant-*.json"))
	if e != nil || len(files) != 1 {
		t.Fatal("historical record absent")
	}
	original, e := os.ReadFile(files[0])
	if e != nil {
		t.Fatal(e)
	}
	var record issuedGrant
	if json.Unmarshal(original, &record) != nil {
		t.Fatal("historical record encoding")
	}
	record.Plan.Outputs[0].Script += "00"
	bad, _ := json.Marshal(record)
	if e = os.WriteFile(files[0], bad, 0600); e != nil {
		t.Fatal(e)
	}
	corruptBefore := issuerFiles(t, p.StateDir)
	denied := replay()
	if denied.Verdict != "refused" || denied.Reason != "ISSUANCE_JOURNAL_CORRUPT" || denied.Plan != nil || len(denied.SignedGrant) != 0 || !reflect.DeepEqual(corruptBefore, issuerFiles(t, p.StateDir)) {
		t.Fatal("corrupt completed record escaped replay gate")
	}
	l.save("corrupt-replay-refused.json", denied)
	if e = os.WriteFile(files[0], original, 0600); e != nil {
		t.Fatal(e)
	}
	assertReplay()
	legacyProof, e := PresentIssuedGrant(old.SignedGrant, l.sendPlan(*old.Plan, true))
	if e != nil {
		t.Fatal(e)
	}
	l.checkGrant("historical-live", p, signed.Grant, legacyProof, 500, "live", "LIVE", false)
	fresh := l.detachedPool(1, true)
	np, _, _ := l.grantFixture("locator-fresh", fresh, 2)
	nip, nr, ne, nk, ns := l.grantIssueInputs(np, "locator-fresh", true)
	tooSmall := ns
	tooSmall.Inputs = append([]su.PlanInput{}, ns.Inputs...)
	tooSmall.Inputs[0].ValueSat = value
	denied = IssueGrant(context.Background(), nil, nip, nr, ne, fresh, tooSmall, "", 500)
	if denied.Reason != "FUNDING_OR_DUST_RESERVE" || denied.Verdict != "refused" || denied.Plan != nil || len(denied.SignedGrant) != 0 {
		t.Fatal("fresh fee boundary passed pre-sign gate")
	}
	assertNoIssuerBurn(t, np.StateDir)
	good := IssueGrant(context.Background(), l.observer, nip, nr, ne, fresh, ns, nk, 500)
	requirePrepared(t, good)
	if good.Plan.Outputs[0].Script != hex.EncodeToString(framedGrantScript(t, good.SignedGrant)) {
		t.Fatal("fresh replay neighbor is not framed")
	}
	l.save("fresh-frame-neighbor.json", good)
}
