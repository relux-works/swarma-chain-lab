package rental

import (
	"bytes"
	"context"
	"encoding/json"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// A pinned pre-domain c8d7 snapshot issuer really prepares and persists an old
// seal-funded plan against this genuine Core node. The new issuer refuses both
// its original spec and an input-only variant without changing any journal.
// The actual old signed grant also fails the new signing-domain check. Nothing
// from the old plan is broadcast. New separate funding prepares next to it.
func TestCoreGrantLegacyReplay(t *testing.T) {
	if os.Getenv("M1_REGTEST") != "1" {
		t.Skip("explicit genuine Core run required")
	}
	oldPath := os.Getenv("M1_OLD_ISSUER")
	oldBin, e := os.ReadFile(oldPath)
	if e != nil || Hash(oldBin) != "b146c6fa6c80984ebc99784c2ce98470177bfc0476781f6ea7a034ee534a3419" {
		t.Fatal("explicit pinned pre-domain issuer required")
	}
	l := newCore(t)
	l.grantIdentity()
	seal := l.witnessPool(1, true)
	p, _, _ := l.grantFixture("old-replay", seal, 2)
	ip, req, event, key, spec := l.grantIssueInputs(p, "old-replay", true)
	oldFund := l.witnessPool(1, true)
	oldSpec := spec
	oldSpec.Inputs = append([]su.PlanInput{}, spec.Inputs...)
	oldSpec.Inputs[0].Point = su.Point{TxID: oldFund.TxID, Vout: oldFund.Vout}
	oldSpec.Inputs[0].Script = p.SealScript
	oldSpec.ChangeScript = p.SealScript
	// Marshal the exact old policy shape, which has neither new optional field.
	rawPolicy, _ := json.Marshal(ip)
	var policy map[string]json.RawMessage
	if e = json.Unmarshal(rawPolicy, &policy); e != nil {
		t.Fatal(e)
	}
	var fields map[string]json.RawMessage
	if e = json.Unmarshal(policy["policy"], &fields); e != nil {
		t.Fatal(e)
	}
	delete(fields, "construction_profile")
	delete(fields, "funding_script")
	delete(fields, "known_pool_seals")
	policy["policy"], _ = json.Marshal(fields)
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
	reqPath := write("old-request.json", json.RawMessage(req))
	eventPath := write("old-event.json", json.RawMessage(event))
	args := []string{"--policy", write("old-policy.json", policy), "--route", write("old-route.json", l.route), "--request", reqPath, "--package-event", eventPath, "--seal", write("old-seal.json", seal), "--spec", write("old-spec.json", oldSpec), "--grant-key-file", key, "--at", "500"}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, oldPath, args...)
	out, e := cmd.Output()
	if e != nil {
		t.Fatal("old issuer failed", e)
	}
	l.rows = append(l.rows, map[string]any{"old_issuer_pid": cmd.ProcessState.Pid(), "exit": cmd.ProcessState.ExitCode(), "binary_sha256": Hash(oldBin)})
	var result GrantIssueResult
	if json.Unmarshal(out, &result) != nil {
		t.Fatal("old issuer result")
	}
	requirePrepared(t, result)
	if _, e := ParseSignedGrant(result.SignedGrant); e == nil || e.Error() != "GRANT_SIGNATURE" {
		t.Fatal("old actual signature domain", e)
	}
	before := issuerFiles(t, p.StateDir)
	for _, mode := range []string{"old-input-and-change", "old-input-only"} {
		variant := oldSpec
		want := "ISSUANCE_TEMPLATE"
		if mode == "old-input-only" {
			variant.ChangeScript = p.FundingScript
			want = "FUNDING_SEAL_SCRIPT"
		}
		got := IssueGrant(context.Background(), nil, ip, req, event, seal, variant, "", 500)
		if got.Verdict != "refused" || got.Reason != want || got.Plan != nil || len(got.SignedGrant) != 0 {
			t.Fatalf("old real replay accepted: %s/%s", got.Verdict, got.Reason)
		}
		if !reflect.DeepEqual(before, issuerFiles(t, p.StateDir)) {
			t.Fatal("old replay changed journal")
		}
		l.save(mode+".json", got)
	}
	fresh := l.witnessPool(1, true)
	next := ip
	next.Policy.StateDir = l.policy("new-replay").StateDir
	_, nextReq, nextEvent, _, nextSpec := l.grantIssueInputs(next.Policy, "new-replay", true)
	good := IssueGrant(context.Background(), l.observer, next, nextReq, nextEvent, fresh, nextSpec, key, 500)
	requirePrepared(t, good)
	replay := IssueGrant(context.Background(), nil, next, nextReq, nextEvent, fresh, nextSpec, "", 1001)
	requirePrepared(t, replay)
	if !replay.Replay || !bytes.Equal(good.SignedGrant, replay.SignedGrant) || !sameJSON(good.Plan, replay.Plan) {
		t.Fatal("new replay neighbor")
	}
	l.save("legacy-replay-summary.json", map[string]any{"old_snapshot": "c8d7a655be31489a89d1021ef20ee65d5562c216", "old_prepared": true, "old_record_unchanged": true, "old_plan_broadcast": false, "new_replay_exact": true})
}
