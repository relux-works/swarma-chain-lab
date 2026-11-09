package rental

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// Separate shipped CLI processes prepare, plan and present v3, require a
// confirmed commitment, reject v2/default and mainnet before reading a route,
// and retain closure and exact replay after the node exits.
func TestCoreGrantCLI(t *testing.T) {
	l := newCore(t)
	l.grantIdentity()
	seal := l.detachedPool(1, true)
	p, _, _ := l.grantFixture("cli", seal, 2)
	ip, request, event, key, spec := l.grantIssueInputs(p, "cli", true)
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
	invoke := func(label, env string, want int, args ...string) []byte {
		t.Helper()
		bin := os.Getenv(env)
		if !filepath.IsAbs(bin) {
			t.Fatal("absolute binary required", env)
		}
		binary, e := os.ReadFile(bin)
		if e != nil {
			t.Fatal(e)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, bin, args...)
		out, e := cmd.Output()
		code := 0
		if e != nil {
			if ee, ok := e.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else {
				t.Fatal(e)
			}
		}
		if code != want || !json.Valid(out) {
			t.Fatalf("CLI %s exit %d: %s", label, code, out)
		}
		l.save(label+".json", map[string]any{"output": json.RawMessage(out), "exit": code, "pid": cmd.ProcessState.Pid(), "binary_sha256": Hash(binary)})
		return out
	}
	route := write("route.json", l.route)
	policy := write("issuer-policy.json", ip)
	funding := write("funding.json", spec)
	args := []string{"--policy", policy, "--route", route, "--request", write("request.json", json.RawMessage(request)), "--package-event", write("event.json", json.RawMessage(event)), "--seal", write("seal.json", seal), "--spec", funding, "--grant-key-file", key, "--at", "500"}
	if e := os.Chmod(key, 0644); e != nil {
		t.Fatal(e)
	}
	var issued GrantIssueResult
	if json.Unmarshal(invoke("issuer-denied", "M1_ISSUER", 1, args...), &issued) != nil || issued.Reason != "KEY_FILE" || len(issued.SignedGrant) != 0 {
		t.Fatal("CLI key denial", issued)
	}
	assertNoIssuerBurn(t, p.StateDir)
	if e := os.Chmod(key, 0600); e != nil {
		t.Fatal(e)
	}
	if json.Unmarshal(invoke("issuer-prepared", "M1_ISSUER", 0, args...), &issued) != nil {
		t.Fatal("CLI issuer JSON")
	}
	requirePrepared(t, issued)
	var plan Plan
	planArgs := []string{"grant-issue", "--policy", policy, "--spec", funding, "--grant", write("signed-grant.json", issued.SignedGrant)}
	if json.Unmarshal(invoke("plan", "M1_PLANNER", 0, planArgs...), &plan) != nil || !sameJSON(plan, *issued.Plan) {
		t.Fatal("CLI plan mismatch")
	}
	id := l.sendPlan(plan, false)
	proof, e := PresentIssuedGrant(issued.SignedGrant, id)
	if e != nil {
		t.Fatal(e)
	}
	signed, e := ParseSignedGrant(issued.SignedGrant)
	if e != nil {
		t.Fatal(e)
	}
	check := []string{"present", "--policy", write("policy.json", p), "--route", route, "--grant", write("presentation.json", json.RawMessage(proof)), "--agent", p.AgentName, "--sender", signed.Grant.GranteeKey, "--at", "500", "--id", issued.GrantID}
	var receipt Receipt
	verify := func(label string, code int, reason string) {
		t.Helper()
		if json.Unmarshal(invoke(label, "M1_KERNEL", code, check...), &receipt) != nil || receipt.Reason != reason {
			t.Fatal("CLI receipt", label, receipt)
		}
	}
	verify("pending", 2, "ISSUANCE_UNCONFIRMED")
	l.mine(1)
	verify("live", 0, "LIVE")
	if receipt.GrantID != issued.GrantID || receipt.AgentName != p.AgentName || receipt.LandlordName != p.LandlordName || receipt.CertificateSHA256 != "" || receipt.StationName != "" {
		t.Fatal("v3 receipt mapping")
	}
	legacy := signDetachedTest(t, testDetached(), 1)
	bad := []string{"check", "--policy", write("policy.json", p), "--route", route, "--grant", write("v2.json", json.RawMessage(legacy)), "--agent", p.AgentName, "--sender", signed.Grant.GranteeKey, "--at", "500"}
	if json.Unmarshal(invoke("v2-default-refused", "M1_KERNEL", 1, bad...), &receipt) != nil || receipt.Reason != "CANONICAL_ENCODING" {
		t.Fatal("CLI default accepted v2")
	}
	main := p
	main.Network = "main"
	main.Genesis = su.MainGenesis
	if json.Unmarshal(invoke("mainnet-refused", "M1_KERNEL", 1, "check", "--policy", write("main-policy.json", main), "--route", "absent-route"), &receipt) != nil || receipt.Reason != "REGTEST_ONLY" {
		t.Fatal("CLI mainnet guard")
	}
	l.revokeDetached(seal, false)
	verify("closed", 1, "SEAL_SPENT")
	l.stop()
	verify("durable", 1, "SEAL_SPENT")
	if !receipt.Closed || receipt.Calls != 0 {
		t.Fatal("CLI durable closure")
	}
	var replay GrantIssueResult
	if json.Unmarshal(invoke("replay", "M1_ISSUER", 0, args...), &replay) != nil || !replay.Replay || !bytes.Equal(replay.SignedGrant, issued.SignedGrant) || !sameJSON(replay.Plan, issued.Plan) {
		t.Fatal("CLI exact replay")
	}
}
