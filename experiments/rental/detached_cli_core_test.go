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
)

// Separate issuer/kernel processes exercise the shipped CLI boundary against
// real Core. Bad key permissions yield no certificate/burn; valid issuance and
// presentation work; wrong id does not replace cache; durable closure survives
// process exit and unavailable Core. Completed issuer replay is byte-identical.
func TestCoreDetachedCLI(t *testing.T) {
	l := newCore(t)
	l.agentValue(1, 3, true)
	seal := l.detachedPool(1, true)
	p, _, _ := l.detached("cli", seal, 2)
	ip, request, event, key := l.detachedIssueInputs(p, "cli", true)
	write := func(name string, value any) string {
		t.Helper()
		b, e := json.Marshal(value)
		if e != nil {
			t.Fatal(e)
		}
		path := filepath.Join(l.private, name)
		if e = os.WriteFile(path, b, 0600); e != nil {
			t.Fatal(e)
		}
		return path
	}
	route := write("route.json", l.route)
	invoke := func(label, env string, want int, argv ...string) []byte {
		t.Helper()
		binary := os.Getenv(env)
		if !filepath.IsAbs(binary) {
			t.Fatal("absolute binary path required", env)
		}
		b, e := os.ReadFile(binary)
		if e != nil {
			t.Fatal(e)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, binary, argv...)
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
			t.Fatalf("CLI %s code%d: %s", label, code, out)
		}
		l.save(label+".json", map[string]any{"output": json.RawMessage(out), "exit": code, "pid": cmd.ProcessState.Pid(), "binary_sha256": Hash(b)})
		return out
	}
	args := []string{"--policy", write("issuer-policy.json", ip), "--route", route, "--request", write("request.json", json.RawMessage(request)), "--package-event", write("event.json", json.RawMessage(event)), "--seal", write("seal.json", seal), "--grant-key-file", key, "--at", "500"}
	if e := os.Chmod(key, 0644); e != nil {
		t.Fatal(e)
	}
	var denied IssueResult
	if json.Unmarshal(invoke("issuer-denied", "M1_ISSUER", 1, args...), &denied) != nil || denied.Reason != "KEY_FILE" || len(denied.Envelope) != 0 {
		t.Fatal("CLI key refusal")
	}
	assertNoIssuerBurn(t, p.StateDir)
	if e := os.Chmod(key, 0600); e != nil {
		t.Fatal(e)
	}
	var issued IssueResult
	if json.Unmarshal(invoke("issuer-issued", "M1_ISSUER", 0, args...), &issued) != nil {
		t.Fatal("CLI issuer result")
	}
	requireIssued(t, issued)
	env, e := ParseDetachedEnvelope(issued.Envelope)
	if e != nil {
		t.Fatal(e)
	}
	check := []string{"present", "--policy", write("policy.json", p), "--route", route, "--certificate", write("certificate.json", issued.Envelope), "--agent", p.AgentName, "--sender", env.Certificate.GranteeKey, "--at", "500", "--id", issued.ID}
	var receipt Receipt
	if json.Unmarshal(invoke("present-live", "M1_KERNEL", 0, check...), &receipt) != nil || receipt.Verdict != "live" {
		t.Fatal("CLI presentation")
	}
	before := cacheBytes(t, p)
	wrong := append([]string(nil), check...)
	wrong[len(wrong)-1] = Hash([]byte("wrong"))
	if json.Unmarshal(invoke("present-wrong-id", "M1_KERNEL", 1, wrong...), &receipt) != nil || receipt.Reason != "PRESENTATION_ID" {
		t.Fatal("CLI presentation id")
	}
	if !bytes.Equal(before, cacheBytes(t, p)) {
		t.Fatal("CLI denial replaced cache")
	}
	l.revokeDetached(seal, false)
	if json.Unmarshal(invoke("present-closed", "M1_KERNEL", 1, check...), &receipt) != nil || !receipt.Closed || receipt.Reason != "SEAL_SPENT" {
		t.Fatal("CLI closure")
	}
	l.stop()
	if json.Unmarshal(invoke("present-durable", "M1_KERNEL", 1, check...), &receipt) != nil || !receipt.Closed || receipt.Calls != 0 {
		t.Fatal("CLI durable closure")
	}
	var replay IssueResult
	if json.Unmarshal(invoke("issuer-replay", "M1_ISSUER", 0, args...), &replay) != nil || !replay.Replay || !bytes.Equal(replay.Envelope, issued.Envelope) {
		t.Fatal("CLI exact replay")
	}
}
