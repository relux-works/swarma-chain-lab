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
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/durable"
)

type delayedNode struct {
	base su.Node
	done bool
}

func (n *delayedNode) Call(ctx context.Context, m string, args ...any) (json.RawMessage, error) {
	if !n.done {
		n.done = true
		time.Sleep(1100 * time.Millisecond)
	}
	return n.base.Call(ctx, m, args...)
}

// A failed read does not close or rewrite an accepted grant. Lock contention,
// corrupt state and clock expiry during observation refuse; recovery with the
// original state remains live. All corruption is confined to this test's root.
func TestCoreStateBoundaries(t *testing.T) {
	l := newCore(t)
	p, c, raw, _ := l.fixture("state")
	l.check("state-live", l.observer, p, raw, c.GranteePubkey, 500, "live", "LIVE", false)
	path := filepath.Join(p.StateDir, "certificate-"+Hash(raw)+".json")
	before, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	l.check("read-failure-after-live", unavailableNode{}, p, raw, c.GranteePubkey, 500, "refused", "NODE_UNAVAILABLE", false)
	after, e := os.ReadFile(path)
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("failed read changed state")
	}
	lock, e := durable.Open(p.StateDir, "rental.lock")
	if e != nil {
		t.Fatal(e)
	}
	l.check("state-busy", l.observer, p, raw, c.GranteePubkey, 500, "refused", "STATE_BUSY", false)
	lock.Close()
	if e = os.WriteFile(path, []byte(`{"version":2}`), 0600); e != nil {
		t.Fatal(e)
	}
	l.check("state-corrupt", l.observer, p, raw, c.GranteePubkey, 500, "refused", "JOURNAL_CORRUPT", false)
	if e = os.WriteFile(path, before, 0600); e != nil {
		t.Fatal(e)
	}
	l.check("state-recovered", l.observer, p, raw, c.GranteePubkey, 500, "live", "LIVE", false)
	fresh := l.policy("time-crossing")
	l.check("expiry-during-read", &delayedNode{base: l.observer}, fresh, raw, c.GranteePubkey, 999, "refused", "EXPIRED", false)
	noCertificateRecord(t, fresh)
	l.check("time-neighbor", l.observer, fresh, raw, c.GranteePubkey, 500, "live", "LIVE", false)
	l.save("state-result.json", map[string]any{"status": "PASS", "read_failure_preserved_state": true, "corrupt_lock_and_expiry_denied": true})
}

// Separate CLI processes exercise exact public-file loading and persistent
// closure across process exit. Route credentials remain only in private/.
func TestCoreCLI(t *testing.T) {
	l := newCore(t)
	binary := os.Getenv("M1_KERNEL")
	if !filepath.IsAbs(binary) {
		t.Fatal("absolute M1_KERNEL required")
	}
	b, e := os.ReadFile(binary)
	if e != nil {
		t.Fatal(e)
	}
	p, c, raw, pool := l.fixture("cli")
	write := func(name string, b []byte) string {
		t.Helper()
		path := filepath.Join(l.private, name)
		if e := os.WriteFile(path, b, 0600); e != nil {
			t.Fatal(e)
		}
		return path
	}
	pb, _ := json.Marshal(p)
	rb, _ := json.Marshal(l.route)
	policyPath := write("policy.json", pb)
	routePath := write("route.json", rb)
	certPath := write("certificate.json", raw)
	invoke := func(label string, want int, reason string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, binary, "check-legacy", "--policy", policyPath, "--route", routePath, "--certificate", certPath, "--station", l.station, "--sender", c.GranteePubkey, "--at", "500")
		out, e := cmd.Output()
		code := 0
		if e != nil {
			if ee, ok := e.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else {
				t.Fatal(e)
			}
		}
		var r Receipt
		if json.Unmarshal(out, &r) != nil || code != want || r.Reason != reason {
			t.Fatalf("CLI %s code%d: %s", label, code, out)
		}
		l.save(label+".json", map[string]any{"receipt": r, "pid": cmd.ProcessState.Pid(), "exit": code, "binary_sha256": Hash(b)})
		if reason == "SEAL_SPENT" && !r.Closed {
			t.Fatal("not closed")
		}
	}
	invoke("cli-live", 0, "LIVE")
	l.revoke(pool, false)
	invoke("cli-close", 1, "SEAL_SPENT")
	l.stop()
	invoke("cli-restart-no-node", 1, "SEAL_SPENT")
	l.save("cli-result.json", map[string]any{"status": "PASS", "separate_processes": true, "binary_sha256": Hash(b)})
}
