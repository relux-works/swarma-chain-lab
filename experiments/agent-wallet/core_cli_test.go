package wallet

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// A freshly compiled production CLI uses the real clock and actual Core/K1.
// File and stable-ID lookup, exact replay, all six commands and argument/cache/
// config refusals are exercised; no test clock or authority shim enters the CLI.
func TestCoreCLI(t *testing.T) {
	l := newCore(t)
	l.now = time.Now().Unix()
	terms := Terms{Version: 1, Recipients: []string{testAddress(3)}, SpendCap: 1000000, NameCap: DefaultNameBudget, NameCount: 3}
	raw, c := l.grant(terms, []string{"names.register", "pay"}, 4000000)
	bin := filepath.Join(l.private, "agent-wallet")
	build := exec.Command("go", "build", "-trimpath", "-o", bin, "./cmd/agent-wallet")
	if output, e := build.CombinedOutput(); e != nil {
		t.Fatalf("CLI build %v %s", e, output)
	}
	b, e := os.ReadFile(bin)
	if e != nil {
		t.Fatal(e)
	}
	l.save("cli-build.json", map[string]any{"sha256": Hash(b), "clock": "production wall clock", "command": "go build -trimpath -o agent-wallet ./cmd/agent-wallet"})
	config := filepath.Join(l.private, "wallet-config.json")
	grant := filepath.Join(l.public, "grant.json")
	request := filepath.Join(l.public, "request.json")
	id := grantID(t, raw)
	cache := filepath.Join(c.ObjectsDir, id+".json")
	r := testRequest()
	r.GrantID = id
	r.Amount = 100000
	r.FeeLimit = 100000
	write := func(path string, b []byte) {
		t.Helper()
		if e := os.WriteFile(path, b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	write(config, canonical(c))
	write(grant, raw)
	write(cache, raw)
	write(filepath.Join(c.ObjectsDir, Hash(canonical(terms))+".json"), canonical(terms))
	write(request, signRequestAt(t, r, 2, l.now))
	invoke := func(label string, want int, args ...string) json.RawMessage {
		t.Helper()
		cmd := exec.Command(bin, append([]string{"--config", config}, args...)...)
		out, e := cmd.Output()
		exit := 0
		if e != nil {
			if x, ok := e.(*exec.ExitError); ok {
				exit = x.ExitCode()
			} else {
				t.Fatal(e)
			}
		}
		if exit != want || !json.Valid(out) {
			t.Fatalf("%s exit %d want %d output %s", label, exit, want, out)
		}
		l.save(label+".json", map[string]any{"exit_code": exit, "result": json.RawMessage(out)})
		return out
	}
	for _, cmd := range []string{"balance", "receive", "history"} {
		invoke("cli-"+cmd, 0, cmd)
	}
	var budget Budget
	if json.Unmarshal(invoke("cli-budget", 0, "budget", "--grant", id), &budget) != nil || !budget.Live || budget.TotalRemaining != 4000000 {
		t.Fatal("CLI budget")
	}
	var spent Receipt
	if json.Unmarshal(invoke("cli-spend", 0, "spend", "--grant", id, "--request", request), &spent) != nil || spent.Status != "executed" {
		t.Fatalf("CLI spend %+v", spent)
	}
	before, _ := os.ReadFile(filepath.Join(c.StateDir, "wallet.json"))
	pool := string(l.rpc("", "getrawmempool"))
	var replay Receipt
	if json.Unmarshal(invoke("cli-replay", 0, "spend", "--grant", grant, "--request", request), &replay) != nil || replay.Status != "already-executed" || replay.TxID != spent.TxID {
		t.Fatal("CLI replay")
	}
	negative := func(label, reason string, args ...string) {
		t.Helper()
		var got Receipt
		if json.Unmarshal(invoke(label, 2, args...), &got) != nil || got.Status != "refused" || got.Reason != reason {
			t.Fatalf("%s %+v", label, got)
		}
		after, _ := os.ReadFile(filepath.Join(c.StateDir, "wallet.json"))
		if string(before) != string(after) || pool != string(l.rpc("", "getrawmempool")) {
			t.Fatal("CLI refusal changed state/effects")
		}
	}
	negative("cli-command", "CLI_COMMAND", "dump-wallet")
	negative("cli-no-grant", "CLI_ARGUMENTS", "spend", "--request", request)
	negative("cli-action", "CLI_ACTION_MISMATCH", "name-register", "--grant", grant, "--request", request)
	negative("cli-test-clock", "CLI_ARGUMENTS", "spend", "--grant", grant, "--request", request, "--now", "500")
	write(cache, []byte("{}"))
	negative("cli-cache-hash", "OBJECT_HASH", "budget", "--grant", id)
	write(cache, raw)
	if e = os.Chmod(config, 0644); e != nil {
		t.Fatal(e)
	}
	negative("cli-config-mode", "CONFIG_PRIVATE_FILE", "balance")
	if e = os.Chmod(config, 0600); e != nil {
		t.Fatal(e)
	}
	l.mine(1)
	r.Action = "names.register"
	r.Amount = 0
	r.Name = "d/cli-wallet-test"
	r.Value = "cli-fixture"
	r.Nonce = Hash([]byte("cli-name"))
	write(request, signRequestAt(t, r, 2, l.now))
	var name Receipt
	if json.Unmarshal(invoke("cli-name-pending", 3, "name-register", "--grant", id, "--request", request), &name) != nil || name.Phase != "name-new-sent" {
		t.Fatalf("CLI name pending %+v", name)
	}
	l.mine(12)
	if json.Unmarshal(invoke("cli-name-complete", 0, "name-register", "--grant", id, "--request", request), &name) != nil || name.Status != "executed" {
		t.Fatalf("CLI name %+v", name)
	}
}
