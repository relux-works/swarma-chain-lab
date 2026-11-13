package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	wallet "github.com/relux-works/swarma-chain-lab/experiments/agent-wallet"
)

func cliArgs() []string {
	return []string{"--config", "/fixture/service.json", "--target-seq", "1", "--released-sat", "1", "--evidence", "conflict", "--conflict-txid", strings.Repeat("a", 64), "--note", "/fixture/note"}
}

// Claim: privileged overrides/positional modes never call the package adapter.
// The positive syntax neighbor forwards exact fields. These adapter fixtures
// never inspect installed host files; actual DK5 refusal is a separate binary
// rehearsal observation, and package tests cover real journal behavior.
// Regression (cli-prohibited-option-fixture-masking): prohibited options are
// added to a complete valid invocation, independently of missing-field checks.
func TestReconcileCLIArguments(t *testing.T) {
	original, preflight := reconcile, checkInstalled
	t.Cleanup(func() { reconcile = original; checkInstalled = preflight })
	calls := 0
	reconcile = func(_ context.Context, path string, q wallet.ReconcileRequest) (wallet.ReconcileResult, error) {
		calls++
		if path != "/fixture/service.json" || q.TargetSeq != 1 || q.ReleasedSat != 1 || q.Evidence != "conflict" || q.NotePath != "/fixture/note" {
			t.Fatal("CLI_FIELDS", path, q)
		}
		return wallet.ReconcileResult{}, errors.New("DK5_SERVICE_GROUP")
	}
	checkInstalled = func() error { return errors.New("DK5_SERVICE_GROUP") }
	reject := func(t *testing.T, args []string) {
		t.Helper()
		before := calls
		var b bytes.Buffer
		code := run(args, &b)
		if calls != before {
			t.Fatal("CLI_PROHIBITED_REACHED_CUSTODY", args)
		}
		if code != 2 || !strings.Contains(b.String(), `"reason":"CLI_ARGUMENTS"`) || strings.Contains(b.String(), `"record"`) {
			t.Fatal("CLI_OVERRIDE", code, b.String())
		}
	}
	for _, flag := range []string{"now", "rpc", "node", "key", "listen", "state-root"} {
		t.Run("prohibited-"+flag, func(t *testing.T) {
			args := append(cliArgs(), "--"+flag, "123")
			reject(t, args)
		})
	}
	for _, args := range [][]string{{}, {"reconcile"}} {
		reject(t, args)
	}
	for _, flag := range []string{"--config", "--target-seq", "--released-sat", "--note"} {
		t.Run("missing-"+flag, func(t *testing.T) {
			args := cliArgs()
			for i := 0; i < len(args); i += 2 {
				if args[i] == flag {
					args = append(args[:i], args[i+2:]...)
					break
				}
			}
			reject(t, args)
		})
	}
	if calls != 0 {
		t.Fatal("CLI_ARGUMENTS_CALLED_CUSTODY")
	}
	var b bytes.Buffer
	if code := run(cliArgs(), &b); code != 2 || !strings.Contains(b.String(), "DK5_") || calls != 1 {
		t.Fatal("CLI_ADAPTER", code, b.String())
	}
	b.Reset()
	if code := run([]string{"--check-installed"}, &b); code != 2 || !strings.Contains(b.String(), "DK5_") {
		t.Fatal("CLI_PREFLIGHT_EXIT", code, b.String())
	}
}

type brokenOutput struct{}

func (brokenOutput) Write([]byte) (int, error) { return 0, errors.New("write failed") }

// Claim: CLI preserves possible-write exit 4 (including lost output), returns 2
// for a known pre-write refusal, and returns 0 only for a successful adapter.
func TestReconcileCLIExitDisposition(t *testing.T) {
	original := reconcile
	t.Cleanup(func() { reconcile = original })
	for _, c := range []struct {
		write, success bool
		want           int
	}{{false, false, 2}, {true, false, 4}, {true, true, 0}} {
		reconcile = func(context.Context, string, wallet.ReconcileRequest) (wallet.ReconcileResult, error) {
			r := wallet.ReconcileResult{MayHaveWritten: c.write, Verified: c.success}
			if !c.success {
				return r, errors.New("JOURNAL_WRITE_UNCERTAIN")
			}
			return r, nil
		}
		var b bytes.Buffer
		if code := run(cliArgs(), &b); code != c.want {
			t.Fatal("CLI_EXIT_DISPOSITION", code, c.want)
		}
		expected := 2
		if c.write {
			expected = 4
		}
		if code := run(cliArgs(), brokenOutput{}); code != expected {
			t.Fatal("CLI_LOST_OUTPUT", code, expected)
		}
	}
}
