package main

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"os"
	"time"

	wallet "github.com/relux-works/swarma-chain-lab/experiments/agent-wallet"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/configguard"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout)) }

// Only package tests replace these adapters; no flag/config/env selects them.
var reconcile = wallet.ReconcileWallet
var checkInstalled = func() error { _, e := configguard.ServiceSet("wallet"); return e }

func run(args []string, out io.Writer) int {
	f := flag.NewFlagSet("agent-wallet-reconcile", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	config := f.String("config", "", "installed service config")
	q := wallet.ReconcileRequest{}
	f.Uint64Var(&q.TargetSeq, "target-seq", 0, "reserve sequence")
	f.Int64Var(&q.ReleasedSat, "released-sat", 0, "positive retained debit release")
	f.StringVar(&q.Evidence, "evidence", "", "conflict only")
	f.StringVar(&q.ConflictTxID, "conflict-txid", "", "confirmed conflicting spender")
	f.StringVar(&q.NotePath, "note", "", "owner-only public operator note")
	emit := func(result wallet.ReconcileResult, reason string, code int) int {
		reply := struct {
			wallet.ReconcileResult
			Reason string `json:"reason"`
		}{result, reason}
		if json.NewEncoder(out).Encode(reply) != nil {
			if result.MayHaveWritten {
				return 4
			}
			return 2
		}
		return code
	}
	if len(args) == 1 && args[0] == "--check-installed" {
		if e := checkInstalled(); e != nil {
			return emit(wallet.ReconcileResult{}, wallet.ActionErrorReason(e), 2)
		}
		return emit(wallet.ReconcileResult{}, "INSTALLED_OK", 0)
	}
	if f.Parse(args) != nil || f.NArg() != 0 || *config == "" || q.TargetSeq == 0 || q.ReleasedSat < 1 || q.NotePath == "" {
		return emit(wallet.ReconcileResult{}, "CLI_ARGUMENTS", 2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	result, e := reconcile(ctx, *config, q)
	if e != nil {
		code := 2
		if result.MayHaveWritten {
			code = 4
		}
		return emit(result, wallet.ActionErrorReason(e), code)
	}
	return emit(result, "RECONCILED", 0)
}
