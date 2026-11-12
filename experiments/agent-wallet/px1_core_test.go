package wallet

// Owner S1. Core layer of T1, T2, T4, T6, T7 and T12 (G2-PAYMENT-EXECUTOR-v1
// §3.8) on a genuine Namecoin Core 28 regtest node with the genuine K1 kernel
// (rental.Check under the W construction profile), the genuine wallet RPC
// routes and real broadcasts. Until S2/S3 land, the wallet-layer journal v2,
// its fold, the UTC day and the canary watcher are the unit fakes of the
// frozen interfaces (px1_fixture_test.go); the service layer (steps 1-7, 20)
// is not exercised here. Run with a fresh root per invocation:
//
//	W1_REGTEST=1 W1_RUN_ROOT=FRESH_ABSOLUTE_DIRECTORY \
//	W1_CORE_CLI=ABSOLUTE_NAMECOIN_CLI W1_CORE_DAEMON=ABSOLUTE_NAMECOIND \
//	go test -count=1 -run '^TestPX1CoreS1$' -v .

import (
	"encoding/json"
	"os"
	"testing"

	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// Claim: the S1 Core steps run in order on one genuine regtest node with the genuine kernel; each step states its own claim.
func TestPX1CoreS1(t *testing.T) {
	l := newPX1Core(t)
	step := func(name string, f func(t *testing.T)) {
		t.Run(name, func(st *testing.T) {
			prev := l.t
			l.t = st
			defer func() { l.t = prev }()
			f(st)
		})
	}
	terms := canonical(px1RegtestTerms())
	budget := int64(500000)
	listed := px1RegtestTerms().Recipients[0]
	created := int64(499)

	// Claim (T1, Core): an allow-listed transfer of exactly transfer_cap fee-inclusive executes; the genuine tx is in the mempool with the quoted fee, and the reserve record carries day and the cap as debit.
	step("T1-at-transfer-cap", func(t *testing.T) {
		g := l.px1IssueGrant(terms, &budget, 2)
		w, j := l.px1OpenG2(g, px1Operator(), px1ExecutorKey)
		fee := l.px1QuoteFee(g.config, listed, 50000)
		got, _ := l.px1Spend(w, g, listed, 100000-fee, fee, 1, created)
		l.save("t1-receipt.json", got)
		if got.Status != "executed" || got.Reserved != 100000 {
			t.Fatalf("T1: want executed at cap (fee %d) got %+v", fee, got)
		}
		var view su.TransactionView
		if e := json.Unmarshal(l.rpc("", "getrawtransaction", got.TxID, true), &view); e != nil || len(view.Vout) != 2 || int64(view.Vout[0].Value) != 100000-fee {
			t.Fatal("T1: effect transaction shape")
		}
		if len(j.records) != 2 || j.records[0].Kind != RecordReserve || j.records[0].Day != px1TestDay(500) || j.records[0].Fee != fee || j.records[1].Kind != RecordComplete {
			t.Fatalf("T1: journal %+v", j.records)
		}
		l.mine(1)
	})

	// Claim (T2, Core): one atom over the transfer cap (amount + fee_limit) refuses TRANSFER_CAP_EXCEEDED with zero records and zero broadcasts; the at-cap neighbour on the same wallet executes.
	step("T2-over-transfer-cap", func(t *testing.T) {
		g := l.px1IssueGrant(terms, &budget, 2)
		w, j := l.px1OpenG2(g, px1Operator(), px1ExecutorKey)
		fee := l.px1QuoteFee(g.config, listed, 50000)
		before := l.px1Mempool()
		got, _ := l.px1Spend(w, g, listed, 100000-fee+1, fee, 1, created)
		if got.Reason != CodeTransferCapExceeded || len(j.records) != 0 || l.px1Mempool() != before {
			t.Fatalf("T2: want %s and no effect got %+v", CodeTransferCapExceeded, got)
		}
		if ok, _ := l.px1Spend(w, g, listed, 100000-fee, fee, 2, created); ok.Status != "executed" {
			t.Fatalf("T2 neighbour: %+v", ok)
		}
		l.mine(1)
	})

	// Claim (T4, Core): after a retained debit the next spend over the remaining total budget refuses TOTAL_BUDGET_EXCEEDED pre-plan (amount) and post-plan (amount + actual fee) without broadcast; the spend that exhausts the budget exactly executes; a budget-absent grant with terms v2 refuses CONTRACT_BUDGET.
	step("T4-total-budget", func(t *testing.T) {
		small := px1RegtestTerms()
		small.SpendCap, small.DayCap = 150000, 150000
		smallRaw := canonical(small)
		b := int64(150000)
		g := l.px1IssueGrant(smallRaw, &b, 3)
		w, j := l.px1OpenG2(g, px1Operator(), px1ExecutorKey)
		fee := l.px1QuoteFee(g.config, listed, 50000)
		if got, _ := l.px1Spend(w, g, listed, 100000-fee, fee, 1, created); got.Status != "executed" {
			t.Fatalf("T4 first: %+v", got)
		}
		l.mine(1)
		before := l.px1Mempool()
		if got, _ := l.px1Spend(w, g, listed, 50001, fee, 2, created); got.Reason != CodeTotalBudgetExceeded {
			t.Fatalf("T4 pre-plan: want %s got %+v", CodeTotalBudgetExceeded, got)
		}
		if got, _ := l.px1Spend(w, g, listed, 50000-fee+1, fee, 3, created); got.Reason != CodeTotalBudgetExceeded {
			t.Fatalf("T4 post-plan: want %s got %+v", CodeTotalBudgetExceeded, got)
		}
		if l.px1Mempool() != before || len(j.records) != 2 {
			t.Fatal("T4: refusal left an effect")
		}
		if got, _ := l.px1Spend(w, g, listed, 50000-fee, fee, 4, created); got.Status != "executed" || got.Reserved != 50000 {
			t.Fatalf("T4 exhausting neighbour: %+v", got)
		}
		l.mine(1)
		absent := l.px1IssueGrant(terms, nil, 1)
		wa, ja := l.px1OpenG2(absent, px1Operator(), px1ExecutorKey)
		if got, _ := l.px1Spend(wa, absent, listed, 50000, 30000, 1, created); got.Reason != CodeContractBudget || len(ja.records) != 0 {
			t.Fatalf("T4 budget absent: want %s got %+v", CodeContractBudget, got)
		}
	})

	// Claim (T6, Core): a landlord seal spend in the mempool before the request refuses GRANT_SEAL_SPENT with no record; a seal spend injected after the wallet reservation refuses at kernel check #4 with the debit retained (refuse-retained) and no payment broadcast.
	step("T6-seal-spent", func(t *testing.T) {
		g := l.px1IssueGrant(terms, &budget, 2)
		w, j := l.px1OpenG2(g, px1Operator(), px1ExecutorKey)
		l.px1Revoke(g)
		if got, _ := l.px1Spend(w, g, listed, 50000, 30000, 1, created); got.Reason != "GRANT_SEAL_SPENT" || len(j.records) != 0 {
			t.Fatalf("T6 before: want GRANT_SEAL_SPENT got %+v", got)
		}
		l.mine(1)
		g2 := l.px1IssueGrant(terms, &budget, 2)
		w2, j2 := l.px1OpenG2(g2, px1Operator(), px1ExecutorKey)
		if ok, _ := l.px1Spend(w2, g2, listed, 50000, 30000, 9, created); ok.Status != "executed" {
			t.Fatalf("T6 live-seal neighbour: %+v", ok)
		}
		n := len(j2.records)
		var revoke string
		w2.hook = func(stage string) {
			if stage == "after-reservation" {
				revoke = l.px1Revoke(g2)
			}
		}
		before := l.px1Mempool()
		got, _ := l.px1Spend(w2, g2, listed, 50000, 30000, 1, created)
		l.save("t6-after-reservation.json", got)
		if got.Status != "refused" || got.Reason != "GRANT_SEAL_SPENT" || revoke == "" || l.px1Mempool() != before+1 {
			t.Fatalf("T6 after reservation: %+v", got)
		}
		if len(j2.records) != n+2 || j2.records[n+1].Kind != RecordRefuseRetained || j2.records[n+1].Reserved != got.Reserved || got.Reserved <= 50000 {
			t.Fatalf("T6: debit not retained: %+v", j2.records)
		}
		l.mine(1)
	})

	// Claim (T7, Core): created_at at not_after refuses REQUEST_TIME before any node call; the grant window closing between reservation and broadcast refuses GRANT_EXPIRED at kernel check #4 with the debit retained and no broadcast.
	step("T7-expired-window", func(t *testing.T) {
		g := l.px1IssueGrant(terms, &budget, 2)
		w, j := l.px1OpenG2(g, px1Operator(), px1ExecutorKey)
		w.clock = func() int64 { return 1005 }
		if got, _ := l.px1Spend(w, g, listed, 50000, 30000, 1, 1000); got.Reason != "REQUEST_TIME" || len(j.records) != 0 {
			t.Fatalf("T7 request time: %+v", got)
		}
		now := int64(500)
		w.clock = func() int64 { return now }
		if ok, _ := l.px1Spend(w, g, listed, 50000, 30000, 3, created); ok.Status != "executed" {
			t.Fatalf("T7 in-window neighbour: %+v", ok)
		}
		n := len(j.records)
		w.hook = func(stage string) {
			if stage == "after-reservation" {
				now = 1000
			}
		}
		before := l.px1Mempool()
		got, _ := l.px1Spend(w, g, listed, 50000, 30000, 2, created)
		l.save("t7-after-reservation.json", got)
		if got.Status != "refused" || got.Reason != "GRANT_EXPIRED" || l.px1Mempool() != before {
			t.Fatalf("T7 after reservation: want GRANT_EXPIRED got %+v", got)
		}
		if len(j.records) != n+2 || j.records[n+1].Kind != RecordRefuseRetained {
			t.Fatalf("T7: debit not retained: %+v", j.records)
		}
	})

	// Claim (T12, Core): a second instance with a fresh state_dir and its own receipt key, given the same grant, refuses TERMS_EXECUTOR_MISMATCH with no record and no broadcast; the named executor executes the same request.
	step("T12-second-instance", func(t *testing.T) {
		g := l.px1IssueGrant(terms, &budget, 2)
		second := g
		second.config.StateDir = g.config.StateDir + "-second"
		second.config.Policy.StateDir = g.config.Policy.StateDir + "-second"
		for _, p := range []string{second.config.StateDir, second.config.Policy.StateDir} {
			if e := os.Mkdir(p, 0700); e != nil {
				t.Fatal(e)
			}
		}
		_, otherKey := testKey(8)
		w2, j2 := l.px1OpenG2(second, px1Operator(), otherKey)
		before := l.px1Mempool()
		if got, _ := l.px1Spend(w2, second, listed, 50000, 30000, 1, created); got.Reason != CodeTermsExecutorMismatch || len(j2.records) != 0 || l.px1Mempool() != before {
			t.Fatalf("T12: want %s got %+v", CodeTermsExecutorMismatch, got)
		}
		w, _ := l.px1OpenG2(g, px1Operator(), px1ExecutorKey)
		if got, _ := l.px1Spend(w, g, listed, 50000, 30000, 1, created); got.Status != "executed" {
			t.Fatalf("T12 named executor: %+v", got)
		}
		l.mine(1)
	})
}
