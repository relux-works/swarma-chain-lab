package wallet

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Real Core validates both name transactions and their resulting name value.
// An immature commitment, expired authority, wrong scope and exhausted name
// allowance cannot reveal/register; each refusal preserves journal and mempool.
func TestCoreNameRegistration(t *testing.T) {
	l := newCore(t)
	terms := Terms{Version: 1, Recipients: []string{testAddress(3)}, SpendCap: 500000, NameCap: DefaultNameBudget, NameCount: 1}
	raw, c := l.grant(terms, []string{"names.register", "pay"}, 3500000)
	w, e := Open(c)
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if w != nil {
			w.Close()
		}
	}()
	w.clock = func() int64 { return 500 }
	r := testRequest()
	r.GrantID = grantID(t, raw)
	r.Action, r.Amount, r.Name, r.Value, r.FeeLimit = "names.register", 0, "d/wallet-name-test", "fixture-value", 100000
	request := signRequest(t, r, 2)
	ctx := context.Background()
	first := w.Execute(ctx, raw, canonical(terms), request, "")
	if first.Status != "pending" || first.Phase != "name-new-sent" {
		t.Fatalf("commit %+v", first)
	}
	l.save("name-commit.json", first)
	unchanged := func(req []byte, now int64, status, reason string) {
		t.Helper()
		before, _ := os.ReadFile(filepath.Join(c.StateDir, "wallet.json"))
		pool := string(l.rpc("", "getrawmempool"))
		w.clock = func() int64 { return now }
		got := w.Execute(ctx, raw, canonical(terms), req, "")
		if got.Status != status || got.Reason != reason {
			t.Fatalf("want %s/%s got %+v", status, reason, got)
		}
		after, _ := os.ReadFile(filepath.Join(c.StateDir, "wallet.json"))
		if string(before) != string(after) || pool != string(l.rpc("", "getrawmempool")) {
			t.Fatal("negative control changed journal/effects")
		}
	}
	unchanged(request, 500, "pending", "NAME_PENDING")
	l.mine(11)
	unchanged(request, 500, "pending", "NAME_PENDING")
	l.mine(1)
	unchanged(request, 1000, "refused", "GRANT_EXPIRED")
	w.Close()
	w = nil
	w, e = Open(c)
	if e != nil {
		t.Fatal(e)
	}
	w.clock = func() int64 { return 500 }
	last := w.Execute(ctx, raw, canonical(terms), request, "")
	if last.Status != "executed" || last.Phase != "complete" {
		t.Fatalf("reveal %+v", last)
	}
	l.save("name-reveal.json", last)
	l.mine(1)
	var view struct {
		Name    string `json:"name"`
		Value   string `json:"value"`
		Address string `json:"address"`
		TxID    string `json:"txid"`
	}
	if json.Unmarshal(l.rpc("", "name_show", r.Name), &view) != nil || view.Name != r.Name || view.Value != r.Value || view.Address != r.Address || view.TxID != last.TxID {
		t.Fatalf("name result %+v", view)
	}
	b, e := w.Budget(ctx, raw, canonical(terms))
	if e != nil || b.NameReserved <= NameDeposit || b.NameReserved >= NameDeposit+2*r.FeeLimit || b.SpendReserved != 0 || b.NamesReserved != 1 {
		t.Fatalf("budget %+v %v", b, e)
	}
	unchanged(request, 500, "already-executed", "DURABLE_RESERVATION_NO_RETRY")
	x := r
	x.Name = "d/wallet-name-second"
	x.Nonce = strings.Repeat("d", 64)
	unchanged(signRequest(t, x, 2), 500, "refused", "NAME_BUDGET_EXCEEDED")
	w.Close()
	w = nil
	other, c2 := l.grant(terms, []string{"pay"}, 3500000)
	w, e = Open(c2)
	if e != nil {
		t.Fatal(e)
	}
	w.clock = func() int64 { return 500 }
	x.GrantID = grantID(t, other)
	pool := string(l.rpc("", "getrawmempool"))
	got := w.Execute(ctx, other, canonical(terms), signRequest(t, x, 2), "")
	if got.Status != "refused" || got.Reason != "GRANT_SCOPE" {
		t.Fatalf("missing scope %+v", got)
	}
	if _, e = os.Stat(filepath.Join(c2.StateDir, "wallet.json")); !os.IsNotExist(e) || pool != string(l.rpc("", "getrawmempool")) {
		t.Fatal("scope refusal wrote state/effect")
	}
}
