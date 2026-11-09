package wallet

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/durable"
)

func privateDir(t *testing.T) string {
	t.Helper()
	p := t.TempDir()
	if e := os.Chmod(p, 0700); e != nil {
		t.Fatal(e)
	}
	return p
}
func testRecord() Record {
	return Record{GrantID: strings.Repeat("a", 64), Nonce: strings.Repeat("b", 64), RequestHash: strings.Repeat("c", 64), Action: "pay", Phase: "reserved", Reserved: 1000, Fee: 100, Inputs: []su.Point{{TxID: strings.Repeat("d", 64)}}, TxID: strings.Repeat("e", 64)}
}

// Invalid persisted records cannot be loaded as free budget or retriable work;
// the positive neighbor is a genuine durable reserved record.
func TestStateControls(t *testing.T) {
	r := testRecord()
	w := &Wallet{state: state{Version: 1, Records: []Record{r}}}
	if e := w.validateState(); e != nil {
		t.Fatal(e)
	}
	for _, c := range []struct {
		name string
		edit func(*Record)
	}{
		{"phase", func(r *Record) { r.Phase = "planned" }},
		{"negative-cost", func(r *Record) { r.Reserved = -1 }},
		{"fee-not-included", func(r *Record) { r.Fee = r.Reserved + 1 }},
		{"unknown-action", func(r *Record) { r.Action = "dump" }},
		{"no-input", func(r *Record) { r.Inputs = nil }},
		{"duplicate-input", func(r *Record) { r.Inputs = append(append([]su.Point{}, r.Inputs...), r.Inputs[0]) }},
		{"pay-name-state", func(r *Record) { r.Phase = "name-new-sent" }},
	} {
		t.Run(c.name, func(t *testing.T) {
			bad := r
			c.edit(&bad)
			w.state.Records = []Record{bad}
			if e := w.validateState(); e == nil {
				t.Fatal("corrupt state admitted")
			}
		})
	}
	w.state.Records = []Record{r, r}
	if e := w.validateState(); e == nil {
		t.Fatal("duplicate nonce admitted")
	}
}

// Independent handles cannot reserve concurrently in the same real state root;
// an invalid existing state file is refused without replacing its bytes.
func TestStoreBoundary(t *testing.T) {
	root := privateDir(t)
	store, e := durable.Open(root, "wallet.lock")
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	if other, e := durable.Open(root, "wallet.lock"); e == nil {
		other.Close()
		t.Fatal("parallel handle admitted")
	} else if e.Error() != "STATE_BUSY" {
		t.Fatal(e)
	}
	w := &Wallet{store: store, state: state{Version: 1, Binding: strings.Repeat("a", 64), Records: []Record{testRecord()}}}
	if e = w.persist(); e != nil {
		t.Fatal(e)
	}
	target := filepath.Join(root, "wallet.json")
	before, _ := os.ReadFile(target)
	if e = os.Chmod(target, 0644); e != nil {
		t.Fatal(e)
	}
	if e = w.persist(); e == nil || !w.poisoned {
		t.Fatal("unwritable journal did not poison")
	}
	after, _ := os.ReadFile(target)
	if string(before) != string(after) {
		t.Fatal("invalid journal replaced")
	}
}

// Contract buckets and the parent total both bind cumulative reservations.
// Names and ordinary spend cannot consume one another's signed allowance.
func TestBudgetAccounting(t *testing.T) {
	r := testRecord()
	r.Reserved = 1000
	w := &Wallet{state: state{Records: []Record{r}}}
	g := Grant{ID: r.GrantID, Budget: 3000}
	terms := Terms{SpendCap: 1500, NameCap: 1500, NameCount: 1}
	if e := w.budgetCheck(g, terms, Request{Action: "pay"}, 500); e != nil {
		t.Fatal(e)
	}
	if e := w.budgetCheck(g, terms, Request{Action: "pay"}, 501); e == nil || e.Error() != "SPEND_BUDGET_EXCEEDED" {
		t.Fatal("spend cap bypass", e)
	}
	if e := w.budgetCheck(g, terms, Request{Action: "names.register"}, 1500); e != nil {
		t.Fatal(e)
	}
	name := r
	name.Action = "names.register"
	name.Reserved = 1000
	w.state.Records = append(w.state.Records, name)
	if e := w.budgetCheck(g, terms, Request{Action: "names.register"}, 1); e == nil || e.Error() != "NAME_BUDGET_EXCEEDED" {
		t.Fatal("name count bypass", e)
	}
	if e := w.budgetCheck(g, terms, Request{Action: "pay"}, 1001); e == nil || e.Error() != "TOTAL_BUDGET_EXCEEDED" {
		t.Fatal("total cap bypass", e)
	}
}
