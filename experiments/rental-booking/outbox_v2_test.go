package booking

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func outboxRead(t *testing.T, root, name string) []byte {
	t.Helper()
	b, e := os.ReadFile(filepath.Join(root, name))
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func outboxIndex(t *testing.T, root string) []string {
	t.Helper()
	var v []string
	if Strict(outboxRead(t, root, "index.json"), &v) != nil {
		t.Fatal("index schema")
	}
	return v
}
func outboxPay(t *testing.T, f *ledgerFixture, b BookingV2) BookingV2 {
	t.Helper()
	n := f.concrete[b.Contract.Payment.Coin]
	n.outputs = append(n.outputs, ledgerOutput{Hash([]byte(b.Contract.BookingID)), b.Script, b.Contract.Payment.AmountAtoms, n.height + 1})
	n.height += 2
	f.refresh(t)
	return f.get(t, b)
}

// Actual booking state transitions export byte-preserved signed envelopes,
// append in eligibility order (not hold order), and replay without duplication.
// Payment nodes here are test doubles; SG1's genuine-Core test reads these files.
func TestOutboxV2(t *testing.T) {
	f := newLedger(t)
	root := f.cfg.StateDir
	if len(outboxIndex(t, root)) != 0 {
		t.Fatal("nonempty initial index")
	}
	a := f.consent(t, f.book(t, "slot0", "btc"))
	b := f.consent(t, f.book(t, "slot1", "ltc"))
	b = outboxPay(t, f, b)
	first := outboxIndex(t, root)
	if len(first) != 1 {
		t.Fatal("missing ready item")
	}
	a = outboxPay(t, f, a)
	next := outboxIndex(t, root)
	if len(next) != 2 || next[0] != first[0] {
		t.Fatal("outbox prefix rewritten")
	}
	for i, book := range []BookingV2{b, a} {
		raw := outboxRead(t, root, next[i]+".json")
		var item signerItem
		if Hash(raw) != next[i] || Strict(raw, &item) != nil || item.ID != Hash([]byte("grant-issue/"+book.Contract.BookingID)) || item.Kind != "grant-issue" || item.Request != string(canonical(book.Issuance)) || item.Publication != string(canonical(book.PackageEvent)) {
			t.Fatal("signed outbox bytes changed")
		}
		if !bytes.Equal([]byte(item.Publication), outboxRead(t, root, "package-event-"+book.Contract.BookingID+".json")) {
			t.Fatal("companion event changed")
		}
	}
	f.concrete["btc"].generation++
	f.refresh(t)
	rev := f.get(t, a)
	idx := outboxIndex(t, root)
	var item signerItem
	if len(idx) != 3 || idx[0] != next[0] || idx[1] != next[1] || Strict(outboxRead(t, root, idx[2]+".json"), &item) != nil || item.Kind != "revoke" || !bytes.Equal(canonical(item.Revoke), canonical(rev.Revoke)) {
		t.Fatal("sticky revoke not appended exactly")
	}
	before := outboxRead(t, root, "index.json")
	f.s.Close()
	f.open(t)
	if !bytes.Equal(before, outboxRead(t, root, "index.json")) {
		t.Fatal("restart duplicated outbox")
	}
}

// Corrupt or partial visible files refuse without rewriting the index; valid
// bytes restore export. An interrupted unindexed immutable item is reusable.
func TestOutboxV2Refusals(t *testing.T) {
	for _, mode := range []string{"index-partial", "index-duplicate", "index-foreign", "item-partial", "item-missing", "item-conflict", "orphan", "capacity"} {
		t.Run(mode, func(t *testing.T) {
			f := newLedger(t)
			b := outboxPay(t, f, f.consent(t, f.book(t, "slot0", "btc")))
			_ = b
			root := f.cfg.StateDir
			original := outboxRead(t, root, "index.json")
			idx := outboxIndex(t, root)
			name := idx[0] + ".json"
			item := outboxRead(t, root, name)
			put := func(name string, raw []byte) {
				t.Helper()
				if e := os.WriteFile(filepath.Join(root, name), raw, 0600); e != nil {
					t.Fatal(e)
				}
			}
			want := "OUTBOX_CONFLICT"
			switch mode {
			case "index-partial":
				put("index.json", []byte("["))
				want = "OUTBOX_INDEX"
			case "index-duplicate":
				put("index.json", canonical([]string{idx[0], idx[0]}))
				want = "OUTBOX_INDEX"
			case "index-foreign":
				put("index.json", canonical([]string{Hash([]byte("foreign"))}))
			case "item-partial":
				put(name, []byte("{"))
			case "item-missing":
				if e := os.Remove(filepath.Join(root, name)); e != nil {
					t.Fatal(e)
				}
			case "item-conflict":
				put(name, append(item, ' '))
			case "orphan":
				put("index.json", []byte("[]"))
				want = ""
			case "capacity": // The closed input bound rejects a too-large index before any write.
				many := make([]string, outboxIndexBound+1)
				for i := range many {
					many[i] = idx[0]
				}
				put("index.json", canonical(many))
				want = "OUTBOX_INDEX"
			}
			before := outboxRead(t, root, "index.json")
			e := f.s.exportV2()
			if want == "" {
				if e != nil || !bytes.Equal(original, outboxRead(t, root, "index.json")) {
					t.Fatal("orphan not recovered", e)
				}
				return
			}
			if e == nil || e.Error() != want || !bytes.Equal(before, outboxRead(t, root, "index.json")) {
				t.Fatal("corrupt outbox admitted or rewritten", e)
			}
			put(name, item)
			put("index.json", original)
			if e = f.s.exportV2(); e != nil {
				t.Fatal("valid neighbor refused", e)
			}
		})
	}
}
