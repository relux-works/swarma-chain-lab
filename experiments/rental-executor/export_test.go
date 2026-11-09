package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// The export projects only the requested slot, exposes complete delivery links,
// marks reservations explicitly, and cannot call a node or mutate journal/disk.
func TestSlotExportReadOnly(t *testing.T) {
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
	x := &Executor{store: &store{root: rootDir(t)}, slots: map[string]Slot{a: {ID: a}, b: {ID: b}}, journal: journal{Reservations: []Reservation{
		{Slot: a, Nonce: Hash([]byte("complete")), EventID: Hash([]byte("event1")), Action: "deliver", Phase: "complete", FileHash: Hash([]byte("file")), RetainUntil: 1000},
		{Slot: a, Nonce: Hash([]byte("reserved")), EventID: Hash([]byte("event2")), Action: "deliver", Phase: "reserved", FileHash: Hash([]byte("uncertain")), RetainUntil: 1000},
		{Slot: b, Nonce: Hash([]byte("other")), EventID: Hash([]byte("other-event")), Action: "pay", Phase: "complete", TxID: Hash([]byte("tx"))},
	}}}
	before := canonical(x.journal)
	got, e := x.ListSlot(a)
	if e != nil || len(got.Effects) != 2 || len(got.Deliverables) != 1 || got.Effects[1].Phase != "reserved" || got.Effects[1].Link != "" || got.Deliverables[0].Link == "" {
		t.Fatal("export leaked slot or uncertain deliverable", e)
	}
	got.Effects[0].FileHash = "modified"
	if !bytes.Equal(before, canonical(x.journal)) {
		t.Fatal("export mutated journal")
	}
	entries, e := os.ReadDir(x.store.root)
	if e != nil || len(entries) != 0 {
		t.Fatal("export wrote disk")
	}
	for _, q := range []string{"bad", strings.Repeat("c", 64)} {
		if _, e = x.ListSlot(q); e == nil {
			t.Fatal("unknown export admitted")
		}
	}
	handler := ExecutorHandler(x)
	for _, tc := range []struct {
		method, path string
		status       int
	}{{"GET", "/slots/" + a, 200}, {"GET", "/slots/" + a + "?x=1", 400}, {"POST", "/slots/" + a, 400}, {"GET", "/slots/bad", 400}, {"GET", "/slots/" + strings.Repeat("c", 64), 404}} {
		r := httptest.NewRequest(tc.method, tc.path, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatal("export HTTP boundary", w.Code)
		}
	}
	x.store.poison = true
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/slots/"+a, nil))
	if w.Code != 503 {
		t.Fatal("poison export not refused")
	}
}

// A real issued grant delivers once. Complete and crash-reserved receipts stay
// readable/replayable after seal closure and restart, without another effect.
func TestCoreClosureReceiptsAndExport(t *testing.T) {
	l := newCore(t)
	p, c, raw, pool := l.issueFixture("closure-export")
	x, b, conf, root := l.executor(p, raw, 1)
	ctx := context.Background()
	file := []byte("public closure fixture\n")
	event := requestFor(c, "closure-file", "deliver", 0)
	tagSet(&event, "target", "sha256:"+Hash(file))
	event = signEvent(event, testKey(2))
	first := x.Execute(ctx, canonical(event), file)
	expectResult(t, first, "executed", "LIVE_RENTER_REQUEST")
	pending := requestFor(c, "reserved-file", "deliver", 0)
	tagSet(&pending, "target", "sha256:"+Hash(file))
	pending = signEvent(pending, testKey(2))
	x.hook = func(phase string) {
		if phase == "reserved" {
			panic("test-crash")
		}
	}
	func() {
		defer func() {
			if recover() != "test-crash" {
				t.Fatal("reservation crash witness")
			}
		}()
		x.Execute(ctx, canonical(pending), file)
	}()
	x.hook = nil
	plan, e := rental.MakePlan(rental.IssuerPolicy{Policy: p}, rental.PlanSpec{Kind: "revoke", Inputs: []su.PlanInput{{Point: su.Point{TxID: pool.Point.TxID, Vout: pool.Point.Vout}, ValueSat: pool.ValueSat, Script: pool.Script, Role: "seal"}}, ChangeScript: l.script, Pool: pool}, nil, nil, nil, 500)
	if e != nil {
		t.Fatal(e)
	}
	l.sendPlan(plan, false)
	for _, want := range []struct {
		event Event
		phase string
	}{{event, "complete"}, {pending, "reserved"}} {
		r := x.Execute(ctx, canonical(want.event), file)
		if r.Status != "already-executed" || r.Phase != want.phase || r.EventID != want.event.ID || r.AuthorityReason != "KERNEL_SEAL_SPENT" {
			t.Fatal("closure lost durable receipt", r)
		}
	}
	fresh := requestFor(c, "closed-new", "deliver", 0)
	tagSet(&fresh, "target", "sha256:"+Hash(file))
	fresh = signEvent(fresh, testKey(2))
	expectResult(t, x.Execute(ctx, canonical(fresh), file), "refused", "KERNEL_SEAL_SPENT")
	journalBefore, e := os.ReadFile(filepath.Join(root, "journal.json"))
	if e != nil {
		t.Fatal(e)
	}
	snapshot, e := x.ListSlot(conf.Slots[0].ID)
	if e != nil || len(snapshot.Effects) != 2 || len(snapshot.Deliverables) != 1 {
		t.Fatal("closed export", e)
	}
	x.Close()
	x, e = Open(root, conf, failingNode{}, b)
	if e != nil {
		t.Fatal(e)
	}
	defer x.Close()
	x.now = func() time.Time { return time.Unix(1001, 0) }
	again, e := x.ListSlot(conf.Slots[0].ID)
	if e != nil || !bytes.Equal(canonical(snapshot), canonical(again)) {
		t.Fatal("restart export changed")
	}
	replay := x.Execute(ctx, canonical(event), file)
	if replay.Status != "already-executed" || replay.EventID != first.EventID || replay.FileHash != first.FileHash || replay.Link != first.Link || replay.AuthorityReason == "" {
		t.Fatal("offline replay lost receipt")
	}
	x.now = func() time.Time { return time.Unix(500, 0) }
	handler := ExecutorHandler(x)
	request := func(event Event, expected int) {
		t.Helper()
		q := canonical(map[string]any{"event": event, "file_base64": ""})
		r := httptest.NewRequest("POST", "/execute", bytes.NewReader(q))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != expected {
			t.Fatal("refusal HTTP status", w.Code)
		}
		var result Receipt
		if json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Status != "refused" {
			t.Fatal("refusal body")
		}
	}
	// Persisted seal closure takes precedence over a subsequent node outage.
	request(requestFor(c, "closed-http", "pay", 1000), http.StatusForbidden)
	request(requestFor(c, "scope", "publish", 0), http.StatusForbidden)
	journalAfter, e := os.ReadFile(filepath.Join(root, "journal.json"))
	if e != nil || !bytes.Equal(journalBefore, journalAfter) || b.calls != 0 {
		t.Fatal("replay/export caused effects or writes")
	}
	l.save("closed-export.json", again)
	l.save("closed-replay.json", replay)
}
