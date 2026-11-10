package journal_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/journal"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
)

// The real file journal binds input and immutable outbox state across restart;
// unknown IDs, changed input, reply-before-receipt and corrupt state cannot advance it.
func TestDeliveryJournal(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "journal")
	st, e := journal.Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	sender, _ := nostr.GeneratePrivKey()
	renter, _ := nostr.GeneratePrivKey()
	slot := testSlot("slot-1", renter.PubKeyHex())
	if e = st.Put(slot); e != nil {
		t.Fatal(e)
	}
	id := strings.Repeat("a", 64)
	if e = st.ChangeDelivery(slot.ID, id, journal.DeliveryReceived, "", nil); e == nil {
		t.Fatal("unknown delivery admitted")
	}
	if old, e := st.RecordInput(slot.ID, id, "question"); e != nil || old {
		t.Fatal("input", e)
	}

	reopened, e := journal.Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	recorded, ok := reopened.Delivery(slot.ID, id)
	if !ok || recorded.Input != "question" || recorded.Phase != journal.DeliveryScreening {
		t.Fatal("input not durable before screening")
	}
	if _, e = st.RecordInput(slot.ID, id, "changed"); e == nil {
		t.Fatal("changed input admitted")
	}
	if e = st.ChangeDelivery(slot.ID, id, journal.DeliveryQueued, "", nil); e != nil {
		t.Fatal(e)
	}
	if d, ok := st.PendingDelivery(slot.ID, nil); !ok || d.Input != "question" || d.ID != id {
		t.Fatal("input not recoverable")
	}
	wrap, _, e := nostr.WrapDM(sender, renter.PubKeyHex(), "answer", [][]string{{"e", id}}, 150)
	if e != nil {
		t.Fatal(e)
	}
	wire, _ := json.Marshal(wrap)
	if e = st.ChangeDelivery(slot.ID, id, journal.DeliveryReady, "answer", wire); e == nil {
		t.Fatal("reply before receive ACK")
	}
	if e = st.ChangeDelivery(slot.ID, id, journal.DeliveryReceived, "", nil); e != nil {
		t.Fatal(e)
	}
	if e = st.ChangeDelivery(slot.ID, id, journal.DeliveryReady, "answer", wire); e != nil {
		t.Fatal(e)
	}
	st, e = journal.Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	d, ok := st.Delivery(slot.ID, id)
	if !ok || !bytes.Equal(d.Wire, wire) || d.Reply != "answer" {
		t.Fatal("outbox bytes lost")
	}
	if e = st.ChangeDelivery(slot.ID, id, journal.DeliveryReady, "changed", wire); e == nil {
		t.Fatal("outbox overwrite admitted")
	}
	if e = st.ChangeDelivery(slot.ID, id, journal.DeliveryAccepted, "", nil); e != nil {
		t.Fatal(e)
	}
	st, e = journal.Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	if _, ok := st.PendingDelivery(slot.ID, nil); ok {
		t.Fatal("accepted delivery dispatched again")
	}
	if old, e := st.RecordInput(slot.ID, id, "question"); e != nil || !old {
		t.Fatal("input dedup lost", e)
	}
	file := filepath.Join(dir, "slot-slot-1.json")
	raw, e := os.ReadFile(file)
	if e != nil {
		t.Fatal(e)
	}
	for _, plant := range []func([]byte) []byte{
		func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"input":"question"`), []byte(`"input":"tampered"`), 1)
		},
		func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"phase":"relay-accepted"`), []byte(`"phase":"unknown"`), 1)
		},
		func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"phase":"relay-accepted"`), []byte(`"Phase":"relay-accepted"`), 1)
		},
		func(b []byte) []byte { return b[:len(b)-1] },
	} {
		bad := plant(raw)
		if bytes.Equal(bad, raw) {
			t.Fatal("plant not applied")
		}
		if os.WriteFile(file, bad, 0600) != nil {
			t.Fatal("plant write")
		}
		if _, e = journal.Open(dir); e == nil {
			t.Fatal("corrupt delivery journal accepted")
		}
		after, _ := os.ReadFile(file)
		if !bytes.Equal(after, bad) {
			t.Fatal("corrupt state rewritten")
		}
		if os.WriteFile(file, raw, 0600) != nil {
			t.Fatal("restore fixture")
		}
		if _, e = journal.Open(dir); e != nil {
			t.Fatal("valid neighbor", e)
		}
	}
}
