package journal_test

import (
	"os"
	"path/filepath"
	"testing"

	"relux.works/swarma-chain-lab/experiments/rental-gateway/journal"
)

func testSlot(id, renter string) *journal.Slot {
	return &journal.Slot{ID: id, StationName: "id/swarma-station-1",
		RenterPubKey: renter, NotBefore: 100, NotAfter: 200}
}

// TestJournalDurableAcrossRestart proves seen ids, refusal counts and
// end state survive reopening the store (gateway restart).
func TestJournalDurableAcrossRestart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "journal")
	st, err := journal.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Put(testSlot("slot-1", "aa")); err != nil {
		t.Fatal(err)
	}
	already, err := st.RecordSeen("slot-1", "rumor-1")
	if err != nil || already {
		t.Fatalf("first RecordSeen = %v, %v", already, err)
	}
	already, _ = st.RecordSeen("slot-1", "rumor-1")
	if !already {
		t.Fatal("replay not detected before restart")
	}
	if n, err := st.AddRefusal("slot-1"); err != nil || n != 1 {
		t.Fatalf("AddRefusal = %d, %v", n, err)
	}
	st2, err := journal.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	already, _ = st2.RecordSeen("slot-1", "rumor-1")
	if !already {
		t.Fatal("seen id lost across restart")
	}
	slot, ok := st2.Get("slot-1")
	if !ok || slot.Refusals != 1 {
		t.Fatalf("refusals after restart = %+v", slot)
	}
	if n, _ := st2.AddRefusal("slot-1"); n != 2 {
		t.Fatalf("second refusal count = %d, want 2", n)
	}
}

// TestJournalOneActiveSlotPerRenter proves duplicate ids and a
// second concurrent slot for one renter are refused, while a slot
// after the first ended is accepted.
func TestJournalOneActiveSlotPerRenter(t *testing.T) {
	st, err := journal.Open(filepath.Join(t.TempDir(), "j"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Put(testSlot("slot-1", "aa")); err != nil {
		t.Fatal(err)
	}
	if err := st.Put(testSlot("slot-1", "bb")); err == nil {
		t.Fatal("duplicate slot id accepted")
	}
	if err := st.Put(testSlot("slot-2", "aa")); err == nil {
		t.Fatal("second active slot for one renter accepted")
	}
	if err := st.Put(testSlot("slot-2", "bb")); err != nil {
		t.Fatalf("other renter refused: %v", err)
	}
	if err := st.MarkEnded("slot-1", "done"); err != nil {
		t.Fatal(err)
	}
	if err := st.Put(testSlot("slot-3", "aa")); err != nil {
		t.Fatalf("slot after previous ended refused: %v", err)
	}
}

// TestJournalUpdateRollback proves a failed persist leaves memory
// and disk in agreement (RM2 M10): MarkEnded on an unwritable dir
// must not flip the in-memory Ended flag.
func TestJournalUpdateRollback(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "journal")
	st, err := journal.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Put(testSlot("slot-1", "aa")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	err = st.MarkEnded("slot-1", "boom")
	_ = os.Chmod(dir, 0700)
	if err == nil {
		t.Fatal("MarkEnded succeeded on unwritable journal dir")
	}
	slot, _ := st.Get("slot-1")
	if slot.Ended {
		t.Fatal("in-memory Ended flipped despite persist failure (would revive on restart)")
	}
	st2, err := journal.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	slot2, _ := st2.Get("slot-1")
	if slot2.Ended {
		t.Fatal("disk says Ended after failed persist")
	}
}
