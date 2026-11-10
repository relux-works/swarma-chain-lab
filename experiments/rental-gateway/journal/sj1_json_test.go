package journal_test

import (
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/journal"
	"os"
	"path/filepath"
	"testing"
)

// Restart refuses ambiguous slot authority without returning a store or changing
// any durable bytes. The adjacent unambiguous record still loads.
func TestSJ1JournalKeys(t *testing.T) {
	valid := `{"id":"slot-1","renter_pubkey":"aa","seen_rumor_ids":null,"operations":null}`
	for _, raw := range []string{`{"id":"slot-1","id":"","renter_pubkey":"aa"}`, `{"id":"","id":"slot-1","renter_pubkey":"aa"}`, `{"id":"slot-1","i\u0064":"slot-2"}`, `{"i\u0064":"slot-1","renter_pubkey":"aa"}`, `{"ID":"slot-1","renter_pubkey":"aa"}`, `{"id":"slot-1","operations":[{"Op_id":"x"}]}`} {
		dir := t.TempDir()
		path := filepath.Join(dir, "slot-1.json")
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if s, err := journal.Open(dir); err == nil || s != nil {
			t.Fatal("SJ1 ambiguous journal admitted")
		}
		got, err := os.ReadFile(path)
		if err != nil || string(got) != raw {
			t.Fatal("refusal rewrote journal", err)
		}
		files, err := os.ReadDir(dir)
		if err != nil || len(files) != 1 {
			t.Fatal("refusal added files", err)
		}
		if err := os.WriteFile(path, []byte(valid), 0600); err != nil {
			t.Fatal(err)
		}
		s, err := journal.Open(dir)
		if err != nil {
			t.Fatal("valid neighbor refused", err)
		}
		if _, ok := s.Get("slot-1"); !ok {
			t.Fatal("valid slot missing")
		}
	}
}
