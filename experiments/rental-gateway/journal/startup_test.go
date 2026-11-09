package journal_test

import (
	"os"
	"testing"

	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/journal"
)

// Both launch intent and promotion survive reopen through the existing durable
// writer. Invalid transitions leave the record unchanged; an ended launch cannot
// become Started. This verifies persistence, not physical power-loss behavior.
func TestStartupJournalTransitions(t *testing.T) {
	dir := t.TempDir()
	s, err := journal.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Put(testSlot("start", "renter")); err != nil {
		t.Fatal(err)
	}
	if err = s.MarkStarted("start"); err == nil {
		t.Fatal("promotion without intent accepted")
	}
	if err = s.MarkStarting("start"); err == nil {
		t.Fatal("intent without credential accepted")
	}
	if err = s.SetChannelSecret("start", "credential", ""); err != nil {
		t.Fatal(err)
	}
	if err = s.MarkStarting("start"); err != nil {
		t.Fatal(err)
	}
	s, err = journal.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	v, _ := s.Get("start")
	if !v.Starting || v.Started {
		t.Fatal("durable starting lost")
	}
	if err = s.MarkStarting("start"); err == nil {
		t.Fatal("duplicate intent accepted")
	}
	if err = s.MarkStarted("start"); err != nil {
		t.Fatal(err)
	}
	s, err = journal.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	v, _ = s.Get("start")
	if v.Starting || !v.Started {
		t.Fatal("durable promotion lost")
	}
	if err = s.MarkStarting("start"); err == nil {
		t.Fatal("started slot relaunched")
	}
	if err = s.MarkStarted("start"); err == nil {
		t.Fatal("duplicate promotion accepted")
	}
	if err = s.Put(testSlot("ended", "other")); err != nil {
		t.Fatal(err)
	}
	if err = s.SetChannelSecret("ended", "credential", ""); err != nil {
		t.Fatal(err)
	}
	if err = s.MarkStarting("ended"); err != nil {
		t.Fatal(err)
	}
	if err = s.MarkEnded("ended", "closed"); err != nil {
		t.Fatal(err)
	}
	if err = s.MarkStarted("ended"); err == nil {
		t.Fatal("ended slot promoted")
	}
	v, _ = s.Get("ended")
	if !v.Starting || v.Started || !v.Ended {
		t.Fatal("failed promotion changed state")
	}
	if err = s.MarkDestroyed("ended"); err != nil {
		t.Fatal(err)
	}
	v, _ = s.Get("ended")
	if v.Starting || !v.Destroyed {
		t.Fatal("destroyed intent retained")
	}
}

// A failed rename (destination temporarily occupied by a directory) must not
// publish either transition in memory or on disk. Restoring the same record
// allows the valid transition; no permission or root-user assumptions are used.
func TestStartupJournalRollback(t *testing.T) {
	for _, promote := range []bool{false, true} {
		t.Run(map[bool]string{false: "intent", true: "promotion"}[promote], func(t *testing.T) {
			dir := t.TempDir()
			s, err := journal.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			if err = s.Put(testSlot("start", "renter")); err != nil {
				t.Fatal(err)
			}
			if err = s.SetChannelSecret("start", "credential", ""); err != nil {
				t.Fatal(err)
			}
			if promote {
				if err = s.MarkStarting("start"); err != nil {
					t.Fatal(err)
				}
			}
			path := dir + "/slot-start.json"
			if err = os.Rename(path, path+".saved"); err != nil {
				t.Fatal(err)
			}
			if err = os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			mark := s.MarkStarting
			if promote {
				mark = s.MarkStarted
			}
			if err = mark("start"); err == nil {
				t.Fatal("failed write reported success")
			}
			v, _ := s.Get("start")
			if v.Starting != promote || v.Started {
				t.Fatal("failed write changed memory")
			}
			if err = os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err = os.Rename(path+".saved", path); err != nil {
				t.Fatal(err)
			}
			disk, err := journal.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			v, _ = disk.Get("start")
			if v.Starting != promote || v.Started {
				t.Fatal("failed write changed durable record")
			}
			if err = mark("start"); err != nil {
				t.Fatal(err)
			}
		})
	}
}
