//go:build darwin || linux

package durable

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// Sixteen simultaneous first opens of one absent lock either acquire the same
// inode or report STATE_BUSY. The winner holds its lock until every attempt
// returns: a second successful holder or a creation error is a failure.
func TestConcurrentFirstOpen(t *testing.T) {
	root := t.TempDir()
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	type result struct {
		s *Store
		e error
	}
	results := make(chan result, 16)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for i := 0; i < 16; i++ {
		workers.Add(1)
		go func() { defer workers.Done(); <-start; s, e := Open(root, "lock"); results <- result{s, e} }()
	}
	close(start)
	workers.Wait()
	close(results)
	winners := 0
	for r := range results {
		if r.e == nil {
			winners++
			defer r.s.Close()
		} else if r.e.Error() != "STATE_BUSY" {
			t.Errorf("unexpected refusal: %v", r.e)
		}
	}
	if winners != 1 {
		t.Fatalf("lock holders=%d, want 1", winners)
	}
}

// Reopen preserves committed bytes; concurrent access, traversal, symlinks,
// hardlinks and unsafe modes are refused without changing the target.
func TestStorageBoundary(t *testing.T) {
	root := t.TempDir()
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	s, e := Open(root, "state.lock")
	if e != nil {
		t.Fatal(e)
	}
	if _, e := Open(root, "state.lock"); e == nil || e.Error() != "STATE_BUSY" {
		t.Fatal(e)
	}
	if e := s.Write("record", []byte("reserved")); e != nil {
		t.Fatal(e)
	}
	s.Close()
	s, e = Open(root, "state.lock")
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	b, e := s.Read("record", 100)
	if e != nil || string(b) != "reserved" {
		t.Fatal(string(b), e)
	}
	if b, e := s.Read("missing", 100); e != nil || b != nil {
		t.Fatal(e)
	}
	for _, n := range []string{"../outside", ".", "/absolute"} {
		if e := s.Write(n, []byte("bad")); e == nil {
			t.Fatal("path accepted")
		}
	}
	path := filepath.Join(root, "record")
	if e := os.Symlink(path, filepath.Join(root, "link")); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Read("link", 100); e == nil || e.Error() != "JOURNAL_FILE" {
		t.Fatal(e)
	}
	if e := s.Write("link", []byte("bad")); e == nil || e.Error() != "JOURNAL_FILE" {
		t.Fatal(e)
	}
	if e := os.Link(path, filepath.Join(root, "hard")); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Read("record", 100); e == nil || e.Error() != "JOURNAL_FILE" {
		t.Fatal(e)
	}
	if e := os.Remove(filepath.Join(root, "hard")); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(path, 0644); e != nil {
		t.Fatal(e)
	}
	if e := s.Write("record", []byte("bad")); e == nil || e.Error() != "JOURNAL_FILE" {
		t.Fatal(e)
	}
	b, e = os.ReadFile(path)
	if e != nil || string(b) != "reserved" {
		t.Fatal("target changed")
	}
}

// Injected sync errors prove the API never reports commit success before file
// and directory sync. This checks failure handling/order on real temp files;
// it is not a physical power-loss test of the filesystem or storage hardware.
func TestSyncFailureBoundary(t *testing.T) {
	root := t.TempDir()
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	s, e := Open(root, "lock")
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if e = s.Write("record", []byte("before")); e != nil {
		t.Fatal(e)
	}
	called := 0
	s.syncFile = func(f *os.File) error {
		called++
		b, e := os.ReadFile(filepath.Join(root, "record"))
		if e != nil || string(b) != "before" {
			t.Fatal("renamed before file sync")
		}
		return errors.New("injected sync failure")
	}
	if e = s.Write("record", []byte("after")); e == nil || e.Error() != "JOURNAL_FSYNC" || called != 1 {
		t.Fatal(e, called)
	}
	b, e := s.Read("record", 100)
	if e != nil || string(b) != "before" {
		t.Fatal("failed file sync replaced record")
	}
	s.syncFile = (*os.File).Sync
	s.syncDirectory = func(string) error { called++; return errors.New("injected directory sync failure") }
	if e = s.Write("record", []byte("uncertain")); e == nil || e.Error() != "JOURNAL_COMMIT" || called != 2 {
		t.Fatal(e, called)
	}
	b, e = s.Read("record", 100)
	if e != nil || string(b) != "uncertain" {
		t.Fatal("uncertain rename lost")
	}
	s.syncDirectory = SyncDir
	if e = s.Write("record", []byte("committed")); e != nil {
		t.Fatal(e)
	}
	b, e = s.Read("record", 100)
	if e != nil || string(b) != "committed" {
		t.Fatal("positive recovery")
	}
}
