package executor

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func rootDir(t *testing.T) string {
	t.Helper()
	p, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(p, 0700); err != nil {
		t.Fatal(err)
	}
	return p
}

// Parallel first creation yields one lifetime lock owner and STATE_BUSY for
// competitors; no accidental ENOENT or concurrent writer is admitted.
func TestConcurrentStoreCreation(t *testing.T) {
	root := rootDir(t)
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make(chan *store, 24)
	errs := make(chan error, 24)
	for range 24 {
		wg.Go(func() { <-start; s, e := openStore(root); results <- s; errs <- e })
	}
	close(start)
	wg.Wait()
	close(results)
	close(errs)
	winners := 0
	for s := range results {
		if s != nil {
			winners++
			defer s.close()
		}
	}
	if winners != 1 {
		t.Fatalf("writers=%d", winners)
	}
	for e := range errs {
		if e != nil && e.Error() != "STATE_BUSY" {
			t.Fatal(e)
		}
	}
}

// A durable write survives reopen; weak permissions and symlink state files
// refuse, preserving the target file. A poisoned handle cannot read or write.
func TestStoreBoundaries(t *testing.T) {
	root := rootDir(t)
	s, e := openStore(root)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.write("state.json", []byte("{}")); e != nil {
		t.Fatal(e)
	}
	s.close()
	s, e = openStore(root)
	if e != nil {
		t.Fatal(e)
	}
	defer s.close()
	b, e := s.read("state.json")
	if e != nil || string(b) != "{}" {
		t.Fatalf("%q %v", b, e)
	}
	if e = os.Chmod(filepath.Join(root, "state.json"), 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = s.read("state.json"); e == nil || e.Error() != "STATE_FILE" {
		t.Fatal(e)
	}
	if e = os.Symlink(filepath.Join(root, "state.json"), filepath.Join(root, "alias")); e != nil {
		t.Fatal(e)
	}
	if e = s.write("alias", []byte("replace")); e == nil {
		t.Fatal("symlink accepted")
	}
	b, _ = os.ReadFile(filepath.Join(root, "state.json"))
	if string(b) != "{}" {
		t.Fatal("target mutated")
	}
	s.poison = true
	if e = s.write("fresh", nil); e == nil {
		t.Fatal("poison write")
	}
}
