//go:build darwin || linux

package singleuse

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The journal preserves a reservation across reopen, excludes a concurrent
// writer, and rejects unsafe state files without changing their contents.
func TestJournalExtractionContract(t *testing.T) {
	root := t.TempDir()
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	p := Policy{StateDir: root, Genesis: RegtestGenesis, Seal: Point{TxID: strings.Repeat("1", 64)}}
	j, e := openJournal(p)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := openJournal(p); publicError(e) != "EXECUTOR_BUSY" {
		t.Fatalf("lock: %v", e)
	}
	r := journalRecord{1, strings.Repeat("2", 64), strings.Repeat("3", 64), strings.Repeat("4", 64), "reserved"}
	if e := j.write(r); e != nil {
		t.Fatal(e)
	}
	j.close()
	j, e = openJournal(p)
	if e != nil {
		t.Fatal(e)
	}
	defer j.close()
	got, e := j.read()
	if e != nil || got == nil || *got != r {
		t.Fatalf("reopen: %+v %v", got, e)
	}
	original, e := os.ReadFile(j.path)
	if e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(j.path, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e := j.read(); publicError(e) != "JOURNAL_FILE" {
		t.Fatalf("permissions: %v", e)
	}
	if e := os.Chmod(j.path, 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Rename(j.path, filepath.Join(root, "saved")); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(filepath.Join(root, "saved"), j.path); e != nil {
		t.Fatal(e)
	}
	if _, e := j.read(); publicError(e) != "JOURNAL_FILE" {
		t.Fatalf("symlink: %v", e)
	}
	after, e := os.ReadFile(filepath.Join(root, "saved"))
	if e != nil || string(original) != string(after) {
		t.Fatal("unsafe read mutated state")
	}
}
