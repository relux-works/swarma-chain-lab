package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Atomic public publication becomes visible without writing through the source;
// absent files mean pending, while traversal/symlink/oversize/writable files and
// cancelled calls refuse. Content authenticity remains bookingbind's obligation.
func TestPresentationDirectory(t *testing.T) {
	root := testRoot(t)
	p, e := openPresentations(root)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	id := strings.Repeat("a", 64)
	if b, e := p.Presentation(context.Background(), id); e != nil || b != nil {
		t.Fatal("absent not pending")
	}
	if _, e := p.Presentation(context.Background(), "../outside"); e == nil {
		t.Fatal("traversal accepted")
	}
	name := filepath.Join(root, id+".json")
	tmp := filepath.Join(root, "pending")
	os.WriteFile(tmp, []byte("public proof"), 0640)
	os.Rename(tmp, name)
	if b, e := p.Presentation(context.Background(), id); e != nil || string(b) != "public proof" {
		t.Fatal("atomic publication not read")
	}
	before, _ := os.ReadFile(name)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := p.Presentation(ctx, id); e == nil {
		t.Fatal("cancel accepted")
	}
	after, _ := os.ReadFile(name)
	if string(before) != string(after) {
		t.Fatal("source mutated")
	}
	os.Remove(name)
	if e := os.WriteFile(tmp, []byte("public proof"), 0640); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(filepath.Base(tmp), name); e != nil {
		t.Fatal(e)
	}
	if _, e := p.Presentation(context.Background(), id); e == nil {
		t.Fatal("symlink accepted")
	}
	os.Remove(name)
	os.WriteFile(name, []byte(strings.Repeat("x", 16385)), 0640)
	if _, e := p.Presentation(context.Background(), id); e == nil {
		t.Fatal("oversize accepted")
	}
	os.WriteFile(name, []byte("public proof"), 0640)
	os.Chmod(name, 0666)
	if _, e := p.Presentation(context.Background(), id); e == nil {
		t.Fatal("writable proof accepted")
	}
	alias := filepath.Join(testRoot(t), "alias")
	os.Symlink(root, alias)
	if _, e := openPresentations(alias); e == nil {
		t.Fatal("directory symlink accepted")
	}
}
