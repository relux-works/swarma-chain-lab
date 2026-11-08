package executor

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func prizes() map[string]string {
	return map[string]string{strings.Repeat("1", 64): hex.EncodeToString(testKey(20).Serialize()), strings.Repeat("2", 64): hex.EncodeToString(testKey(21).Serialize())}
}

// Unknown, cross-slot and revoked tokens cannot release a key; a valid token
// can. Revocation survives restart, and raw token/key bytes never enter state.
func TestTrackBControls(t *testing.T) {
	root := rootDir(t)
	b, e := OpenTrackB(root, "regtest", prizes())
	if e != nil {
		t.Fatal(e)
	}
	a := strings.Repeat("1", 64)
	other := strings.Repeat("2", 64)
	tok, e := b.Mint(a)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = b.Mint(a); e == nil || e.Error() != "TOKEN_EXISTS" {
		t.Fatal(e)
	}
	if key, e := b.Claim(a, tok); e != nil || key != prizes()[a] {
		t.Fatal("valid claim failed")
	}
	for _, v := range [][2]string{{other, tok}, {a, strings.Repeat("0", 64)}, {a, ""}, {strings.Repeat("4", 64), tok}} {
		if key, e := b.Claim(v[0], v[1]); e == nil || e.Error() != "TOKEN_REFUSED" || key != "" {
			t.Fatal("invalid token released key")
		}
	}
	if e = b.Revoke(a); e != nil {
		t.Fatal(e)
	}
	if key, e := b.Claim(a, tok); e == nil || e.Error() != "TOKEN_REFUSED" || key != "" {
		t.Fatal("revoked key")
	}
	b.Close()
	b, e = OpenTrackB(root, "regtest", prizes())
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	if _, e = b.Claim(a, tok); e == nil {
		t.Fatal("revoked after restart")
	}
	if _, e = b.Mint(a); e == nil {
		t.Fatal("resurrection")
	}
	tok2, e := b.Mint(other)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = b.Claim(other, tok2); e != nil {
		t.Fatal(e)
	}
	list, e := b.List()
	if e != nil || len(list) != 2 || !list[0].Revoked || list[1].Revoked {
		t.Fatal("list")
	}
	raw, e := os.ReadFile(filepath.Join(root, "trackb.json"))
	if e != nil {
		t.Fatal(e)
	}
	for _, secret := range []string{tok, tok2, prizes()[a], prizes()[other]} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("secret persisted in audit")
		}
	}
	if len(b.state.Audit) != 14 {
		t.Fatalf("audit calls %d", len(b.state.Audit))
	}
}

// A persistence failure prevents key release and poisons subsequent operations;
// no retry can use mutated in-memory state after an uncertain commit.
func TestTrackBAuditFailure(t *testing.T) {
	root := rootDir(t)
	b, e := OpenTrackB(root, "regtest", prizes())
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	slot := strings.Repeat("1", 64)
	token, e := b.Mint(slot)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = b.Claim(slot, token); e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(filepath.Join(root, "trackb.json"), 0644); e != nil {
		t.Fatal(e)
	}
	if key, e := b.Claim(slot, token); e == nil || key != "" {
		t.Fatal("release without audit")
	}
	if !b.store.poison {
		t.Fatal("not poisoned")
	}
	if _, e = b.Mint(strings.Repeat("2", 64)); e == nil {
		t.Fatal("poison ignored")
	}
}

// Concurrent mints produce exactly one token and one live record, not rotations.
func TestTrackBConcurrentMint(t *testing.T) {
	b, e := OpenTrackB(rootDir(t), "regtest", prizes())
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	var wg sync.WaitGroup
	ok := make(chan bool, 16)
	for range 16 {
		wg.Go(func() {
			_, e := b.Mint(strings.Repeat("1", 64))
			if e != nil && e.Error() != "TOKEN_EXISTS" {
				t.Error(e)
			}
			ok <- e == nil
		})
	}
	wg.Wait()
	close(ok)
	n := 0
	for v := range ok {
		if v {
			n++
		}
	}
	if n != 1 || len(b.state.Tokens) != 1 || len(b.state.Audit) != 16 {
		t.Fatal("mint race")
	}
}
