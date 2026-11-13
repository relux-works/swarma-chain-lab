package executor

import (
	"strings"
	"testing"
)

// Each mint refusal returns an erased token, beside a usable opaque mint/claim.
func TestN1bMintRefusalClearsCredential(t *testing.T) {
	b, e := OpenTrackB(rootDir(t), "regtest", prizes())
	if e != nil {
		t.Fatal("mint fixture refused")
	}
	defer b.Close()
	slot := strings.Repeat("1", 64)
	token, e := b.Mint(slot)
	if e != nil || token.IsZero() {
		t.Fatal("mint positive control refused")
	}
	if _, e = b.Claim(slot, token); e != nil {
		t.Fatal("minted credential unusable")
	}
	for _, tc := range []struct{ slot, reason string }{{slot, "TOKEN_EXISTS"}, {strings.Repeat("f", 64), "UNKNOWN_SLOT"}} {
		refused, e := b.Mint(tc.slot)
		if e == nil || e.Error() != tc.reason || !refused.IsZero() || refused.Reveal() != "" {
			t.Fatal("mint refusal retained credentials")
		}
	}
	b.store.poison = true
	refused, e := b.Mint(slot)
	if e == nil || e.Error() != "TRACKB_UNAVAILABLE" || !refused.IsZero() {
		t.Fatal("unavailable mint retained credentials")
	}
}
