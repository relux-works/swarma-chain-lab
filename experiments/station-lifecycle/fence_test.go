package lifecycle

import (
	"strconv"
	"strings"
	"testing"
)

// Canonical boot identity/uint64 timestamps and overflow-safe elapsed comparisons
// reject aliases, early probes and same-boot regression; reboot invalidates old work.
func TestCreateFence(t *testing.T) {
	f := CreateFence{BootID: "0f8e1c3a-6b2d-4e7f-9a1b-2c3d4e5f6a7b", IssuedBoottimeNS: "10000000000"}
	if !f.Valid() {
		t.Fatal("valid fence rejected")
	}
	for _, raw := range []string{"", "01", "-1", "1.0", "18446744073709551616", "100000000000000000000"} {
		b := f
		b.IssuedBoottimeNS = raw
		if b.Valid() {
			t.Fatal("noncanonical timestamp accepted")
		}
	}
	for _, raw := range []string{"", strings.ToUpper(f.BootID), strings.ReplaceAll(f.BootID, "-", "")} {
		b := f
		b.BootID = raw
		if b.Valid() {
			t.Fatal("noncanonical boot accepted")
		}
	}
	for _, n := range []uint64{0, 9_000_000_000, 15_000_000_000, 15_999_999_999} {
		now := f
		now.IssuedBoottimeNS = strconv.FormatUint(n, 10)
		if f.Elapsed(now) {
			t.Fatal("early or regressed clock proved absence")
		}
	}
	now := f
	now.IssuedBoottimeNS = "16000000000"
	if !f.Elapsed(now) {
		t.Fatal("six-second fence not released")
	}
	now.BootID = "1f8e1c3a-6b2d-4e7f-9a1b-2c3d4e5f6a7b"
	now.IssuedBoottimeNS = "1"
	if !f.Elapsed(now) {
		t.Fatal("reboot did not invalidate old request")
	}
	f.IssuedBoottimeNS = "18446744073709551615"
	now = f
	if !f.Valid() || f.Elapsed(now) {
		t.Fatal("overflow weakened fence")
	}
	now.BootID = "invalid"
	if f.Elapsed(now) {
		t.Fatal("invalid clock proved absence")
	}
}
