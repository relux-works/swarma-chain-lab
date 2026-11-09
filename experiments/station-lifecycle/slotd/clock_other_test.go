//go:build !linux

package slotd

import "testing"

// Production never substitutes a wall/process clock when Linux boot identity
// is unavailable. Tests of r4 use only explicit injected clocks.
func TestNoBootClockFallback(t *testing.T) {
	if _, e := SystemBootClock(); e == nil || e.Error() != "SLOTD_LINUX_ONLY" {
		t.Fatal("non-Linux clock fallback", e)
	}
}
