package screen

import (
	"context"
	"testing"
)

// Explicit off permits content independently of text but honors cancellation;
// it says nothing about grant authority, which is checked before screening.
func TestOff(t *testing.T) {
	s := Off{}
	if d, e := s.Screen(context.Background(), "any text"); e != nil || !d.Allow {
		t.Fatal("off refused")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if d, e := s.Screen(ctx, "any text"); e == nil || d.Allow {
		t.Fatal("cancel allowed")
	}
}
