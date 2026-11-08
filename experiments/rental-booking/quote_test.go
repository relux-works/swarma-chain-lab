package booking

import (
	"math"
	"testing"
)

// Exact integer quotes round up by one atom when needed; stale, future,
// nonpositive and overflowing inputs cannot produce a payable booking quote.
func TestQuoteGuards(t *testing.T) {
	q, e := NewQuote(100, 3000000, 1000, 60, 1060)
	if e != nil || q.PriceNMCSat != 33333334 {
		t.Fatalf("round up: %+v %v", q, e)
	}
	for _, tc := range []struct {
		name                          string
		cents, micros, asof, age, now int64
		code                          string
	}{
		{"stale", 100, 3000000, 1000, 60, 1061, "QUOTE_RATE"},
		{"future", 100, 3000000, 1061, 60, 1060, "QUOTE_RATE"},
		{"zero_rate", 100, 0, 1000, 60, 1060, "QUOTE_RATE"},
		{"negative_price", -1, 3000000, 1000, 60, 1060, "QUOTE_RATE"},
		{"zero_max_age", 100, 3000000, 1000, 0, 1060, "QUOTE_RATE"},
		{"overflow", math.MaxInt64, 1, 1000, 60, 1060, "QUOTE_AMOUNT"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, e := NewQuote(tc.cents, tc.micros, tc.asof, tc.age, tc.now)
			if e == nil || e.Error() != tc.code || out != (Quote{}) {
				t.Fatalf("refusal/state: %+v %v", out, e)
			}
			if _, e = NewQuote(100, 1000000, 1000, 60, 1060); e != nil {
				t.Fatal(e)
			}
		})
	}
}
