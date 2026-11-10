package nostr

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

// Real nested encryption at maximum timestamp width independently verifies the
// preflight's full-event size, both NIP44 limits and two explicit relay caps.
func TestDeliveryReplySize(t *testing.T) {
	sender, e := GeneratePrivKey()
	if e != nil {
		t.Fatal(e)
	}
	renter, e := GeneratePrivKey()
	if e != nil {
		t.Fatal(e)
	}
	tags := [][]string{{"e", strings.Repeat("d", 64)}}
	for _, tc := range []struct {
		name, text           string
		nipFits, defaultFits bool
	}{
		{"fitting", strings.Repeat("a", 24000), true, true},
		{"plain", strings.Repeat("a", 32768), true, false},
		{"unicode", strings.Repeat("я", 16384), true, false},
		{"quotes", strings.Repeat(`"`, 32768), false, false},
		{"html", strings.Repeat("<", 32768), false, false},
		{"seal-overflow", strings.Repeat("<", 1600) + strings.Repeat("a", 31168), false, false},
		{"backslash", strings.Repeat(`\`, 32768), false, false},
		{"control", strings.Repeat("\x01", 8192), false, false},
		{"line-separator", strings.Repeat("\u2028", 10922), false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, _, e := WrapDM(sender, renter.PubKeyHex(), tc.text, tags, math.MaxInt64)
			if (e == nil) != tc.nipFits {
				t.Fatal("real NIP44 witness mismatch", e)
			}
			if e == nil {
				raw, _ := json.Marshal(w)
				n, ok := deliveryEventSize(tc.text)
				if !ok || n != len(raw) {
					t.Fatal("full wrapped event size mismatch", n, len(raw))
				}
			}
			for _, cap := range []int{65536, 131072} {
				wantFit := tc.nipFits
				if cap == 65536 {
					wantFit = tc.defaultFits
				}
				normalized := BoundDeliveryReply(tc.text, cap)
				if (normalized == tc.text) != wantFit {
					t.Fatal("delivery relay bound mismatch", cap)
				}
				w, _, e := WrapDM(sender, renter.PubKeyHex(), normalized, tags, math.MaxInt64)
				if e != nil {
					t.Fatal("bounded neighbor did not wrap", e)
				}
				raw, _ := json.Marshal(w)
				if len(raw) > cap {
					t.Fatal("bounded event exceeds relay cap")
				}
				dm, e := UnwrapDM(w, renter)
				if e != nil || dm.Rumor.Content != normalized {
					t.Fatal("bounded neighbor changed", e)
				}
			}
		})
	}
	// Adjacent plaintext lengths at the default relay's actual padding boundary.
	lo, hi := 0, 32768
	for lo+1 < hi {
		mid := (lo + hi) / 2
		s := strings.Repeat("a", mid)
		if BoundDeliveryReply(s, 65536) == s {
			lo = mid
		} else {
			hi = mid
		}
	}
	for _, n := range []int{lo, hi} {
		w, _, e := WrapDM(sender, renter.PubKeyHex(), strings.Repeat("a", n), tags, math.MaxInt64)
		if e != nil {
			t.Fatal(e)
		}
		raw, _ := json.Marshal(w)
		if (len(raw) <= 65536) != (n == lo) {
			t.Fatal("relay padding neighbor mismatch", n, len(raw))
		}
	}
	t.Logf("maximum reserved-metadata plain bytes at cap65536: %d", lo)
	for _, s := range []string{strings.Repeat("a", 32769), string([]byte{0xff})} {
		if BoundDeliveryReply(s, 65536) != DeliverySizeNotice {
			t.Fatal("invalid delivery text escaped")
		}
	}
	n, ok := deliveryEventSize(DeliverySizeNotice)
	if !ok || !ValidDeliveryEventLimit(n) || ValidDeliveryEventLimit(n-1) || ValidDeliveryEventLimit(0) || ValidDeliveryEventLimit(131073) || !ValidDeliveryEventLimit(131072) {
		t.Fatal("relay cap validation missing")
	}
}
