package booking

import (
	"reflect"
	"testing"
)

// Catalogue intersects [owned now, until), describes all configured durations,
// shares cross-coin capacity, returns copies, and never writes ledger state.
func TestCatalogueV2(t *testing.T) {
	f := newLedger(t)
	f.s.cfg.Slots = append(f.s.cfg.Slots, Slot{"expired", "id/old", f.now - 600, f.now - 300, "advance"}, Slot{"started", "id/started", f.now - 1, f.now + 1799, "advance"}, Slot{"short", "id/short", f.now - 1, f.now + 1499, "start_now"}, Slot{"current", "id/current", f.now - 1, f.now + 1799, "start_now"})
	before := f.raw(t)
	c, e := f.s.Catalogue(f.now+3601, 64)
	if e != nil {
		t.Fatal(e)
	}
	if len(c.Slots) != 4 || c.Slots[0].ID != "current" || c.Slots[1].ID != "slot0" || c.Slots[1].NotAfter <= f.now+3601 {
		t.Fatal("window/start filters", c.Slots)
	}
	if !reflect.DeepEqual(c.SlotLengths, []int64{300, 1500, 1800, 3600}) {
		t.Fatal("configured durations", c.SlotLengths)
	}
	if c.PriceUSDCents != 100 || c.PrivacyNotice != PrivacyNotice || c.PrivacySHA256 != Hash([]byte(PrivacyNotice)) {
		t.Fatal("catalogue metadata")
	}
	c.Template.Allowed[0] = "changed"
	c.Slots[0].ID = "changed"
	if f.s.cfg.Template.Allowed[0] != "deliver" {
		t.Fatal("template alias")
	}
	if f.raw(t) != before {
		t.Fatal("catalogue wrote state")
	}
	f.book(t, "slot0", "ltc")
	held, e := f.s.Catalogue(f.now+3601, 64)
	if e != nil {
		t.Fatal(e)
	}
	for _, slot := range held.Slots {
		if slot.ID == "slot0" {
			t.Fatal("held interval advertised")
		}
	}
	limited, e := f.s.Catalogue(f.now+3601, 1)
	if e != nil || len(limited.Slots) != 1 || limited.Slots[0].ID != "current" {
		t.Fatal("limit/order", e)
	}
	for _, v := range []struct {
		until int64
		limit int
	}{{f.now, 1}, {f.now + 7*24*3600 + 1, 1}, {f.now + 1, 0}, {f.now + 1, 65}} {
		before = f.raw(t)
		out, e := f.s.Catalogue(v.until, v.limit)
		if e == nil || e.Error() != "CATALOGUE_BOUNDS" || len(out.Slots) != 0 || f.raw(t) != before {
			t.Fatal("bounds/state", e)
		}
	}
	f.now += 1200
	free, e := f.s.Catalogue(f.now+3601, 64)
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, slot := range free.Slots {
		found = found || slot.ID == "slot0"
	}
	if !found {
		t.Fatal("expired hold still blocks catalogue")
	}
}
