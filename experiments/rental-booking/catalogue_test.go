package booking

import (
	"bytes"
	"testing"
)

// Catalogue is a bounded read-only view: active holds and issued overlaps are
// absent, expiry frees a slot, and caller mutation cannot edit service config.
func TestCatalogue(t *testing.T) {
	f := newFixture(t)
	before := canonical(f.s.state)
	c, e := f.s.Catalogue(f.now+86400, 16)
	if e != nil || len(c.Slots) != 2 || c.Template.ID != "demo" || c.PriceUSDCents != 100 || len(c.SlotLengths) != 1 || c.SlotLengths[0] != 3600 || !bytes.Equal(before, canonical(f.s.state)) {
		t.Fatal("catalogue initial read", e)
	}
	c.Template.Allowed[0] = "changed"
	c.Slots[0].ID = "changed"
	c, e = f.s.Catalogue(f.now+86400, 1)
	if e != nil || len(c.Slots) != 1 || c.Slots[0].ID != "one" || c.Template.Allowed[0] != "deliver" {
		t.Fatal("catalogue alias or bound")
	}
	b := f.book(t, "one")
	before = canonical(f.s.state)
	c, e = f.s.Catalogue(f.now+86400, 16)
	if e != nil || len(c.Slots) != 1 || c.Slots[0].ID != "two" || !bytes.Equal(before, canonical(f.s.state)) {
		t.Fatal("held slot advertised")
	}
	f.now = b.HoldExpiresAt
	c, e = f.s.Catalogue(f.now+86400, 16)
	if e != nil || len(c.Slots) != 2 {
		t.Fatal("expired hold did not free slot")
	}
	f.s.state.Bookings[0].Issuance = &IssuanceRequest{}
	c, e = f.s.Catalogue(f.now+86400, 16)
	if e != nil || len(c.Slots) != 1 {
		t.Fatal("issued overlap advertised")
	}
}

// Invalid windows/limits and poisoned state refuse without partial catalogue;
// valid controls still expose only slots intersecting the bounded future view.
func TestCatalogueBounds(t *testing.T) {
	f := newFixture(t)
	for _, v := range []struct {
		until int64
		limit int
	}{{f.now, 1}, {f.now + 7*86400 + 1, 1}, {f.now + 86400, 0}, {f.now + 86400, 65}} {
		c, e := f.s.Catalogue(v.until, v.limit)
		if e == nil || e.Error() != "CATALOGUE_BOUNDS" || len(c.Slots) != 0 {
			t.Fatal("invalid catalogue bounds admitted")
		}
	}
	c, e := f.s.Catalogue(f.now+100, 16)
	if e != nil || len(c.Slots) != 0 {
		t.Fatal("out-of-window slot advertised")
	}
	f.s.store.poisoned = true
	c, e = f.s.Catalogue(f.now+86400, 16)
	if e == nil || e.Error() != "STATE_UNAVAILABLE" || len(c.Slots) != 0 {
		t.Fatal("poisoned catalogue served")
	}
	f.s.store.poisoned = false
	c, e = f.s.Catalogue(f.now+86400, 16)
	if e != nil || len(c.Slots) != 2 {
		t.Fatal("catalogue neighbor refused")
	}
}

// until bounds the start, not the end; advertised lengths describe the whole
// configured template. Started advance slots, ended slots and start-now slots
// inside the service-owned minimum remaining margin are not offered.
func TestCatalogueWindowPolicy(t *testing.T) {
	f := newFixture(t)
	n := f.now
	f.s.cfg.Slots = []Slot{
		{"straddles", "id/station-a", n + 10, n + 2010, "advance"},
		{"boundary", "id/station-b", n + 20, n + 3020, "advance"},
		{"began", "id/station-c", n, n + 2000, "advance"},
		{"ended", "id/station-d", n - 2000, n, "start_now"},
		{"short", "id/station-e", n - 1000, n + 1499, "start_now"},
		{"enough", "id/station-f", n - 1000, n + 1500, "start_now"},
	}
	c, e := f.s.Catalogue(n+20, 16)
	if e != nil || len(c.Slots) != 2 || c.Slots[0].ID != "enough" || c.Slots[1].ID != "straddles" {
		t.Fatalf("catalogue window/policy selection: %+v %v", c.Slots, e)
	}
	if len(c.SlotLengths) != 4 || c.SlotLengths[0] != 2000 || c.SlotLengths[3] != 3000 {
		t.Fatalf("configured lengths lost: %v", c.SlotLengths)
	}
	if c.Slots[1].NotAfter <= n+20 {
		t.Fatal("valid straddling slot clipped")
	}
}
