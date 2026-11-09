package booking

import "sort"

// Catalogue is a read-only snapshot, not a reservation. Book rechecks availability.
// It contains no renter keys, payment addresses or private booking metadata.
type Catalogue struct {
	Template       Template `json:"template"`
	TemplateSHA256 string   `json:"template_sha256"`
	PriceUSDCents  int64    `json:"price_usd_cents"`
	SlotLengths    []int64  `json:"slot_lengths"`
	Slots          []Slot   `json:"slots"`
	PrivacyNotice  string   `json:"privacy_notice"`
	PrivacySHA256  string   `json:"privacy_sha256"`
}

// Catalogue returns at most limit free slots intersecting [now, until), ordered
// by start then ID. The clock is service-owned; callers cannot retime eligibility.
func (s *Service) Catalogue(until int64, limit int) (Catalogue, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock().Unix()
	if now < 0 || until <= now || until-now > 7*86400 || limit < 1 || limit > 64 {
		return Catalogue{}, refuse("CATALOGUE_BOUNDS")
	}
	if s.store.poisoned {
		return Catalogue{}, refuse("STATE_UNAVAILABLE")
	}
	c := Catalogue{Template: s.cfg.Template, TemplateSHA256: s.cfg.TemplateSHA256, PriceUSDCents: s.cfg.PriceUSDCents, SlotLengths: []int64{}, Slots: []Slot{}, PrivacyNotice: PrivacyNotice, PrivacySHA256: Hash([]byte(PrivacyNotice))}
	c.Template.Allowed = append([]string{}, c.Template.Allowed...)
	c.Template.Forbidden = append([]string{}, c.Template.Forbidden...)
	lengths := map[int64]bool{}
	for _, slot := range s.cfg.Slots {
		lengths[slot.NotAfter-slot.NotBefore] = true
		if slot.NotBefore >= until || slot.NotAfter <= now || (slot.PaymentPolicy == "advance" && slot.NotBefore <= now) || s.startWindowClosed(slot, now) {
			continue
		}
		busy := false
		for _, b := range s.state.Bookings {
			if b.Contract.StationName == slot.StationName && b.Contract.NotBefore < slot.NotAfter && slot.NotBefore < b.Contract.NotAfter && (b.HoldExpiresAt > now || b.Issuance != nil) {
				busy = true
				break
			}
		}
		if !busy {
			c.Slots = append(c.Slots, slot)
		}
	}
	for n := range lengths {
		c.SlotLengths = append(c.SlotLengths, n)
	}
	sort.Slice(c.SlotLengths, func(i, j int) bool { return c.SlotLengths[i] < c.SlotLengths[j] })
	sort.Slice(c.Slots, func(i, j int) bool {
		a, b := c.Slots[i], c.Slots[j]
		if a.NotBefore == b.NotBefore {
			return a.ID < b.ID
		}
		return a.NotBefore < b.NotBefore
	})
	if len(c.Slots) > limit {
		c.Slots = c.Slots[:limit]
	}
	return c, nil
}
