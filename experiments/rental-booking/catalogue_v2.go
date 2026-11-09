package booking

import "sort"

// CatalogueV2 is an advisory, detached snapshot. Signed terms and payment
// addresses are created only by Book's atomic interval/index reservation.
type CatalogueV2 struct {
	Template       Template `json:"template"`
	TemplateSHA256 string   `json:"template_sha256"`
	PriceUSDCents  int64    `json:"price_usd_cents"`
	SlotLengths    []int64  `json:"slot_lengths"`
	Slots          []Slot   `json:"slots"`
	PrivacyNotice  string   `json:"privacy_notice"`
	PrivacySHA256  string   `json:"privacy_sha256"`
}

func (s *ServiceV2) Catalogue(until int64, limit int) (CatalogueV2, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now, e := s.nowV2()
	if e != nil {
		return CatalogueV2{}, e
	}
	if until <= now || until-now > 7*24*3600 || limit < 1 || limit > 64 {
		return CatalogueV2{}, refuse("CATALOGUE_BOUNDS")
	}
	t := s.cfg.Template
	t.Allowed = append([]string{}, t.Allowed...)
	t.Forbidden = append([]string{}, t.Forbidden...)
	out := CatalogueV2{Template: t, TemplateSHA256: s.cfg.TemplateSHA256, PriceUSDCents: s.cfg.PriceUSDCents, SlotLengths: []int64{}, Slots: []Slot{}, PrivacyNotice: PrivacyNotice, PrivacySHA256: Hash([]byte(PrivacyNotice))}
	lengths := map[int64]bool{}
	for _, slot := range s.cfg.Slots {
		lengths[slot.NotAfter-slot.NotBefore] = true
		// Until bounds the start, not the end. A start-now slot can intersect the
		// window even though it started before now. All other Book filters apply.
		if slot.NotBefore < until && slot.NotAfter > now && s.slotAvailableV2(slot, now) == nil {
			out.Slots = append(out.Slots, slot)
		}
	}
	for length := range lengths {
		out.SlotLengths = append(out.SlotLengths, length)
	}
	sort.Slice(out.SlotLengths, func(i, j int) bool { return out.SlotLengths[i] < out.SlotLengths[j] })
	sort.Slice(out.Slots, func(i, j int) bool {
		a, b := out.Slots[i], out.Slots[j]
		if a.NotBefore != b.NotBefore {
			return a.NotBefore < b.NotBefore
		}
		return a.ID < b.ID
	})
	if len(out.Slots) > limit {
		out.Slots = out.Slots[:limit]
	}
	return out, nil
}
