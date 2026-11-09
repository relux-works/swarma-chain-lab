package booking

import "bytes"

// signerItem is SG1's wire envelope, not signer authority. Request/publication
// are JSON strings so decoding the outer object preserves the signed bytes.
// Keep this dependency one-way: SG1 consumes booking and validates these fields.
type signerItem struct {
	ID          string           `json:"id"`
	Kind        string           `json:"kind"`
	Request     string           `json:"request,omitempty"`
	Publication string           `json:"publication,omitempty"`
	Revoke      *RevokeRequestV2 `json:"revoke,omitempty"`
}

const outboxIndexBound = 4096

// exportV2 runs under the booking lock (or exclusive startup lock). Immutable
// artifacts reach durable storage before the atomic index commit. Interrupted
// exports may leave unindexed files, which a replay checks and reuses.
func (s *ServiceV2) exportV2() error {
	desired := map[string][]byte{}
	order := []string{}
	artifacts := map[string][]byte{}
	for _, b := range s.state.Bookings {
		id := b.Contract.BookingID
		for _, a := range []struct {
			name    string
			present bool
			value   any
		}{
			{"package", b.Package != nil, b.Package},
			{"package-event", b.PackageEvent != nil, b.PackageEvent},
			{"issue", b.Issuance != nil, b.Issuance},
			{"revoke", b.Revoke != nil, b.Revoke},
		} {
			if a.present {
				artifacts[a.name+"-"+id+".json"] = canonical(a.value)
			}
		}
		items := []signerItem{}
		if b.Issuance != nil {
			if b.PackageEvent == nil {
				return refuse("OUTBOX_ITEM")
			}
			items = append(items, signerItem{ID: Hash([]byte("grant-issue/" + id)), Kind: "grant-issue", Request: string(canonical(b.Issuance)), Publication: string(canonical(b.PackageEvent))})
		}
		if b.Revoke != nil {
			items = append(items, signerItem{ID: Hash([]byte("revoke/" + id)), Kind: "revoke", Revoke: b.Revoke})
		}
		for _, item := range items {
			raw := canonical(item)
			if len(raw) > 65536 {
				return refuse("OUTBOX_BOUND")
			}
			h := Hash(raw)
			if _, ok := desired[h]; ok {
				return refuse("OUTBOX_CONFLICT")
			}
			desired[h] = raw
			order = append(order, h)
		}
	}
	if len(order) > outboxIndexBound {
		return refuse("OUTBOX_BOUND")
	}
	index := []string{}
	old, e := s.store.read("index.json", 1<<20)
	if e != nil {
		return e
	}
	if old != nil && (Strict(old, &index) != nil || index == nil || len(index) > outboxIndexBound) {
		return refuse("OUTBOX_INDEX")
	}
	seen := map[string]bool{}
	for _, h := range index {
		if !hexSize(h, 32) || seen[h] {
			return refuse("OUTBOX_INDEX")
		}
		seen[h] = true
		raw, ok := desired[h]
		if !ok {
			return refuse("OUTBOX_CONFLICT")
		}
		stored, e := s.store.read(h+".json", 65536)
		if e != nil {
			return e
		}
		if !bytes.Equal(stored, raw) {
			return refuse("OUTBOX_CONFLICT")
		}
	}
	// Preserve the entire old prefix: an older hold may become eligible after a
	// newer one. Re-sorting the ledger on every export would invalidate cursors.
	for _, h := range order {
		if !seen[h] {
			index = append(index, h)
		}
	}
	for name, raw := range artifacts {
		if e := s.store.write(name, raw, true); e != nil {
			return e
		}
	}
	for _, h := range order {
		if e := s.store.write(h+".json", desired[h], true); e != nil {
			return e
		}
	}
	next := canonical(index)
	if bytes.Equal(old, next) {
		return nil
	}
	return s.store.write("index.json", next, false)
}
