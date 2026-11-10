package journal

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"unicode/utf8"

	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
)

var ErrDelivery = errors.New("journal: delivery refused")

const MaxDeliveries = 1024

// Delivery binds admitted input, station receipt and the immutable signed outbox.
// Screening-in-progress is never dispatched after a crash; the outcome is uncertain.
// Records are retained with the existing slot journal, including after slot end.
type Delivery struct {
	Checksum  string          `json:"checksum"`
	ID        string          `json:"id"`
	Input     string          `json:"input"`
	InputHash string          `json:"input_hash"`
	Phase     string          `json:"phase"`
	Reply     string          `json:"reply"`
	Wire      json.RawMessage `json:"wire,omitempty"`
}

const (
	DeliveryScreening = "screening"
	DeliveryQueued    = "queued"
	DeliveryReceived  = "received"
	DeliveryReady     = "ready"
	DeliveryAccepted  = "relay-accepted"
	DeliveryRefused   = "refused"
)

func hashText(s string) string { b := sha256.Sum256([]byte(s)); return hex.EncodeToString(b[:]) }
func deliveryID(id string) bool {
	b, e := hex.DecodeString(id)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == id
}

func deliveryChecksum(d Delivery) string {
	d.Checksum = ""
	raw, _ := json.Marshal(d)
	return hashText(string(raw))
}

func validDeliveries(slot *Slot) bool {
	if len(slot.Deliveries) > MaxDeliveries {
		return false
	}
	seen := map[string]bool{}
	for _, d := range slot.Deliveries {
		if d.Checksum != deliveryChecksum(d) || !deliveryID(d.ID) || seen[d.ID] || !slot.HasSeen(d.ID) || !utf8.ValidString(d.Input) || len(d.Input) > 65535 || d.InputHash != hashText(d.Input) || !utf8.ValidString(d.Reply) || len(d.Reply) > 32768 {
			return false
		}
		seen[d.ID] = true
		switch d.Phase {
		case DeliveryScreening, DeliveryQueued, DeliveryReceived, DeliveryRefused:
			if d.Reply != "" || len(d.Wire) != 0 {
				return false
			}
		case DeliveryReady, DeliveryAccepted:
			ev, e := nostr.ParseEvent(d.Wire)
			if e != nil || ev.Kind != nostr.KindGiftWrap || nostr.VerifySignature(ev) != nil {
				return false
			}
			recipient, ok := ev.TagFirst("p")
			if !ok || recipient != slot.RenterPubKey {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// RecordInput atomically retains input and replay identity before any screening
// or station effect. Reusing a delivery ID with different input fails closed.
func (st *Store) RecordInput(id, delivery, input string) (bool, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	s, ok := st.slots[id]
	if !ok || st.poisoned || !deliveryID(delivery) || !utf8.ValidString(input) || len(input) > 65535 {
		return false, ErrDelivery
	}
	for _, d := range s.Deliveries {
		if d.ID == delivery {
			if d.Input != input {
				return false, ErrDelivery
			}
			return true, nil
		}
	}
	if s.HasSeen(delivery) {
		return true, nil
	} // old seen-only records are never regenerated
	if s.Ended || s.Destroyed || len(s.Deliveries) >= MaxDeliveries {
		return false, ErrDelivery
	}
	next := copySlot(s)
	next.SeenRumorIDs = append(next.SeenRumorIDs, delivery)
	next.rebuildSeen()
	record := Delivery{ID: delivery, Input: input, InputHash: hashText(input), Phase: DeliveryScreening}
	record.Checksum = deliveryChecksum(record)
	next.Deliveries = append(next.Deliveries, record)
	if e := st.persistDeliveryLocked(next); e != nil {
		return false, e
	}
	st.slots[id] = next
	return false, nil
}

func (st *Store) Delivery(id, delivery string) (Delivery, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	s := st.slots[id]
	if s == nil || st.poisoned {
		return Delivery{}, false
	}
	for _, d := range s.Deliveries {
		if d.ID == delivery {
			d.Wire = append(json.RawMessage(nil), d.Wire...)
			return d, true
		}
	}
	return Delivery{}, false
}

// PendingDelivery restores an unacknowledged turn after either side reconnects.
// It never promotes an uncommitted screening verdict to an admitted delivery.
func (st *Store) PendingDelivery(id string, offered map[string]bool) (Delivery, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	s := st.slots[id]
	if s == nil || st.poisoned || s.Ended || s.Destroyed {
		return Delivery{}, false
	}
	for _, d := range s.Deliveries {
		if offered[d.ID] {
			continue
		}
		switch d.Phase {
		case DeliveryQueued, DeliveryReceived, DeliveryReady:
			d.Wire = append(json.RawMessage(nil), d.Wire...)
			return d, true
		}
	}
	return Delivery{}, false
}

func (st *Store) ChangeDelivery(id, delivery, phase, reply string, wire []byte) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	s := st.slots[id]
	if s == nil || st.poisoned || s.Ended || s.Destroyed {
		return ErrDelivery
	}
	next := copySlot(s)
	for i, d := range next.Deliveries {
		if d.ID != delivery {
			continue
		}
		allowed := false
		switch phase {
		case DeliveryQueued, DeliveryRefused:
			allowed = d.Phase == DeliveryScreening
		case DeliveryReceived:
			allowed = d.Phase == DeliveryQueued || d.Phase == DeliveryReceived || d.Phase == DeliveryReady || d.Phase == DeliveryAccepted
			if allowed && d.Phase != DeliveryQueued {
				return nil
			}
		case DeliveryReady:
			allowed = d.Phase == DeliveryReceived
		case DeliveryAccepted:
			allowed = d.Phase == DeliveryReady || d.Phase == DeliveryAccepted
			if allowed {
				reply = d.Reply
				wire = d.Wire
			}
		}
		if !allowed {
			return ErrDelivery
		}
		d.Phase = phase
		d.Reply = reply
		d.Wire = append(json.RawMessage(nil), wire...)
		d.Checksum = deliveryChecksum(d)
		next.Deliveries[i] = d
		if !validDeliveries(next) {
			return ErrDelivery
		}
		if e := st.persistDeliveryLocked(next); e != nil {
			return e
		}
		st.slots[id] = next
		return nil
	}
	return ErrDelivery
}

// Only delivery write ambiguity activates the outbox safety barrier; existing
// startup rollback semantics remain unchanged. Once poisoned, all slot writes
// refuse until reopen so another operation cannot overwrite uncertain outbox state.
func (st *Store) persistDeliveryLocked(slot *Slot) error {
	err := st.persistLocked(slot)
	if err != nil {
		st.poisoned = true
	}
	return err
}
