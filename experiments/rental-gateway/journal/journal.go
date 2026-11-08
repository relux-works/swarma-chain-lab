// Package journal persists per-slot gateway state (slot registration,
// seen rumor ids, screening-refusal counter, end state) with
// fsync-before-act writes: temp file + fsync + rename + dir fsync.
// A crash may lose an in-flight delivery, never a recorded refusal
// count or a seen-id entry that was already acted on.
package journal

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Slot is the durable record for one rental slot.
type Slot struct {
	ID             string   `json:"id"`
	StationName    string   `json:"station_name"`
	RenterPubKey   string   `json:"renter_pubkey"` // 64 lower hex, grantee key
	CertificateB64 string   `json:"certificate_b64"`
	ContractSHA256 string   `json:"contract_sha256"`
	NotBefore      int64    `json:"not_before"`
	NotAfter       int64    `json:"not_after"` // half-open: [NotBefore, NotAfter)
	Started        bool     `json:"started"`
	SeenRumorIDs   []string `json:"seen_rumor_ids"`
	Refusals       int      `json:"refusals"`
	Ended          bool     `json:"ended"`
	EndReason      string   `json:"end_reason,omitempty"`
	Destroyed      bool     `json:"destroyed"`

	seen map[string]bool `json:"-"`
}

// Store is a directory of slot files with an in-memory cache.
type Store struct {
	dir   string
	mu    sync.Mutex
	slots map[string]*Slot
}

// Open loads (or creates) the journal directory (mode 0700).
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, slots: map[string]*Slot{}}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range ents {
		name := e.Name()
		if !strings.HasPrefix(name, "slot-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		var slot Slot
		if err := json.Unmarshal(raw, &slot); err != nil {
			return nil, fmt.Errorf("journal %s: %w", name, err)
		}
		slot.rebuildSeen()
		s.slots[slot.ID] = &slot
	}
	return s, nil
}

func (s *Slot) rebuildSeen() {
	s.seen = make(map[string]bool, len(s.SeenRumorIDs))
	for _, id := range s.SeenRumorIDs {
		s.seen[id] = true
	}
}

// HasSeen reports whether a rumor id was already recorded.
func (s *Slot) HasSeen(rumorID string) bool { return s.seen[rumorID] }

func validSlotID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func (st *Store) path(id string) string {
	return filepath.Join(st.dir, "slot-"+id+".json")
}

// persistLocked durably writes one slot. Caller holds st.mu.
func (st *Store) persistLocked(slot *Slot) error {
	raw, err := json.Marshal(slot)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(st.dir, ".tmp-slot-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, st.path(slot.ID)); err != nil {
		return err
	}
	return syncDir(st.dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// Put registers a new slot durably. Duplicate ids and a second
// not-ended slot for the same renter (v1: one active slot per
// renter) are refused.
func (st *Store) Put(slot *Slot) error {
	if !validSlotID(slot.ID) {
		return fmt.Errorf("journal: invalid slot id %q", slot.ID)
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if _, ok := st.slots[slot.ID]; ok {
		return fmt.Errorf("journal: slot %s exists", slot.ID)
	}
	for _, other := range st.slots {
		if other.RenterPubKey == slot.RenterPubKey && !other.Ended && !other.Destroyed {
			return fmt.Errorf("journal: renter already has active slot %s", other.ID)
		}
	}
	slot.rebuildSeen()
	if err := st.persistLocked(slot); err != nil {
		return err
	}
	st.slots[slot.ID] = slot
	return nil
}

// Get returns a copy of one slot record.
func (st *Store) Get(id string) (*Slot, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	s, ok := st.slots[id]
	if !ok {
		return nil, false
	}
	cp := *s
	cp.SeenRumorIDs = append([]string(nil), s.SeenRumorIDs...)
	cp.rebuildSeen()
	return &cp, true
}

// ActiveByRenter returns the renter's single not-ended slot copy.
func (st *Store) ActiveByRenter(renterPubKey string) (*Slot, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, s := range st.slots {
		if s.RenterPubKey == renterPubKey && !s.Ended && !s.Destroyed {
			cp := *s
			cp.SeenRumorIDs = append([]string(nil), s.SeenRumorIDs...)
			cp.rebuildSeen()
			return &cp, true
		}
	}
	return nil, false
}

// All returns copies of every slot, sorted by id.
func (st *Store) All() []*Slot {
	st.mu.Lock()
	defer st.mu.Unlock()
	out := make([]*Slot, 0, len(st.slots))
	for _, s := range st.slots {
		cp := *s
		cp.SeenRumorIDs = append([]string(nil), s.SeenRumorIDs...)
		cp.rebuildSeen()
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// RecordSeen durably records a rumor id. It reports true when the id
// was already present (a replay). The new entry is fsynced before
// this returns, so delivery may safely happen afterwards.
func (st *Store) RecordSeen(id, rumorID string) (already bool, err error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	s, ok := st.slots[id]
	if !ok {
		return false, fmt.Errorf("journal: no slot %s", id)
	}
	if s.seen[rumorID] {
		return true, nil
	}
	s.seen[rumorID] = true
	s.SeenRumorIDs = append(s.SeenRumorIDs, rumorID)
	if err := st.persistLocked(s); err != nil {
		delete(s.seen, rumorID)
		s.SeenRumorIDs = s.SeenRumorIDs[:len(s.SeenRumorIDs)-1]
		return false, err
	}
	return false, nil
}

// AddRefusal durably increments the screening-refusal counter and
// returns the new count. Fsynced before return: callers act on the
// count (e.g. end the slot at 2) only after this succeeds.
func (st *Store) AddRefusal(id string) (int, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	s, ok := st.slots[id]
	if !ok {
		return 0, fmt.Errorf("journal: no slot %s", id)
	}
	s.Refusals++
	if err := st.persistLocked(s); err != nil {
		s.Refusals--
		return 0, err
	}
	return s.Refusals, nil
}

// MarkStarted durably records session start.
func (st *Store) MarkStarted(id string) error {
	return st.update(id, func(s *Slot) { s.Started = true })
}

// MarkEnded durably records slot end with a reason. Idempotent: a
// second end keeps the first reason.
func (st *Store) MarkEnded(id, reason string) error {
	return st.update(id, func(s *Slot) {
		if !s.Ended {
			s.Ended = true
			s.EndReason = reason
		}
	})
}

// MarkDestroyed durably records station destruction (implies ended).
func (st *Store) MarkDestroyed(id string) error {
	return st.update(id, func(s *Slot) {
		s.Ended = true
		s.Destroyed = true
		if s.EndReason == "" {
			s.EndReason = "destroyed"
		}
	})
}

func (st *Store) update(id string, fn func(*Slot)) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	s, ok := st.slots[id]
	if !ok {
		return fmt.Errorf("journal: no slot %s", id)
	}
	fn(s)
	return st.persistLocked(s)
}
