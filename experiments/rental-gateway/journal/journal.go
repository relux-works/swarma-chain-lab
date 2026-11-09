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
	BookingID      string   `json:"booking_id,omitempty"` // M3 booking id (Track B key)
	ContractSHA256 string   `json:"contract_sha256"`
	NotBefore      int64    `json:"not_before"`
	NotAfter       int64    `json:"not_after"` // half-open: [NotBefore, NotAfter)
	Started        bool     `json:"started"`
	Starting       bool     `json:"starting,omitempty"` // retained on failed start until destruction
	SeenRumorIDs   []string `json:"seen_rumor_ids"`
	Refusals       int      `json:"refusals"`
	Ended          bool     `json:"ended"`
	EndReason      string   `json:"end_reason,omitempty"`
	Destroyed      bool     `json:"destroyed"`
	// ChannelSecretHex is the per-slot stationlink credential key
	// (64 lower hex = 32 bytes). Journal files are 0600 in a 0700
	// dir on the gateway host only. Cleared durably at slot end.
	ChannelSecretHex string `json:"channel_secret_hex,omitempty"`
	// TokenSHA256 is the hash of the per-slot Track B token (the
	// token itself lives only in the station home).
	TokenSHA256 string `json:"token_sha256,omitempty"`
	// StationHome/User locate the created station for Destroy after
	// a gateway restart (no PID is ever persisted).
	StationHome string `json:"station_home,omitempty"`
	StationUser string `json:"station_user,omitempty"`
	// Operations are the durable closer-operation records.
	Operations []OpRecord `json:"operations,omitempty"`

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

// copySlot deep-copies a slot for return outside the lock: slices
// (seen ids, operation records and their report lists) must never
// share backing storage with the stored slot.
func copySlot(s *Slot) *Slot {
	cp := *s
	cp.SeenRumorIDs = append([]string(nil), s.SeenRumorIDs...)
	if s.Operations != nil {
		cp.Operations = make([]OpRecord, len(s.Operations))
		for i, r := range s.Operations {
			r.Removed = append([]string(nil), r.Removed...)
			r.Kept = append([]string(nil), r.Kept...)
			cp.Operations[i] = r
		}
	}
	cp.rebuildSeen()
	return &cp
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
	return copySlot(s), true
}

// ActiveByRenter returns the renter's single not-ended slot copy.
func (st *Store) ActiveByRenter(renterPubKey string) (*Slot, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, s := range st.slots {
		if s.RenterPubKey == renterPubKey && !s.Ended && !s.Destroyed {
			return copySlot(s), true
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
		out = append(out, copySlot(s))
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

// SetChannelSecret durably registers the per-slot stationlink
// secret (hex) and Track B token hash minted at station Create.
// Fsynced before the station process starts, so hello can never
// race ahead of the gateway-side credential.
func (st *Store) SetChannelSecret(id, secretHex, tokenSHA256 string) error {
	return st.update(id, func(s *Slot) {
		s.ChannelSecretHex = secretHex
		s.TokenSHA256 = tokenSHA256
	})
}

// MarkStarting durably records launch intent before the driver can run a payload.
func (st *Store) MarkStarting(id string) error {
	return st.updateChecked(id, func(s *Slot) error {
		if s.Starting || s.Started || s.Ended || s.Destroyed || s.ChannelSecretHex == "" {
			return fmt.Errorf("journal: slot cannot start")
		}
		s.Starting = true
		return nil
	})
}

// MarkStarted promotes a pending launch; concurrent end must never be undone.
func (st *Store) MarkStarted(id string) error {
	return st.updateChecked(id, func(s *Slot) error {
		if !s.Starting || s.Started || s.Ended || s.Destroyed {
			return fmt.Errorf("journal: slot cannot promote")
		}
		s.Starting, s.Started = false, true
		return nil
	})
}

// MarkEnded durably records slot end with a reason. Idempotent: a
// second end keeps the first reason.
func (st *Store) MarkEnded(id, reason string) error {
	return st.update(id, func(s *Slot) {
		if !s.Ended {
			s.Ended = true
			s.EndReason = reason
		}
		s.ChannelSecretHex = "" // channel secret dies at slot end
	})
}

// MarkDestroyed durably records station destruction (implies ended).
func (st *Store) MarkDestroyed(id string) error {
	return st.update(id, func(s *Slot) {
		s.Ended = true
		s.Destroyed = true
		s.Starting = false
		s.ChannelSecretHex = ""
		if s.EndReason == "" {
			s.EndReason = "destroyed"
		}
	})
}

func (st *Store) update(id string, fn func(*Slot)) error {
	return st.updateChecked(id, func(s *Slot) error { fn(s); return nil })
}

func (st *Store) updateChecked(id string, fn func(*Slot) error) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	s, ok := st.slots[id]
	if !ok {
		return fmt.Errorf("journal: no slot %s", id)
	}
	backup := *s // seen map is never mutated by update callers
	if err := fn(s); err != nil {
		*s = backup
		return err
	}
	if err := st.persistLocked(s); err != nil {
		seen := s.seen
		*s = backup
		s.seen = seen
		return err
	}
	return nil
}

// Operation kinds recorded for closer-facing gateway operations.
const (
	OpEndSlot      = "end_slot"
	OpFinalMessage = "final_message"
	OpDestroy      = "destroy"
	OpStateStarted = "started"
	OpStateDone    = "done"
	OpStateFailed  = "failed"
)

// OpRecord is the durable result record for one (slot, operation
// id). State started is fsynced BEFORE the effect runs; done/failed
// are fsynced after. A final-message record also carries the exact
// event to publish, persisted before the first publish attempt.
type OpRecord struct {
	OpID          string   `json:"op_id"`
	Kind          string   `json:"kind"`
	State         string   `json:"state"`
	Reason        string   `json:"reason,omitempty"`
	Error         string   `json:"error,omitempty"`
	EventID       string   `json:"event_id,omitempty"`
	EventB64      string   `json:"event_b64,omitempty"`
	ContentSHA256 string   `json:"content_sha256,omitempty"`
	Removed       []string `json:"removed,omitempty"`
	Kept          []string `json:"kept,omitempty"`
	UpdatedAt     int64    `json:"updated_at"`
}

// ErrOpConflict reports a different operation id for a kind that
// already has a started or done record on this slot.
var ErrOpConflict = fmt.Errorf("journal: operation conflict")

// BeginState says what BeginOperation found for an operation id.
type BeginState int

const (
	BeginNew      BeginState = iota // fresh started record persisted; run the effect
	BeginExisting                   // record already existed; inspect its State
)

func validOpID(id string) bool {
	return id != "" && len(id) <= 128 && !strings.ContainsAny(id, " \t\r\n")
}

// copyOpRecord returns a record whose report slices never alias
// the stored record (RM2-04 F3).
func copyOpRecord(r OpRecord) OpRecord {
	r.Removed = append([]string(nil), r.Removed...)
	r.Kept = append([]string(nil), r.Kept...)
	return r
}

// BeginOperation returns the existing record for (slot, opID), or
// durably persists a new started record. A different op id for a
// kind with a started/done record is ErrOpConflict; failed records
// do not block a fresh attempt under a new id.
func (st *Store) BeginOperation(id, kind, opID, reason string, now int64) (OpRecord, BeginState, error) {
	if !validOpID(opID) {
		return OpRecord{}, BeginNew, fmt.Errorf("journal: invalid operation id %q", opID)
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	s, ok := st.slots[id]
	if !ok {
		return OpRecord{}, BeginNew, fmt.Errorf("journal: no slot %s", id)
	}
	for _, r := range s.Operations {
		if r.OpID == opID {
			if r.Kind != kind {
				return copyOpRecord(r), BeginExisting, ErrOpConflict
			}
			return copyOpRecord(r), BeginExisting, nil
		}
	}
	for _, r := range s.Operations {
		if r.Kind == kind && r.State != OpStateFailed {
			return copyOpRecord(r), BeginExisting, ErrOpConflict
		}
	}
	rec := OpRecord{OpID: opID, Kind: kind, State: OpStateStarted, Reason: reason, UpdatedAt: now}
	s.Operations = append(s.Operations, rec)
	if err := st.persistLocked(s); err != nil {
		s.Operations = s.Operations[:len(s.Operations)-1]
		return OpRecord{}, BeginNew, err
	}
	return rec, BeginNew, nil
}

func (st *Store) mutateOp(id, opID string, fn func(*OpRecord)) (OpRecord, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	s, ok := st.slots[id]
	if !ok {
		return OpRecord{}, fmt.Errorf("journal: no slot %s", id)
	}
	for i := range s.Operations {
		if s.Operations[i].OpID == opID {
			backup := s.Operations[i]
			fn(&s.Operations[i])
			if err := st.persistLocked(s); err != nil {
				s.Operations[i] = backup
				return OpRecord{}, err
			}
			return copyOpRecord(s.Operations[i]), nil
		}
	}
	return OpRecord{}, fmt.Errorf("journal: no operation %s on slot %s", opID, id)
}

// AttachOperationEvent persists the exact final-message event
// (id + bytes + content hash) into a started record, before any
// publish attempt.
func (st *Store) AttachOperationEvent(id, opID, eventID, eventB64, contentSHA256 string, now int64) (OpRecord, error) {
	return st.mutateOp(id, opID, func(r *OpRecord) {
		r.EventID, r.EventB64, r.ContentSHA256, r.UpdatedAt = eventID, eventB64, contentSHA256, now
	})
}

// CompleteOperation durably marks an operation done, recording the
// destroy report for destroy operations. The report slices are
// copied in and out (RM2-04 F3): neither the caller's slices nor a
// returned record ever alias the stored record.
func (st *Store) CompleteOperation(id, opID string, removed, kept []string, now int64) (OpRecord, error) {
	return st.mutateOp(id, opID, func(r *OpRecord) {
		r.State, r.Error, r.UpdatedAt = OpStateDone, "", now
		r.Removed = append([]string(nil), removed...)
		r.Kept = append([]string(nil), kept...)
	})
}

// FailOperation durably marks an operation failed with its error.
func (st *Store) FailOperation(id, opID, errMsg string, now int64) (OpRecord, error) {
	return st.mutateOp(id, opID, func(r *OpRecord) {
		r.State, r.Error, r.UpdatedAt = OpStateFailed, errMsg, now
	})
}

// LookupOperation returns the recorded result for (slot, opID):
// the closer's answer after an uncertain outcome.
func (st *Store) LookupOperation(id, opID string) (OpRecord, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	s, ok := st.slots[id]
	if !ok {
		return OpRecord{}, false
	}
	for _, r := range s.Operations {
		if r.OpID == opID {
			return copyOpRecord(r), true
		}
	}
	return OpRecord{}, false
}

// SetStationHandle durably records where the station lives (home,
// OS user) so Destroy can re-derive its handle after a gateway
// restart. PIDs are deliberately never persisted.
func (st *Store) SetStationHandle(id, home, user string) error {
	return st.update(id, func(s *Slot) {
		s.StationHome, s.StationUser = home, user
	})
}
