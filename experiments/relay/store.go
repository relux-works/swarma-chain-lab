package relay

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"unicode/utf8"

	"relux.works/swarma-chain-lab/experiments/rental-gateway/nostr"
)

type snapshot struct {
	Version int            `json:"version"`
	Events  []*nostr.Event `json:"events"`
}
type eventStore struct {
	cfg      Config
	lock     *os.File
	events   map[string]*nostr.Event
	poisoned bool
	save     func([]byte) error
}

func validEvent(raw []byte, c Config) (*nostr.Event, error) {
	if len(raw) > c.MaxEventBytes || !utf8.Valid(raw) {
		return nil, fail("EVENT_SIZE")
	}
	var shape nostr.Event
	if strict(raw, &shape) != nil {
		return nil, fail("EVENT")
	}
	e, err := nostr.ParseEvent(raw)
	if err != nil || nostr.VerifySignature(e) != nil {
		return nil, fail("EVENT")
	}
	if e.Kind != 1059 && e.Kind != 8181 && e.Kind != 8182 {
		return nil, fail("EVENT_KIND")
	}
	if len(e.Tags) > 128 {
		return nil, fail("EVENT_TAGS")
	}
	recipients := 0
	for _, t := range e.Tags {
		if len(t) > 8 {
			return nil, fail("EVENT_TAGS")
		}
		if t[0] == "p" {
			if len(t) < 2 || !hex(t[1], 64) {
				return nil, fail("EVENT_RECIPIENT")
			}
			recipients++
		}
	}
	if e.Kind == 1059 && recipients != 1 {
		return nil, fail("EVENT_RECIPIENT")
	}
	return e, nil
}
func live(e *nostr.Event, c Config, now int64) bool {
	return e.CreatedAt >= now-c.RetentionSeconds && e.CreatedAt <= now+c.FutureSeconds
}
func owned(st os.FileInfo, mode os.FileMode) bool {
	s, ok := st.Sys().(*syscall.Stat_t)
	return ok && s.Uid == uint32(os.Geteuid()) && st.Mode().Perm() == mode && (st.IsDir() || s.Nlink == 1)
}
func openStore(c Config, now int64) (*eventStore, error) {
	// An explicitly provisioned private state root is required; no traversal of
	// symlinks and no chmod of an existing foreign directory.
	if e := os.Mkdir(c.StateDir, 0700); e != nil && !os.IsExist(e) {
		return nil, fail("STORE_ROOT")
	}
	parent, e := os.Open(filepath.Dir(c.StateDir))
	if e != nil {
		return nil, fail("STORE_ROOT")
	}
	e = parent.Sync()
	ce := parent.Close()
	if e != nil || ce != nil {
		return nil, fail("STORE_ROOT")
	}
	path, e := filepath.EvalSymlinks(c.StateDir)
	st, se := os.Lstat(c.StateDir)
	if e != nil || se != nil || path != c.StateDir || !st.IsDir() || !owned(st, 0700) {
		return nil, fail("STORE_ROOT")
	}
	f, e := os.OpenFile(filepath.Join(c.StateDir, "lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if e != nil {
		return nil, fail("STORE_LOCK")
	}
	st, e = f.Stat()
	if e != nil || !st.Mode().IsRegular() || !owned(st, 0600) || syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		f.Close()
		return nil, fail("STORE_LOCK")
	}
	s := &eventStore{cfg: c, lock: f, events: map[string]*nostr.Event{}}
	s.save = s.atomicWrite
	ok := false
	defer func() {
		if !ok {
			s.close()
		}
	}()
	data, e := os.OpenFile(filepath.Join(c.StateDir, "events.json"), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if os.IsNotExist(e) {
		ok = true
		return s, nil
	}
	if e != nil {
		return nil, fail("STORE_READ")
	}
	defer data.Close()
	st, e = data.Stat()
	if e != nil || !st.Mode().IsRegular() || !owned(st, 0600) {
		return nil, fail("STORE_READ")
	}
	raw, e := io.ReadAll(io.LimitReader(data, int64(c.MaxStoreBytes)+1))
	if e != nil || len(raw) > c.MaxStoreBytes {
		return nil, fail("STORE_SIZE")
	}
	var snap snapshot
	if strict(raw, &snap) != nil || snap.Version != 1 || snap.Events == nil || len(snap.Events) > c.MaxEvents {
		return nil, fail("STORE_CORRUPT")
	}
	seen := map[string]bool{}
	for _, event := range snap.Events {
		b, _ := json.Marshal(event)
		v, e := validEvent(b, c)
		if e != nil || seen[v.ID] {
			return nil, fail("STORE_CORRUPT")
		}
		seen[v.ID] = true
		if live(v, c, now) {
			s.events[v.ID] = v
		}
	}
	// Persist pruning so an old wall clock cannot resurrect already removed data.
	if len(s.events) != len(snap.Events) {
		raw, _ := s.encode(s.events)
		if s.save(raw) != nil {
			return nil, fail("STORE_WRITE")
		}
	}
	ok = true
	return s, nil
}
func (s *eventStore) close() {
	if s.lock != nil {
		_ = syscall.Flock(int(s.lock.Fd()), syscall.LOCK_UN)
		_ = s.lock.Close()
		s.lock = nil
	}
}
func (s *eventStore) encode(events map[string]*nostr.Event) ([]byte, error) {
	list := make([]*nostr.Event, 0, len(events))
	for _, e := range events {
		list = append(list, e)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	raw, e := json.Marshal(snapshot{1, list})
	if e != nil || len(raw) > s.cfg.MaxStoreBytes {
		return nil, fail("STORE_CAPACITY")
	}
	return raw, nil
}
func (s *eventStore) atomicWrite(raw []byte) error {
	f, e := os.CreateTemp(s.cfg.StateDir, ".events-")
	if e != nil {
		return fail("STORE_WRITE")
	}
	name := f.Name()
	defer os.Remove(name)
	if _, e = io.Copy(f, bytes.NewReader(raw)); e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil || ce != nil {
		return fail("STORE_WRITE")
	}
	if os.Rename(name, filepath.Join(s.cfg.StateDir, "events.json")) != nil {
		return fail("STORE_WRITE")
	}
	d, e := os.Open(s.cfg.StateDir)
	if e != nil {
		return fail("STORE_WRITE")
	}
	e = d.Sync()
	ce = d.Close()
	if e != nil || ce != nil {
		return fail("STORE_WRITE")
	}
	return nil
}

// put is called under the relay mutex. A failed persistence poisons the store:
// even if rename happened, no future duplicate can falsely ACK uncertain bytes.
func (s *eventStore) put(e *nostr.Event, now int64) (bool, error) {
	if s.poisoned {
		return false, fail("STORE_UNAVAILABLE")
	}
	if !live(e, s.cfg, now) {
		return false, fail("EVENT_TIME")
	}
	if _, ok := s.events[e.ID]; ok {
		return true, nil
	}
	next := map[string]*nostr.Event{}
	for id, v := range s.events {
		if live(v, s.cfg, now) {
			next[id] = v
		}
	}
	if len(next) >= s.cfg.MaxEvents {
		return false, fail("STORE_CAPACITY")
	}
	next[e.ID] = e
	raw, err := s.encode(next)
	if err != nil {
		return false, err
	}
	if s.save(raw) != nil {
		s.poisoned = true
		return false, fail("STORE_WRITE")
	}
	s.events = next
	return false, nil
}

func (s *eventStore) prune(now int64) error {
	if s.poisoned {
		return fail("STORE_UNAVAILABLE")
	}
	next := map[string]*nostr.Event{}
	for id, e := range s.events {
		if live(e, s.cfg, now) {
			next[id] = e
		}
	}
	if len(next) == len(s.events) {
		return nil
	}
	raw, e := s.encode(next)
	if e != nil {
		return e
	}
	if s.save(raw) != nil {
		s.poisoned = true
		return fail("STORE_WRITE")
	}
	s.events = next
	return nil
}
