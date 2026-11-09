package grantstore

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/single-use/durable"
)

type Config struct {
	Root            string   `json:"root"`
	PublicURL       string   `json:"public_url"`
	Writers         []string `json:"writers"`
	MaxBlobBytes    int64    `json:"max_blob_bytes"`
	MaxBlobs        int      `json:"max_blobs"`
	MaxTotalBytes   int64    `json:"max_total_bytes"`
	MaxReplay       int      `json:"max_replay"`
	MaxReplayPerKey int      `json:"max_replay_per_key"`
	SkewSeconds     int64    `json:"skew_seconds"`
}
type Descriptor struct {
	URL      string `json:"url"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
	Type     string `json:"type"`
	Uploaded int64  `json:"uploaded"`
}
type metadata struct {
	Version    int        `json:"version"`
	Descriptor Descriptor `json:"descriptor"`
	Owner      string     `json:"owner"`
	Readers    []string   `json:"readers"`
}
type replayEntry struct {
	ID     string `json:"id"`
	Expiry int64  `json:"expiry"`
	PubKey string `json:"pubkey,omitempty"`
}
type replayState struct {
	Version  int           `json:"version"`
	LastTime int64         `json:"last_time"`
	Entries  []replayEntry `json:"entries"`
}
type Server struct {
	mu       sync.Mutex
	cfg      Config
	hostname string
	journal  *durable.Store
	blobs    map[string]metadata
	total    int64
	replay   replayState
	now      func() time.Time
	failed   bool
	closed   bool
	// Tests inject failures only into isolated stores; no production flag.
	hook func(string) error
}

var errStorage = errors.New("storage unavailable")

func (s *Server) step(stage string) error {
	if s.hook != nil {
		return s.hook(stage)
	}
	return nil
}
func Open(c Config) (*Server, error) {
	if c.MaxBlobBytes == 0 {
		c.MaxBlobBytes = 1 << 20
	}
	if c.MaxBlobs == 0 {
		c.MaxBlobs = 1024
	}
	if c.MaxTotalBytes == 0 {
		c.MaxTotalBytes = 64 << 20
	}
	if c.MaxReplay == 0 {
		c.MaxReplay = 512
	}
	if c.MaxReplayPerKey == 0 {
		c.MaxReplayPerKey = min(32, c.MaxReplay/2)
	}
	if c.SkewSeconds == 0 {
		c.SkewSeconds = 30
	}
	if c.MaxBlobBytes < 1 || c.MaxBlobBytes > 64<<20 || c.MaxBlobs < 1 || c.MaxBlobs > 4096 || c.MaxTotalBytes < c.MaxBlobBytes || c.MaxTotalBytes > 1<<30 || c.MaxReplay < 2 || c.MaxReplay > 512 || c.MaxReplayPerKey < 1 || c.MaxReplayPerKey >= c.MaxReplay || c.SkewSeconds < 0 || c.SkewSeconds > 60 || len(c.Writers) == 0 || len(c.Writers) > 64 {
		return nil, errors.New("invalid store limits")
	}
	u, e := serverURL(c.PublicURL)
	if e != nil {
		return nil, e
	}
	c.PublicURL = strings.TrimSuffix(u.String(), "/")
	seen := map[string]bool{}
	for _, w := range c.Writers {
		if !key(w) || seen[w] {
			return nil, errors.New("invalid writer")
		}
		seen[w] = true
	}
	j, e := durable.Open(c.Root, "store.lock")
	if e != nil {
		return nil, e
	}
	s := &Server{cfg: c, hostname: u.Hostname(), journal: j, blobs: map[string]metadata{}, now: time.Now, replay: replayState{Version: 2, Entries: []replayEntry{}}}
	if e = s.load(); e != nil {
		j.Close()
		return nil, e
	}
	return s, nil
}
func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		s.journal.Close()
	}
}
func canonical(raw []byte, v any) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return false
	}
	b, e := json.Marshal(v)
	return e == nil && bytes.Equal(raw, b)
}
func (s *Server) load() error {
	raw, e := s.journal.Read("replay.json", 65536)
	if e != nil {
		return e
	}
	if raw != nil {
		s.replay, e = decodeReplay(raw)
		if e != nil || s.replay.LastTime < 0 || s.replay.Entries == nil || len(s.replay.Entries) > s.cfg.MaxReplay {
			return errStorage
		}
		ids := map[string]bool{}
		for _, v := range s.replay.Entries {
			if !digest(v.ID) || ids[v.ID] || v.Expiry < 0 || (v.PubKey != "" && !key(v.PubKey)) {
				return errStorage
			}
			ids[v.ID] = true
		}
	}
	dirs, e := os.ReadDir(s.cfg.Root)
	if e != nil {
		return e
	}
	for _, d := range dirs {
		name := d.Name()
		if name == "store.lock" || name == "replay.json" {
			continue
		}
		path := filepath.Join(s.cfg.Root, name)
		if strings.HasPrefix(name, ".upload-") || strings.HasPrefix(name, ".delete-") {
			info, e := os.Lstat(path)
			if e != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
				return errStorage
			}
			if e = os.RemoveAll(path); e != nil {
				return e
			}
			if e = durable.SyncDir(s.cfg.Root); e != nil {
				return e
			}
			continue
		}
		if strings.HasPrefix(name, ".journal-") {
			info, e := os.Lstat(path)
			if e != nil || !durable.PrivateRegular(info) {
				return errStorage
			}
			if e = os.Remove(path); e != nil {
				return e
			}
			continue
		}
		if !digest(name) || !d.IsDir() {
			return errStorage
		}
		info, e := os.Lstat(path)
		if e != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
			return errStorage
		}
		b, e := privateRead(filepath.Join(path, "metadata.json"), 16384)
		if e != nil {
			return e
		}
		var m metadata
		if !canonical(b, &m) || m.Version != 1 || m.Descriptor.SHA256 != name || m.Descriptor.Size < 0 || m.Descriptor.Size > s.cfg.MaxBlobBytes || m.Descriptor.Type != "application/octet-stream" || m.Descriptor.Uploaded < 0 || !key(m.Owner) || !sort.StringsAreSorted(m.Readers) || len(m.Readers) < 1 || len(m.Readers) > 65 {
			return errStorage
		}
		readers := map[string]bool{}
		for _, r := range m.Readers {
			if !key(r) || readers[r] {
				return errStorage
			}
			readers[r] = true
		}
		if !readers[m.Owner] {
			return errStorage
		}
		// The bytes/ACL are durable; the descriptor URL follows the current
		// configured endpoint (for example a new loopback port after restart).
		suffix := "/" + name + ".bin"
		if !strings.HasSuffix(m.Descriptor.URL, suffix) {
			return errStorage
		}
		if _, e := serverURL(strings.TrimSuffix(m.Descriptor.URL, suffix)); e != nil {
			return errStorage
		}
		m.Descriptor.URL = s.cfg.PublicURL + suffix
		data, e := privateRead(filepath.Join(path, "blob"), s.cfg.MaxBlobBytes)
		if e != nil || int64(len(data)) != m.Descriptor.Size || Hash(data) != name {
			return errStorage
		}
		if len(s.blobs) >= s.cfg.MaxBlobs || s.total+m.Descriptor.Size > s.cfg.MaxTotalBytes {
			return errStorage
		}
		s.blobs[name] = m
		s.total += m.Descriptor.Size
	}
	if raw == nil && len(s.blobs) > 0 {
		return errStorage
	}
	return nil
}
func privateRead(path string, limit int64) ([]byte, error) {
	info, e := os.Lstat(path)
	if e != nil || !durable.PrivateRegular(info) || info.Size() < 0 || info.Size() > limit {
		return nil, errStorage
	}
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return nil, errStorage
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(info, opened) {
		return nil, errStorage
	}
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || int64(len(b)) != info.Size() {
		return nil, errStorage
	}
	return b, nil
}
func writeFile(path string, b []byte) error {
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	return ce
}
func (s *Server) reserve(a authorization, now int64) (int, error) {
	if now < s.replay.LastTime {
		return 503, errors.New("clock rollback")
	}
	next := replayState{Version: 2, LastTime: now, Entries: []replayEntry{}}
	keySlots := 0
	for _, v := range s.replay.Entries {
		if v.Expiry > now {
			if v.ID == a.Event.ID {
				return 401, errAuth
			}
			next.Entries = append(next.Entries, v)
			if v.PubKey == a.Event.PubKey {
				keySlots++
			}
		}
	}
	if len(next.Entries) >= s.cfg.MaxReplay {
		return 429, errors.New("auth capacity")
	}
	if keySlots >= s.cfg.MaxReplayPerKey {
		return 429, errors.New("key auth capacity")
	}
	next.Entries = append(next.Entries, replayEntry{ID: a.Event.ID, Expiry: a.Expiry, PubKey: a.Event.PubKey})
	b, e := encodeReplay(next)
	if e != nil {
		return 503, errStorage
	}
	if e := s.journal.Write("replay.json", b); e != nil {
		s.failed = true
		return 503, errStorage
	}
	s.replay = next
	if e := s.step("reserved"); e != nil {
		s.failed = true
		return 503, errStorage
	}
	return 0, nil
}
func readersFor(a authorization) []string {
	m := map[string]bool{a.Event.PubKey: true}
	for _, p := range a.Readers {
		m[p] = true
	}
	r := []string{}
	for p := range m {
		r = append(r, p)
	}
	sort.Strings(r)
	return r
}
func (s *Server) put(a authorization, data []byte, now int64) (Descriptor, int, error) {
	hash := Hash(data)
	readers := readersFor(a)
	if old, ok := s.blobs[hash]; ok {
		if old.Owner != a.Event.PubKey || strings.Join(old.Readers, ",") != strings.Join(readers, ",") {
			return Descriptor{}, 409, errors.New("upload conflict")
		}
		return old.Descriptor, 200, nil
	}
	if len(s.blobs) >= s.cfg.MaxBlobs || s.total+int64(len(data)) > s.cfg.MaxTotalBytes {
		return Descriptor{}, 429, errors.New("storage capacity")
	}
	desc := Descriptor{URL: s.cfg.PublicURL + "/" + hash + ".bin", SHA256: hash, Size: int64(len(data)), Type: "application/octet-stream", Uploaded: now}
	m := metadata{1, desc, a.Event.PubKey, readers}
	b, _ := json.Marshal(m)
	tmp, e := os.MkdirTemp(s.cfg.Root, ".upload-")
	if e != nil {
		return Descriptor{}, 503, errStorage
	}
	defer os.RemoveAll(tmp)
	e = writeFile(filepath.Join(tmp, "blob"), data)
	if e == nil {
		e = s.step("blob_synced")
	}
	if e == nil {
		e = writeFile(filepath.Join(tmp, "metadata.json"), b)
	}
	if e == nil {
		e = durable.SyncDir(tmp)
	}
	if e == nil {
		e = s.step("before_publish")
	}
	if e != nil {
		return Descriptor{}, 503, errStorage
	}
	if e = os.Rename(tmp, filepath.Join(s.cfg.Root, hash)); e != nil {
		return Descriptor{}, 503, errStorage
	}
	if e = s.step("published"); e == nil {
		e = durable.SyncDir(s.cfg.Root)
	}
	if e != nil {
		s.failed = true
		return Descriptor{}, 503, errStorage
	}
	s.blobs[hash] = m
	s.total += desc.Size
	return desc, 201, nil
}
func (s *Server) remove(hash string) error {
	tmp, e := os.MkdirTemp(s.cfg.Root, ".delete-")
	if e != nil {
		return e
	}
	if e = os.Remove(tmp); e != nil {
		return e
	}
	if e = s.step("before_delete"); e != nil {
		return e
	}
	if e = os.Rename(filepath.Join(s.cfg.Root, hash), tmp); e != nil {
		return e
	}
	if e = s.step("deleted"); e == nil {
		e = durable.SyncDir(s.cfg.Root)
	}
	if e != nil {
		s.failed = true
		return e
	}
	s.total -= s.blobs[hash].Descriptor.Size
	delete(s.blobs, hash)
	if e = os.RemoveAll(tmp); e != nil {
		s.failed = true
		return e
	}
	if e = durable.SyncDir(s.cfg.Root); e != nil {
		s.failed = true
	}
	return e
}
