package chainview

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
)

// ClockState contains only B3.2 and B3.7 state, never a grant closure.
type ClockState struct {
	KeptMark    int64            `json:"kept_mark"`
	FirstSights map[string]int64 `json:"first_sights"`
}

// ClockStore serializes read/modify/write. The callback receives an owned copy;
// it must not recursively call the store. A successful return commits the whole
// update before admission. Implementations must reject decreasing marks and
// changes/removals of existing first sights, and must retain no callback aliases.
type ClockStore interface {
	Transact(func(*ClockState) error) error
}

func cloneState(s ClockState) ClockState {
	copy := ClockState{KeptMark: s.KeptMark, FirstSights: make(map[string]int64, len(s.FirstSights))}
	for hash, time := range s.FirstSights {
		copy.FirstSights[hash] = time
	}
	return copy
}

func validState(s ClockState) error {
	if s.KeptMark < 0 || s.FirstSights == nil {
		return errors.New("invalid clock state")
	}
	for hash, time := range s.FirstSights {
		if hash == "" || time < 0 || time > s.KeptMark {
			return errors.New("invalid first sight")
		}
	}
	return nil
}

func validUpdate(before, after ClockState) error {
	if err := validState(after); err != nil {
		return err
	}
	if after.KeptMark < before.KeptMark {
		return errors.New("kept mark decreased")
	}
	for hash, time := range before.FirstSights {
		if next, ok := after.FirstSights[hash]; !ok || next != time {
			return errors.New("first sight changed or removed")
		}
	}
	return nil
}

// MemoryStore provides the same transaction invariants, without durability.
type MemoryStore struct {
	mu    sync.Mutex
	state ClockState
}

func NewMemoryStore(initial ClockState) (*MemoryStore, error) {
	if err := validState(initial); err != nil {
		return nil, err
	}
	return &MemoryStore{state: cloneState(initial)}, nil
}

func (s *MemoryStore) Transact(change func(*ClockState) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneState(s.state)
	if err := change(&next); err != nil {
		return err
	}
	if err := validUpdate(s.state, next); err != nil {
		return err
	}
	s.state = cloneState(next)
	return nil
}

// ReadClockState returns an owned snapshot via the store's serialization point.
func ReadClockState(s ClockStore) (ClockState, error) {
	var state ClockState
	err := s.Transact(func(current *ClockState) error { state = cloneState(*current); return nil })
	return state, err
}

// Storage refusals are operational errors, not draft profile findings.
var (
	ErrStoreUncertain  = errors.New("STORE_UNCERTAIN")
	ErrStoreContinuity = errors.New("STORE_CONTINUITY")
)

const (
	StoreUncertain  Code = "STORE_UNCERTAIN"
	StoreContinuity Code = "STORE_CONTINUITY"
)

// FileStore serializes processes with a stable lock. Its continuity sentinel is
// outside the snapshot directory. Both directories are trusted operator inputs;
// never alias paths, remove the lock, or restore live directories.
type FileStore struct {
	path, sentinel string
	// The seam executes real filesystem operations unless a test injects a fault.
	// It is instance-local; production has neither hooks nor shared mutable state.
	before func(string) error
	after  func(string)
}

type diskState struct {
	Version     int              `json:"version"`
	Generation  uint64           `json:"generation"`
	KeptMark    *int64           `json:"kept_mark"`
	FirstSights map[string]int64 `json:"first_sights"`
}

type sentinelState struct {
	Version    int    `json:"version"`
	Generation uint64 `json:"generation"`
	KeptMark   *int64 `json:"kept_mark"`
}

func defaultSentinel(path string) string {
	if absolute, err := filepath.Abs(path); err == nil {
		path = absolute
	}
	return filepath.Join(filepath.Dir(filepath.Clean(path))+".continuity", filepath.Base(path)+".sentinel")
}

// CreateFileStore explicitly initializes a new snapshot and a new sentinel.
// The snapshot parent must exist. A sibling continuity directory is created
// with mode 0700 if needed; it must be backed up separately from the data dir.
func CreateFileStore(path string, initial ClockState) (*FileStore, error) {
	if err := validState(initial); err != nil {
		return nil, err
	}
	sentinel := defaultSentinel(path)
	if err := os.Mkdir(filepath.Dir(sentinel), 0700); err != nil && !os.IsExist(err) {
		return nil, err
	}
	if err := syncDirectory(filepath.Dir(filepath.Dir(sentinel))); err != nil {
		return nil, err
	}
	return CreateFileStoreAt(path, sentinel, initial)
}

// CreateFileStoreAt permits explicit disjoint snapshot and sentinel directories.
// Both parents must exist. It refuses to replace either file or a pending marker.
func CreateFileStoreAt(path, sentinel string, initial ClockState) (*FileStore, error) {
	if err := validState(initial); err != nil {
		return nil, err
	}
	s, err := fileStoreAt(path, sentinel)
	if err != nil {
		return nil, err
	}
	err = s.locked(func() error {
		for _, p := range []string{s.path, s.sentinel, s.path + ".pending", s.sentinel + ".pending"} {
			if _, err := os.Lstat(p); !os.IsNotExist(err) {
				if err != nil {
					return err
				}
				return os.ErrExist
			}
		}
		if err := s.writeSnapshot(initial, 1); err != nil {
			return err
		}
		return s.writeSentinel(1, initial.KeptMark)
	})
	if err != nil {
		return nil, err
	}
	return s, nil
}

func fileStoreAt(path, sentinel string) (*FileStore, error) {
	paths := []*string{&path, &sentinel}
	for _, p := range paths {
		absolute, err := filepath.Abs(*p)
		if err != nil {
			return nil, continuity(err)
		}
		dir, err := filepath.EvalSymlinks(filepath.Dir(absolute))
		if err != nil {
			return nil, continuity(err)
		}
		*p = filepath.Join(dir, filepath.Base(absolute))
	}
	a, b := filepath.Dir(path), filepath.Dir(sentinel)
	if a == b || strings.HasPrefix(a, b+string(os.PathSeparator)) || strings.HasPrefix(b, a+string(os.PathSeparator)) {
		return nil, fmt.Errorf("%w: snapshot and sentinel directories must be disjoint", ErrStoreContinuity)
	}
	return &FileStore{path: path, sentinel: sentinel}, nil
}

// OpenFileStore never initializes missing data. A successful open reestablishes
// durability and rolls an interrupted one-generation commit forward.
func OpenFileStore(path string) (*FileStore, error) {
	return OpenFileStoreAt(path, defaultSentinel(path))
}

func OpenFileStoreAt(path, sentinel string) (*FileStore, error) {
	s, err := fileStoreAt(path, sentinel)
	if err != nil {
		return nil, err
	}
	return openFileStore(s)
}

func openFileStore(s *FileStore) (*FileStore, error) {
	if err := s.locked(func() error { _, err := s.load(); return err }); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *FileStore) locked(run func() error) error {
	lock, err := os.OpenFile(s.path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return uncertain(err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return uncertain(err)
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	return run()
}

func uncertain(err error) error  { return fmt.Errorf("%w: %w", ErrStoreUncertain, err) }
func continuity(err error) error { return fmt.Errorf("%w: %w", ErrStoreContinuity, err) }

func readJSON(path string, value any) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("state is not a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("trailing state data")
	}
	return nil
}

func readSnapshot(path string) (diskState, error) {
	var d diskState
	if err := readJSON(path, &d); err != nil {
		return d, continuity(err)
	}
	if d.Version != 2 || d.Generation == 0 || d.KeptMark == nil {
		return d, continuity(errors.New("missing version, generation or mark"))
	}
	if err := validState(ClockState{*d.KeptMark, d.FirstSights}); err != nil {
		return d, continuity(err)
	}
	return d, nil
}

func readSentinel(path string) (sentinelState, error) {
	var d sentinelState
	if err := readJSON(path, &d); err != nil {
		return d, continuity(err)
	}
	if d.Version != 2 || d.Generation == 0 || d.KeptMark == nil || *d.KeptMark < 0 {
		return d, continuity(errors.New("invalid sentinel"))
	}
	return d, nil
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// perform is a filesystem seam, including a post-operation crash checkpoint.
func (s *FileStore) perform(step string, operation func() error) error {
	if s.before != nil {
		if err := s.before(step); err != nil {
			return uncertain(err)
		}
	}
	if err := operation(); err != nil {
		return uncertain(err)
	}
	if s.after != nil {
		s.after(step)
	}
	return nil
}

// write establishes the pending marker durably BEFORE any data rename. A
// failed clear leaves the marker. Even if unlink succeeded but its fsync failed,
// load always repeats a fresh barrier, so visible absence never authorizes alone.
func (s *FileStore) write(path, kind string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	var pending *os.File
	if err := s.perform(kind+".pending-open", func() (err error) {
		pending, err = os.OpenFile(path+".pending", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		return err
	}); err != nil {
		return err
	}
	defer pending.Close()
	if err := s.perform(kind+".pending-write", func() error { _, err := pending.Write([]byte("PENDING\n")); return err }); err != nil {
		return err
	}
	if err := s.perform(kind+".pending-sync", pending.Sync); err != nil {
		return err
	}
	if err := s.perform(kind+".pending-close", pending.Close); err != nil {
		return err
	}
	if err := s.perform(kind+".pending-directory-sync", func() error { return syncDirectory(dir) }); err != nil {
		return err
	}
	var file *os.File
	if err := s.perform(kind+".temp-create", func() (err error) { file, err = os.CreateTemp(dir, ".clock-*"); return err }); err != nil {
		return err
	}
	name := file.Name()
	defer func() { file.Close(); os.Remove(name) }()
	if err := s.perform(kind+".temp-write", func() error { _, err := file.Write(append(data, '\n')); return err }); err != nil {
		return err
	}
	if err := s.perform(kind+".temp-sync", file.Sync); err != nil {
		return err
	}
	if err := s.perform(kind+".temp-close", file.Close); err != nil {
		return err
	}
	if err := s.perform(kind+".rename", func() error { return os.Rename(name, path) }); err != nil {
		return err
	}
	if err := s.perform(kind+".directory-sync", func() error { return syncDirectory(dir) }); err != nil {
		return err
	}
	if err := s.perform(kind+".marker-clear", func() error { return os.Remove(path + ".pending") }); err != nil {
		return err
	}
	return s.perform(kind+".clear-directory-sync", func() error { return syncDirectory(dir) })
}

func (s *FileStore) writeSnapshot(state ClockState, generation uint64) error {
	return s.write(s.path, "snapshot", diskState{2, generation, &state.KeptMark, state.FirstSights})
}
func (s *FileStore) writeSentinel(generation uint64, mark int64) error {
	return s.write(s.sentinel, "sentinel", sentinelState{2, generation, &mark})
}

func (s *FileStore) settle(path, kind string, value any) error {
	if _, err := os.Lstat(path + ".pending"); err == nil {
		return s.write(path, kind, value)
	} else if !os.IsNotExist(err) {
		return uncertain(err)
	}
	// This barrier is also required on clean/no-op transactions: absence of the
	// marker can be visible after an unlink whose directory sync failed.
	if err := s.perform(kind+".barrier-file-sync", func() error {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		return f.Sync()
	}); err != nil {
		return err
	}
	return s.perform(kind+".barrier-directory-sync", func() error { return syncDirectory(filepath.Dir(path)) })
}

func (s *FileStore) load() (diskState, error) {
	snapshot, err := readSnapshot(s.path)
	if err != nil {
		return snapshot, err
	}
	sentinel, err := readSentinel(s.sentinel)
	if err != nil {
		return snapshot, err
	}
	if err := s.settle(s.path, "snapshot", snapshot); err != nil {
		return snapshot, err
	}
	if err := s.settle(s.sentinel, "sentinel", sentinel); err != nil {
		return snapshot, err
	}
	if snapshot.Generation == sentinel.Generation && *snapshot.KeptMark == *sentinel.KeptMark {
		return snapshot, nil
	}
	if sentinel.Generation < math.MaxUint64 && snapshot.Generation == sentinel.Generation+1 && *snapshot.KeptMark >= *sentinel.KeptMark {
		return snapshot, s.writeSentinel(snapshot.Generation, *snapshot.KeptMark)
	}
	return snapshot, continuity(errors.New("snapshot/sentinel generation or mark mismatch"))
}

func (s *FileStore) Transact(change func(*ClockState) error) error {
	return s.locked(func() error {
		disk, err := s.load()
		if err != nil {
			return err
		}
		before := ClockState{*disk.KeptMark, disk.FirstSights}
		next := cloneState(before)
		if err := change(&next); err != nil {
			return err
		}
		if err := validUpdate(before, next); err != nil {
			return err
		}
		if reflect.DeepEqual(before, next) {
			return nil
		}
		if disk.Generation == math.MaxUint64 {
			return continuity(errors.New("generation exhausted"))
		}
		if err := s.writeSnapshot(next, disk.Generation+1); err != nil {
			return err
		}
		return s.writeSentinel(disk.Generation+1, next.KeptMark)
	})
}
