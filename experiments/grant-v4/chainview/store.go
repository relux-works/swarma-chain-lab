package chainview

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
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

// FileStore uses an advisory lock, atomic rename, file fsync and directory fsync
// on a local Unix filesystem. Every access reloads under the same path's lock,
// including accesses from separately opened instances/processes. The directory
// and path are trusted operator inputs. Use one canonical path; do not remove
// the lock file or replace/restore the directory while the store is in use.
// This does not detect restoration of an older valid copy or attest disk hardware.
type FileStore struct{ path string }

type diskState struct {
	Version     int              `json:"version"`
	KeptMark    *int64           `json:"kept_mark"`
	FirstSights map[string]int64 `json:"first_sights"`
}

// CreateFileStore initializes an explicitly new store. It never replaces an
// existing file. The parent directory must already exist.
func CreateFileStore(path string, initial ClockState) (*FileStore, error) {
	if err := validState(initial); err != nil {
		return nil, err
	}
	s := &FileStore{path: filepath.Clean(path)}
	err := s.locked(func() error {
		if _, err := os.Lstat(s.path); !os.IsNotExist(err) {
			if err != nil {
				return err
			}
			return os.ErrExist
		}
		return s.write(initial)
	})
	if err != nil {
		return nil, err
	}
	return s, nil
}

// OpenFileStore fails on missing or malformed data; opening is never implicit
// initialization. Loss/rollback recovery needs a separate operator decision.
func OpenFileStore(path string) (*FileStore, error) {
	s := &FileStore{path: filepath.Clean(path)}
	if err := s.locked(func() error { _, err := s.read(); return err }); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *FileStore) locked(run func() error) error {
	lock, err := os.OpenFile(s.path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	return run()
}

func (s *FileStore) read() (ClockState, error) {
	info, err := os.Lstat(s.path)
	if err != nil {
		return ClockState{}, err
	}
	if !info.Mode().IsRegular() {
		return ClockState{}, errors.New("clock state is not a regular file")
	}
	file, err := os.Open(s.path)
	if err != nil {
		return ClockState{}, err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var disk diskState
	if err := decoder.Decode(&disk); err != nil {
		return ClockState{}, err
	}
	if disk.Version != 1 || disk.KeptMark == nil {
		return ClockState{}, errors.New("missing clock state version or mark")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return ClockState{}, errors.New("trailing clock state data")
	}
	state := ClockState{*disk.KeptMark, disk.FirstSights}
	return state, validState(state)
}

func (s *FileStore) write(state ClockState) (err error) {
	dir := filepath.Dir(s.path)
	file, err := os.CreateTemp(dir, ".clock-*")
	if err != nil {
		return err
	}
	name := file.Name()
	defer func() { file.Close(); os.Remove(name) }()
	if err = json.NewEncoder(file).Encode(diskState{1, &state.KeptMark, state.FirstSights}); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = os.Rename(name, s.path); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (s *FileStore) Transact(change func(*ClockState) error) error {
	return s.locked(func() error {
		before, err := s.read()
		if err != nil {
			return fmt.Errorf("read clock state: %w", err)
		}
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
		return s.write(next)
	})
}
