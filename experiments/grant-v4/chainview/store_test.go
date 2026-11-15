package chainview

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
)

// TestV4StoreInvariants proves both stores reject partial callback failures,
// mark rollback and changed/removed sightings without retaining mutable aliases.
func TestV4StoreInvariants(t *testing.T) {
	for _, fileBacked := range []bool{false, true} {
		t.Run(fmt.Sprint(fileBacked), func(t *testing.T) {
			initial := ClockState{1000, map[string]int64{"old": 990}}
			var s ClockStore
			if fileBacked {
				var err error
				s, err = CreateFileStore(filepath.Join(t.TempDir(), "clock.json"), initial)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				s = mustMemory(t, initial)
			}
			initial.FirstSights["old"] = 1
			if mustState(t, s).FirstSights["old"] != 990 {
				t.Fatal("retained initial map")
			}
			for _, mutate := range []func(*ClockState) error{
				func(s *ClockState) error { s.KeptMark--; return nil },
				func(s *ClockState) error { s.FirstSights["old"]++; return nil },
				func(s *ClockState) error { delete(s.FirstSights, "old"); return nil },
				func(s *ClockState) error { s.FirstSights["new"] = 999; return errors.New("aborted callback") },
				func(s *ClockState) error { s.FirstSights["future"] = 1001; return nil },
			} {
				before := mustState(t, s)
				if err := s.Transact(mutate); err == nil {
					t.Fatal("forbidden update accepted")
				}
				if after := mustState(t, s); !reflect.DeepEqual(after, before) {
					t.Fatalf("failed update changed state: %+v", after)
				}
			}
			var retained *ClockState
			if err := s.Transact(func(state *ClockState) error { state.FirstSights["new"] = 1000; retained = state; return nil }); err != nil {
				t.Fatal(err)
			}
			retained.KeptMark = 0
			retained.FirstSights["new"] = 0
			copy := mustState(t, s)
			copy.FirstSights["old"] = 0
			if got := mustState(t, s); got.KeptMark != 1000 || got.FirstSights["new"] != 1000 || got.FirstSights["old"] != 990 {
				t.Fatal("state alias", got)
			}
		})
	}
}

// TestV4FileStoreInvalidData proves absent, malformed, incomplete and non-file
// stores fail to reopen, and explicit initialization never overwrites a store.
func TestV4FileStoreInvalidData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clock.json")
	if _, err := OpenFileStore(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing store: %v", err)
	}
	for _, data := range []string{"", "{", `{}`, `{"version":1,"first_sights":{}}`,
		`{"version":1,"kept_mark":10}`, `{"version":2,"kept_mark":10,"first_sights":{}}`,
		`{"version":1,"kept_mark":10,"first_sights":{"tip":11}}`,
		`{"version":1,"kept_mark":10,"first_sights":{},"closure":true}`,
		`{"version":1,"kept_mark":10,"first_sights":{}} {}`,
	} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenFileStore(path); err == nil {
			t.Fatalf("invalid store opened: %q", data)
		}
		if got, err := os.ReadFile(path); err != nil || string(got) != data {
			t.Fatal("opening changed invalid data")
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	s, err := CreateFileStore(path, ClockState{10, map[string]int64{}})
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CreateFileStore(path, ClockState{0, map[string]int64{}}); !errors.Is(err, os.ErrExist) {
		t.Fatal("reinitialized existing store", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("existing bytes replaced")
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("state permissions", err)
	}
	// A new instance reloads the on-disk state, with no shared in-memory cache.
	reopened, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(mustState(t, s), mustState(t, reopened)) {
		t.Fatal("reopened state changed")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileStore(path); err == nil {
		t.Fatal("directory accepted")
	}
}

// TestV4FileStoreConcurrentWriters proves distinct opened instances serialize
// 24 concurrent updates without losing sightings; no distributed-FS claim.
func TestV4FileStoreConcurrentWriters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clock.json")
	s, err := CreateFileStore(path, ClockState{1000, map[string]int64{}})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errors := make(chan error, 24)
	for i := range 24 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			x, err := OpenFileStore(path)
			if err != nil {
				errors <- err
				return
			}
			err = x.Transact(func(state *ClockState) error {
				state.FirstSights[fmt.Sprint(i)] = 1000
				state.KeptMark = max(state.KeptMark, int64(1000+i))
				return nil
			})
			if err != nil {
				errors <- err
			}
		}()
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
	if got := mustState(t, s); len(got.FirstSights) != 24 || got.KeptMark != 1023 {
		t.Fatal("lost update", got)
	}
}

// TestV4FileStoreProcessRestart proves an exited process's first sight and mark
// survive reopening, a rollback refusal and a returning tip in the parent.
func TestV4FileStoreProcessRestart(t *testing.T) {
	if path := os.Getenv("CHAINVIEW_TEST_CHILD_STORE"); path != "" {
		s, err := OpenFileStore(path)
		if err != nil {
			t.Fatal(err)
		}
		c := mustClock(t, labParameters(), s)
		code, err := c.Observe(ClockInput{TipHash: "original", Now: 1000, HeaderTime: 1017})
		if err != nil {
			t.Fatal(err)
		}
		wantCode(t, code, "")
		return
	}
	path := filepath.Join(t.TempDir(), "clock.json")
	if _, err := CreateFileStore(path, ClockState{990, map[string]int64{}}); err != nil {
		t.Fatal(err)
	}
	child := exec.Command(os.Args[0], "-test.run=^TestV4FileStoreProcessRestart$", "-test.v")
	child.Env = append(os.Environ(), "CHAINVIEW_TEST_CHILD_STORE="+path)
	var output bytes.Buffer
	child.Stdout, child.Stderr = &output, &output
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Logf("store child pid=%d", child.Process.Pid)
	if err := child.Wait(); err != nil {
		t.Fatalf("child: %v\n%s", err, output.String())
	}
	s, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	c := mustClock(t, labParameters(), s)
	before := mustState(t, s)
	code, err := c.Observe(ClockInput{TipHash: "new", Now: 999, HeaderTime: 999})
	if err != nil {
		t.Fatal(err)
	}
	wantCode(t, code, ObservationClock)
	if got := mustState(t, s); !reflect.DeepEqual(got, before) {
		t.Fatal("rollback after restart wrote state", got)
	}
	code, err = c.Observe(ClockInput{TipHash: "another", Now: 1050, HeaderTime: 1050})
	if err != nil {
		t.Fatal(err)
	}
	wantCode(t, code, "")
	code, err = c.Observe(ClockInput{TipHash: "original", Now: 1100, HeaderTime: 1017})
	if err != nil {
		t.Fatal(err)
	}
	wantCode(t, code, TipAge)
	if got := mustState(t, s); got.FirstSights["original"] != 1000 || got.KeptMark != 1050 {
		t.Fatal("return/reset changed state", got)
	}
}

type failedStore struct{}

func (failedStore) Transact(func(*ClockState) error) error { return errors.New("store unavailable") }

// TestV4StoreFailure proves unavailable storage returns an error before a
// clock decision can be used; it does not model every filesystem crash point.
func TestV4StoreFailure(t *testing.T) {
	c := mustClock(t, labParameters(), failedStore{})
	if _, err := c.Observe(ClockInput{TipHash: "tip", Now: 1000, HeaderTime: 1000}); err == nil {
		t.Fatal("storage failure hidden")
	}
}

// TestV4FileStoreWriteFailure proves an actual failed file write prevents a
// passing clock decision and preserves old bytes, then succeeds after repair.
func TestV4FileStoreWriteFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Fatal("run filesystem refusal controls as a non-root user")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "clock.json")
	s, err := CreateFileStore(path, ClockState{990, map[string]int64{}})
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(dir, 0700); err != nil {
			t.Error(err)
		}
	})
	c := mustClock(t, labParameters(), s)
	input := ClockInput{TipHash: "tip", Now: 1000, HeaderTime: 1000}
	if _, err := c.Observe(input); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("want actual write permission refusal, got %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("failed write changed kept bytes", err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	code, err := c.Observe(input)
	if err != nil {
		t.Fatal(err)
	}
	wantCode(t, code, "")
	if got := mustState(t, s); got.KeptMark != 1000 || got.FirstSights["tip"] != 1000 {
		t.Fatal(got)
	}
}
