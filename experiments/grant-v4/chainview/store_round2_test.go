package chainview

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func roundStore(t *testing.T) *FileStore {
	t.Helper()
	s, err := CreateFileStore(filepath.Join(t.TempDir(), "clock.json"), ClockState{100, map[string]int64{"tip": 100}})
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func roundInput() ClockInput { return ClockInput{TipHash: "tip", Now: 150, HeaderTime: 150} }
func refuseUncertain(t *testing.T, s *FileStore) {
	t.Helper()
	code, err := mustClock(t, labParameters(), s).Observe(roundInput())
	if code != StoreUncertain || !errors.Is(err, ErrStoreUncertain) {
		t.Fatalf("want STORE_UNCERTAIN, got %s / %v", code, err)
	}
}
func faultStep(step string) func(string) error {
	return func(current string) error {
		if current == step {
			return syscall.EIO
		}
		return nil
	}
}

// Each injected write failure refuses now, on retry, on a newly opened handle,
// and in a separately started process until a real fresh barrier succeeds.
// Both records use the same seam; no power-loss/hardware emulation is claimed.
func TestReviewDirectorySyncRetry(t *testing.T) {
	if path := os.Getenv("CHAINVIEW_FAULT_PATH"); path != "" {
		s, err := fileStoreAt(path, defaultSentinel(path))
		if err != nil {
			t.Fatal(err)
		}
		s.before = faultStep(os.Getenv("CHAINVIEW_FAULT_STEP"))
		if _, err := openFileStore(s); !errors.Is(err, ErrStoreUncertain) {
			t.Fatalf("restart open lacked named uncertainty: %v", err)
		}
		refuseUncertain(t, s)
		return
	}
	for _, kind := range []string{"snapshot", "sentinel"} {
		for _, phase := range []string{"temp-sync", "rename", "directory-sync", "marker-clear", "clear-directory-sync"} {
			step := kind + "." + phase
			t.Run(step, func(t *testing.T) {
				s := roundStore(t)
				s.before = faultStep(step)
				refuseUncertain(t, s)
				// A failed unlink-dir-sync leaves no visible marker. Repeating that same
				// unavailable directory barrier must still refuse on all subsequent reads.
				if phase == "clear-directory-sync" {
					s.before = func(current string) error {
						if current == step || current == kind+".barrier-directory-sync" {
							return syscall.EIO
						}
						return nil
					}
				}
				refuseUncertain(t, s)
				reopened, err := fileStoreAt(s.path, s.sentinel)
				if err != nil {
					t.Fatal(err)
				}
				reopened.before = s.before
				if _, err := openFileStore(reopened); !errors.Is(err, ErrStoreUncertain) {
					t.Fatalf("reopen lacked named uncertainty: %v", err)
				}
				refuseUncertain(t, reopened)
				// In the clear-dir-sync case the restart injects the corresponding fresh
				// directory barrier failure because the marker may already be absent.
				restartStep := step
				if phase == "clear-directory-sync" {
					restartStep = kind + ".barrier-directory-sync"
				}
				child := exec.Command(os.Args[0], "-test.run=^TestReviewDirectorySyncRetry$", "-test.v")
				child.Env = append(os.Environ(), "CHAINVIEW_FAULT_PATH="+s.path, "CHAINVIEW_FAULT_STEP="+restartStep)
				output, err := child.CombinedOutput()
				if err != nil {
					t.Fatalf("restart refused incorrectly: %v\n%s", err, output)
				}
				s.before = nil
				healthy, err := OpenFileStore(s.path)
				if err != nil {
					t.Fatal(err)
				}
				code, err := mustClock(t, labParameters(), healthy).Observe(roundInput())
				if code != "" || err != nil {
					t.Fatalf("fresh successful barrier did not authorize: %s %v", code, err)
				}
			})
		}
	}
}

// The real directory-open denial also refuses on retry/reopen; repairing its
// permissions permits a fresh barrier. This retains the review's public witness.
func TestReviewDirectoryOpenRetry(t *testing.T) {
	s := roundStore(t)
	dir := filepath.Dir(s.path)
	if err := os.Chmod(dir, 0300); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(dir, 0700); err != nil {
			t.Error(err)
		}
	})
	c := mustClock(t, labParameters(), s)
	for range 2 {
		if code, err := c.Observe(roundInput()); err == nil || code == "" {
			t.Fatalf("directory permission failure admitted: %s %v", code, err)
		}
	}
	if _, err := OpenFileStore(s.path); err == nil {
		t.Fatal("unavailable directory reopened")
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if code, err := c.Observe(roundInput()); err != nil || code != "" {
		t.Fatal(code, err)
	}
}

// A no-op after rename must not bypass an outstanding uncertain commit, and
// the normal no-op control still passes after a successful recovery barrier.
func TestV4UncertainNoOp(t *testing.T) {
	s := roundStore(t)
	s.before = faultStep("snapshot.marker-clear")
	refuseUncertain(t, s)
	before, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	refuseUncertain(t, s)
	after, err := os.ReadFile(s.path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("retry changed the staged decision", err)
	}
	s.before = nil
	code, err := mustClock(t, labParameters(), s).Observe(roundInput())
	if err != nil || code != "" {
		t.Fatal("no-op positive control", code, err)
	}
}

func updateRound(t *testing.T, s *FileStore, mark int64) {
	t.Helper()
	if err := s.Transact(func(state *ClockState) error { state.KeptMark = mark; return nil }); err != nil {
		t.Fatal(err)
	}
}
func saveBytes(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func restoreBytes(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
}
func continuityRefused(t *testing.T, s *FileStore) {
	t.Helper()
	if _, err := OpenFileStore(s.path); !errors.Is(err, ErrStoreContinuity) {
		t.Fatalf("want STORE_CONTINUITY: %v", err)
	}
	code, err := mustClock(t, labParameters(), s).Observe(roundInput())
	if code != StoreContinuity || !errors.Is(err, ErrStoreContinuity) {
		t.Fatalf("continuity admitted: %s %v", code, err)
	}
}

// Restoring the complete data directory alone cannot restore its disjoint
// sentinel; older data, a >1 generation gap and a decreased mark all refuse.
// Equal generations and snapshot=sentinel+1 are the only accepted relations.
func TestReviewRolledBackStoreRefused(t *testing.T) {
	for _, variant := range []string{"older-snapshot", "newer-gap", "equal-generation-mark-change", "decreased-mark"} {
		t.Run(variant, func(t *testing.T) {
			s := roundStore(t)
			oldSnapshot, oldSentinel := saveBytes(t, s.path), saveBytes(t, s.sentinel)
			updateRound(t, s, 200)
			if _, err := OpenFileStore(s.path); err != nil {
				t.Fatal("normal restart", err)
			}
			switch variant {
			case "older-snapshot":
				restoreBytes(t, s.path, oldSnapshot)
			case "newer-gap":
				updateRound(t, s, 300)
				restoreBytes(t, s.sentinel, oldSentinel)
			case "equal-generation-mark-change":
				var d diskState
				if err := json.Unmarshal(saveBytes(t, s.path), &d); err != nil {
					t.Fatal(err)
				}
				*d.KeptMark = 150
				b, _ := json.Marshal(d)
				restoreBytes(t, s.path, b)
			case "decreased-mark":
				restoreBytes(t, s.sentinel, oldSentinel)
				var d diskState
				if err := json.Unmarshal(saveBytes(t, s.path), &d); err != nil {
					t.Fatal(err)
				}
				*d.KeptMark = 99
				d.FirstSights = map[string]int64{}
				b, _ := json.Marshal(d)
				restoreBytes(t, s.path, b)
			}
			beforeSnap, beforeSent := saveBytes(t, s.path), saveBytes(t, s.sentinel)
			continuityRefused(t, s)
			if !bytes.Equal(beforeSnap, saveBytes(t, s.path)) || !bytes.Equal(beforeSent, saveBytes(t, s.sentinel)) {
				t.Fatal("continuity refusal changed records")
			}
		})
	}
}

// Missing continuity is never implicit initialization; explicit recovery is
// required. This test pairs that refusal with a fresh valid-store control.
func TestV4MissingSentinelRefused(t *testing.T) {
	s := roundStore(t)
	if _, err := OpenFileStore(s.path); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(s.sentinel); err != nil {
		t.Fatal(err)
	}
	continuityRefused(t, s)
	if _, err := os.Stat(s.sentinel); !os.IsNotExist(err) {
		t.Fatal("missing sentinel recreated", err)
	}
}

// The old-snapshot witness also refuses in a genuinely new process. A normal
// restart of the same current snapshot is tested before planting restoration.
func TestReviewRestoredFileAfterProcessRestart(t *testing.T) {
	if path := os.Getenv("CHAINVIEW_RESTORED_PATH"); path != "" {
		_, err := OpenFileStore(path)
		if !errors.Is(err, ErrStoreContinuity) {
			t.Fatalf("restored file opened: %v", err)
		}
		return
	}
	s := roundStore(t)
	old := saveBytes(t, s.path)
	updateRound(t, s, 200)
	if _, err := OpenFileStore(s.path); err != nil {
		t.Fatal(err)
	}
	restoreBytes(t, s.path, old)
	child := exec.Command(os.Args[0], "-test.run=^TestReviewRestoredFileAfterProcessRestart$", "-test.v")
	child.Env = append(os.Environ(), "CHAINVIEW_RESTORED_PATH="+s.path)
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("restart: %v\n%s", err, output)
	}
}

// Every observed filesystem step of an ordinary update is followed by an
// actual process exit. Reopen settles old/new visible state without operator
// recovery. This models process crashes; storage hardware remains trusted.
func TestV4CommitCrashPoints(t *testing.T) {
	if path := os.Getenv("CHAINVIEW_CRASH_PATH"); path != "" {
		s, err := OpenFileStore(path)
		if err != nil {
			t.Fatal(err)
		}
		index, _ := strconv.Atoi(os.Getenv("CHAINVIEW_CRASH_INDEX"))
		n := 0
		s.after = func(string) {
			n++
			if n == index {
				os.Exit(77)
			}
		}
		updateRound(t, s, 200)
		t.Fatal("crash checkpoint not reached")
	}
	control := roundStore(t)
	var steps []string
	control.after = func(step string) { steps = append(steps, step) }
	updateRound(t, control, 200)
	if len(steps) < 26 {
		t.Fatal("missing commit steps", steps)
	}
	for i, step := range steps {
		t.Run(fmt.Sprintf("%02d-%s", i+1, step), func(t *testing.T) {
			s := roundStore(t)
			child := exec.Command(os.Args[0], "-test.run=^TestV4CommitCrashPoints$", "-test.v")
			child.Env = append(os.Environ(), "CHAINVIEW_CRASH_PATH="+s.path, "CHAINVIEW_CRASH_INDEX="+strconv.Itoa(i+1))
			output, err := child.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 77 {
				t.Fatalf("crash point not reached: %v\n%s", err, output)
			}
			reopened, err := OpenFileStore(s.path)
			if err != nil {
				t.Fatal("plain crash required operator", err)
			}
			state := mustState(t, reopened)
			if state.KeptMark != 100 && state.KeptMark != 200 {
				t.Fatal("unexpected crash mark", state)
			}
			if !reflect.DeepEqual(state.FirstSights, map[string]int64{"tip": 100}) {
				t.Fatal("lost first sight")
			}
			updateRound(t, reopened, 200)
			if got := mustState(t, reopened).KeptMark; got != 200 {
				t.Fatal(got)
			}
		})
	}
}

// A one-generation interrupted update rolls the sentinel FORWARD, preserving
// the larger mark; a subsequent restart uses the repaired equal generation.
func TestV4InterruptedCommitOpens(t *testing.T) {
	s := roundStore(t)
	old := saveBytes(t, s.sentinel)
	updateRound(t, s, 200)
	restoreBytes(t, s.sentinel, old)
	opened, err := OpenFileStore(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if got := mustState(t, opened).KeptMark; got != 200 {
		t.Fatal(got)
	}
	a, err := readSnapshot(s.path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := readSentinel(s.sentinel)
	if err != nil {
		t.Fatal(err)
	}
	if a.Generation != b.Generation || *a.KeptMark != *b.KeptMark {
		t.Fatal("sentinel not rolled forward")
	}
	if _, err := OpenFileStore(s.path); err != nil {
		t.Fatal(err)
	}
}

// Deliberate same-authority restoration of BOTH records with the clock is a
// documented limit, not a claim of rollback resistance. A single-file restore
// refuses in the adjacent tests; restoring all trusted inputs cannot be detected.
func TestV4BothFilesRestoreDocumentedLimit(t *testing.T) {
	s := roundStore(t)
	oldSnap, oldSent := saveBytes(t, s.path), saveBytes(t, s.sentinel)
	updateRound(t, s, 200)
	restoreBytes(t, s.path, oldSnap)
	restoreBytes(t, s.sentinel, oldSent)
	opened, err := OpenFileStore(s.path)
	if err != nil {
		t.Fatal(err)
	}
	code, err := mustClock(t, labParameters(), opened).Observe(ClockInput{TipHash: "tip", Now: 150, HeaderTime: 150})
	if err != nil || code != "" {
		t.Fatal("documented same-authority limit changed", code, err)
	}
}

// Explicit recovery takes MAX of all available marks including earlier audit
// intents, logs before mutation, preserves sights, and never silently resets.
func TestV4OperatorRecoveryMaximum(t *testing.T) {
	for _, variant := range []string{"sentinel-maximum", "snapshot-maximum", "missing-sentinel", "audit-maximum"} {
		t.Run(variant, func(t *testing.T) {
			s := roundStore(t)
			oldSnapshot, oldSentinel := saveBytes(t, s.path), saveBytes(t, s.sentinel)
			updateRound(t, s, 200)
			updateRound(t, s, 300)
			want := int64(300)
			switch variant {
			case "sentinel-maximum", "audit-maximum":
				restoreBytes(t, s.path, oldSnapshot)
			case "snapshot-maximum":
				restoreBytes(t, s.sentinel, oldSentinel)
			case "missing-sentinel":
				if err := os.Remove(s.sentinel); err != nil {
					t.Fatal(err)
				}
			}
			continuityRefused(t, s)
			audit := filepath.Join(filepath.Dir(s.sentinel), "recovery.json")
			if variant == "audit-maximum" {
				events := []recoveryEvent{{Status: "started", SnapshotMark: 450, SentinelMark: 425, RecoveredMark: 400, Generation: 10}}
				b, _ := json.Marshal(events)
				restoreBytes(t, audit, b)
				want = 450
			}
			recovered, err := RecoverFileStoreAt(s.path, s.sentinel, audit)
			if err != nil {
				t.Fatal(err)
			}
			state := mustState(t, recovered)
			if state.KeptMark != want || state.FirstSights["tip"] != 100 {
				t.Fatal("recovery lowered present maximum or lost sight", state)
			}
			data, err := RecoveryAudit(audit)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(data), `"committed"`) || !strings.Contains(string(data), `"started"`) {
				t.Fatal("missing audit", string(data))
			}
			if _, err := OpenFileStore(s.path); err != nil {
				t.Fatal(err)
			}
		})
	}
	// A failed audit write must prevent state mutation.
	s := roundStore(t)
	before := saveBytes(t, s.path)
	if _, err := RecoverFileStoreAt(s.path, s.sentinel, filepath.Join(t.TempDir(), "absent", "audit.json")); err == nil {
		t.Fatal("missing audit accepted")
	}
	if !bytes.Equal(before, saveBytes(t, s.path)) {
		t.Fatal("unaudited mutation")
	}
	// Canonicalized aliases must not let the audit overwrite a store record.
	if _, err := RecoverFileStoreAt(s.path, s.sentinel, s.path); err == nil {
		t.Fatal("overlapping audit accepted")
	}
	if !bytes.Equal(before, saveBytes(t, s.path)) {
		t.Fatal("audit alias overwrote snapshot")
	}
}

// Snapshot and continuity directories must be disjoint, including through
// symlink aliases. Separate sibling directories are the valid control.
func TestV4ContinuityLocations(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "data")
	nested := filepath.Join(data, "nested")
	outside := filepath.Join(root, "continuity")
	for _, p := range []string{data, nested, outside} {
		if err := os.MkdirAll(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(data, alias); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(data, "clock.json")
	for _, sentinel := range []string{filepath.Join(data, "sentinel"), filepath.Join(nested, "sentinel"), filepath.Join(alias, "sentinel")} {
		if _, err := CreateFileStoreAt(path, sentinel, ClockState{100, map[string]int64{}}); !errors.Is(err, ErrStoreContinuity) {
			t.Fatal("overlapping directory accepted", err)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("overlap refusal created data", err)
		}
	}
	sentinel := filepath.Join(outside, "sentinel")
	if _, err := CreateFileStoreAt(path, sentinel, ClockState{100, map[string]int64{}}); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileStoreAt(path, sentinel); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(sentinel); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(outside); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileStoreAt(path, sentinel); !errors.Is(err, ErrStoreContinuity) {
		t.Fatal("missing continuity directory lacked named refusal", err)
	}
}

// The ordering trace proves a durable marker precedes rename and the directory
// fsync precedes marker removal, for snapshot first and sentinel second.
func TestV4DurabilityOrder(t *testing.T) {
	s := roundStore(t)
	var steps []string
	s.after = func(step string) { steps = append(steps, step) }
	updateRound(t, s, 200)
	var want []string
	for _, kind := range []string{"snapshot", "sentinel"} {
		want = append(want, kind+".barrier-file-sync", kind+".barrier-directory-sync")
	}
	for _, kind := range []string{"snapshot", "sentinel"} {
		for _, phase := range []string{"pending-open", "pending-write", "pending-sync", "pending-close", "pending-directory-sync", "temp-create", "temp-write", "temp-sync", "temp-close", "rename", "directory-sync", "marker-clear", "clear-directory-sync"} {
			want = append(want, kind+"."+phase)
		}
	}
	if !reflect.DeepEqual(steps, want) {
		t.Fatalf("durability order: got %v, want %v", steps, want)
	}
}
