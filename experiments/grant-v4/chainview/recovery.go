package chainview

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"time"
)

type recoveryEvent struct {
	Time          string `json:"time"`
	Status        string `json:"status"`
	SnapshotMark  int64  `json:"snapshot_mark"`
	SentinelMark  int64  `json:"sentinel_mark"`
	RecoveredMark int64  `json:"recovered_mark"`
	Generation    uint64 `json:"generation"`
}

// ErrRecoveryPathCollision refuses overlapping managed names before any write.
var ErrRecoveryPathCollision = errors.New("RECOVERY_PATH_COLLISION")

// canonicalRecoveryPath resolves parent aliases but preserves the final name:
// record I/O rejects final-component symlinks rather than following them.
func canonicalRecoveryPath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, filepath.Base(absolute)), nil
}

func recoveryPaths(path, sentinel, audit string) (string, string, string, error) {
	paths := []string{path, sentinel, audit}
	for i, path := range paths {
		canonical, err := canonicalRecoveryPath(path)
		if err != nil {
			return "", "", "", err
		}
		paths[i] = canonical
	}
	path, sentinel, audit = paths[0], paths[1], paths[2]
	// Derive markers from canonical record names, exactly as write does. Include
	// every stable name before fileStoreAt's placement checks and lock creation.
	paths = append(paths, path+".pending", sentinel+".pending", path+".lock", audit+".pending")
	seen := make(map[string]bool, len(paths))
	for _, path := range paths {
		if seen[path] {
			return "", "", "", fmt.Errorf("%w: managed names overlap", ErrRecoveryPathCollision)
		}
		seen[path] = true
	}
	return path, sentinel, audit, nil
}

// RecoverFileStoreAt is an explicit operator action, never an open fallback.
// It preserves every available snapshot sight and takes MAX of the snapshot,
// sentinel and previous recovery-log marks. Malformed present records refuse;
// a missing snapshot refuses because lost first sights cannot be reconstructed.
// The durable audit intent precedes mutation; a committed event follows it.
func RecoverFileStoreAt(path, sentinel, audit string) (*FileStore, error) {
	path, sentinel, audit, err := recoveryPaths(path, sentinel, audit)
	if err != nil {
		return nil, err
	}
	s, err := fileStoreAt(path, sentinel)
	if err != nil {
		return nil, err
	}
	err = s.locked(func() error {
		snapshot, err := readSnapshot(s.path)
		if err != nil {
			return err
		}
		mark, generation := *snapshot.KeptMark, snapshot.Generation
		sentinelMark := int64(0)
		old, err := readSentinel(s.sentinel)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err == nil {
			sentinelMark = *old.KeptMark
			mark = max(mark, sentinelMark)
			generation = max(generation, old.Generation)
		}
		var events []recoveryEvent
		if err := readJSON(audit, &events); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("read recovery audit: %w", err)
		}
		for _, event := range events {
			mark = max(mark, event.SnapshotMark, event.SentinelMark, event.RecoveredMark)
			generation = max(generation, event.Generation)
		}
		if generation == math.MaxUint64 {
			return continuity(errors.New("generation exhausted"))
		}
		event := recoveryEvent{time.Now().UTC().Format(time.RFC3339Nano), "started", *snapshot.KeptMark, sentinelMark, mark, generation + 1}
		events = append(events, event)
		if err := s.write(audit, "audit", events); err != nil {
			return err
		}
		state := ClockState{mark, snapshot.FirstSights}
		if err := s.writeSnapshot(state, generation+1); err != nil {
			return err
		}
		if err := s.writeSentinel(generation+1, mark); err != nil {
			return err
		}
		event.Status = "committed"
		events = append(events, event)
		return s.write(audit, "audit", events)
	})
	if err != nil {
		return nil, err
	}
	return s, nil
}

// RecoveryAudit is a bounded inspection helper for the recovery command. It
// validates the audit JSON before returning it for operator review.
func RecoveryAudit(path string) ([]byte, error) {
	var events []recoveryEvent
	if err := readJSON(path, &events); err != nil {
		return nil, err
	}
	return json.MarshalIndent(events, "", "  ")
}
