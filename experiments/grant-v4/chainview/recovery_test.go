package chainview

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type recoveryFileImage struct {
	Mode     fs.FileMode
	Modified int64
	Data     string
}

// Capture names, modes, modification times and bytes, including directories, so
// refusal cannot hide a created lock, a truncated marker or a removed record.
func recoveryTree(t *testing.T, root string) map[string]recoveryFileImage {
	t.Helper()
	image := map[string]recoveryFileImage{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		var data []byte
		if info.Mode().IsRegular() {
			data, err = os.ReadFile(path)
			if err != nil {
				return err
			}
		}
		image[path] = recoveryFileImage{info.Mode(), info.ModTime().UnixNano(), string(data)}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return image
}

// Both review overlap shapes refuse by name before changing any filesystem
// entry. The same restored records recover MAX and first sights with a disjoint
// audit, so rejecting every recovery cannot satisfy this regression.
func TestDeltaRecoveryDerivedPathCollision(t *testing.T) {
	for _, record := range []string{"snapshot", "sentinel"} {
		t.Run(record, func(t *testing.T) {
			root := t.TempDir()
			data, continuity := filepath.Join(root, "data"), filepath.Join(root, "continuity")
			for _, dir := range []string{data, continuity} {
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
			}
			path, sentinel := filepath.Join(data, "clock"), filepath.Join(continuity, "clock")
			if record == "snapshot" {
				path += ".pending"
			} else {
				sentinel += ".pending"
			}
			s, err := CreateFileStoreAt(path, sentinel, ClockState{100, map[string]int64{"tip": 100}})
			if err != nil {
				t.Fatal(err)
			}
			old, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Transact(func(state *ClockState) error { state.KeptMark = 200; return nil }); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, old, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := OpenFileStoreAt(path, sentinel); !errors.Is(err, ErrStoreContinuity) {
				t.Fatalf("partial restore: %v", err)
			}
			audit := filepath.Join(data, "clock")
			if record == "sentinel" {
				audit = filepath.Join(continuity, "clock")
			}
			before := recoveryTree(t, root)
			if _, err := RecoverFileStoreAt(path, sentinel, audit); !errors.Is(err, ErrRecoveryPathCollision) {
				t.Errorf("want RECOVERY_PATH_COLLISION, got %v", err)
			}
			if after := recoveryTree(t, root); !reflect.DeepEqual(before, after) {
				t.Error("collision changed filesystem entries")
			}
			if t.Failed() {
				return
			}
			s, err = RecoverFileStoreAt(path, sentinel, filepath.Join(continuity, "disjoint-audit"))
			if err != nil {
				t.Fatal(err)
			}
			state, err := ReadClockState(s)
			if err != nil || state.KeptMark != 200 || !reflect.DeepEqual(state.FirstSights, map[string]int64{"tip": 100}) {
				t.Fatalf("disjoint recovery lost state: %+v, %v", state, err)
			}
			if _, err := OpenFileStoreAt(path, sentinel); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Every feasible equality among snapshot, sentinel, their markers, lock, audit
// and audit marker refuses before lock creation. Equal markers also imply equal
// base names; a base cannot equal its own suffixed name, and .lock cannot equal
// a .pending suffix. Those impossible pairs need no artificial path model.
func TestRecoveryManagedPathCollisions(t *testing.T) {
	cases := []struct{ name, snapshot, sentinel, audit string }{
		{"snapshot-sentinel", "x", "x", "audit"},
		{"snapshot-marker-sentinel-marker", "x", "x", "audit"},
		{"snapshot-sentinel-marker", "x.pending", "x", "audit"},
		{"snapshot-marker-sentinel", "x", "x.pending", "audit"},
		{"lock-sentinel", "x", "x.lock", "audit"},
		{"snapshot-audit", "x", "other", "x"},
		{"snapshot-marker-audit-marker", "x", "other", "x"},
		{"sentinel-audit", "other", "x", "x"},
		{"sentinel-marker-audit-marker", "other", "x", "x"},
		{"snapshot-marker-audit", "x", "other", "x.pending"},
		{"sentinel-marker-audit", "other", "x", "x.pending"},
		{"lock-audit", "x", "other", "x.lock"},
		{"snapshot-audit-marker", "x.pending", "other", "x"},
		{"sentinel-audit-marker", "other", "x.pending", "x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			// No valid JSON is needed: path refusal must precede record reads.
			for _, name := range []string{tc.snapshot, tc.sentinel, tc.audit} {
				if err := os.WriteFile(filepath.Join(root, name), []byte("unchanged\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before := recoveryTree(t, root)
			if _, err := RecoverFileStoreAt(filepath.Join(root, tc.snapshot), filepath.Join(root, tc.sentinel), filepath.Join(root, tc.audit)); !errors.Is(err, ErrRecoveryPathCollision) {
				t.Fatalf("want named collision: %v", err)
			}
			if !reflect.DeepEqual(before, recoveryTree(t, root)) {
				t.Fatal("collision changed filesystem entries")
			}
		})
	}
}

// Parent symlinks and relative/unclean names cannot conceal collisions; final
// component symlinks retain their own name for the ordinary I/O checks.
func TestRecoveryCanonicalPaths(t *testing.T) {
	root := t.TempDir()
	data, continuity := filepath.Join(root, "data"), filepath.Join(root, "continuity")
	for _, dir := range []string{data, continuity} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(data, alias); err != nil {
		t.Fatal(err)
	}
	path, sentinel := filepath.Join(data, "x.pending"), filepath.Join(continuity, "clock")
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	relative, err := filepath.Rel(cwd, alias)
	if err != nil {
		t.Fatal(err)
	}
	for _, audit := range []string{filepath.Join(alias, "x"), relative + "/../alias/./x", data + "/../data/x"} {
		before := recoveryTree(t, root)
		if _, err := RecoverFileStoreAt(path, sentinel, audit); !errors.Is(err, ErrRecoveryPathCollision) {
			t.Fatalf("alias collision: %v", err)
		}
		if !reflect.DeepEqual(before, recoveryTree(t, root)) {
			t.Fatal("alias collision wrote files")
		}
	}
	final := filepath.Join(data, "link")
	if err := os.Symlink(path, final); err != nil {
		t.Fatal(err)
	}
	canonical, err := canonicalRecoveryPath(final)
	if err != nil || canonical != final {
		t.Fatalf("followed final symlink: %q, %v", canonical, err)
	}
}
