package main

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/relux-works/swarma-chain-lab/experiments/grant-v4/chainview"
)

// The real command refuses incomplete arguments without changing records; with
// explicit paths it logs recovery and retains the largest available mark.
func TestRecoveryCommand(t *testing.T) {
	if os.Getenv("CHAINVIEW_RECOVERY_COMMAND") == "1" {
		os.Args = append([]string{os.Args[0]}, strings.Split(os.Getenv("CHAINVIEW_RECOVERY_ARGS"), "\n")...)
		main()
		return
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "clock.json")
	sentinel := filepath.Join(dir+".continuity", "clock.json.sentinel")
	s, err := chainview.CreateFileStore(path, chainview.ClockState{KeptMark: 100, FirstSights: map[string]int64{"tip": 100}})
	if err != nil {
		t.Fatal(err)
	}
	old, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Transact(func(state *chainview.ClockState) error { state.KeptMark = 200; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, old, 0600); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) ([]byte, error) {
		child := exec.Command(os.Args[0], "-test.run=^TestRecoveryCommand$", "-test.v")
		child.Env = append(os.Environ(), "CHAINVIEW_RECOVERY_COMMAND=1", "CHAINVIEW_RECOVERY_ARGS="+strings.Join(args, "\n"))
		return child.CombinedOutput()
	}
	output, err := run("-snapshot", path)
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 2 || !bytes.Contains(output, []byte("paths are required")) {
		t.Fatalf("argument refusal: %v\n%s", err, output)
	}
	current, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(current, old) {
		t.Fatal("argument refusal changed snapshot", err)
	}
	audit := filepath.Join(dir+".continuity", "recovery.json")
	output, err = run("-snapshot", path, "-sentinel", sentinel, "-audit", audit)
	if err != nil || !bytes.Contains(output, []byte(`"committed"`)) {
		t.Fatalf("command recovery: %v\n%s", err, output)
	}
	opened, err := chainview.OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	state, err := chainview.ReadClockState(opened)
	if err != nil || state.KeptMark != 200 || state.FirstSights["tip"] != 100 {
		t.Fatal("recovery lost maximum or sight", state, err)
	}
}

// The actual command refuses both derived-sidecar overlaps with exit 1, no
// committed audit, and unchanged records/markers; disjoint audits recover MAX.
func TestDeltaRecoveryCommandDerivedPathCollision(t *testing.T) {
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
			s, err := chainview.CreateFileStoreAt(path, sentinel, chainview.ClockState{KeptMark: 100, FirstSights: map[string]int64{"tip": 100}})
			if err != nil {
				t.Fatal(err)
			}
			old, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Transact(func(state *chainview.ClockState) error { state.KeptMark = 200; return nil }); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, old, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := chainview.OpenFileStoreAt(path, sentinel); !errors.Is(err, chainview.ErrStoreContinuity) {
				t.Fatalf("partial restore: %v", err)
			}
			audit := filepath.Join(data, "clock")
			if record == "sentinel" {
				audit = filepath.Join(continuity, "clock")
			}
			// Deliberately remove the prior lock to detect even lock creation.
			if err := os.Remove(path + ".lock"); err != nil {
				t.Fatal(err)
			}
			before := commandRecoveryTree(t, root)
			run := func(audit string) ([]byte, error) {
				child := exec.Command(os.Args[0], "-test.run=^TestRecoveryCommand$", "-test.v")
				child.Env = append(os.Environ(), "CHAINVIEW_RECOVERY_COMMAND=1", "CHAINVIEW_RECOVERY_ARGS="+strings.Join([]string{"-snapshot", path, "-sentinel", sentinel, "-audit", audit}, "\n"))
				return child.CombinedOutput()
			}
			output, err := run(audit)
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 1 || !bytes.Contains(output, []byte("RECOVERY_PATH_COLLISION")) || bytes.Contains(output, []byte(`"committed"`)) {
				t.Fatalf("collision command: %v\n%s", err, output)
			}
			if !reflect.DeepEqual(before, commandRecoveryTree(t, root)) {
				t.Fatal("refused command changed filesystem")
			}
			output, err = run(filepath.Join(continuity, "disjoint-audit"))
			if err != nil || !bytes.Contains(output, []byte(`"committed"`)) {
				t.Fatalf("disjoint command: %v\n%s", err, output)
			}
			opened, err := chainview.OpenFileStoreAt(path, sentinel)
			if err != nil {
				t.Fatal(err)
			}
			state, err := chainview.ReadClockState(opened)
			if err != nil || state.KeptMark != 200 || !reflect.DeepEqual(state.FirstSights, map[string]int64{"tip": 100}) {
				t.Fatalf("lost maximum/sights: %+v, %v", state, err)
			}
		})
	}
}

type commandFileImage struct {
	Mode     os.FileMode
	Modified int64
	Data     string
}

func commandRecoveryTree(t *testing.T, root string) map[string]commandFileImage {
	t.Helper()
	image := map[string]commandFileImage{}
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
		image[path] = commandFileImage{info.Mode(), info.ModTime().UnixNano(), string(data)}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return image
}
