package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
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
