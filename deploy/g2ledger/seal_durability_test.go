//go:build linux

package g2ledger

import (
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// Claim: each append fsync checkpoint fails closed after a new Open, for both
// intent and commit. Only the selected fsync faults; all writes/closes work.
// This is restart/process evidence on this filesystem, not power-loss emulation.
func TestLedgerFailedSealSurvivesReopen(t *testing.T) {
	for _, phase := range []string{"intent", "commit"} {
		for _, checkpoint := range []string{"guard", "guard-directory", "records", "head", "head-directory"} {
			t.Run(phase+"/"+checkpoint, func(t *testing.T) {
				f := setup(t)
				older := f.create(t, "older", "file", "remove")
				target := filepath.Join(f.root, "target")
				injected := false
				f.l.sync = func(file *os.File) error {
					event := ""
					switch {
					case file.Name() == unsealedName:
						event = "guard"
					case file.Name() == recordsName:
						event = "records"
					case strings.HasPrefix(file.Name(), ".HEAD-"):
						event = "head"
					case file == f.l.dir:
						raw, err := os.ReadFile(filepath.Join(f.dir, "HEAD"))
						must(t, err)
						var h head
						must(t, json.Unmarshal(raw, &h))
						event = "guard-directory"
						if h.Count == uint64(len(f.l.rows)+1) {
							event = "head-directory"
						}
					}
					currentPhase := "intent"
					if len(f.l.rows) == 4 {
						currentPhase = "commit"
					}
					if currentPhase == phase && event == checkpoint {
						injected = true
						return syscall.EIO
					}
					return file.Sync()
				}
				err := f.l.CreateFS(target, f.src, "file", "remove", uint32(os.Geteuid()), uint32(os.Getegid()), 0600)
				want := 1
				if phase == "commit" {
					want = 3
					exists(t, target)
				} else {
					absent(t, target)
				}
				code(t, err, want)
				if !injected || !strings.Contains(err.Error(), "input/output error") {
					t.Fatal("named fsync injection not applied", err)
				}
				f.l.Close()
				_, err = Open(f.dir, f.sys)
				code(t, err, 1)
				if !strings.Contains(err.Error(), "LEDGER_UNSEALED") {
					t.Fatal(err)
				}
				code(t, Run([]string{"replay", "-dir", f.dir, "-mode", "station"}, f.sys, io.Discard), 1)
				exists(t, older)
				if phase == "commit" {
					exists(t, target)
				}
			})
		}
	}
	f := setup(t)
	p := f.create(t, "target", "file", "remove")
	f.reopen(t)
	must(t, f.l.Replay("station"))
	absent(t, p)
}

// Claim: a separate producer process killed or returning EIO at the final HEAD
// directory fsync cannot confer deletion authority to a new CLI-adapter process.
// SIGKILL occurs immediately before that fsync, after the real HEAD rename.
func TestLedgerSealCheckpointSubprocess(t *testing.T) {
	if mode := os.Getenv("G2_TEST_SEAL_CHILD"); mode != "" {
		dir := os.Getenv("G2_TEST_SEAL_DIR")
		l, err := Open(dir, newSystem())
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		count := 0
		l.sync = func(file *os.File) error {
			count++
			if count == 10 { // final commit directory fsync, after 5 intent checkpoints
				if mode == "kill" {
					syscall.Kill(os.Getpid(), syscall.SIGKILL)
					panic("SIGKILL returned")
				}
				if mode == "eio" {
					return syscall.EIO
				}
			}
			return file.Sync()
		}
		err = l.CreateFS(os.Getenv("G2_TEST_SEAL_TARGET"), os.Getenv("G2_TEST_SEAL_SOURCE"), "file", "remove", uint32(os.Geteuid()), uint32(os.Getegid()), 0600)
		if mode == "eio" && (ExitCode(err) != 3 || !strings.Contains(err.Error(), "HEAD_DIRECTORY_SYNC")) {
			t.Fatal(err)
		}
		if mode == "control" {
			must(t, err)
		}
		return
	}
	for _, mode := range []string{"control", "eio", "kill"} {
		t.Run(mode, func(t *testing.T) {
			f := setup(t)
			target := filepath.Join(f.root, "target")
			f.l.Close()
			cmd := exec.Command(os.Args[0], "-test.run=^TestLedgerSealCheckpointSubprocess$", "-test.count=1")
			cmd.Env = append(os.Environ(), "G2_TEST_SEAL_CHILD="+mode, "G2_TEST_SEAL_DIR="+f.dir, "G2_TEST_SEAL_TARGET="+target, "G2_TEST_SEAL_SOURCE="+f.src)
			output, err := cmd.CombinedOutput()
			if mode == "kill" {
				exit, ok := err.(*exec.ExitError)
				if !ok || exit.ProcessState.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
					t.Fatalf("kill not applied: %v %s", err, output)
				}
			} else if err != nil {
				t.Fatalf("child %s: %v %s", mode, err, output)
			}
			exists(t, target)
			got := Run([]string{"replay", "-dir", f.dir, "-mode", "station"}, f.sys, io.Discard)
			if mode == "control" {
				must(t, got)
				absent(t, target)
			} else {
				code(t, got, 1)
				exists(t, target)
			}
			t.Log("child_pid="+strconv.Itoa(cmd.Process.Pid), "mode="+mode)
		})
	}
}
