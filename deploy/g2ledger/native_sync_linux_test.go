//go:build linux

package g2ledger

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Claim: with both sync hooks nil, CreateFS executes exactly one real payload
// and parent fsync, in that order before writing the commit record, and all
// guard/guard-dir/record/head/head-dir syncs for intent and commit. Actual EIO
// at either syscall leaves the named orphan across verify/replay and preserves
// older work. This requires Linux strace/ptrace; it is not power-loss evidence.
func TestLedgerCreateFSNativeSync(t *testing.T) {
	if os.Getenv("G2_NATIVE_SYNC_CHILD") == "1" {
		l, err := Open(os.Getenv("G2_NATIVE_SYNC_LEDGER"), newSystem())
		must(t, err)
		defer l.Close()
		if l.payloadSync != nil || l.sync != nil {
			t.Fatal("native control must have no hooks")
		}
		target := os.Getenv("G2_NATIVE_SYNC_TARGET")
		err = l.CreateFS(target, os.Getenv("G2_NATIVE_SYNC_SOURCE"), "file", "remove", uint32(os.Geteuid()), uint32(os.Getegid()), 0600)
		if os.Getenv("G2_NATIVE_SYNC_FAULT") == "control" {
			must(t, err)
		} else {
			code(t, err, 3)
			if err.Error() != "g2-ledger: ORPHAN "+target || !l.poisoned {
				t.Fatalf("wrong orphan/poison: %v", err)
			}
		}
		return
	}
	if _, err := exec.LookPath("strace"); err != nil {
		t.Fatal("native fsync contract requires strace:", err)
	}
	for _, checkpoint := range []string{"control", "payload", "parent"} {
		t.Run(checkpoint, func(t *testing.T) {
			f := setup(t)
			older := f.create(t, "older", "file", "remove")
			target := filepath.Join(f.root, "target")
			f.l.Close()
			tracePath := filepath.Join(t.TempDir(), "sync.trace")
			args := []string{"-f", "-yy", "-s", "4096", "-e", "trace=fsync,write", "-o", tracePath}
			if checkpoint != "control" {
				selected := target
				if checkpoint == "parent" {
					selected = f.root
				}
				args = append(args, "-P", selected, "-e", "inject=fsync:error=EIO:when=1")
			}
			args = append(args, os.Args[0], "-test.run=^TestLedgerCreateFSNativeSync$", "-test.count=1")
			cmd := exec.Command("strace", args...)
			cmd.Env = append(os.Environ(), "G2_NATIVE_SYNC_CHILD=1", "G2_NATIVE_SYNC_LEDGER="+f.dir, "G2_NATIVE_SYNC_TARGET="+target, "G2_NATIVE_SYNC_SOURCE="+f.src, "G2_NATIVE_SYNC_FAULT="+checkpoint)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("native child: %v\n%s", err, output)
			}
			t.Log("strace_pid=" + strconv.Itoa(cmd.Process.Pid))
			raw, err := os.ReadFile(tracePath)
			must(t, err)
			trace := string(raw)
			payload, parent, commit := -1, -1, -1
			payloadCount, parentCount := 0, 0
			var checkpoints []string
			for i, line := range strings.Split(trace, "\n") {
				if strings.Contains(line, "fsync(") {
					switch {
					case strings.Contains(line, "<"+target+">"):
						checkpoints = append(checkpoints, "payload")
					case strings.Contains(line, "<"+f.root+">"):
						checkpoints = append(checkpoints, "parent")
					case strings.Contains(line, "<"+f.dir+"/"+unsealedName+">"):
						checkpoints = append(checkpoints, "guard")
					case strings.Contains(line, "<"+f.dir+"/"+recordsName+">"):
						checkpoints = append(checkpoints, "records")
					case strings.Contains(line, "<"+f.dir+"/.HEAD-"):
						checkpoints = append(checkpoints, "head")
					case strings.Contains(line, "<"+f.dir+">"):
						checkpoints = append(checkpoints, "ledger-dir")
					}

					if strings.Contains(line, "<"+target+">") {
						payload, payloadCount = i, payloadCount+1
					}
					if strings.Contains(line, "<"+f.root+">") {
						parent, parentCount = i, parentCount+1
					}
				}
				if strings.Contains(line, "write(") && strings.Contains(line, `\"op\":\"commit\"`) {
					commit = i
				}
			}
			if checkpoint == "control" {
				want := "guard,ledger-dir,records,head,ledger-dir,payload,parent,guard,ledger-dir,records,head,ledger-dir"
				if strings.Join(checkpoints, ",") != want {
					t.Fatalf("missing/reordered real sync: got %v want %s\n%s", checkpoints, want, trace)
				}
				if payloadCount != 1 || parentCount != 1 || !(payload < parent && parent < commit) {
					t.Fatalf("required native payload/parent sync order missing: counts=%d/%d positions=%d/%d/%d\n%s", payloadCount, parentCount, payload, parent, commit, trace)
				}
			} else if !strings.Contains(trace, "(INJECTED)") || !strings.Contains(trace, "EIO") {
				t.Fatalf("required %s fsync checkpoint was never executed/faulted\n%s", checkpoint, trace)
			}
			exists(t, target)
			exists(t, older)
			for _, op := range []string{"verify", "replay"} {
				args := []string{op, "-dir", f.dir}
				if op == "replay" {
					args = append(args, "-mode", "station")
				}
				err := Run(args, f.sys, io.Discard)
				if checkpoint == "control" {
					must(t, err)
				} else {
					code(t, err, 3)
					if err.Error() != "g2-ledger: ORPHAN "+target {
						t.Fatal(err)
					}
					exists(t, target)
					exists(t, older)
				}
			}
			if checkpoint == "control" {
				absent(t, target)
				absent(t, older)
			}
		})
	}
}
