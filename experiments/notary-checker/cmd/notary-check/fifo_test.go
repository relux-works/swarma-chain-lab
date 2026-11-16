package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestInputProcessHelper(t *testing.T) {
	if os.Getenv("NOTARY_INPUT_CHILD") != "1" {
		return
	}
	args := strings.Split(os.Getenv("NOTARY_INPUT_ARGS"), "\n")
	os.Exit(run(args, os.Stdout, os.Stderr))
}

// Every file flag accepts its regular positive control and promptly refuses a
// FIFO as INPUT_READ. The child process bounds a restored blocking-open mutant.
func TestInputFIFORefusal(t *testing.T) {
	names := []string{"parent", "child", "parent-contract", "child-contract", "request", "policy", "notary-value", "statement", "parent-text", "child-text", "offline-name-fixture"}
	for _, kind := range names {
		t.Run(kind, func(t *testing.T) {
			var args []string
			for _, n := range names[:8] {
				args = append(args, "-"+n, "../../testdata/positive/"+n+".json")
			}
			args = append(args, "-at", "1700000100")
			if kind == "parent-text" || kind == "child-text" {
				path := filepath.Join(t.TempDir(), "empty")
				if err := os.WriteFile(path, nil, 0600); err != nil {
					t.Fatal(err)
				}
				args = append(args, "-"+kind, path)
			} else if kind == "offline-name-fixture" {
				args = append(args, "-"+kind, "../../testdata/mvp-names.json")
			}
			var out, errs bytes.Buffer
			if code := run(args, &out, &errs); code != 0 || !strings.HasPrefix(out.String(), "ATTEST ") {
				t.Fatalf("regular control: %d %q %q", code, out.String(), errs.String())
			}
			fifo := filepath.Join(t.TempDir(), "fifo")
			if err := syscall.Mkfifo(fifo, 0600); err != nil {
				t.Fatal(err)
			}
			args = append(args, "-"+kind, fifo)
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, exe, "-test.run=^TestInputProcessHelper$")
			cmd.Env = append(os.Environ(), "GORACE=atexit_sleep_ms=0", "NOTARY_INPUT_CHILD=1", "NOTARY_INPUT_ARGS="+strings.Join(args, "\n"))
			out.Reset()
			errs.Reset()
			cmd.Stdout = &out
			cmd.Stderr = &errs
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Logf("owned CLI helper PID %d", cmd.Process.Pid)
			err = cmd.Wait()
			if ctx.Err() != nil {
				t.Fatal("FIFO open did not refuse within 3s")
			}
			if e, ok := err.(*exec.ExitError); !ok || e.ExitCode() != 2 || out.String() != "REFUSED INPUT_READ\n" {
				t.Fatalf("FIFO refusal: %v %q %q", err, out.String(), errs.String())
			}
		})
	}
}
