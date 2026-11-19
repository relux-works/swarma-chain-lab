//go:build linux

package main

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

// The command still compiles with the non-Linux refusal stub. This checks the
// Darwin build boundary, not execution or Linux broker qualification on Darwin.
func TestManagedNonLinuxBuild(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "vet", ".")
	command.Env = append(os.Environ(), "GOOS=darwin", "GOARCH=arm64", "GOWORK=off")
	if err := command.Start(); err != nil {
		t.Fatal("non-Linux build check could not start")
	}
	t.Logf("owned cross-build command PID=%d", command.Process.Pid)
	if err := command.Wait(); err != nil {
		t.Fatal("non-Linux command build regressed")
	}
}
