package main

import (
	"os"
	"os/exec"
	"testing"

	"golang.org/x/sys/unix"
)

// Real consumer fixtures retain their valid and refusal neighbors under 0077.
// A child confines the process-global mask; root ownership remains the existing
// labelled seam. These local fixture tests do not establish installed-host custody.
func TestDK5FixtureUmask(t *testing.T) {
	if os.Getenv("DK5_CONSUMER_UMASK_CHILD") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestDK5FixtureUmask$", "-test.v")
		cmd.Env = append(os.Environ(), "DK5_CONSUMER_UMASK_CHILD=1")
		if out, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("installed fixture umask child: %v\n%s", e, out)
		}
		return
	}
	old := unix.Umask(0077)
	t.Cleanup(func() { unix.Umask(old) })
	t.Run("TestDK5InstalledMode", TestDK5InstalledMode)
	t.Run("TestCLI", TestCLI)
	t.Run("TestPinnedCLI", TestPinnedCLI)
}
