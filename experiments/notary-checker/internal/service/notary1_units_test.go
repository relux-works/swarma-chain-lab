package service

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Claim: systemd parses both shipped units and their declared dependency graph
// in an offline root. Placeholder executables/targets satisfy path resolution;
// no unit or executable is started. This does not prove runtime sandbox support.
// A missing-ExecStart control must trigger the intended diagnostic, proving
// the verifier actually checks the submitted unit rather than unrelated setup.
func TestNotary1UnitsVerify(t *testing.T) {
	analyze, err := exec.LookPath("systemd-analyze")
	if err != nil {
		t.Skip("systemd-analyze unavailable; target verification remains required")
	}
	root := t.TempDir()
	write := func(relative, value string, mode os.FileMode) {
		t.Helper()
		path := filepath.Join(root, relative)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(value), mode); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"sysinit.target", "basic.target", "local-fs.target", "shutdown.target", "multi-user.target",
		"sockets.target", "timers.target", "paths.target", "slices.target", "system.slice", "-.slice"} {
		write("etc/systemd/system/"+name, "[Unit]\nDescription=Offline verification fixture\n", 0644)
	}
	for _, path := range []string{"opt/namecoin/28.0/bin/namecoind", "opt/namecoin/28.0/bin/namecoin-cli",
		"opt/notary-service/v0.1.1/notary-service", "usr/bin/install"} {
		write(path, "#!/bin/sh\nexit 0\n", 0755)
	}
	var notary string
	for _, name := range []string{"namecoind-regtest.service", "notary-service.service"} {
		raw, err := os.ReadFile(filepath.Join("../../deploy/notary1", name))
		if err != nil {
			t.Fatal(err)
		}
		write("etc/systemd/system/"+name, string(raw), 0644)
		if name == "notary-service.service" {
			notary = string(raw)
		}
	}
	verify := func() ([]byte, error) {
		cmd := exec.Command(analyze, "verify", "--man=no", "--generators=no", "--recursive-errors=yes", "--root="+root,
			"namecoind-regtest.service", "notary-service.service")
		cmd.Env = append(os.Environ(), "LC_ALL=C", "SYSTEMD_LOG_LEVEL=warning")
		return cmd.CombinedOutput()
	}
	if output, err := verify(); err != nil {
		t.Fatalf("shipped units rejected: %v\n%s", err, output)
	}
	lines := strings.Split(notary, "\n")
	var changed []string
	removed := 0
	for _, line := range lines {
		if strings.HasPrefix(line, "ExecStart=") {
			removed++
			continue
		}
		changed = append(changed, line)
	}
	if removed != 1 {
		t.Fatal("control must remove exactly one ExecStart")
	}
	write("etc/systemd/system/notary-service.service", strings.Join(changed, "\n"), 0644)
	if output, err := verify(); err == nil || !strings.Contains(string(output), "no ExecStart=") {
		t.Fatalf("missing-ExecStart control did not fail as intended: %v\n%s", err, output)
	}
}
