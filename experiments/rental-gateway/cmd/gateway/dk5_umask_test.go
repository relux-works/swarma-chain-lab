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
// Short names keep the local-test Unix socket fixture within its 100-byte bound.
func TestDK5Umask(t *testing.T) {
	if os.Getenv("DK5_CONSUMER_UMASK_CHILD") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestDK5Umask$", "-test.v")
		cmd.Env = append(os.Environ(), "DK5_CONSUMER_UMASK_CHILD=1")
		if out, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("installed fixture umask child: %v\n%s", e, out)
		}
		return
	}
	old := unix.Umask(0077)
	t.Cleanup(func() { unix.Umask(old) })
	t.Run("installed", TestDK5InstalledMode)
	t.Run("files", TestConfigFiles)
	t.Run("state", TestPrivateDirNoRedirectedEffects)
	t.Run("pins", TestConfigPlaceholderPins)
	t.Run("tls", TestGatewayTLSAuthority)
	t.Run("transport", TestRemoteStationTransport)
	t.Run("recovery", TestServeStartupRecovery)
	t.Run("expiry", TestServeExpiryDuringRelayOutage)
}
