package g2ledger

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Claim: literal runtime prefixes stay refused when an existing component redirects elsewhere.
// This read-only Linux fixture uses /run/shm ->
// /dev/shm; all created files and ledgers remain in the private test directory.
func TestLedgerLiteralRuntimePrefixRefused(t *testing.T) {
	target, err := filepath.EvalSymlinks("/run/shm")
	must(t, err)
	if runtimePath(target) {
		t.Fatal("fixture must redirect outside /run", target)
	}
	for _, path := range []string{"/run/shm/pr99-not-created", "/var/run/shm/pr99-not-created"} {
		t.Run(path, func(t *testing.T) {
			err := targetPathPolicy(path)
			if !errors.Is(err, errVolatileRuntime) {
				t.Errorf("literal runtime target lacks refusal: path=%s resolved-parent=%s policy=%v", path, target, err)
			}
			f := setup(t)
			ledger := filepath.Join(f.root, "refused-ledger")
			err = Init(ledger, filepath.Join(f.root, "manifest.json"), filepath.Join(f.root, "baseline"), InitOptions{Purpose: "station", Scope: Scope{Paths: []ScopePath{{Path: path, Kind: "file"}}}, System: f.sys})
			if ExitCode(err) != 1 || !strings.Contains(err.Error(), volatileRuntimeReason) {
				t.Errorf("public init lacks runtime refusal: exit=%d err=%v", ExitCode(err), err)
			}
			absent(t, ledger)
		})
	}
	for _, path := range []string{"/var/lib/pr99-not-created", filepath.Join(t.TempDir(), "persistent")} {
		must(t, targetPathPolicy(path))
	}
	if os.Getuid() == 0 {
		t.Fatal("probe requires non-root execution")
	}
}
