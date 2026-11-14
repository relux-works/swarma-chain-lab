package g2ledger

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Claim: the kernel-equivalent nested-symlink/.. spelling of /run receives the
// same public init refusal and baseline exclusion as a direct /run alias.
func TestReviewPR99VolatileDotDotAlias(t *testing.T) {
	if info, err := os.Stat("/run/lock"); err != nil || !info.IsDir() {
		t.Fatal("read-only /run/lock fixture unavailable", err)
	}
	for _, spelling := range []string{"direct", "symlink-dotdot"} {
		t.Run(spelling, func(t *testing.T) {
			fixture := setup(t)
			bridge := filepath.Join(t.TempDir(), "bridge")
			must(t, os.Symlink("/run/lock", bridge))
			alias := filepath.Join(fixture.root, "volatile-alias")
			destination := "/run"
			if spelling == "symlink-dotdot" {
				destination = bridge + "/.."
			}
			must(t, os.Symlink(destination, alias))
			resolved, err := filepath.EvalSymlinks(alias)
			must(t, err)
			if resolved != "/run" {
				t.Fatalf("fixture does not resolve to /run: %q", resolved)
			}
			t.Logf("alias resolves to %s; policy=%v", resolved, targetPathPolicy(alias))
			t.Run("init-refusal", func(t *testing.T) {
				ledger := filepath.Join(t.TempDir(), "refused-ledger")
				err := Init(ledger, filepath.Join(fixture.root, "manifest.json"), filepath.Join(fixture.root, "baseline"), InitOptions{Purpose: "station", Scope: Scope{Paths: []ScopePath{{Path: filepath.Join(alias, "missing-fixture"), Kind: "file"}}}, System: fixture.sys})
				if ExitCode(err) != 1 || !strings.Contains(err.Error(), volatileRuntimeReason) {
					t.Fatalf("runtime alias missing named refusal: exit=%d err=%v", ExitCode(err), err)
				}
				absent(t, ledger)
			})
			t.Run("baseline-exclusion", func(t *testing.T) {
				fixture.l.Close()
				var output bytes.Buffer
				err := Run([]string{"replay", "-dir", fixture.dir, "-mode", "station"}, fixture.sys, &output)
				t.Logf("replay_exit=%d output=%s", ExitCode(err), output.String())
				if err != nil {
					t.Fatalf("excluded /run alias created an unlisted baseline difference: %v", err)
				}
				if strings.Contains(output.String(), `"unlisted":1`) {
					t.Fatal("volatile alias counted as unlisted")
				}
				exists(t, alias)
			})
		})
	}
}

// Claim: a policy lookup error from a sibling symlink target is observable;
// this probe records whether baseline inspection propagates or classifies it.
func TestReviewPR99VolatileLookupProbe(t *testing.T) {
	fixture := setup(t)
	loop := filepath.Join(fixture.root, "loop")
	must(t, os.Symlink(loop, loop))
	t.Logf("policy_error=%v", targetPathPolicy(loop))
	fixture.l.Close()
	err := Run([]string{"replay", "-dir", fixture.dir, "-mode", "station"}, fixture.sys, io.Discard)
	t.Logf("replay_exit=%d error=%v", ExitCode(err), err)
}
