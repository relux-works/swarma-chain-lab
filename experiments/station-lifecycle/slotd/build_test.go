package slotd

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Go's actual source selection excludes fake symbols from default Darwin and
// every Linux build, including a mistakenly supplied tag. The tagged Darwin
// source is the positive control; final verification also cross-builds Linux.
func TestFakeBuildBoundary(t *testing.T) {
	for _, tc := range []struct {
		os, tags string
		fake     bool
	}{{"darwin", "", false}, {"linux", "", false}, {"linux", "slotdfake", false}, {"darwin", "slotdfake", true}} {
		for _, pkg := range []string{".", "../cmd/station-manager"} {
			c := exec.Command("go", "list", "-json", "-tags="+tc.tags, pkg)
			c.Env = append(os.Environ(), "GOOS="+tc.os, "GOARCH=amd64", "CGO_ENABLED=0", "GOWORK=off", "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off")
			raw, e := c.Output()
			if e != nil {
				t.Fatal("build selection unavailable", e)
			}
			var p struct{ GoFiles []string }
			if json.Unmarshal(raw, &p) != nil {
				t.Fatal("build selection JSON")
			}
			found := false
			for _, name := range p.GoFiles {
				found = found || strings.Contains(name, "fake")
			}
			if found != tc.fake {
				t.Fatalf("fake build boundary %s/%s/%s", tc.os, tc.tags, pkg)
			}
		}
	}
}
