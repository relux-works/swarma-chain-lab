package service

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	check "github.com/relux-works/swarma-chain-lab/experiments/notary-checker"
)

// Claim: the real Service cannot expose the credential through its unexported
// reader pointer, including fmtPointer bad-verb restarts for %s, %q and %t.
func TestRPCPasswordServiceContainer(t *testing.T) {
	const synthetic = "n6-synthetic-password"
	path := filepath.Join(t.TempDir(), "credential")
	if err := os.WriteFile(path, []byte("synthetic-user:"+synthetic), 0600); err != nil {
		t.Fatal(err)
	}
	n, err := check.NewNodeNameReader("http://127.0.0.1:1", path)
	if err != nil {
		t.Fatal(err)
	}
	s := &Service{node: n}
	for _, verb := range []string{"%v", "%+v", "%x", "%d", "%s", "%q", "%t"} {
		// A plain service-shaped container must expose the synthetic control.
		control := &struct{ node *struct{ password string } }{&struct{ password string }{synthetic}}
		if (verb == "%s" || verb == "%q" || verb == "%t") && !strings.Contains(fmt.Sprintf(verb, control), synthetic) {
			t.Fatal("plain Service control missing")
		}
		out := fmt.Sprintf(verb, s)
		if strings.Contains(out, synthetic) {
			t.Fatal("Service diagnostic contains credential for " + verb)
		}
	}
}
