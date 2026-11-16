package modelproxy

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/relux-works/swarma-chain-lab/experiments/model-proxy/internal/redactcheck"
)

// These existing codec.Secret holders must conceal synthetic credentials under
// the same battery as session tokens. FileSource is loaded through its real API;
// the helper copies only a quiescent source, before any concurrent use.
func TestOtherHoldersBadVerb(t *testing.T) {
	const raw = "a86d21e57fb049c3d1725e8049bc6f3027e1a9d5b46c803f"
	forbidden := redactcheck.SecretForms([]byte(raw))
	t.Run("UpstreamCredential", func(t *testing.T) {
		redactcheck.Check(t, UpstreamCredential{Scheme: SchemeAPIKey, Value: NewAPIKey(Secret(raw)), Version: "public-version"}, forbidden...)
	})
	t.Run("UpstreamKey", func(t *testing.T) { redactcheck.Check(t, NewAPIKey(Secret(raw)), forbidden...) })
	t.Run("Credential", func(t *testing.T) { redactcheck.Check(t, Credential{Bearer: NewBearer(Secret(raw))}, forbidden...) })
	t.Run("FileSource", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "credential")
		if err := os.WriteFile(path, []byte(raw), 0400); err != nil {
			t.Fatal(err)
		}
		source := NewFileSource(path)
		issued, err := source.Credential(context.Background())
		if err != nil || string(issued.Value.Reveal()) != raw {
			t.Fatal("synthetic file source control refused or changed")
		}
		redactcheck.CheckPointer(t, source, forbidden...)
	})
}
