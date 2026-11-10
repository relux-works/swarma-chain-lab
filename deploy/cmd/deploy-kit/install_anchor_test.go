package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"
)

// Renderer validates its public inputs before writing anything; it does not
// certify an install or read/sign private bytes. Unknown/missing flags refuse.
func TestRenderInstallAnchor(t *testing.T) {
	pub, _, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	der, e := x509.MarshalPKIXPublicKey(pub)
	if e != nil {
		t.Fatal(e)
	}
	args := []string{"--manifest", "/etc/swarma/model/install.json", "--signature", "/etc/swarma/model/install.sig", "--manifest-sha256", strings.Repeat("a", 64), "--release-sha256", strings.Repeat("b", 64), "--algorithm", "ed25519", "--public-key", base64.StdEncoding.EncodeToString(der)}
	var out bytes.Buffer
	if e := renderInstallAnchor(args, &out); e != nil || !strings.HasPrefix(out.String(), "[Service]\n") {
		t.Fatal("anchor positive", e)
	}
	for _, extra := range [][]string{{"--public-key", "malformed"}, {"--algorithm", "rsa-pss-sha256"}, {"--unknown"}, {"--algorithm", "unknown"}, {"--manifest", "relative"}, {"--public-key", "bad\nline"}} {
		out.Reset()
		if e := renderInstallAnchor(append(append([]string{}, args...), extra...), &out); e == nil || out.Len() != 0 {
			t.Fatal("invalid anchor wrote output", e)
		}
	}
}
