package diagnosticcheck

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

// Claim: each required rendering is detected; addresses and redaction are
// accepted. This calibrates the instrument independently of holder behavior.
func TestDetectorRenderings(t *testing.T) {
	raw := []byte("0123456789abcdef0123456789abcdef")
	d := NewDetector(raw, true)
	var words [8]uint32
	for i := range words {
		words[i] = binary.BigEndian.Uint32(raw[28-4*i : 32-4*i])
	}
	for _, tc := range []struct{ name, out string }{
		{"plaintext", string(raw)}, {"raw-byte", fmt.Sprintf("%s", raw)},
		{"hex", hex.EncodeToString(raw)}, {"uppercase-hex", strings.ToUpper(hex.EncodeToString(raw))},
		{"decimal-byte", fmt.Sprint(raw)}, {"byte-literal", fmt.Sprintf("%#v", raw)},
		{"limbs", fmt.Sprint(words)}, {"limb-literal", fmt.Sprintf("%#v", words)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !d.Leaks(tc.out) {
				t.Fatal("detector missed synthetic control")
			}
		})
	}
	for _, safe := range []string{"[REDACTED]", "0xc00001c080", "&{0xc00001c080}", "<nil>"} {
		if d.Leaks(safe) {
			t.Fatal("detector rejected address/redaction control")
		}
	}
}
