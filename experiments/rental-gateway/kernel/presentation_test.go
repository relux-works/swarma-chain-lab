package kernel_test

import (
	"crypto/sha256"
	"encoding/hex"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernel"
	"strings"
	"testing"
)

// The transport seam hashes the signed object only, agrees with an independent
// hash construction, and bounds decoded bytes inclusively. This fixture has no
// authority: signatures and the complete schema are tested by the real binding.
func TestPresentationTransport(t *testing.T) {
	signed := `{"grant":{"version":3,"marker":"x"},"signature":"` + strings.Repeat("a", 128) + `"}`
	raw := `{"signed_grant":` + signed + `,"issuance":{"txid":"` + strings.Repeat("b", 64) + `"}}`
	sum := sha256.Sum256([]byte(signed))
	want := hex.EncodeToString(sum[:])
	for _, proof := range []string{raw, strings.Replace(raw, strings.Repeat("b", 64), strings.Repeat("c", 64), 1)} {
		got, err := kernel.PresentationID([]byte(proof))
		if err != nil || got != want {
			t.Fatalf("stable ID: %s %v", got, err)
		}
	}
	exact := strings.Replace(raw, `"marker":"x"`, `"marker":"`+strings.Repeat("x", 16384-len(raw)+1)+`"`, 1)
	if len(exact) != 16384 {
		t.Fatal("boundary fixture")
	}
	if _, err := kernel.PresentationID([]byte(exact)); err != nil {
		t.Fatal("16384-byte presentation refused", err)
	}
	cases := map[string]string{
		"empty": "", "json": "not JSON", "legacy": `{"certificate":{"version":2},"signature":"` + strings.Repeat("a", 128) + `"}`,
		"version":    strings.Replace(raw, `"version":3`, `"version":2`, 1),
		"whitespace": raw + " ", "trailing": raw + raw,
		"missing-issuance":  `{"signed_grant":` + signed + `}`,
		"short-locator":     strings.Replace(raw, strings.Repeat("b", 64), "bb", 1),
		"uppercase-locator": strings.Replace(raw, strings.Repeat("b", 64), strings.Repeat("B", 64), 1),
		"signature":         strings.Replace(raw, strings.Repeat("a", 128), "zz", 1),
		"unknown":           strings.Replace(raw, `{"signed_grant":`, `{"extra":0,"signed_grant":`, 1),
		"duplicate":         strings.Replace(raw, `{"signed_grant":`, `{"signed_grant":`+signed+`,"signed_grant":`, 1),
		"signed-duplicate":  strings.Replace(raw, `"signature":`, `"grant":{"version":3},"signature":`, 1),
		"oversize":          strings.Replace(exact, `"marker":"x`, `"marker":"xx`, 1),
	}
	for name, bad := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := kernel.PresentationID([]byte(bad)); err == nil {
				t.Fatal("malformed framing accepted")
			}
			if _, err := kernel.PresentationID([]byte(raw)); err != nil {
				t.Fatal("valid neighbour refused", err)
			}
		})
	}
}

// RawMessage must not hide a second/escaped version from framing. Refusal
// returns no presentation hash; the positive control retains opaque grant fields.
func TestSJ1PresentationKeys(t *testing.T) {
	frame := func(grant string) []byte {
		return []byte(`{"signed_grant":{"grant":` + grant + `,"signature":"` + strings.Repeat("a", 128) + `"},"issuance":{"txid":"` + strings.Repeat("b", 64) + `"}}`)
	}
	for _, grant := range []string{`{"version":3,"version":2}`, `{"version":2,"version":3}`, `{"version":3,"vers\u0069on":2}`, `{"vers\u0069on":3}`, `{"version":3,"extra":{"grant":1,"grant":2}}`} {
		if id, err := kernel.PresentationID(frame(grant)); err == nil || id != "" {
			t.Fatal("SJ1 ambiguous presentation admitted")
		}
		if _, err := kernel.PresentationID(frame(`{"version":3,"extra":{"note":"a\nb"}}`)); err != nil {
			t.Fatal("valid neighbor refused", err)
		}
	}
}
