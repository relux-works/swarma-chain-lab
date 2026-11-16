package service

import (
	"testing"
)

// J9 changes no supported checker admission. The actual HTTP handler used by
// serve signs the regular v3 control once; the v4 row projections, malformed /2
// row and undesignated policy refuse at their existing codes with zero signer
// calls and no partial output. v4 row octets are not specified by the pin.
func TestJ9RefusalsNeverSign(t *testing.T) {
	for _, c := range []struct{ name, want string }{
		{"positive-same-owner", "ATTEST"},
		{"negative-j9-v4-no-certifier", "GRANT_FIELD"},
		{"negative-j9-v4-other-certifier", "GRANT_FIELD"},
		{"negative-j9-v3-no-certifier", "CONTRACT_DELEGATE"},
		{"negative-j9-v3-other-certifier", "NOTARY_NOT_DESIGNATED"},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, req, _ := setupForVector(t, fixtureNamed(t, c.name))
			original := s.sign
			calls := 0
			s.sign = func(d []byte) (string, error) { calls++; return original(d) }
			status, result, _ := submit(t, s, encode(t, req))
			if c.want == "ATTEST" {
				if status != 200 || result.Decision != c.want || calls != 1 || len(result.SignedAttestation) == 0 || result.AnchorFrame == "" {
					t.Fatalf("positive: %d %s signs=%d", status, result.Decision, calls)
				}
			} else if status != 422 || result.Decision != c.want || calls != 0 || len(result.SignedAttestation) != 0 || result.AnchorFrame != "" {
				t.Fatalf("refusal: %d %s signs=%d", status, result.Decision, calls)
			}
		})
	}
}
