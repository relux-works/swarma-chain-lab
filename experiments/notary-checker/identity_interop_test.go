package notarycheck

import (
	"os"
	"testing"
)

func identityBytes(t *testing.T, name string) []byte {
	t.Helper()
	b, e := os.ReadFile("../grantcheck/testdata/identity-interop/" + name)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

// Claim: the pinned issuer's /1 root has valid v3 signatures and consent;
// the certification API refuses that unsupported contract as CONTRACT_ENCODING.
// A root is not a delegable /2 parent/child certification bundle. No child,
// notary statement or liveness observation is synthesized for this junction.
func TestIdentityInteropRootBoundary(t *testing.T) {
	for _, tc := range []struct{ proof, contract string }{{"presentation.json", "contract.json"}, {"wrong-profile.json", "wrong-profile-contract.json"}} {
		raw := identityBytes(t, tc.proof)
		contract := identityBytes(t, tc.contract)
		if _, err := readGrant(raw, 1795000000); err != nil {
			t.Fatal("valid v3 signature envelope refused", err)
		}
		_, err := Check(Input{Parent: raw, Child: raw, ParentContract: contract, ChildContract: contract, At: 1795000000})
		if err == nil || err.Error() != "CONTRACT_ENCODING" {
			t.Fatalf("unsupported certification contract: %v", err)
		}
	}
}

// Claim: outer signatures and inner consent, version and time checks refuse
// these exact exported mutations beside the valid /1 v3 parsing control.
// Seal/script/spend/holders/current-chain checks are outside readGrant's API.
func TestIdentityInteropReadRefusals(t *testing.T) {
	for _, tc := range []struct{ name, want string }{{"wrong-consent", "GRANT_CONSENT"}, {"wrong-grantee", "GRANT_CONSENT"}, {"wrong-version", "GRANT_FIELD"}, {"tampered-byte", "GRANT_SIGNATURE"}, {"expired-window", "GRANT_EXPIRED"}} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := readGrant(identityBytes(t, "presentation.json"), 1795000000); err != nil {
				t.Fatal(err)
			}
			_, err := readGrant(identityBytes(t, tc.name+".json"), 1795000000)
			if err == nil || err.Error() != tc.want {
				t.Fatalf("got %v want %s", err, tc.want)
			}
			t.Logf("notary readGrant: %s", err)
		})
	}
	for _, name := range []string{"wrong-seal", "wrong-locator", "wrong-profile"} {
		if _, err := readGrant(identityBytes(t, name+".json"), 1795000000); err != nil {
			t.Fatalf("parser unexpectedly judged chain state: %s: %v", name, err)
		}
	}
}
