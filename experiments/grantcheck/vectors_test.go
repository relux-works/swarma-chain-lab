package grantcheck

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

// Recorded outputs exercise the consumer's closed routing contract offline.
// They attest only to the recorded Core run, not to present chain liveness;
// no fixture is available to the production checker as an authority shortcut.
func TestRecordedVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/verdicts-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var file vectorFile
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err = d.Decode(&file); err != nil {
		t.Fatal(err)
	}
	if file.Version != 1 || file.DaemonSHA256 != "86b85483da23c83f7de134a5bf28bad8e3c6a8dbfe2af71a5e889a7b1547787f" || file.CLISHA256 != "5cccdfe19aef6b427373c200bda72d4dd66b5be2c5f93b7e8b08b9d6a81fdd4d" || !validKey(file.IssuerPubkey) {
		t.Fatal("fixture provenance pins")
	}
	want := map[string]struct {
		decision      Decision
		code          Code
		closed, retry bool
	}{
		"absent-in": {Exchange, CodeNoGrant, false, false}, "absent-out": {Refused, CodeNoGrant, false, false},
		"live-in": {Live, CodeLive, false, false}, "live-out": {Live, CodeLive, false, false}, "live-cache": {Live, CodeLive, false, false},
		"foreign": {Refused, CodeBindingMismatch, false, false}, "not-yet": {Exchange, CodeNotYet, false, false}, "expired": {Exchange, CodeExpired, false, false},
		"identity-isolation": {Refused, CodeNoGrant, false, false}, "malformed": {Refused, CodeInvalidPresentation, false, false}, "legacy": {Refused, CodeInvalidPresentation, false, false}, "oversize": {Refused, CodeOversize, false, false},
		"read-failure": {Refused, CodeVerifierUnavailable, false, true}, "grant-pending": {Refused, CodeGrantPending, false, true},
		"seal-mempool": {Exchange, CodeSealSpent, true, false}, "closed-out": {Refused, CodeSealSpent, true, false}, "closed-restart": {Exchange, CodeSealSpent, true, false},
		"rotation-pending": {Refused, CodeIdentityPending, false, true}, "rotation-pending-out": {Refused, CodeIdentityPending, false, true},
		"rotation-confirmed": {Exchange, CodeLandlordRotated, true, false}, "rotation-closed-out": {Refused, CodeLandlordRotated, true, false},
	}
	if len(file.Vectors) != len(want) {
		t.Fatal("fixture matrix incomplete")
	}
	for _, v := range file.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			expect, ok := want[v.Name]
			if !ok {
				t.Fatal("unexpected or duplicate vector")
			}
			delete(want, v.Name)
			assertVerdict(t, v.Expected, expect.decision, expect.code, expect.closed, expect.retry)
			if !validKey(v.Peer) || v.Setup == "" || (v.Direction != "in" && v.Direction != "out") || v.VerifierTime < 0 {
				t.Fatal("vector input contract")
			}
			if v.Expected.Decision == Live {
				if v.Proof == nil {
					t.Fatal("live provenance lacks issued proof")
				}
				g := proofGrant(t, v.Proof.Bytes)
				if g.ID() != v.Expected.GrantID || g.Grant.GranteeKey != v.Peer || g.Grant.NotBefore != v.Expected.NotBefore || g.Grant.NotAfter != v.Expected.NotAfter || v.Expected.CheckedAt != v.VerifierTime || g.Grant.IssuerKey != file.IssuerPubkey {
					t.Fatal("live fixture metadata binding")
				}
			}
		})
	}
}
