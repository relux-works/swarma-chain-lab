package grantcheck

import (
	"encoding/json"
	"strings"
	"testing"
)

// The accepted routing table independently fixes every code's inbound route,
// outbound route, closure and retry classification; unknown codes fail closed.
func TestRoutingContract(t *testing.T) {
	tests := []struct {
		code          Code
		decision      Decision
		closed, retry bool
	}{
		{CodeLive, Live, false, false},
		{CodeNoGrant, Exchange, false, false},
		{CodeNotYet, Exchange, false, false},
		{CodeExpired, Exchange, false, false},
		{CodeSealSpent, Exchange, true, false},
		{CodeLandlordRotated, Exchange, true, false},
		{CodeLandlordChanged, Exchange, true, false},
		{CodeIdentityPending, Refused, false, true},
		{CodeGrantPending, Refused, false, true},
		{CodeBindingMismatch, Refused, false, false},
		{CodeInvalidPresentation, Refused, false, false},
		{CodeOversize, Refused, false, false},
		{CodeInvalidPeer, Refused, false, false},
		{CodeVerifierUnavailable, Refused, false, true},
		{CodeStateUnavailable, Refused, false, true},
		{CodeClockInvalid, Refused, false, true},
		{CodeCancelled, Refused, false, true},
		{CodeBusy, Refused, false, true},
		{CodeCheckFailed, Refused, false, false},
	}
	for _, tc := range tests {
		t.Run(string(tc.code), func(t *testing.T) {
			for _, inbound := range []bool{true, false} {
				want := tc.decision
				if !inbound && want == Exchange {
					want = Refused
				}
				v := route(tc.code, inbound, tc.closed)
				if v.Decision != want || v.Code != tc.code || v.Closed != tc.closed || v.Retryable != tc.retry {
					t.Fatalf("routing contract inbound=%v: %+v", inbound, v)
				}
				if len(v.Scope) != 0 || v.GrantID != "" {
					t.Fatal("routing invented metadata")
				}
				bad := route(tc.code, inbound, !tc.closed)
				if bad.Decision != Refused || bad.Code != CodeCheckFailed || bad.Closed || bad.Retryable {
					t.Fatalf("inconsistent closure admitted: %+v", bad)
				}
			}
		})
	}
}

// A code outside the closed vocabulary cannot carry received error text out.
func TestUnknownCodeRedaction(t *testing.T) {
	const marker = "sensitive-marker-from-untrusted-node"
	for _, inbound := range []bool{true, false} {
		v := route(Code(marker), inbound, false)
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if v.Code != CodeCheckFailed || v.Decision != Refused || v.Retryable || strings.Contains(string(b), marker) {
			t.Fatal("unknown code escaped refusal boundary")
		}
	}
}
