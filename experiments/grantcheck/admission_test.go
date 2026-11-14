package grantcheck

import "testing"

// Every current code has a fixed seam reason/retry classification; caller-supplied Retryable cannot widen it.
func TestA2ADecisionTable(t *testing.T) {
	tests := []struct {
		code                    Code
		reason                  string
		retry, closed, exchange bool
	}{
		{CodeLive, "allowed", false, false, false},
		{CodeNoGrant, "denied", false, false, true},
		{CodeNotYet, "denied", false, false, true},
		{CodeExpired, "denied", false, false, true},
		{CodeSealSpent, "denied", false, true, true},
		{CodeLandlordRotated, "denied", false, true, true},
		{CodeLandlordChanged, "denied", false, true, true},
		{CodeIdentityPending, "dependency_unavailable", true, false, false},
		{CodeGrantPending, "dependency_unavailable", true, false, false},
		{CodeBindingMismatch, "denied", false, false, false},
		{CodeInvalidPresentation, "denied", false, false, false},
		{CodeOversize, "denied", false, false, false},
		{CodeInvalidPeer, "denied", false, false, false},
		{CodeVerifierUnavailable, "dependency_unavailable", true, false, false},
		{CodeStateUnavailable, "storage_error", true, false, false},
		{CodeClockInvalid, "dependency_unavailable", true, false, false},
		{CodeCancelled, "dependency_unavailable", true, false, false},
		{CodeBusy, "dependency_unavailable", true, false, false},
		{CodeCheckFailed, "policy_error", false, false, false},
	}
	allowed := map[string]bool{"allowed": true, "exchange": true, "denied": true, "dependency_unavailable": true, "policy_invalid": true, "policy_error": true, "exchange_outbound": true, "held_age": true, "held_count": true, "exchange_capacity": true, "storage_error": true}
	for _, tc := range tests {
		t.Run(string(tc.code), func(t *testing.T) {
			d := Refused
			if tc.code == CodeLive {
				d = Live
			}
			for _, inputRetry := range []bool{false, true} {
				v := Verdict{Decision: d, Code: tc.code, Closed: tc.closed, Retryable: inputRetry}
				verdict, reason, retry := v.A2ADecision()
				if verdict != string(d) || reason != tc.reason || retry != tc.retry || !allowed[reason] {
					t.Fatalf("seam mapping: %s %s %v", verdict, reason, retry)
				}
				if tc.exchange {
					v.Decision = Exchange
					verdict, reason, retry = v.A2ADecision()
					if verdict != "exchange" || reason != "exchange" || retry || !allowed[reason] {
						t.Fatal("lifecycle exchange mapping")
					}
				}
			}
		})
	}
}

// Unknown codes, invalid decisions and contradictory closure cannot map to allowed or escape the seam's closed set.
func TestA2ADecisionFailClosed(t *testing.T) {
	for _, v := range []Verdict{
		{}, {Decision: Live, Code: "future", Retryable: true},
		{Decision: Live, Code: CodeInvalidPeer}, {Decision: Exchange, Code: CodeInvalidPresentation},
		{Decision: Refused, Code: CodeLive}, {Decision: Live, Code: CodeLive, Closed: true},
		{Decision: Refused, Code: CodeSealSpent}, {Decision: Exchange, Code: CodeExpired, Closed: true},
		{Decision: Refused, Code: CodeStateUnavailable, Closed: true}, {Decision: "future", Code: CodeNoGrant},
	} {
		d, reason, retry := v.A2ADecision()
		if d != "refused" || reason != "policy_invalid" || retry {
			t.Fatalf("unsafe mapping: %s %s %v", d, reason, retry)
		}
	}
	d, reason, retry := (Verdict{Decision: Live, Code: CodeLive}).A2ADecision()
	if d != "live" || reason != "allowed" || retry {
		t.Fatal("valid neighbour refused")
	}
}
