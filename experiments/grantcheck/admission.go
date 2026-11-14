package grantcheck

// A2ADecision maps only this closed grantcheck vocabulary to the a2a admission
// seam's closed verdict/reason vocabulary, without importing that internal seam.
// It recomputes Retryable and rejects contradictory decisions or closure rather
// than trusting mutable verdict fields. The adapter still enforces direction:
// Exchange is inbound-only. Aggregate outbound Live has no per-grant metadata.
func (v Verdict) A2ADecision() (verdict, reason string, retryable bool) {
	reason = "denied"
	switch v.Code {
	case CodeLive:
		if v.Decision == Live && !v.Closed {
			return "live", "allowed", false
		}
		return "refused", "policy_invalid", false
	case CodeNoGrant, CodeNotYet, CodeExpired, CodeSealSpent, CodeLandlordRotated, CodeLandlordChanged:
		closed := v.Code == CodeSealSpent || v.Code == CodeLandlordRotated || v.Code == CodeLandlordChanged
		if v.Closed != closed {
			return "refused", "policy_invalid", false
		}
		if v.Decision == Exchange {
			return "exchange", "exchange", false
		}
	case CodeIdentityPending, CodeGrantPending, CodeVerifierUnavailable, CodeClockInvalid, CodeCancelled, CodeBusy:
		reason, retryable = "dependency_unavailable", true
	case CodeStateUnavailable:
		reason, retryable = "storage_error", true
	case CodeCheckFailed:
		reason = "policy_error"
	case CodeBindingMismatch, CodeInvalidPresentation, CodeOversize, CodeInvalidPeer:
	default:
		return "refused", "policy_invalid", false
	}
	if v.Decision != Refused {
		return "refused", "policy_invalid", false
	}
	if v.Closed && v.Code != CodeSealSpent && v.Code != CodeLandlordRotated && v.Code != CodeLandlordChanged {
		return "refused", "policy_invalid", false
	}
	return "refused", reason, retryable
}
