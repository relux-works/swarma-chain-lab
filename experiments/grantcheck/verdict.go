// Package grantcheck checks regtest rental grants at the a2a daemon's (a2ad) authenticated
// per-identity boundary. A verdict is an observation, never a reusable token.
package grantcheck

// Decision describes routing only. Only Live permits an inbox write or reply.
type Decision string

const (
	Live     Decision = "live"
	Refused  Decision = "refused"
	Exchange Decision = "exchange"
)

// Code is a closed vocabulary; node errors and received text never become codes.
type Code string

const (
	CodeLive                Code = "live"
	CodeNoGrant             Code = "no_grant"
	CodeNotYet              Code = "not_yet"
	CodeExpired             Code = "expired"
	CodeSealSpent           Code = "seal_spent"
	CodeLandlordRotated     Code = "landlord_rotated"
	CodeLandlordChanged     Code = "landlord_changed"
	CodeIdentityPending     Code = "identity_pending"
	CodeGrantPending        Code = "grant_pending"
	CodeBindingMismatch     Code = "binding_mismatch"
	CodeInvalidPresentation Code = "invalid_presentation"
	CodeOversize            Code = "oversize"
	CodeInvalidPeer         Code = "invalid_peer"
	CodeVerifierUnavailable Code = "verifier_unavailable"
	CodeStateUnavailable    Code = "state_unavailable"
	CodeClockInvalid        Code = "clock_invalid"
	CodeCancelled           Code = "cancelled"
	CodeBusy                Code = "busy"
	CodeCheckFailed         Code = "check_failed"
)

// Presentation carries the complete canonical v3 proof and its signed-grant ID.
// A non-nil empty or malformed presentation is not absence and cannot use cache.
type Presentation struct {
	GrantID string `json:"grant_id"`
	Bytes   []byte `json:"bytes"`
}

// Verdict contains bounded public metadata. Scope exists only for Live.
// Retryable is a fixed classification, not authority or a promise of success.
// The a2a daemon (a2ad) holds retryable events in its bounded queue and checks them again.
type Verdict struct {
	Decision  Decision `json:"decision"`
	Code      Code     `json:"code"`
	GrantID   string   `json:"grant_id,omitempty"`
	Scope     []string `json:"scope,omitempty"`
	NotBefore int64    `json:"not_before,omitempty"`
	NotAfter  int64    `json:"not_after,omitempty"`
	CheckedAt int64    `json:"checked_at"`
	Closed    bool     `json:"closed"`
	Retryable bool     `json:"retryable"`
}

// route is the only constructor for public routing/Retryable classification.
// Closure must accompany one of K1's three positively established close reasons.
func route(code Code, inbound, closed bool) Verdict {
	v := Verdict{Decision: Refused, Code: code}
	switch code {
	case CodeLive:
		if closed {
			return route(CodeCheckFailed, inbound, false)
		}
		v.Decision = Live
	case CodeNoGrant, CodeNotYet, CodeExpired:
		if closed {
			return route(CodeCheckFailed, inbound, false)
		}
		if inbound {
			v.Decision = Exchange
		}
	case CodeSealSpent, CodeLandlordRotated, CodeLandlordChanged:
		if !closed {
			return route(CodeCheckFailed, inbound, false)
		}
		v.Closed = true
		if inbound {
			v.Decision = Exchange
		}
	case CodeVerifierUnavailable, CodeStateUnavailable, CodeBusy, CodeCancelled,
		CodeClockInvalid, CodeGrantPending, CodeIdentityPending:
		if closed {
			return route(CodeCheckFailed, inbound, false)
		}
		v.Retryable = true
	case CodeBindingMismatch, CodeInvalidPresentation, CodeOversize, CodeInvalidPeer, CodeCheckFailed:
		if closed {
			return route(CodeCheckFailed, inbound, false)
		}
	default:
		return route(CodeCheckFailed, inbound, false)
	}
	return v
}
