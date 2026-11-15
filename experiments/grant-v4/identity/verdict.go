package identity

import (
	"bytes"
	"errors"
)

// Refusal names a draft refusal, not a durable closure.
type Refusal string

func (r Refusal) Error() string { return string(r) }

const (
	IssuerNameChanged        Refusal = "ISSUER_NAME_CHANGED"
	IssuerSnapshot           Refusal = "ISSUER_SNAPSHOT"
	IssuerHistoryUnavailable Refusal = "ISSUER_HISTORY_UNAVAILABLE"
	RecipientNameNotHeld     Refusal = "RECIPIENT_NAME_NOT_HELD"
	RecipientNameUnavailable Refusal = "RECIPIENT_NAME_UNAVAILABLE"
	NotaryNameChanged        Refusal = "NOTARY_NAME_CHANGED"
	NotaryCheckpoint         Refusal = "NOTARY_CHECKPOINT"
	NotaryValueUnauthorized  Refusal = "NOTARY_VALUE_UNAUTHORIZED"
	NotaryHistoryUnavailable Refusal = "NOTARY_HISTORY_UNAVAILABLE"
	ConsentEvidence          Refusal = "CONSENT_EVIDENCE"
	ConsentKey               Refusal = "CONSENT_KEY"
)

var ErrHistoryPredicate = errors.New("identity: unstated or invalid history predicate")

// Decision has an explicit passing bit: its zero value never passes. For issuer
// history Refusals has the first applicable O7.1 row only. For notary history it
// is a SET of findings: O7.3 gives no priority among simultaneous walk findings.
// No function in this module records closure or changes the supplied state.
type Decision struct {
	passed   bool
	refusals []Refusal
}

func (d Decision) Passes() bool        { return d.passed }
func (d Decision) Refusals() []Refusal { return append([]Refusal(nil), d.refusals...) }

func decide(codes ...Refusal) Decision {
	return Decision{passed: len(codes) == 0, refusals: codes}
}

// CheckHistory applies O7.1 or O7.3 on stated readings. Issuers do not acquire
// the draft's unaccepted current-writer extension. Notaries ignore Swarma.
func CheckHistory(s StatedName, p HistoryPredicate) Decision {
	unavailable, changed, snapshot := IssuerHistoryUnavailable, IssuerNameChanged, IssuerSnapshot
	if p.Rule == NotaryHistory {
		unavailable, changed, snapshot = NotaryHistoryUnavailable, NotaryNameChanged, NotaryCheckpoint
	}
	if !p.valid(s) {
		return decide(unavailable)
	}
	live, known := s.live()
	if known && live == Expired {
		return decide(changed)
	}
	w := walk(s, "")
	unsupported, breakFound, inView := !known || !w.complete, false, true
	for _, out := range w.outputs {
		if inView {
			if out.Reading == AnotherKey || (p.Rule == IssuerHistory &&
				(out.Swarma == nil || !bytes.Equal(out.Swarma, p.Swarma))) {
				breakFound = true
			}
			if out.Reading != Controlled && out.Reading != AnotherKey {
				unsupported = true
			}
			if out.Height.h <= p.From.h {
				inView = false
			}
		}
	}
	registrationChanged := w.complete && w.registration != p.Registration
	aboveStart := w.complete && w.registration == p.Registration && w.outputs[len(w.outputs)-1].Height.h > p.From.h
	if p.Rule == IssuerHistory {
		// O7.1: proven change precedes snapshot, which precedes missing facts.
		if breakFound || registrationChanged {
			return decide(changed)
		}
		if aboveStart {
			return decide(snapshot)
		}
		if unsupported {
			return decide(unavailable)
		}
		return decide()
	}
	var findings []Refusal
	if breakFound || registrationChanged {
		findings = append(findings, changed)
	}
	if aboveStart {
		findings = append(findings, snapshot)
	}
	if unsupported {
		findings = append(findings, unavailable)
	}
	if len(findings) != 0 {
		return decide(findings...)
	}
	// J3 puts the checkpoint and walk before the current writer check.
	switch w.outputs[0].Writer {
	case WrittenByOwner:
		return decide()
	case WrittenByAnother:
		return decide(NotaryValueUnauthorized)
	default:
		return decide(NotaryHistoryUnavailable)
	}
}

// CheckRecipientOwner applies O7.2 to the current output only, with no walk,
// registration pin, exact-output pin or namespace restriction.
func CheckRecipientOwner(s StatedName) Decision {
	live, known := s.live()
	if known && live == Expired {
		return decide(RecipientNameNotHeld)
	}
	if !known || !s.Transactions || len(s.Outputs) == 0 {
		return decide(RecipientNameUnavailable)
	}
	out := s.Outputs[0]
	if !out.Available || !bytes.Equal(out.Name, s.Name) ||
		(out.Prefix != PrefixUpdate && out.Prefix != PrefixRegistration) {
		return decide(RecipientNameUnavailable)
	}
	if out.Reading == AnotherKey {
		return decide(RecipientNameNotHeld)
	}
	if out.Reading != Controlled {
		return decide(RecipientNameUnavailable)
	}
	return decide()
}

// consentOutput establishes only W7.6 conditions 1-4 (O7.4), stopping at
// evidence. It needs no registration or ownership check before that output.
func consentOutput(s StatedName, recent Height, evidence string) (StatedOutput, bool) {
	if !s.valid() || !recent.known || recent.h > s.Tip.h || evidence == "" {
		return StatedOutput{}, false
	}
	w := walk(s, evidence)
	if !w.complete || len(w.outputs) == 0 {
		return StatedOutput{}, false
	}
	out := w.outputs[len(w.outputs)-1]
	if out.ID != evidence || out.Height.h > recent.h || out.Reading != Controlled {
		return StatedOutput{}, false
	}
	if len(w.outputs) > 1 && w.outputs[len(w.outputs)-2].Height.h <= recent.h {
		return StatedOutput{}, false
	}
	live, err := CheckLive(out.Height.h, recent.h, s.Depth)
	return out, err == nil && live == Live
}

// CheckConsentEvidence checks historical ownership and currency, not a consent
// signature, binding, age, single-use record, or channel key (condition 5).
func CheckConsentEvidence(s StatedName, recent Height, evidence string) Decision {
	if _, ok := consentOutput(s, recent, evidence); !ok {
		return decide(ConsentEvidence)
	}
	return decide()
}

// ChangeReading is the O7.5 owner-signed change predicate, not a journal action.
type ChangeReading uint8

const (
	ChangeUnproven ChangeReading = iota
	ChangeUnchanged
	ChangeProved
)

// ReadOwnerSignedChange uses O3/O4 readings relative to the SAME bound pin.
// Unsupported new ownership proves no transfer, but a supported prefix with
// changed/absent member octets still proves that independent ground of change.
func ReadOwnerSignedChange(spent, next StatedOutput) ChangeReading {
	if !spent.Available || !next.Available || spent.Reading != Controlled || next.Writer != WrittenByOwner ||
		!bytes.Equal(spent.Name, next.Name) || spent.Swarma == nil ||
		(spent.Prefix != PrefixUpdate && spent.Prefix != PrefixRegistration) || next.Prefix != PrefixUpdate {
		return ChangeUnproven
	}
	if next.Reading == AnotherKey || next.Swarma == nil || !bytes.Equal(spent.Swarma, next.Swarma) {
		return ChangeProved
	}
	if next.Reading == Controlled {
		return ChangeUnchanged
	}
	return ChangeUnproven
}
