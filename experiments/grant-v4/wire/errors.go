// Package wire implements the proposed LIP-0020 wire layer. It grants no
// authority and performs no node reads, signing, persistence or external effects.
package wire

// Code is a first-refusal code. Refused readers return no object.
type Code string

func (c Code) Error() string { return string(c) }

const (
	WireSize           Code = "WIRE_SIZE"
	WireJSON           Code = "WIRE_JSON"
	WireDuplicate      Code = "WIRE_DUPLICATE"
	WireValue          Code = "WIRE_VALUE"
	WireNumber         Code = "WIRE_NUMBER"
	WireString         Code = "WIRE_STRING"
	WireNotCanonical   Code = "WIRE_NOT_CANONICAL"
	WireType           Code = "WIRE_TYPE"
	WireMember         Code = "WIRE_MEMBER"
	WireInteger        Code = "WIRE_INTEGER"
	WireKey            Code = "WIRE_KEY"
	WireSignatureForm  Code = "WIRE_SIGNATURE_FORM"
	WireSignature      Code = "WIRE_SIGNATURE"
	WireID             Code = "WIRE_ID"
	AssentBinding      Code = "ASSENT_BINDING"
	AssentParty        Code = "ASSENT_PARTY"
	ConsentShape       Code = "CONSENT_SHAPE"
	ConsentBinding     Code = "CONSENT_BINDING"
	ConsentKey         Code = "CONSENT_KEY"
	ConsentEvidence    Code = "CONSENT_EVIDENCE"
	ConsentSignature   Code = "CONSENT_SIGNATURE"
	ConsentTime        Code = "CONSENT_TIME"
	ConsentAge         Code = "CONSENT_AGE"
	ConsentConsumed    Code = "CONSENT_CONSUMED"
	IssuanceMode       Code = "ISSUANCE_MODE"
	IssuanceFrame      Code = "ISSUANCE_FRAME"
	IssuanceCommitment Code = "ISSUANCE_COMMITMENT"
)
