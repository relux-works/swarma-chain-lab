package wire

// GrantFacts are independently established inputs, NOT a parsed grant or a
// wire schema. W9.4 step 1 has no content until the grant has members. A caller
// must supply these facts; this module cannot authenticate them or a grant.
type GrantFacts struct {
	Mode                                             RecipientMode
	Genesis, Contract, ID, Signature, ContentAddress string
	IssuerPublicKey, PartyPublicKey                  string
	RequestPublicKey, RecipientName                  string
	RecentBlockHeight                                uint64
}

// IssuanceInput holds separately supplied parts, not a serialized presentation.
// Evidence must describe NameOutput under W7.6, obtained by the caller. Now is
// the verifier's clock in Unix seconds; issuer age/consumption are separate.
type IssuanceInput struct {
	Grant                          *GrantFacts
	IssuerAssent, RecipientConsent []byte
	NameOutput                     *Outpoint
	Evidence                       *Evidence
	Now                            uint64
	Frame                          Frame
}

// CheckIssuance applies W9.4 steps 2-6 to stated grant facts. Its result is a
// preparation conditional on those facts, never admission of a real grant.
// Raw grants remain unsupported (W3.1); no presentation schema is invented.
// Refusal returns no preparation, signed part or signature, and changes no state.
func CheckIssuance(in IssuanceInput) (*Preparation, error) {
	if in.Grant == nil {
		return nil, WireType
	}
	g := *in.Grant
	if g.Mode != ByKey && g.Mode != ByName || g.Mode == ByKey && in.NameOutput != nil || g.Mode == ByName && in.NameOutput == nil {
		return nil, IssuanceMode
	}
	a, err := ReadAssent(in.IssuerAssent, AssentContext{g.Genesis, g.Contract, g.PartyPublicKey})
	if err != nil {
		return nil, err
	}
	c, err := ReadConsent(in.RecipientConsent, ConsentContext{
		Mode: g.Mode, Genesis: g.Genesis, Contract: g.Contract,
		IssuerPublicKey: g.IssuerPublicKey, RequestPublicKey: g.RequestPublicKey,
		RecipientName: g.RecipientName, RecentBlockHeight: g.RecentBlockHeight,
		Now: in.Now, Evidence: in.Evidence,
	})
	if err != nil {
		return nil, err
	}
	return CheckIssuanceAnchor(PreparationParts{
		Mode: g.Mode, Genesis: g.Genesis, Contract: g.Contract,
		GrantID: g.ID, GrantSignature: g.Signature,
		AssentParty: a.payload.root.get("party").text, AssentSignature: a.Signature(),
		ConsentID: c.ID(), ConsentSignature: c.Signature(), NameOutput: in.NameOutput,
	}, g.ContentAddress, in.Frame)
}
