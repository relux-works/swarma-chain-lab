package rental

import (
	"encoding/json"

	su "relux.works/swarma-chain-lab/experiments/single-use"
)

// GrantConsent retains the renter's actual NIP-01 signed event. Its signature
// is never reinterpreted as a signature over the raw contract hash.
type GrantConsent struct {
	ContractSHA256 string `json:"contract_sha256"`
	ConsentEvent   Event  `json:"consent_event"`
	LandlordSig    string `json:"landlord_sig"`
}
type Grant struct {
	Version        int          `json:"version"`
	Network        string       `json:"network"`
	Genesis        string       `json:"genesis"`
	AgentName      string       `json:"agent_name"`
	LandlordName   string       `json:"landlord_name"`
	IssuerKey      string       `json:"issuer_key"`
	GranteeKey     string       `json:"grantee_key"`
	GranteeName    string       `json:"grantee_name,omitempty"`
	ContractSHA256 string       `json:"contract_sha256"`
	Scope          []string     `json:"scope"`
	NotBefore      int64        `json:"not_before"`
	NotAfter       int64        `json:"not_after"`
	Seal           Point        `json:"seal"`
	Budget         *int64       `json:"budget,omitempty"`
	Consent        GrantConsent `json:"consent"`
}
type SignedGrant struct {
	Grant     Grant  `json:"grant"`
	Signature string `json:"signature"`
}
type IssuanceProof struct {
	TxID string `json:"txid"`
}
type GrantPresentation struct {
	SignedGrant SignedGrant   `json:"signed_grant"`
	Issuance    IssuanceProof `json:"issuance"`
}

func (g Grant) Validate() error {
	if g.Version != 3 || !su.NetworkPinned(g.Network, g.Genesis) {
		return bad("GRANT_NETWORK")
	}
	if !station(g.AgentName) || !station(g.LandlordName) || g.AgentName == g.LandlordName || (g.GranteeName != "" && !station(g.GranteeName)) {
		return bad("GRANT_NAME")
	}
	if !pubkey(g.IssuerKey) || !pubkey(g.GranteeKey) {
		return bad("GRANT_KEY")
	}
	if !digest(g.ContractSHA256) || !digest(g.Seal.TxID) {
		return bad("GRANT_HASH")
	}
	if !validGrantScope(g.Scope) {
		return bad("GRANT_SCOPE")
	}
	if g.NotBefore < 0 || g.NotAfter <= g.NotBefore || g.NotAfter > 253402300799 {
		return bad("GRANT_TIME")
	}
	if g.Budget != nil && (*g.Budget < 0 || *g.Budget > MaxMoney) {
		return bad("GRANT_BUDGET")
	}
	if g.Consent.ContractSHA256 != g.ContractSHA256 {
		return bad("CONSENT_CONTRACT")
	}
	e := g.Consent.ConsentEvent
	if !eventValid(e, g.NotAfter-1) || e.Pubkey != g.GranteeKey || e.Kind != 8181 || e.Content != "" || len(e.Tags) != 4 {
		return bad("RENTER_CONSENT_EVENT")
	}
	if len(e.Tags[2]) != 2 || len(e.Tags[3]) != 2 || !digest(e.Tags[2][1]) || !digest(e.Tags[3][1]) || !sameJSON(e.Tags, [][]string{{"t", "swarma-rental-consent-v1"}, {"contract", g.ContractSHA256}, {"booking", e.Tags[2][1]}, {"privacy", e.Tags[3][1]}}) {
		return bad("RENTER_CONSENT_BINDING")
	}
	if !VerifySignature(g.IssuerKey, g.ContractSHA256, g.Consent.LandlordSig) {
		return bad("LANDLORD_CONSENT_SIGNATURE")
	}
	return nil
}
func (g Grant) Canonical() ([]byte, error) {
	if e := g.Validate(); e != nil {
		return nil, e
	}
	return json.Marshal(g)
}
func (g Grant) BudgetSat() int64 {
	if g.Budget == nil {
		return 0
	}
	return *g.Budget
}

// SigningHash separates the grant signature from the raw contract-hash
// countersignature. This fixed ASCII prefix has no terminator or length field;
// it is a protocol prefix, not the BIP-340 tagged-hash construction.
func (g Grant) SigningHash() (string, error) {
	b, e := g.Canonical()
	if e != nil {
		return "", e
	}
	return grantSigningDigest(b), nil
}
func grantSigningDigest(canonicalGrant []byte) string {
	return Hash(append([]byte("swarma-grant-v3"), canonicalGrant...))
}
func ParseSignedGrant(raw []byte) (SignedGrant, error) {
	var signed SignedGrant
	if e := canonical(raw, &signed); e != nil {
		return signed, e
	}
	b, e := signed.Grant.Canonical()
	if e != nil {
		return signed, e
	}
	if !VerifySignature(signed.Grant.IssuerKey, grantSigningDigest(b), signed.Signature) {
		return signed, bad("GRANT_SIGNATURE")
	}
	return signed, nil
}
func (s SignedGrant) ID() string { b, _ := json.Marshal(s); return Hash(b) }
func ParseGrantPresentation(raw []byte) (GrantPresentation, error) {
	var p GrantPresentation
	if e := canonical(raw, &p); e != nil {
		return p, e
	}
	b, _ := json.Marshal(p.SignedGrant)
	if _, e := ParseSignedGrant(b); e != nil {
		return p, e
	}
	if !digest(p.Issuance.TxID) {
		return p, bad("ISSUANCE_LOCATOR")
	}
	return p, nil
}

// IssuanceCommitment binds the stable signed grant id and actual consent
// proofs. The issuance locator is deliberately absent, avoiding a txid cycle.
func IssuanceCommitment(s SignedGrant) (string, error) {
	b, e := json.Marshal(s)
	if e != nil {
		return "", bad("GRANT_ENCODING")
	}
	if _, e = ParseSignedGrant(b); e != nil {
		return "", e
	}
	g := s.Grant
	data := []byte("swarma-issue-v1")
	for _, v := range []string{g.ContractSHA256, g.Consent.ConsentEvent.ID, g.Consent.ConsentEvent.Sig, g.Consent.LandlordSig, Hash(b)} {
		data = append(data, mustDecodeKey(v)...)
	}
	return Hash(data), nil
}

// PresentIssuedGrant attaches a public untrusted locator, not a live verdict.
// Check must bind this locator to its own node before admitting the grant.
func PresentIssuedGrant(raw []byte, txid string) ([]byte, error) {
	s, e := ParseSignedGrant(raw)
	if e != nil {
		return nil, e
	}
	if !digest(txid) {
		return nil, bad("ISSUANCE_LOCATOR")
	}
	return json.Marshal(GrantPresentation{s, IssuanceProof{txid}})
}
