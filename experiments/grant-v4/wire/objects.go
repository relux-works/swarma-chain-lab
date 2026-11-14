package wire

import "encoding/hex"

const MaxAssentSize = 1024
const MaxPreparationSize = 2048

// SignedObject is an admitted assent at the wire layer. Binding to an issuing
// party is separately checked with ReadAssent. All byte accessors return copies.
type SignedObject struct {
	document, payload *Document
	signature         string
}

func (o *SignedObject) Bytes() []byte          { return o.document.Bytes() }
func (o *SignedObject) Payload() []byte        { return o.payload.Bytes() }
func (o *SignedObject) Signature() string      { return o.signature }
func (o *SignedObject) ID() string             { return hashHex(o.Payload()) }
func (o *SignedObject) ContentAddress() string { return hashHex(o.Bytes()) }
func (o *SignedObject) Digest() [32]byte       { return TaggedHash(string(ContractAssent), o.Payload()) }
func (o *SignedObject) CheckReference(reference string) error {
	if reference != o.ID() {
		return WireID
	}
	return nil
}

func exactMembers(v *value, required []string, optional ...string) bool {
	if v == nil || v.kind != '{' {
		return false
	}
	allowed := map[string]bool{}
	for _, k := range required {
		allowed[k] = true
		if v.get(k) == nil {
			return false
		}
	}
	for _, k := range optional {
		allowed[k] = true
	}
	for _, m := range v.members {
		if !allowed[m.name] {
			return false
		}
	}
	return true
}
func hexMember(v *value, name string, n int) bool {
	x := v.get(name)
	return x != nil && x.kind == 's' && hexForm(x.text, n)
}
func requireType(v *value, t Type) error {
	x := v.get("type")
	if x == nil || x.kind != 's' || x.text != string(t) {
		return WireType
	}
	return nil
}

// ReadSigned selects the signed-object pipeline from the caller's expected
// type, never from the document. Only the assent currently has a signed schema.
func ReadSigned(b []byte, expected Type) (*SignedObject, error) {
	if expected != ContractAssent {
		return nil, WireType
	}
	d, err := ParseDocument(b, MaxAssentSize)
	if err != nil {
		return nil, err
	}
	if !exactMembers(d.root, []string{"payload", "signature"}) {
		return nil, WireMember
	}
	p := d.root.get("payload")
	if err := requireType(p, expected); err != nil {
		return nil, err
	}
	if !exactMembers(p, []string{"contract", "genesis", "party", "type"}) {
		return nil, WireMember
	}
	for _, k := range []string{"contract", "genesis", "party"} {
		if !hexMember(p, k, 32) {
			return nil, WireMember
		}
	}
	key := p.get("party").text
	if err := CheckSigningKey(key); err != nil {
		return nil, err
	}
	// Signature encoding precedes key-of-place verification; the assent's
	// member key was already validated in W9.3.
	sigText := d.root.get("signature").stringValue()
	if !hexForm(sigText, 64) {
		return nil, WireSignatureForm
	}
	pd := &Document{p}
	digest := TaggedHash(p.get("type").text, pd.Bytes())
	raw, _ := hex.DecodeString(sigText)
	if err := VerifyBIP340(key, digest, raw); err != nil {
		return nil, err
	}
	return &SignedObject{d, pd, sigText}, nil
}

// AssentContext states the opaque contract/chain binding and contract party.
// The caller is responsible for obtaining these from its verified grant.
type AssentContext struct{ Genesis, Contract, PartyPublicKey string }

func ReadAssent(b []byte, context AssentContext, references ...string) (*SignedObject, error) {
	o, err := ReadSigned(b, ContractAssent)
	if err != nil {
		return nil, err
	}
	for _, reference := range references {
		if err := o.CheckReference(reference); err != nil {
			return nil, err
		}
	}
	p := o.payload.root
	if p.get("genesis").text != context.Genesis || p.get("contract").text != context.Contract {
		return nil, AssentBinding
	}
	if p.get("party").text != context.PartyPublicKey {
		return nil, AssentParty
	}
	return o, nil
}

// EncodeAssentPayload builds canonical octets for a signer. It does not sign.
func EncodeAssentPayload(genesis, contract, party string) ([]byte, error) {
	for _, s := range []string{genesis, contract, party} {
		if !hexForm(s, 32) {
			return nil, WireMember
		}
	}
	if err := CheckSigningKey(party); err != nil {
		return nil, err
	}
	return EncodeDocument(map[string]any{"type": string(ContractAssent), "genesis": genesis, "contract": contract, "party": party}, MaxAssentSize)
}

// EncodeSignedAssent accepts only a signature that verifies for the payload.
func EncodeSignedAssent(payload []byte, signature string) ([]byte, error) {
	d, err := ParseDocument(payload, MaxAssentSize)
	if err != nil {
		return nil, err
	}
	b := append([]byte(`{"payload":`), d.Bytes()...)
	b = append(b, `,"signature":`...)
	b = appendString(b, signature)
	b = append(b, '}')
	o, err := ReadSigned(b, ContractAssent)
	if err != nil {
		return nil, err
	}
	return o.Bytes(), nil
}

// Preparation is a stored unsigned payload. It does not establish that any
// named signed part exists, verifies, or was anchored.
type Preparation struct{ document *Document }

func (p *Preparation) Bytes() []byte        { return p.document.Bytes() }
func (p *Preparation) Commitment() [32]byte { return TaggedHash(string(Issuance), p.Bytes()) }

// ReadUnsigned selects the unsigned-payload pipeline. There is no signed form
// for an issuance preparation and no support for types without member schemas.
func ReadUnsigned(b []byte, expected Type) (*Preparation, error) {
	if expected != Issuance {
		return nil, WireType
	}
	d, err := ParseDocument(b, MaxPreparationSize)
	if err != nil {
		return nil, err
	}
	v := d.root
	if err := requireType(v, expected); err != nil {
		return nil, err
	}
	if !exactMembers(v, []string{"contract", "genesis", "grant_id", "grant_signature", "issuer_assent", "recipient_consent", "type"}) {
		return nil, WireMember
	}
	a, c := v.get("issuer_assent"), v.get("recipient_consent")
	if !exactMembers(a, []string{"party", "signature"}) || !exactMembers(c, []string{"event_id", "signature"}, "name_output") {
		return nil, WireMember
	}
	n := c.get("name_output")
	if n != nil && !exactMembers(n, []string{"txid", "vout"}) {
		return nil, WireMember
	}
	// Values follow canonical member order at every depth; keys come last.
	for _, k := range []string{"contract", "genesis", "grant_id"} {
		if !hexMember(v, k, 32) {
			return nil, WireMember
		}
	}
	if !hexMember(v, "grant_signature", 64) || !hexMember(a, "party", 32) || !hexMember(a, "signature", 64) || !hexMember(c, "event_id", 32) {
		return nil, WireMember
	}
	if n != nil {
		if !hexMember(n, "txid", 32) {
			return nil, WireMember
		}
		x := n.get("vout")
		if x.kind != 'd' {
			return nil, WireMember
		}
		if _, err := ParseInteger(x.text, 4294967295); err != nil {
			return nil, WireInteger
		}
	}
	if !hexMember(c, "signature", 64) {
		return nil, WireMember
	}
	if err := CheckSigningKey(a.get("party").text); err != nil {
		return nil, err
	}
	return &Preparation{d}, nil
}
