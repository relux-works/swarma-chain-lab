package wire

import (
	"bytes"
	"encoding/hex"
	"strconv"
)

const MaxConsentSize = 2048
const MaxConsentAge uint64 = 259200
const MaxTimestamp uint64 = 253402300799

type RecipientMode string

const (
	ByKey  RecipientMode = "key"
	ByName RecipientMode = "name"
)

// Evidence contains stated node findings for W7.6, not a proof or a node
// adapter. Missing findings fail closed. The caller must independently obtain
// these facts under the ownership profile, which LIP-0020 leaves open.
type Evidence struct {
	Confirmed                                        bool
	Height                                           uint64
	OperationOfName, LiveAtRecentBlock, OwnerMatches bool
	SpentAtHeight                                    *uint64
	YieldsPublicKey                                  string
}

type ConsentContext struct {
	Mode                                                                RecipientMode
	Genesis, Contract, IssuerPublicKey, RequestPublicKey, RecipientName string
	RecentBlockHeight, Now                                              uint64
	Evidence                                                            *Evidence
}

// Consent is a wire-valid event checked against the stated context. It is no
// authority to act and no claim about a real chain or issuer consumption.
type Consent struct {
	root      *value
	createdAt uint64
}

func (c *Consent) ID() string        { return c.root.get("id").text }
func (c *Consent) Signature() string { return c.root.get("sig").text }
func (c *Consent) PublicKey() string { return c.root.get("pubkey").text }
func (c *Consent) CreatedAt() uint64 { return c.createdAt }
func (c *Consent) Bytes() []byte     { return eventBytes(c.root) }

var eventMembers = []string{"id", "pubkey", "created_at", "kind", "tags", "content", "sig"}

func eventBytes(v *value) []byte {
	b := []byte{'{'}
	for i, k := range eventMembers {
		if i > 0 {
			b = append(b, ',')
		}
		b = appendString(b, k)
		b = append(b, ':')
		b = appendValue(b, v.get(k))
	}
	return append(b, '}')
}
func eventPreimage(v *value) []byte {
	return serialize(&value{kind: '[', elements: []*value{{kind: 'd', text: "0"}, v.get("pubkey"), v.get("created_at"), v.get("kind"), v.get("tags"), v.get("content")}})
}
func printable(v *value) bool {
	if v.kind == 's' {
		for _, r := range v.text {
			if r < 0x20 || r > 0x7e {
				return false
			}
		}
	}
	for _, m := range v.members {
		for _, r := range m.name {
			if r < 0x20 || r > 0x7e {
				return false
			}
		}
		if !printable(m.value) {
			return false
		}
	}
	for _, x := range v.elements {
		if !printable(x) {
			return false
		}
	}
	return true
}
func parseConsent(b []byte) (*Consent, error) {
	v, err := parseDocument(b, MaxConsentSize)
	if err != nil {
		return nil, ConsentShape
	}
	if !exactMembers(v, eventMembers) || !printable(v) {
		return nil, ConsentShape
	}
	for _, k := range []string{"id", "pubkey"} {
		if !hexMember(v, k, 32) {
			return nil, ConsentShape
		}
	}
	if !hexMember(v, "sig", 64) || v.get("content").kind != 's' || v.get("content").text != "" {
		return nil, ConsentShape
	}
	if v.get("kind").kind != 'd' || v.get("kind").text != "8181" || v.get("created_at").kind != 'd' {
		return nil, ConsentShape
	}
	created, err := ParseInteger(v.get("created_at").text, MaxTimestamp)
	if err != nil || created == 0 {
		return nil, ConsentShape
	}
	tags := v.get("tags")
	if tags.kind != '[' || (len(tags.elements) != 4 && len(tags.elements) != 5) {
		return nil, ConsentShape
	}
	names := []string{"t", "genesis", "contract", "issuer", "name"}
	for i, t := range tags.elements {
		if t.kind != '[' || len(t.elements) != 2 || t.elements[0].kind != 's' || t.elements[1].kind != 's' || t.elements[0].text != names[i] {
			return nil, ConsentShape
		}
	}
	if tags.elements[0].elements[1].text != "swarma-contract-consent/1" {
		return nil, ConsentShape
	}
	for _, i := range []int{1, 2, 3} {
		if !hexForm(tags.elements[i].elements[1].text, 32) {
			return nil, ConsentShape
		}
	}
	if CheckSigningKey(v.get("pubkey").text) != nil || CheckSigningKey(tags.elements[3].elements[1].text) != nil {
		return nil, ConsentShape
	}
	if !bytes.Equal(b, eventBytes(v)) || v.get("id").text != hashHex(eventPreimage(v)) {
		return nil, ConsentShape
	}
	return &Consent{v, created}, nil
}

// ReadConsent selects the event pipeline, which has its own fixed wire order
// and no registry type. It reports the first of the five W7.4 steps.
func ReadConsent(b []byte, ctx ConsentContext) (*Consent, error) {
	c, err := parseConsent(b)
	if err != nil {
		return nil, err
	}
	tags := c.root.get("tags").elements
	if tags[1].elements[1].text != ctx.Genesis || tags[2].elements[1].text != ctx.Contract || tags[3].elements[1].text != ctx.IssuerPublicKey {
		return nil, ConsentBinding
	}
	switch ctx.Mode {
	case ByKey:
		if len(tags) != 4 {
			return nil, ConsentBinding
		}
		if c.PublicKey() != ctx.RequestPublicKey {
			return nil, ConsentKey
		}
	case ByName:
		if len(tags) != 5 || tags[4].elements[1].text != ctx.RecipientName {
			return nil, ConsentBinding
		}
		e := ctx.Evidence
		if e == nil || !e.Confirmed || e.Height > ctx.RecentBlockHeight || !e.OperationOfName || !e.LiveAtRecentBlock || !e.OwnerMatches || (e.SpentAtHeight != nil && *e.SpentAtHeight <= ctx.RecentBlockHeight) {
			return nil, ConsentEvidence
		}
		if e.YieldsPublicKey != c.PublicKey() {
			return nil, ConsentKey
		}
	default:
		return nil, ConsentBinding
	}
	id, _ := hex.DecodeString(c.ID())
	var digest [32]byte
	copy(digest[:], id)
	raw, _ := hex.DecodeString(c.Signature())
	if VerifyBIP340(c.PublicKey(), digest, raw) != nil {
		return nil, ConsentSignature
	}
	if c.createdAt > ctx.Now {
		return nil, ConsentTime
	}
	return c, nil
}

// EncodeConsentEvent builds the NIP-01 id and exact fixed-order wire form.
// It checks shape and signature, but has no grant context or clock to bind.
func EncodeConsentEvent(publicKey string, createdAt uint64, tags [][2]string, signature string) ([]byte, error) {
	tagValue := &value{kind: '['}
	for _, t := range tags {
		tagValue.elements = append(tagValue.elements, &value{kind: '[', elements: []*value{{kind: 's', text: t[0]}, {kind: 's', text: t[1]}}})
	}
	v := &value{kind: '{', members: []member{{"id", &value{kind: 's'}}, {"pubkey", &value{kind: 's', text: publicKey}}, {"created_at", &value{kind: 'd', text: strconv.FormatUint(createdAt, 10)}}, {"kind", &value{kind: 'd', text: "8181"}}, {"tags", tagValue}, {"content", &value{kind: 's'}}, {"sig", &value{kind: 's', text: signature}}}}
	v.get("id").text = hashHex(eventPreimage(v))
	c, err := parseConsent(eventBytes(v))
	if err != nil {
		return nil, err
	}
	digestBytes, _ := hex.DecodeString(c.ID())
	var digest [32]byte
	copy(digest[:], digestBytes)
	raw, _ := hex.DecodeString(signature)
	if VerifyBIP340(publicKey, digest, raw) != nil {
		return nil, ConsentSignature
	}
	return c.Bytes(), nil
}

// Snapshot is a caller-supplied consistent snapshot, not a chain observation.
type Snapshot struct {
	RecentBlockHeight uint64
	Name              SnapshotName
}
type SnapshotName struct {
	Confirmed          bool
	Height             uint64
	Live, OwnerMatches bool
	YieldsPublicKey    string
}

// CheckIssuerConditions evaluates the issuer vectors as pure stated-input
// checks. It never consumes a consent or signs. A real issuer must durably
// reserve the id before signing, with its own concurrency/recovery contract.
func CheckIssuerConditions(b []byte, ctx ConsentContext, snapshot *Snapshot, consumed []string) error {
	if ctx.Mode == ByName {
		if snapshot == nil {
			return ConsentEvidence
		}
		n := snapshot.Name
		ctx.RecentBlockHeight = snapshot.RecentBlockHeight
		ctx.Evidence = &Evidence{Confirmed: n.Confirmed, Height: n.Height, OperationOfName: true, LiveAtRecentBlock: n.Live, OwnerMatches: n.OwnerMatches, YieldsPublicKey: n.YieldsPublicKey}
	}
	c, err := ReadConsent(b, ctx)
	if err != nil {
		return err
	}
	if ctx.Now-c.createdAt > MaxConsentAge {
		return ConsentAge
	}
	for _, id := range consumed {
		if id == c.ID() {
			return ConsentConsumed
		}
	}
	return nil
}
