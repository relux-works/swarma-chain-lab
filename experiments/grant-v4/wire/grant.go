package wire

import (
	"encoding/hex"
	"math"
	"strings"

	"github.com/relux-works/swarma-chain-lab/experiments/grant-v4/identity"
)

const MaxGrantSize = 65536

const (
	GrantShape    Code = "GRANT_SHAPE"
	GrantDelegate Code = "GRANT_DELEGATE"
	ChildSigner   Code = "CHILD_SIGNER"
	ChainDepth    Code = "CHAIN_DEPTH"
	NotDelegable  Code = "NOT_DELEGABLE"
)

// GrantFailure names the first failed step of W9.1/W11.8. Rule is set for
// W11.9 and W11.10 only. It is diagnostic, not an additional refusal code.
type GrantFailure struct {
	Code Code
	Step int
	Rule int
}

func (e *GrantFailure) Error() string { return e.Code.Error() }
func (e *GrantFailure) Unwrap() error { return e.Code }

// GrantContext contains only a previously verified parent and a reference.
// JudgeProposals enables the explicitly undetermined points of W11.10 in a
// laboratory read. False checks every binding rule, not those proposals.
// Neither mode is an admission decision or a chain observation.
type GrantContext struct {
	Parent         *SignedGrant
	Reference      *string
	JudgeProposals bool
}

// SignedGrant is an immutable verified document, NOT admitted authority.
// In particular it establishes no name, height, seal, row or issuer liveness.
// Only VerifyGrant constructs a useful value. Every byte accessor makes a copy.
type SignedGrant struct{ object *SignedObject }

func (g *SignedGrant) Bytes() []byte { return g.object.Bytes() }
func (g *SignedGrant) Payload() []byte {
	if g == nil || g.object == nil {
		return nil
	}
	return g.object.Payload()
}
func (g *SignedGrant) Signature() string      { return g.object.Signature() }
func (g *SignedGrant) ID() string             { return g.object.ID() }
func (g *SignedGrant) Digest() [32]byte       { return g.object.Digest() }
func (g *SignedGrant) ContentAddress() string { return g.object.ContentAddress() }

// SealScript derives the W-profile witness key hash from the signed output
// key, preserving its parity. It asserts no existence or spend state.
func (g *SignedGrant) SealScript() []byte {
	pin, _ := identity.ParsePin(g.object.payload.root.get("seal").get("key").text)
	hash := pin.Hash160()
	return append([]byte{0, 20}, hash[:]...)
}

// VerifyGrant implements LIP-0020 W9.1, W9.2, W9.3 and W11.1-W11.10 at
// specification version 0.1.53. It returns no object after any refusal.
func VerifyGrant(b []byte, context GrantContext) (*SignedGrant, error) {
	fail := func(step int, err error) (*SignedGrant, error) {
		return nil, &GrantFailure{Code: err.(Code), Step: step}
	}
	d, err := ParseDocument(b, MaxGrantSize)
	if err != nil {
		return fail(1, err)
	}
	if !exactMembers(d.root, []string{"payload", "signature"}) {
		return fail(2, WireMember)
	}
	p := d.root.get("payload")
	if err := requireType(p, Grant); err != nil {
		return fail(3, err)
	}
	schema := grantPayloadSchema()
	// Names across the entire tree precede values; values across the entire
	// tree precede curve membership. Values follow canonical member order.
	for _, phase := range []int{0, 1, 2} {
		if err := schema.check(p, phase); err != nil {
			return fail(4, err)
		}
	}
	sig := d.root.get("signature").stringValue()
	if !hexForm(sig, 64) {
		return fail(5, WireSignatureForm)
	}
	key, refusal := p.get("issuer").get("grant_key").stringValue(), WireSignature
	if parentID := p.get("parent"); parentID != nil {
		parent := context.Parent
		if parent == nil || parent.object == nil || parentID.text != parent.ID() {
			return fail(6, WireID)
		}
		pp := parent.object.payload.root
		if pp.get("parent") != nil {
			return fail(6, ChainDepth)
		}
		if pp.get("delegate") == nil {
			return fail(6, NotDelegable)
		}
		key, refusal = pp.get("delegate").get("key").text, ChildSigner
	}
	o := &SignedObject{document: d, payload: &Document{p}, signature: sig}
	raw, _ := hex.DecodeString(sig)
	if VerifyBIP340(key, o.Digest(), raw) != nil {
		return fail(7, refusal)
	}
	if context.Reference != nil && *context.Reference != o.ID() {
		return fail(8, WireID)
	}
	if rule := grantShapeRule(p); rule != 0 {
		return nil, &GrantFailure{Code: GrantShape, Step: 9, Rule: rule}
	}
	if rule := grantDelegateRule(p, context.JudgeProposals); rule != 0 {
		return nil, &GrantFailure{Code: GrantDelegate, Step: 9, Rule: rule}
	}
	return &SignedGrant{object: o}, nil
}

// A schema has exactly one of fields/choose, element, or leaf. Validation has
// three passes so a late unknown name wins over an early invalid value/key.
type grantSchema struct {
	fields   map[string]*grantSchema
	optional map[string]bool
	choose   func(*value) *grantSchema
	element  *grantSchema
	minimum  int
	maximum  int // -1 means no count cap beyond the document's byte bound
	leaf     func(*value, int) error
}

func grantObject(fields map[string]*grantSchema, optional ...string) *grantSchema {
	s := &grantSchema{fields: fields, optional: map[string]bool{}}
	for _, name := range optional {
		s.optional[name] = true
	}
	return s
}
func grantArray(element *grantSchema, minimum, maximum int) *grantSchema {
	return &grantSchema{element: element, minimum: minimum, maximum: maximum}
}
func (s *grantSchema) check(v *value, phase int) error {
	if s.choose != nil {
		return s.choose(v).check(v, phase)
	}
	if s.fields != nil {
		if v == nil || v.kind != '{' {
			if phase == 1 {
				return WireMember
			}
			return nil
		}
		if phase == 0 {
			for name := range s.fields {
				if !s.optional[name] && v.get(name) == nil {
					return WireMember
				}
			}
			for _, m := range v.members {
				if s.fields[m.name] == nil {
					return WireMember
				}
			}
		}
		for _, m := range v.members {
			if err := s.fields[m.name].check(m.value, phase); err != nil {
				return err
			}
		}
		return nil
	}
	if s.element != nil {
		if v == nil || v.kind != '[' {
			if phase == 1 {
				return WireMember
			}
			return nil
		}
		if phase == 1 && (len(v.elements) < s.minimum || s.maximum >= 0 && len(v.elements) > s.maximum) {
			return WireMember
		}
		for _, x := range v.elements {
			if err := s.element.check(x, phase); err != nil {
				return err
			}
		}
		return nil
	}
	return s.leaf(v, phase)
}

func grantForm(form func(*value) bool) *grantSchema {
	return &grantSchema{leaf: func(v *value, phase int) error {
		if phase == 1 && !form(v) {
			return WireMember
		}
		return nil
	}}
}
func grantText(bound int) *grantSchema {
	return grantForm(func(v *value) bool {
		if v == nil || v.kind != 's' || len(v.text) == 0 || len(v.text) > bound {
			return false
		}
		for _, c := range []byte(v.text) {
			if c < 32 || c > 126 {
				return false
			}
		}
		return true
	})
}
func grantHex(n int) *grantSchema {
	return grantForm(func(v *value) bool { return v != nil && v.kind == 's' && hexForm(v.text, n) })
}
func grantInteger(kind byte, low, high uint64) *grantSchema {
	return &grantSchema{leaf: func(v *value, phase int) error {
		if phase != 1 {
			return nil
		}
		if v == nil || v.kind != kind {
			return WireMember
		}
		n, err := ParseInteger(v.text, high)
		if err != nil || n < low {
			return WireInteger
		}
		return nil
	}}
}
func grantKey(output bool) *grantSchema {
	return &grantSchema{leaf: func(v *value, phase int) error {
		if phase == 0 {
			return nil
		}
		n := 32
		if output {
			n = 33
		}
		if phase == 1 {
			if v == nil || v.kind != 's' || !hexForm(v.text, n) || output && !strings.HasPrefix(v.text, "02") && !strings.HasPrefix(v.text, "03") {
				return WireMember
			}
			return nil
		}
		key := v.text
		if output {
			if _, err := identity.ParsePin(key); err != nil {
				return WireKey
			}
			return nil
		}
		return CheckSigningKey(key)
	}}
}

func grantPayloadSchema() *grantSchema {
	hash, text, signing, output := grantHex(32), grantText(255), grantKey(false), grantKey(true)
	index, height := grantInteger('d', 0, math.MaxUint32), grantInteger('d', 0, MaxNumber)
	outpoint := grantObject(map[string]*grantSchema{"txid": hash, "vout": index})
	pin := grantObject(map[string]*grantSchema{"name": text, "owner": output, "registration": outpoint})
	executor := grantObject(map[string]*grantSchema{"key": signing, "name": text})
	limit := grantObject(map[string]*grantSchema{"amount": grantInteger('s', 0, math.MaxUint64), "kind": text, "resource": text, "unit": text, "period": text}, "period")
	limits, actions := grantArray(limit, 0, -1), grantArray(text, 0, -1)
	byKey := grantObject(map[string]*grantSchema{"key": signing})
	byName := grantObject(map[string]*grantSchema{"name": text, "owner": output})
	byClass := grantObject(map[string]*grantSchema{"class": grantArray(pin, 1, -1)})
	recipient := func(class bool) *grantSchema {
		return &grantSchema{choose: func(v *value) *grantSchema {
			if class && v.get("class") != nil {
				return byClass
			}
			if v.get("key") != nil {
				return byKey
			}
			return byName
		}}
	}
	script := grantForm(func(v *value) bool {
		return v != nil && v.kind == 's' && len(v.text) >= 2 && len(v.text) <= 200 && len(v.text)%2 == 0 && hexForm(v.text, len(v.text)/2)
	})
	stop := grantObject(map[string]*grantSchema{"txid": hash, "first": index, "script": script})
	rangeSchema := grantObject(map[string]*grantSchema{"count": grantInteger('d', 1, 4096), "first": index, "script": script, "stop": stop, "txid": hash}, "stop")
	template := &grantSchema{choose: func(v *value) *grantSchema {
		fields := map[string]*grantSchema{"executor": executor, "recipient": recipient(true), "limits": limits}
		if v.get("no_certifier") != nil {
			fields["no_certifier"] = grantForm(func(v *value) bool { return v != nil && v.kind == 't' })
		} else {
			fields["certifier"] = text
		}
		return grantObject(fields)
	}}
	group := grantObject(map[string]*grantSchema{"template": template, "ranges": grantArray(rangeSchema, 1, 16)})
	delegate := grantObject(map[string]*grantSchema{
		"key": signing, "child_seal_key": output, "actions": actions,
		"pools": limits, "notaries": grantArray(pin, 0, 4), "groups": grantArray(group, 1, 16),
	}, "child_seal_key")
	return &grantSchema{choose: func(v *value) *grantSchema {
		fields := map[string]*grantSchema{
			"type": text, "genesis": hash, "contract": hash, "executor": executor,
			"recipient": recipient(false), "actions": actions, "limits": limits,
			"not_before_height": height, "not_after_height": height, "recent_block": hash,
			"seal": grantObject(map[string]*grantSchema{"construction": grantText(32), "kind": grantText(32), "key": output, "outpoint": outpoint}),
		}
		if v.get("parent") != nil {
			fields["parent"], fields["ordinal"] = hash, height
			return grantObject(fields)
		}
		fields["issuer"] = grantObject(map[string]*grantSchema{"grant_key": signing, "name": text, "owner": output, "registration": outpoint})
		fields["delegate"] = delegate
		return grantObject(fields, "delegate")
	}}
}
