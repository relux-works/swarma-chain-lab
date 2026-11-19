package wire

import (
	"bytes"
	"fmt"
)

const (
	ChildContractDiffers   Code = "CHILD_CONTRACT_DIFFERS"
	SubjectMismatch        Code = "SUBJECT_MISMATCH"
	DelegateKeyReuse       Code = "DELEGATE_KEY_REUSE"
	ChildSealKey           Code = "CHILD_SEAL_KEY"
	ChildOrdinal           Code = "CHILD_ORDINAL"
	ChildAgentNotAllowed   Code = "CHILD_AGENT_NOT_ALLOWED"
	ChildGranteeNotAllowed Code = "CHILD_GRANTEE_NOT_ALLOWED"
	ChildActionsWider      Code = "CHILD_ACTIONS_WIDER"
	ChildBudgetOver        Code = "CHILD_BUDGET_OVER"
	LimitKindUndefined     Code = "LIMIT_KIND_UNDEFINED"
	ChildWindowNotNested   Code = "CHILD_WINDOW_NOT_NESTED"
)

// ChildAttenuationFailure is an ordered refusal of the evaluated document slice
// of LIP-0014 section 8.4 at spec 0.1.61, commit 464c445f. Step is its F number.
// It is not the outcome of the full admission predicate.
type ChildAttenuationFailure struct {
	Code Code
	Step int
}

func (e *ChildAttenuationFailure) Error() string { return e.Code.Error() }
func (e *ChildAttenuationFailure) Unwrap() error { return e.Code }

func childRefusalV4(step int, code Code) error {
	return &ChildAttenuationFailure{Step: step, Code: code}
}

// ChildDocumentInputError identifies a missing verified child or a root supplied
// in its place. It is a local input error, not a protocol refusal or admission.
type ChildDocumentInputError struct{ Kind string }

func (e *ChildDocumentInputError) Error() string { return "invalid verified child input: " + e.Kind }

// ChildAttenuationEvaluation records passing F5 and F8-F18, using the caller's
// F11 observation input and F1/F2 already-verified document preconditions.
// F13(b) selected-group/range W11.10 rules are also held by that verification.
// It is NOT admission: F3, F6, F7, F19-F24 and A1 belong to the caller or other
// layers. GroupIndex and RangeIndex are zero-based signed-array positions;
// RowCoin is the selected signed outpoint, not evidence of its chain state.
// A refusal returns the zero value, never a partially evaluated result.
type ChildAttenuationEvaluation struct {
	GroupIndex int
	RangeIndex int
	RowCoin    Outpoint
}

// ParentNameObservation holds the F7.3 facts supplied by the admission/junction
// caller, never by the child presenter. Genesis and TipHash are lowercase
// 32-byte hashes in node display order; TipHeight is the observed tip height.
// ChannelKeys is the complete, nonempty set of channel signing keys yielded by
// Name in that observation, in the current Nostr profile's x-only BIP-340 form.
// The caller establishes provenance, completeness, owner control and observation
// health; this pure evaluator cannot authenticate those claims or read a node.
// The input and its slice are neither mutated nor retained.
type ParentNameObservation struct {
	Name        string
	Genesis     string
	TipHash     string
	TipHeight   uint64
	ChannelKeys []string
}

// ParentNameObservationError is an invalid local input contract, not a protocol
// refusal code or an admission result. The pin assigns no code to malformed
// caller-supplied facts. KeyIndex is -1 unless Kind identifies a bad set entry.
type ParentNameObservationError struct {
	Kind     ParentNameObservationErrorKind
	KeyIndex int
}

// ParentNameObservationErrorKind identifies the invalid caller input.
type ParentNameObservationErrorKind string

const (
	ParentObservationMissing    ParentNameObservationErrorKind = "missing"
	ParentObservationUnexpected ParentNameObservationErrorKind = "unexpected"
	ParentObservationName       ParentNameObservationErrorKind = "name"
	ParentObservationIdentity   ParentNameObservationErrorKind = "identity"
	ParentObservationChain      ParentNameObservationErrorKind = "chain"
	ParentObservationEmpty      ParentNameObservationErrorKind = "empty"
	ParentObservationDuplicate  ParentNameObservationErrorKind = "duplicate"
	ParentObservationKey        ParentNameObservationErrorKind = "key"
)

func (e *ParentNameObservationError) Error() string {
	return fmt.Sprintf("invalid parent-name observation: %s (key index %d)", e.Kind, e.KeyIndex)
}

// validate checks all entries before membership, so a forbidden key cannot hide
// malformed trailing input. Signed-octet refusals are checked before this call.
func (o *ParentNameObservation) validate(parent *value) error {
	bad := func(kind ParentNameObservationErrorKind, index int) error {
		return &ParentNameObservationError{Kind: kind, KeyIndex: index}
	}
	name := parent.get("recipient").get("name")
	if name == nil {
		if o != nil {
			return bad(ParentObservationUnexpected, -1)
		}
		return nil
	}
	if o == nil {
		return bad(ParentObservationMissing, -1)
	}
	if o.Name != name.text {
		return bad(ParentObservationName, -1)
	}
	if !hexForm(o.Genesis, 32) || !hexForm(o.TipHash, 32) {
		return bad(ParentObservationIdentity, -1)
	}
	if o.Genesis != parent.get("genesis").text {
		return bad(ParentObservationChain, -1)
	}
	if len(o.ChannelKeys) == 0 {
		return bad(ParentObservationEmpty, -1)
	}
	seen := make(map[string]bool, len(o.ChannelKeys))
	for i, key := range o.ChannelKeys {
		if CheckSigningKey(key) != nil {
			return bad(ParentObservationKey, i)
		}
		if seen[key] {
			return bad(ParentObservationDuplicate, i)
		}
		seen[key] = true
	}
	return nil
}

func childChannelContainsV4(keys []string, delegation string) bool {
	for _, key := range keys {
		if key == delegation {
			return true
		}
	}
	return false
}

// CheckChildAttenuationV4 evaluates F5 and F8-F18 of LIP-0014 section 8.4
// at spec 0.1.61 (464c445f), with F1/F2 held by immutable verified documents
// and F11 facts supplied by the admission/junction caller. It repeats parent
// binding, selects the F13 row in the in-force order of LIP-0026 section 8 and
// W11.6, and compares F14-F18 against that row. No limit profile is adopted.
// Observation is nil for a by-key parent and valid for a by-name parent.
// No input is mutated or retained; no parsing, node/seal read, write or I/O
// occurs. Passing this slice is NOT admission: F3, F6, F7, F19-F24 and A1
// remain obligations of the caller or other layers, not of this result.
func CheckChildAttenuationV4(parent, child *SignedGrant, observation *ParentNameObservation) (ChildAttenuationEvaluation, error) {
	if parent == nil || parent.object == nil {
		return ChildAttenuationEvaluation{}, childRefusalV4(2, WireID)
	}
	if child == nil || child.object == nil {
		return ChildAttenuationEvaluation{}, &ChildDocumentInputError{Kind: "missing"}
	}
	p, c := parent.object.payload.root, child.object.payload.root
	if c.get("parent") == nil {
		return ChildAttenuationEvaluation{}, &ChildDocumentInputError{Kind: "root"}
	}
	if c.get("parent").text != parent.ID() {
		return ChildAttenuationEvaluation{}, childRefusalV4(2, WireID)
	}
	if p.get("parent") != nil {
		return ChildAttenuationEvaluation{}, childRefusalV4(2, ChainDepth)
	}
	d := p.get("delegate")
	if d == nil {
		return ChildAttenuationEvaluation{}, childRefusalV4(2, NotDelegable)
	}
	if c.get("contract").text != p.get("contract").text {
		return ChildAttenuationEvaluation{}, childRefusalV4(5, ChildContractDiffers)
	}
	if c.get("genesis").text != p.get("genesis").text {
		return ChildAttenuationEvaluation{}, childRefusalV4(8, SubjectMismatch)
	}
	roles := []string{
		p.get("issuer").get("grant_key").text,
		p.get("issuer").get("owner").text,
		childRecipientKeyV4(p.get("recipient")),
		p.get("seal").get("key").text,
	}
	for _, n := range d.get("notaries").elements {
		roles = append(roles, n.get("owner").text)
	}
	delegation := d.get("key").text
	for _, key := range roles {
		if childKeyXV4(key) == delegation {
			return ChildAttenuationEvaluation{}, childRefusalV4(9, DelegateKeyReuse)
		}
	}
	seal := d.get("child_seal_key")
	if seal == nil {
		return ChildAttenuationEvaluation{}, childRefusalV4(10, ChildSealKey)
	}
	for _, key := range append(roles, delegation) {
		if childKeyXV4(key) == childKeyXV4(seal.text) {
			return ChildAttenuationEvaluation{}, childRefusalV4(10, DelegateKeyReuse)
		}
	}
	for _, key := range []string{c.get("seal").get("key").text, childRecipientKeyV4(c.get("recipient"))} {
		if childKeyXV4(key) == delegation {
			return ChildAttenuationEvaluation{}, childRefusalV4(11, DelegateKeyReuse)
		}
	}
	if err := observation.validate(p); err != nil {
		return ChildAttenuationEvaluation{}, err
	}
	if observation != nil && childChannelContainsV4(observation.ChannelKeys, delegation) {
		return ChildAttenuationEvaluation{}, childRefusalV4(11, DelegateKeyReuse)
	}
	if c.get("seal").get("key").text != seal.text {
		return ChildAttenuationEvaluation{}, childRefusalV4(12, ChildSealKey)
	}
	var count uint64
	for _, group := range d.get("groups").elements {
		for _, rng := range group.get("ranges").elements {
			count += grantNumber(rng.get("count")) // Verified schema: at most 1,048,576 rows.
		}
	}
	ordinal := grantNumber(c.get("ordinal"))
	if ordinal == 0 || ordinal > count {
		return ChildAttenuationEvaluation{}, childRefusalV4(13, ChildOrdinal)
	}
	remaining := ordinal - 1
	for groupIndex, group := range d.get("groups").elements {
		for rangeIndex, rng := range group.get("ranges").elements {
			rangeCount := grantNumber(rng.get("count"))
			if remaining >= rangeCount {
				remaining -= rangeCount
				continue
			}
			template := group.get("template")
			if err := checkChildTemplateV4(p, c, template); err != nil {
				return ChildAttenuationEvaluation{}, err
			}
			return ChildAttenuationEvaluation{GroupIndex: groupIndex, RangeIndex: rangeIndex,
				RowCoin: Outpoint{TxID: rng.get("txid").text, Vout: grantNumber(rng.get("first")) + remaining}}, nil
		}
	}
	return ChildAttenuationEvaluation{}, childRefusalV4(13, ChildOrdinal)
}

func childKeyXV4(key string) string {
	if len(key) == 66 {
		return key[2:]
	}
	return key
}
func childRecipientKeyV4(recipient *value) string {
	if key := recipient.get("key"); key != nil {
		return key.text
	}
	return recipient.get("owner").text
}

// checkChildTemplateV4 evaluates F14-F18 against the signed F13-selected
// template. VerifyGrant already holds selected-group/range W11.10 rules 4/5.
func checkChildTemplateV4(p, c, template *value) error {
	if !bytes.Equal(serialize(c.get("executor")), serialize(template.get("executor"))) {
		return childRefusalV4(14, ChildAgentNotAllowed)
	}
	r := template.get("recipient")
	if r.get("class") != nil {
		if c.get("recipient").get("name") == nil {
			return childRefusalV4(15, ChildGranteeNotAllowed)
		}
	} else if !bytes.Equal(serialize(c.get("recipient")), serialize(r)) {
		return childRefusalV4(15, ChildGranteeNotAllowed)
	}
	actions := map[string]bool{}
	for _, action := range p.get("delegate").get("actions").elements {
		actions[action.text] = true
	}
	for _, action := range c.get("actions").elements {
		if !actions[action.text] {
			return childRefusalV4(16, ChildActionsWider)
		}
	}
	keys := map[string]bool{}
	for _, limit := range template.get("limits").elements {
		keys[grantLimitKey(limit)] = true
	}
	for _, limit := range c.get("limits").elements {
		if !keys[grantLimitKey(limit)] {
			return childRefusalV4(17, ChildBudgetOver)
		}
	}
	// T9/W11.14: this side runs no proposed LIP-0031 profile, including "policy".
	// Never treat an unknown kind as absent or guess ceiling/floor arithmetic.
	if len(c.get("limits").elements) != 0 || len(template.get("limits").elements) != 0 {
		return childRefusalV4(17, LimitKindUndefined)
	}
	if grantNumber(c.get("not_before_height")) < grantNumber(p.get("not_before_height")) ||
		grantNumber(c.get("not_after_height")) > grantNumber(p.get("not_after_height")) {
		return childRefusalV4(18, ChildWindowNotNested)
	}
	return nil
}
