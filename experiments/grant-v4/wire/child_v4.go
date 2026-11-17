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

// ChildAttenuationFailure is a refusal of the document-comparison slice of
// LIP-0014 section 8.4 at spec 0.1.55, commit 1e58a9f9. Step is its F number.
// Open is nonempty, and Code empty, when the pinned spec or missing non-document
// facts prevent a decision. Open is diagnostic text, never a protocol code.
type ChildAttenuationFailure struct {
	Code Code
	Step int
	Open string
}

func (e *ChildAttenuationFailure) Error() string {
	if e.Open != "" {
		return fmt.Sprintf("OPEN F%d: %s", e.Step, e.Open)
	}
	return e.Code.Error()
}
func (e *ChildAttenuationFailure) Unwrap() error {
	if e.Code == "" {
		return nil
	}
	return e.Code
}

func childRefusalV4(step int, code Code) error {
	return &ChildAttenuationFailure{Step: step, Code: code}
}
func childOpenV4(step int, reason string) error {
	return &ChildAttenuationFailure{Step: step, Open: reason}
}

// CheckChildAttenuationV4 compares immutable, already verified documents under
// spec 0.1.55. The parent supplies the W11.8 ancestry/delegation context: there
// is no depth member in v4, and a child cannot itself be a parent. The function
// repeats the parent binding so a child verified against a different parent
// cannot be substituted. It performs no parsing, normalization, writes or I/O.
//
// This is NOT the full admission predicate: F3/F6/F7 and node/attestation checks
// need inputs beyond two documents. At this pin F13's count order awaits an
// explicit owner decision (LIP-0026 section 8 versus W11.6). Consequently a
// pair that reaches that unresolved row refuses with Open and no invented code;
// no public call currently accepts. See STEPS-B3a-CHILD.md for the exact boundary.
func CheckChildAttenuationV4(parent, child *SignedGrant) error {
	if parent == nil || parent.object == nil {
		return childRefusalV4(2, WireID)
	}
	if child == nil || child.object == nil {
		return childOpenV4(2, "an already verified child document is required")
	}
	p, c := parent.object.payload.root, child.object.payload.root
	if c.get("parent") == nil {
		return childOpenV4(2, "the verified document is a root, not a child")
	}
	if c.get("parent").text != parent.ID() {
		return childRefusalV4(2, WireID)
	}
	if p.get("parent") != nil {
		return childRefusalV4(2, ChainDepth)
	}
	d := p.get("delegate")
	if d == nil {
		return childRefusalV4(2, NotDelegable)
	}
	if c.get("contract").text != p.get("contract").text {
		return childRefusalV4(5, ChildContractDiffers)
	}
	if c.get("genesis").text != p.get("genesis").text {
		return childRefusalV4(8, SubjectMismatch)
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
			return childRefusalV4(9, DelegateKeyReuse)
		}
	}
	seal := d.get("child_seal_key")
	if seal == nil {
		return childRefusalV4(10, ChildSealKey)
	}
	for _, key := range append(roles, delegation) {
		if childKeyXV4(key) == childKeyXV4(seal.text) {
			return childRefusalV4(10, DelegateKeyReuse)
		}
	}
	for _, key := range []string{c.get("seal").get("key").text, childRecipientKeyV4(c.get("recipient"))} {
		if childKeyXV4(key) == delegation {
			return childRefusalV4(11, DelegateKeyReuse)
		}
	}
	if p.get("recipient").get("name") != nil {
		return childOpenV4(11, "F11 requires the current channel keys read by F7.3; documents contain no such facts")
	}
	if c.get("seal").get("key").text != seal.text {
		return childRefusalV4(12, ChildSealKey)
	}
	var count uint64
	for _, group := range d.get("groups").elements {
		for _, rng := range group.get("ranges").elements {
			count += grantNumber(rng.get("count")) // Verified schema: at most 1,048,576 rows.
		}
	}
	ordinal := grantNumber(c.get("ordinal"))
	if ordinal == 0 || ordinal > count {
		return childRefusalV4(13, ChildOrdinal)
	}
	return childOpenV4(13, "ordinal count order: W11.6 specifies signed order; LIP-0026 section 8 says it binds no reader until owner acceptance")
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

// checkChildTemplateV4 implements the decidable F14-F18 comparisons against an
// already selected signed template. It is private: F13 cannot select one until
// its OPEN is resolved. Tests exercise these comparisons without pretending
// that a caller-supplied template or ordinal mapping establishes authority.
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
	// T9/W11.14: no kind is defined at this pin, including "policy".
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
