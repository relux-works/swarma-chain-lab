package identity

import "bytes"

const (
	ChildOrdinal            Refusal = "CHILD_ORDINAL"
	ChildAgentNotAllowed    Refusal = "CHILD_AGENT_NOT_ALLOWED"
	ChildGranteeNotAllowed  Refusal = "CHILD_GRANTEE_NOT_ALLOWED"
	ChildBudgetOver         Refusal = "CHILD_BUDGET_OVER"
	ClassLandlord           Refusal = "CLASS_LANDLORD"
	ClassLandlordChanged    Refusal = "CLASS_LANDLORD_CHANGED"
	ClassCheckpoint         Refusal = "CLASS_CHECKPOINT"
	ClassValueUnauthorized  Refusal = "CLASS_VALUE_UNAUTHORIZED"
	ClassLandlordPending    Refusal = "CLASS_LANDLORD_PENDING"
	ClassHolder             Refusal = "CLASS_HOLDER"
	ClassWriter             Refusal = "CLASS_WRITER"
	ClassHistoryUnavailable Refusal = "CLASS_HISTORY_UNAVAILABLE"
)

func validLandlord(p LandlordPin) bool {
	return p.Name != "" && p.Owner.Valid() && rowTxID(p.Registration.TxID)
}
func sameLandlord(a, b LandlordPin) bool {
	return a.Name == b.Name && a.Registration == b.Registration && a.Owner == b.Owner
}
func validRowRecipient(r RowRecipient) bool {
	modes := 0
	if r.Key != nil {
		modes++
		if *r.Key == "" {
			return false
		}
	}
	if r.Name != nil {
		modes++
		if len(r.Name.Name) == 0 || !r.Name.Owner.Valid() {
			return false
		}
	}
	if r.Class != nil {
		modes++
		if len(r.Class) == 0 {
			return false
		}
		names := make(map[string]bool)
		for _, l := range r.Class {
			if !validLandlord(l) || names[l.Name] {
				return false
			}
			names[l.Name] = true
		}
	}
	return modes == 1
}

// CheckRowTemplate implements R9.1, R10.1, R10.2 and J9.4. The caller must
// establish the parent's pinned notaries; their names here are checked identities,
// not an alternate notary identity resolver. Empty Certifier explicitly means none.
func CheckRowTemplate(profile R1Profile, issuer LandlordPin, notaries []string, t RowTemplate) error {
	if profile != R1DraftLab {
		return ErrR1Profile
	}
	if !validLandlord(issuer) || !validRowRecipient(t.Recipient) {
		return R1RuleError("R9.1")
	}
	if t.Certifier != "" {
		for _, n := range notaries {
			if n == t.Certifier {
				return nil
			}
		}
		return R1RuleError("R10.1")
	}
	if t.StopCoin != nil {
		return R1RuleError("R10.5")
	}
	if t.Recipient.Name != nil {
		return nil
	}
	if len(t.Recipient.Class) != 1 || !sameLandlord(t.Recipient.Class[0], issuer) {
		return R1RuleError("R10.2")
	}
	return nil
}

// ClassNameEvidence holds raw current-output octets and the inputs of the
// operation that created it. No separately supplied value/channel key is trusted.
type ClassNameEvidence struct {
	Script       []byte
	ConfirmedAt  Height
	Inputs       []Input
	Current      CurrentStatus
	Transactions bool
}

// ClassLandlordEvidence is one coherent node observation, tied to its exact
// signed binding. RegistrationID maps that binding to the walk's opaque ID.
// PendingKnown=false proves no absence. Value must be the current output's value
// extracted by the observation adapter; this module has no node adapter.
type ClassLandlordEvidence struct {
	Binding               LandlordPin
	Name                  StatedName
	RegistrationID        string
	Value                 []byte
	PendingKnown, Pending bool
}
type ClassObservation struct {
	Tip, Recent Height
	Depth       int64
	Chain       Chain
	Recipient   ClassNameEvidence
	Landlords   []ClassLandlordEvidence
	// ParentAdmitted is required for R10.3's skipped issuer checks. It is an
	// independently established result, never a presenter-supplied credential.
	ParentAdmitted bool
}

// RowRecipientResult never claims an attestation or a complete grant passed.
// Required means a later certifier pipeline remains mandatory; false means
// there is no attestation to read. On refusal no key or policy is returned.
type RowRecipientResult struct {
	Key                 string
	AttestationRequired bool
}

func classLandlordHistory(e ClassLandlordEvidence, o ClassObservation, exact bool) error {
	s := e.Name
	if !validLandlord(e.Binding) || string(s.Name) != e.Binding.Name || s.Owner != e.Binding.Owner || s.Tip != o.Tip || s.Depth != o.Depth || !o.Tip.known || !o.Recent.known || o.Recent.h > o.Tip.h {
		return ClassHistoryUnavailable
	}
	// R9.5 step 1 distinguishes proved absence from an unavailable fact.
	switch s.Current {
	case CurrentOutput:
	case NoLiveOutput:
		return ClassLandlordChanged
	default:
		return ClassHistoryUnavailable
	}
	if exact {
		if !o.ParentAdmitted {
			return ClassHistoryUnavailable
		}
	} else {
		live, known := s.live()
		if !known {
			return ClassHistoryUnavailable
		}
		if live != Live {
			return ClassLandlordChanged
		}
		w := walk(s, "")
		if !w.complete || e.RegistrationID == "" {
			return ClassHistoryUnavailable
		}
		if w.registration != e.RegistrationID {
			return ClassLandlordChanged
		}
		reg := w.outputs[len(w.outputs)-1]
		if reg.Height.h > o.Recent.h {
			return ClassCheckpoint
		}
		for _, out := range w.outputs {
			if out.Reading == AnotherKey {
				return ClassLandlordChanged
			}
			if out.Reading != Controlled {
				return ClassHistoryUnavailable
			}
			if out.Height.h <= o.Recent.h {
				break
			}
		}
	}
	if !s.Transactions || len(s.Outputs) == 0 || !s.Outputs[0].Available {
		return ClassHistoryUnavailable
	}
	switch s.Outputs[0].Writer {
	case WrittenByAnother:
		return ClassValueUnauthorized
	case WrittenByOwner:
	default:
		return ClassHistoryUnavailable
	}
	if !e.PendingKnown {
		return ClassHistoryUnavailable
	}
	if e.Pending {
		return ClassLandlordPending
	}
	return nil
}

// CheckRowRecipient implements R2.3 then R9.3-R9.10/R10.3 on stated facts.
// It never takes an attestation argument: R10.4 cannot accidentally read one.
// Use CheckR1Child to place executor/limit comparisons before these node facts.
func CheckRowRecipient(profile R1Profile, issuer LandlordPin, t RowTemplate, child Recipient, o ClassObservation) (RowRecipientResult, error) {
	fail := func(err error) (RowRecipientResult, error) { return RowRecipientResult{}, err }
	if profile != R1DraftLab {
		return fail(ErrR1Profile)
	}
	if !validLandlord(issuer) || !validRowRecipient(t.Recipient) {
		return fail(ChildGranteeNotAllowed)
	}
	// Recheck the no-certifier restriction even for this standalone predicate.
	if t.Certifier == "" {
		if err := CheckRowTemplate(profile, issuer, nil, t); err != nil {
			return fail(err)
		}
	}
	if (child.RequestKey == nil) == (child.ByName == nil) {
		return fail(ChildGranteeNotAllowed)
	}
	exact := t.Recipient.Name != nil
	if t.Recipient.Key != nil {
		if child.RequestKey == nil || *child.RequestKey != *t.Recipient.Key {
			return fail(ChildGranteeNotAllowed)
		}
		return RowRecipientResult{*child.RequestKey, true}, nil
	}
	if child.ByName == nil || !child.ByName.Owner.Valid() || len(child.ByName.Name) == 0 {
		return fail(ChildGranteeNotAllowed)
	}
	if exact && (!bytes.Equal(child.ByName.Name, t.Recipient.Name.Name) || child.ByName.Owner != t.Recipient.Name.Owner) {
		return fail(ChildGranteeNotAllowed)
	}
	// O7.2 precedes every class check. Current output proof is independent of
	// the value's parse, pointer and channel key.
	e := o.Recipient
	if !o.Tip.known || o.Depth <= 0 || e.Current == CurrentUnknown {
		return fail(RecipientNameUnavailable)
	}
	if e.Current == NoLiveOutput {
		return fail(RecipientNameNotHeld)
	}
	if !e.Transactions {
		return fail(RecipientNameUnavailable)
	}
	live, err := CheckLive(e.ConfirmedAt.h, o.Tip.h, o.Depth)
	if !e.ConfirmedAt.known || err != nil {
		return fail(RecipientNameUnavailable)
	}
	if live != Live {
		return fail(RecipientNameNotHeld)
	}
	reading, ns := ReadOutput(e.Script, child.ByName.Owner, e.ConfirmedAt, o.Chain)
	if !bytes.Equal(ns.Name, child.ByName.Name) || (ns.Prefix != PrefixUpdate && ns.Prefix != PrefixRegistration) {
		return fail(RecipientNameUnavailable)
	}
	if reading == AnotherKey {
		return fail(RecipientNameNotHeld)
	}
	if reading != Controlled {
		return fail(RecipientNameUnavailable)
	}
	if exact && t.Certifier != "" {
		_, nostr, err := r1ValueMembers(ns.Value)
		key := r1Channel(nostr)
		if err != nil || key == "" {
			return fail(ErrChannel)
		}
		return RowRecipientResult{key, true}, nil
	}
	value, valueErr := ReadR1Value(profile, ns.Value)
	if valueErr != nil || value.Landlord == "" {
		return fail(ClassLandlord)
	}
	landlords := t.Recipient.Class
	if exact {
		landlords = []LandlordPin{issuer}
	}
	var selected *LandlordPin
	for i := range landlords {
		if landlords[i].Name == value.Landlord {
			selected = &landlords[i]
			break
		}
	}
	if selected == nil {
		return fail(ClassLandlord)
	}
	var landlord *ClassLandlordEvidence
	for i := range o.Landlords {
		if sameLandlord(o.Landlords[i].Binding, *selected) {
			if landlord != nil {
				return fail(ClassHistoryUnavailable)
			}
			landlord = &o.Landlords[i]
		}
	}
	if landlord == nil {
		return fail(ClassHistoryUnavailable)
	}
	if err := classLandlordHistory(*landlord, o, exact); err != nil {
		return fail(err)
	}
	lv, err := ReadR1Value(profile, landlord.Value)
	if err != nil || lv.Grant == "" {
		return fail(ClassHolder)
	}
	held := false
	for _, h := range lv.Holders {
		if h == child.ByName.Owner {
			held = true
		}
	}
	if !held {
		return fail(ClassHolder)
	}
	operation := OpUpdate
	if ns.Prefix == PrefixRegistration {
		operation = OpRegistration
	}
	unsupported, written := false, false
	for _, h := range lv.Holders {
		switch CheckWriter(operation, ns.Name, e.Inputs, h, o.Chain) {
		case WrittenByOwner:
			written = true
		case WriterUnsupported:
			unsupported = true
		}
	}
	if !written {
		if unsupported {
			return fail(ClassHistoryUnavailable)
		}
		return fail(ClassWriter)
	}
	if value.ChannelKey == "" {
		return fail(ErrChannel)
	}
	return RowRecipientResult{value.ChannelKey, t.Certifier != ""}, nil
}

// R1Parent and R1Child are typed facts only. The parent must already have
// passed the issuer/grant pipeline; a child still needs coin/anchor checks and,
// where Required is true, its certifier's pipeline. No parser is invented.
type R1Parent struct {
	Issuer   LandlordPin
	Notaries []string
	Rows     RowGroups
}
type R1Child struct {
	Ordinal   uint64
	Executor  RowExecutor
	Recipient Recipient
	Limits    []RowLimit
}

func CheckR1Parent(profile R1Profile, p R1Parent) error {
	if _, err := CheckRowGroups(profile, p.Rows); err != nil {
		return err
	}
	for _, g := range p.Rows.Groups {
		if g.Template.Executor.Name == "" || !validSigningKey(g.Template.Executor.Key) {
			return R1RuleError("R8.1")
		}
		if err := CheckRowTemplate(profile, p.Issuer, p.Notaries, g.Template); err != nil {
			return err
		}
	}
	return nil
}

// CheckR1Child preserves R2 order: ordinal, executor, recipient, limits, then
// recipient/class node predicates. It never returns a key after any refusal.
func CheckR1Child(profile R1Profile, p R1Parent, c R1Child, o ClassObservation) (RowRecipientResult, error) {
	fail := func(err error) (RowRecipientResult, error) { return RowRecipientResult{}, err }
	if err := CheckR1Parent(profile, p); err != nil {
		return fail(err)
	}
	if !o.ParentAdmitted {
		return fail(ClassHistoryUnavailable)
	}
	selected, err := SelectRow(profile, p.Rows, c.Ordinal)
	if err != nil {
		return fail(err)
	}
	t := p.Rows.Groups[selected.Group-1].Template
	if c.Executor != t.Executor {
		return fail(ChildAgentNotAllowed)
	}
	// Structural R2.3 precedes the limit ceiling, but proof-by-name comes later.
	if (c.Recipient.RequestKey == nil) == (c.Recipient.ByName == nil) {
		return fail(ChildGranteeNotAllowed)
	}
	if t.Recipient.Key != nil {
		if c.Recipient.RequestKey == nil || *c.Recipient.RequestKey != *t.Recipient.Key {
			return fail(ChildGranteeNotAllowed)
		}
	} else {
		if c.Recipient.ByName == nil || !c.Recipient.ByName.Owner.Valid() || len(c.Recipient.ByName.Name) == 0 {
			return fail(ChildGranteeNotAllowed)
		}
		if t.Recipient.Name != nil && (!bytes.Equal(c.Recipient.ByName.Name, t.Recipient.Name.Name) || c.Recipient.ByName.Owner != t.Recipient.Name.Owner) {
			return fail(ChildGranteeNotAllowed)
		}
	}
	row, _ := limitMap(t.Limits)
	child, ok := limitMap(c.Limits)
	if !ok {
		return fail(ChildBudgetOver)
	}
	for k, amount := range child {
		if row[k] == nil || amount.Cmp(row[k]) > 0 {
			return fail(ChildBudgetOver)
		}
	}
	return CheckRowRecipient(profile, p.Issuer, t, c.Recipient, o)
}
