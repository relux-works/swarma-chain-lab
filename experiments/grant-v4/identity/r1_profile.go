package identity

import "errors"

// R1SpecTag and R1SpecCommit pin the explicit R1InForce051 decision profile.
const R1SpecTag = "v0.1.51"
const R1SpecCommit = "bd3bc80e5543d8a563343ec05abd1a5f3f67284c"

var (
	ErrR1DraftRule = errors.New("R1_DRAFT_RULE_UNAVAILABLE")
	ErrR1FactRange = errors.New("R1_FACT_RANGE_UNAVAILABLE")
)

// R1Rule names independently selectable predicates, not grant wire members.
// Mixed rules are split at the decision boundary documented in R1-DECISIONS-051.md.
type R1Rule string

const (
	R1Groups            R1Rule = "groups"
	R1Ranges            R1Rule = "ranges"
	R1Pools             R1Rule = "pools"
	R1DistinctCoins     R1Rule = "distinct-coins"
	R1Templates         R1Rule = "templates"
	R1Fit               R1Rule = "row-fit"
	R1Class             R1Rule = "class"
	R1Holders           R1Rule = "holders"
	R1Capacity          R1Rule = "capacity"
	R1NoCertifier       R1Rule = "no-certifier"
	R1GroupBounds       R1Rule = "group-bounds"
	R1RangeWitness      R1Rule = "range-witness"
	R1OrdinalOrder      R1Rule = "ordinal-order"
	R1ParentAtomic      R1Rule = "parent-atomic"
	R1HolderOrder       R1Rule = "holder-order"
	R1RecentCheckpoint  R1Rule = "recent-checkpoint"
	R1LandlordWriter    R1Rule = "landlord-writer"
	R1ClassCodesOrder   R1Rule = "class-codes-order"
	R1ExactShortcut     R1Rule = "exact-shortcut"
	R1IgnoreAttestation R1Rule = "ignore-attestation"
)

// RequireR1Rule reports availability only; it never claims the facts passed.
// Unknown rules and profiles fail closed. Diagnostic strings in the in-force
// predicates are local codes, not adoption of the draft's normative code/order.
func RequireR1Rule(profile R1Profile, rule R1Rule) error {
	if profile != R1DraftLab && profile != R1InForce051 {
		return ErrR1Profile
	}
	switch rule {
	case R1Groups, R1Ranges, R1Pools, R1DistinctCoins, R1Templates, R1Fit,
		R1Class, R1Holders, R1Capacity, R1NoCertifier:
		return nil
	case R1GroupBounds, R1RangeWitness, R1OrdinalOrder, R1ParentAtomic,
		R1HolderOrder, R1RecentCheckpoint, R1LandlordWriter, R1ClassCodesOrder,
		R1ExactShortcut, R1IgnoreAttestation:
		if profile == R1DraftLab {
			return nil
		}
		return ErrR1DraftRule
	default:
		return ErrR1DraftRule
	}
}

// CheckR1Fit checks J1.2/R2 on an independently established selected template.
// It does not select a row: the ordinal traversal proposal is unavailable in
// R1InForce051. The caller must establish that template-to-ordinal binding.
// No parent, coin, class, attestation or whole-child admission is established.
func CheckR1Fit(profile R1Profile, rows uint64, t RowTemplate, c R1Child) error {
	if err := RequireR1Rule(profile, R1Fit); err != nil {
		return err
	}
	if c.Ordinal < 1 || c.Ordinal > rows {
		return ChildOrdinal
	}
	if c.Executor != t.Executor {
		return ChildAgentNotAllowed
	}
	if !validRowRecipient(t.Recipient) || (c.Recipient.RequestKey == nil) == (c.Recipient.ByName == nil) {
		return ChildGranteeNotAllowed
	}
	if t.Recipient.Key != nil {
		if c.Recipient.RequestKey == nil || *c.Recipient.RequestKey != *t.Recipient.Key {
			return ChildGranteeNotAllowed
		}
	} else {
		if c.Recipient.ByName == nil || !c.Recipient.ByName.Owner.Valid() || len(c.Recipient.ByName.Name) == 0 {
			return ChildGranteeNotAllowed
		}
		if t.Recipient.Name != nil && (string(c.Recipient.ByName.Name) != string(t.Recipient.Name.Name) || c.Recipient.ByName.Owner != t.Recipient.Name.Owner) {
			return ChildGranteeNotAllowed
		}
	}
	row, ok := limitMap(t.Limits)
	if !ok {
		return ChildBudgetOver
	}
	child, ok := limitMap(c.Limits)
	if !ok {
		return ChildBudgetOver
	}
	for key, amount := range child {
		if row[key] == nil || amount.Cmp(row[key]) > 0 {
			return ChildBudgetOver
		}
	}
	return nil
}
