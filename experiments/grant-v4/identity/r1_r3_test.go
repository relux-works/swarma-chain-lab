package identity

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"
)

// The strict LIP-0010 section 2.1 reading requires byte zero to be '{'; each
// whitespace refusal has a canonical positive and returns no parsed binding.
func TestR1TopLevelPrefix(t *testing.T) {
	valid := []byte(`{"swarma":{"landlord":{"grant":"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"}}}`)
	for _, prefix := range []string{" ", "\t", "\n", "\r\n"} {
		t.Run(fmt.Sprintf("prefix_%x", prefix), func(t *testing.T) {
			if result, err := ReadR1Value(R1DraftLab, valid); err != nil || result.Grant == "" {
				t.Fatalf("positive control: %v", err)
			}
			result, err := ReadR1Value(R1DraftLab, append([]byte(prefix), valid...))
			if err != ErrR1Value || !reflect.DeepEqual(result, R1Value{}) {
				t.Fatalf("bytes before object must refuse: prefix=%q result=%+v err=%v", prefix, result, err)
			}
			r1Record(t, fmt.Sprintf("r3-value-prefix-%x", prefix), err.Error())
		})
	}
}

// Both class and certified exact-name child paths refuse leading whitespace
// beside their unchanged valid controls, without returning a key or policy.
func TestR1ChildTopLevelPrefix(t *testing.T) {
	for _, exact := range []bool{false, true} {
		t.Run(fmt.Sprintf("certified_exact_%t", exact), func(t *testing.T) {
			for _, prefix := range []string{" ", "\t", "\n", "\r\n"} {
				t.Run(fmt.Sprintf("prefix_%x", prefix), func(t *testing.T) {
					parent, child, observation := r1FullParent(t)
					if exact {
						parent.Rows.Groups[0].Template.Recipient = RowRecipient{Name: child.Recipient.ByName}
					}
					if result, err := CheckR1Child(R1DraftLab, parent, child, observation); err != nil || result.Key == "" {
						t.Fatalf("positive control: %v", err)
					}
					parsed, ok := ParseNameScript(observation.Recipient.Script)
					if !ok {
						t.Fatal("parse control")
					}
					observation.Recipient.Script = rev375NameValue(t, observation.Recipient.Script, append([]byte(prefix), parsed.Value...))
					result, err := CheckR1Child(R1DraftLab, parent, child, observation)
					expected := error(ClassLandlord)
					if exact {
						expected = ErrChannel
					}
					if err != expected || result != (RowRecipientResult{}) {
						t.Fatalf("child leading bytes: expected=%v actual=%v result=%+v", expected, err, result)
					}
					r1Record(t, fmt.Sprintf("r3-child-prefix-%t-%x", exact, prefix), err.Error())
				})
			}
		})
	}
}

// O7.2 row 1 and R9.9 require the same NOT_HELD code for the same proved
// absence, with current-owner positives in both APIs. These are stated facts.
func TestR1RecipientAbsenceAgreesWithOwner(t *testing.T) {
	parent, child, observation := r1FullParent(t)
	e := observation.Recipient
	name := child.Recipient.ByName
	state := StatedName{
		Name: bytes.Clone(name.Name), Owner: name.Owner, Tip: observation.Tip,
		Depth: observation.Depth, Current: e.Current, Transactions: e.Transactions,
		Outputs: []StatedOutput{ReadStatedOutput("current", e.Script, e.ConfirmedAt, e.Inputs, name.Owner, observation.Chain)},
	}
	if result, err := CheckR1Child(R1DraftLab, parent, child, observation); err != nil || result.Key == "" {
		t.Fatalf("child positive control: %v", err)
	}
	if d := CheckRecipientOwner(state); !d.Passes() {
		t.Fatalf("owner positive control: %v", d.Refusals())
	}
	observation.Recipient = ClassNameEvidence{Current: NoLiveOutput}
	state.Current, state.Outputs, state.Transactions = NoLiveOutput, nil, false
	result, err := CheckR1Child(R1DraftLab, parent, child, observation)
	refusals := CheckRecipientOwner(state).Refusals()
	if err != RecipientNameNotHeld || result != (RowRecipientResult{}) || len(refusals) != 1 || refusals[0] != RecipientNameNotHeld || err != refusals[0] {
		t.Fatalf("same proved absence must be NOT_HELD: child=%v owner=%v result=%+v", err, refusals, result)
	}
	r1Record(t, "r3-recipient-absence-cross-path", err.Error())
}
