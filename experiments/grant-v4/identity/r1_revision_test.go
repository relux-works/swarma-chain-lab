package identity

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"
)

// A valid binding is the positive control for each forbidden post-object suffix (LIP-0010 section 2.1).
func TestRev375TopLevelSuffix(t *testing.T) {
	valid := []byte(`{"swarma":{"landlord":{"grant":"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"}}}`)
	for _, suffix := range []string{" ", "\n", "\t", "\r\n", " {}"} {
		t.Run(fmt.Sprintf("suffix_%x", suffix), func(t *testing.T) {
			if _, err := ReadR1Value(R1DraftLab, valid); err != nil {
				t.Fatalf("positive control: %v", err)
			}
			result, err := ReadR1Value(R1DraftLab, append(bytes.Clone(valid), suffix...))
			if err != ErrR1Value || !reflect.DeepEqual(result, R1Value{}) {
				t.Fatalf("LIP-0010 section 2.1: bytes after object must refuse; suffix=%q err=%v leaked_grant=%t", suffix, err, result.Grant != "")
			}
			r1Record(t, fmt.Sprintf("r2-value-%x", suffix), err.Error())
		})
	}
}

func rev375NameValue(t *testing.T, script, value []byte) []byte {
	t.Helper()
	parsed, ok := ParseNameScript(script)
	if !ok || parsed.Prefix != PrefixUpdate {
		t.Fatal("expected update control")
	}
	push := func(target, data []byte) []byte {
		switch {
		case len(data) <= 75:
			target = append(target, byte(len(data)))
		case len(data) <= 255:
			target = append(target, 0x4c, byte(len(data)))
		default:
			target = append(target, 0x4d, byte(len(data)), byte(len(data)>>8))
		}
		return append(target, data...)
	}
	result := push([]byte{0x53}, parsed.Name)
	result = push(result, value)
	result = append(result, 0x6d, 0x75)
	return append(result, parsed.AddressScript...)
}

// The composed child predicate must not admit a nonconforming current value in either name path.
func TestRev375ChildTopLevelSuffix(t *testing.T) {
	for _, exact := range []bool{false, true} {
		t.Run(fmt.Sprintf("certified_exact_%t", exact), func(t *testing.T) {
			for _, suffix := range []string{" ", "\t", "\n", "\r\n", " {}"} {
				t.Run(fmt.Sprintf("suffix_%x", suffix), func(t *testing.T) {
					parent, child, observation := r1FullParent(t)
					if exact {
						parent.Rows.Groups[0].Template.Recipient = RowRecipient{Name: child.Recipient.ByName}
					}
					if _, err := CheckR1Child(R1DraftLab, parent, child, observation); err != nil {
						t.Fatalf("positive control: %v", err)
					}
					parsed, ok := ParseNameScript(observation.Recipient.Script)
					if !ok {
						t.Fatal("parse control")
					}
					observation.Recipient.Script = rev375NameValue(t, observation.Recipient.Script, append(bytes.Clone(parsed.Value), suffix...))
					result, err := CheckR1Child(R1DraftLab, parent, child, observation)
					expected := error(ClassLandlord)
					if exact {
						expected = ErrChannel
					}
					if err != expected || result != (RowRecipientResult{}) {
						t.Fatalf("LIP-0010 section 2.1 through CheckR1Child: expected=%v actual=%v key_returned=%t", expected, err, result.Key != "")
					}
					r1Record(t, fmt.Sprintf("r2-child-%t-%x", exact, suffix), err.Error())
				})
			}
		})
	}
}

// LIP-0026 v0.1.49 R9.5: "`L` is live at the tip of the observation (LIP-0021 O5.1)."
// Its refusal table: "`L` has no live output at the tip; the walk ended at another registration; an output of the stretch from the checkpoint reads as another key" -> "`CLASS_LANDLORD_CHANGED`".
// "Nothing was proved at a step" -> "`CLASS_HISTORY_UNAVAILABLE`".
// The current positive passes beside proved absence, unknown and undefined states;
// all refusals return no key or policy. This checks stated facts, not node proof.
func TestRev375LandlordNoLiveOutput(t *testing.T) {
	for _, test := range []struct {
		name     string
		status   CurrentStatus
		expected error
	}{
		{"proved_absent", NoLiveOutput, ClassLandlordChanged},
		{"unavailable", CurrentUnknown, ClassHistoryUnavailable},
		{"undefined_3", 3, ClassHistoryUnavailable},
		{"undefined_99", 99, ClassHistoryUnavailable},
		{"undefined_255", 255, ClassHistoryUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			parent, child, observation := r1FullParent(t)
			if _, err := CheckR1Child(R1DraftLab, parent, child, observation); err != nil {
				t.Fatalf("positive control: %v", err)
			}
			observation.Landlords[0].Name.Current = test.status
			observation.Landlords[0].Name.Outputs = nil
			result, err := CheckR1Child(R1DraftLab, parent, child, observation)
			if err != test.expected || result != (RowRecipientResult{}) {
				t.Fatalf("R9.5 first step: status=%d expected=%v actual=%v", test.status, test.expected, err)
			}
			r1Record(t, fmt.Sprintf("r2-landlord-%d", test.status), err.Error())
		})
	}
}
