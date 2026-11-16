package identity

import (
	"bytes"
	"encoding/json"
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

// Unsupported enum values must not establish the recipient current-output fact; each has a live positive control.
func TestRev375RecipientStatus(t *testing.T) {
	for number := 0; number < 256; number++ {
		status := CurrentStatus(number)
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			parent, child, observation := r1FullParent(t)
			if _, err := CheckR1Child(R1DraftLab, parent, child, observation); err != nil {
				t.Fatalf("positive control: %v", err)
			}
			observation.Recipient.Current = status
			expected := error(RecipientNameUnavailable)
			if status == CurrentOutput {
				expected = nil
			} else if status == NoLiveOutput {
				expected = RecipientNameNotHeld
			}
			result, err := CheckR1Child(R1DraftLab, parent, child, observation)
			if err != expected || (err != nil && result != (RowRecipientResult{})) || (err == nil && result.Key == "") {
				t.Fatalf("recipient current-output fact: status=%d expected=%v actual=%v key_returned=%t", status, expected, err, result.Key != "")
			}
			outcome := "pass"
			if err != nil {
				outcome = err.Error()
			}
			r1Record(t, fmt.Sprintf("r2-recipient-%d", status), outcome)
		})
	}
}

// All byte-sized caller status values are checked beside the same live control.
// Only the defined affirmative states pass. These are stated facts, not chain
// authenticity; int-backed Reading/Writer also test negative/out-of-byte values.
func TestR1LandlordStatusEnums(t *testing.T) {
	for _, kind := range []string{"current", "reading", "writer"} {
		for number := -1; number <= 256; number++ {
			if kind == "current" && (number < 0 || number > 255) {
				continue
			}
			t.Run(fmt.Sprintf("%s/%d", kind, number), func(t *testing.T) {
				parent, child, o := r1FullParent(t)
				if result, err := CheckR1Child(R1DraftLab, parent, child, o); err != nil || result.Key == "" {
					t.Fatalf("positive control: %v", err)
				}
				expected := error(ClassHistoryUnavailable)
				state := &o.Landlords[0].Name
				switch kind {
				case "current":
					state.Current = CurrentStatus(number)
					if number == int(CurrentOutput) {
						expected = nil
					}
					if number == int(NoLiveOutput) {
						expected = ClassLandlordChanged
					}
				case "reading":
					state.Outputs[0].Reading = Reading(number)
					if number == int(Controlled) {
						expected = nil
					}
					if number == int(AnotherKey) {
						expected = ClassLandlordChanged
					}
				case "writer":
					state.Outputs[0].Writer = Writer(number)
					if number == int(WrittenByOwner) {
						expected = nil
					}
					if number == int(WrittenByAnother) {
						expected = ClassValueUnauthorized
					}
				}
				result, err := CheckR1Child(R1DraftLab, parent, child, o)
				if err != expected || (err != nil && result != (RowRecipientResult{})) || (err == nil && result.Key == "") {
					t.Fatalf("closed %s status %d: expected=%v actual=%v key_returned=%t", kind, number, expected, err, result.Key != "")
				}
			})
		}
	}
}

// All exported R1 entry points require precisely the draft enum, including omitted/null/zero JSON configuration.
func TestRev375EveryProfile(t *testing.T) {
	parent, child, observation := r1FullParent(t)
	template := parent.Rows.Groups[0].Template
	parsed, ok := ParseNameScript(observation.Recipient.Script)
	if !ok {
		t.Fatal("parse positive")
	}
	check := func(t *testing.T, profile R1Profile) {
		expected := error(ErrR1Profile)
		if profile == R1DraftLab {
			expected = nil
		}
		if _, err := ReadR1Value(profile, parsed.Value); err != expected {
			t.Fatalf("value profile=%d: %v", profile, err)
		}
		if _, err := CheckRowGroups(profile, parent.Rows); err != expected {
			t.Fatalf("groups profile=%d: %v", profile, err)
		}
		if _, err := SelectRow(profile, parent.Rows, child.Ordinal); err != expected {
			t.Fatalf("select profile=%d: %v", profile, err)
		}
		if err := CheckRowTemplate(profile, parent.Issuer, parent.Notaries, template); err != expected {
			t.Fatalf("template profile=%d: %v", profile, err)
		}
		if err := CheckR1Parent(profile, parent); err != expected {
			t.Fatalf("parent profile=%d: %v", profile, err)
		}
		if _, err := CheckRowRecipient(profile, parent.Issuer, template, child.Recipient, observation); err != expected {
			t.Fatalf("recipient profile=%d: %v", profile, err)
		}
		if _, err := CheckR1Child(profile, parent, child, observation); err != expected {
			t.Fatalf("child profile=%d: %v", profile, err)
		}
	}
	for number := 0; number <= 255; number++ {
		t.Run(fmt.Sprintf("enum_%d", number), func(t *testing.T) { check(t, R1DraftLab); check(t, R1Profile(number)) })
	}
	for _, raw := range []string{`{}`, `{"profile":null}`, `{"profile":0}`, `{"profile":1}`, `{"profile":255}`} {
		t.Run("config_"+raw, func(t *testing.T) {
			var config struct {
				Profile R1Profile `json:"profile"`
			}
			if err := json.Unmarshal([]byte(raw), &config); err != nil {
				t.Fatal(err)
			}
			check(t, R1DraftLab)
			check(t, config.Profile)
		})
	}
}

// The maximum stated group/range/coin counts fit exactly; the next ordinal and one-unit pool shortage refuse beside that positive.
func TestRev375MaximumGroups(t *testing.T) {
	parent, _, _ := r1FullParent(t)
	rows := parent.Rows
	template := rows.Groups[0].Template
	template.Limits[0].Amount = "1"
	rows.Groups = nil
	for groupNumber := 0; groupNumber < 16; groupNumber++ {
		group := RowGroup{Template: template}
		for rangeNumber := 0; rangeNumber < 16; rangeNumber++ {
			group.Ranges = append(group.Ranges, RowRange{
				TxID: fmt.Sprintf("%064x", groupNumber*16+rangeNumber+1), First: 4294963200, Count: 4096,
				Script: append([]byte{0, 20}, make([]byte, 20)...),
			})
		}
		rows.Groups = append(rows.Groups, group)
	}
	rows.Pools = []RowLimit{{Key: template.Limits[0].Key, Amount: "1048576"}}
	total, err := CheckRowGroups(R1DraftLab, rows)
	if err != nil || total != 1048576 {
		t.Fatalf("maximum positive: rows=%d err=%v", total, err)
	}
	last, err := SelectRow(R1DraftLab, rows, total)
	if err != nil || last.Group != 16 || last.Range != 16 || last.Coin.Vout != 4294967295 {
		t.Fatalf("maximum selector: %+v %v", last, err)
	}
	if result, err := SelectRow(R1DraftLab, rows, total+1); err != ChildOrdinal || !reflect.DeepEqual(result, SelectedRow{}) {
		t.Fatalf("overflow ordinal: %+v %v", result, err)
	}
	rows.Pools[0].Amount = "1048575"
	if total, err := CheckRowGroups(R1DraftLab, rows); err != R1RuleError("R8.5") || total != 0 {
		t.Fatalf("pool shortage: %d %v", total, err)
	}
}

// Every named positive neighbour is executed directly before its pinned negative; fixture files remain unchanged.
func TestRev375NamedPositiveNeighbours(t *testing.T) {
	var groups struct {
		Parents []struct {
			ID        string
			Parent    r1FixtureParent
			Neighbour string `json:"valid_neighbour"`
			Expect    map[string]any
		}
	}
	r1Fixture(t, "groups-vectors.json", &groups)
	for _, negative := range groups.Parents {
		if negative.Neighbour == "" {
			continue
		}
		t.Run(negative.ID, func(t *testing.T) {
			found := false
			for _, positive := range groups.Parents {
				if positive.ID == negative.Neighbour {
					found = true
					if _, err := CheckRowGroups(R1DraftLab, r1Parent(positive.Parent)); err != nil {
						t.Fatalf("named positive %s: %v", positive.ID, err)
					}
				}
			}
			if !found {
				t.Fatal("missing named positive")
			}
			if _, err := CheckRowGroups(R1DraftLab, r1Parent(negative.Parent)); err == nil || err.Error() != negative.Expect["rule"] {
				t.Fatalf("negative: %v", err)
			}
		})
	}
	var classes struct {
		Templates []struct {
			ID        string
			Template  r1FixtureTemplate
			Neighbour string `json:"valid_neighbour"`
			Expect    map[string]any
		}
	}
	r1Fixture(t, "class-vectors.json", &classes)
	for _, negative := range classes.Templates {
		if negative.Neighbour == "" {
			continue
		}
		t.Run(negative.ID, func(t *testing.T) {
			found := false
			for _, positive := range classes.Templates {
				if positive.ID == negative.Neighbour {
					found = true
					fixture := positive.Template
					if err := CheckRowTemplate(R1DraftLab, r1Landlord(t, fixture.Issuer), fixture.Notaries, r1Template(t, fixture)); err != nil {
						t.Fatalf("named positive %s: %v", positive.ID, err)
					}
				}
			}
			if !found {
				t.Fatal("missing named positive")
			}
			fixture := negative.Template
			if err := CheckRowTemplate(R1DraftLab, r1Landlord(t, fixture.Issuer), fixture.Notaries, r1Template(t, fixture)); err == nil || err.Error() != negative.Expect["rule"] {
				t.Fatalf("negative: %v", err)
			}
		})
	}
	var holders struct {
		Values []struct {
			ID, Value string
			Neighbour string `json:"valid_neighbour"`
		}
	}
	r1Fixture(t, "holders-vectors.json", &holders)
	for _, negative := range holders.Values {
		if negative.Neighbour == "" {
			continue
		}
		t.Run(negative.ID, func(t *testing.T) {
			found := false
			for _, positive := range holders.Values {
				if positive.ID == negative.Neighbour {
					found = true
					if _, err := ReadR1Value(R1DraftLab, []byte(positive.Value)); err != nil {
						t.Fatalf("named positive %s: %v", positive.ID, err)
					}
				}
			}
			if !found {
				t.Fatal("missing named positive")
			}
			if result, err := ReadR1Value(R1DraftLab, []byte(negative.Value)); err != ErrR1Value || !reflect.DeepEqual(result, R1Value{}) {
				t.Fatalf("negative: %v", err)
			}
		})
	}
}
