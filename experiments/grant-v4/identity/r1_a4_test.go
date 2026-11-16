package identity

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// Every octet length 0..520 is exercised: below the 100-byte canonical minimum
// these inputs refuse; every remaining length has a valid landlord control.
// Independent enumeration bounds the maximum; Python compares every verdict,
// including zero results on invalid shapes and a multibyte owner-data control.
func TestR1HoldersCapacityRange(t *testing.T) {
	key := "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
	base := `{"swarma":{"landlord":{"grant":"` + key + `"}}}`
	type capacityCase struct {
		name, raw string
		valid     bool
	}
	var cases []capacityCase
	for size := 0; size <= 520; size++ {
		raw := strings.Repeat("x", size)
		if size >= len(base) {
			raw = base[:len(base)-1] + strings.Repeat(" ", size-len(base)) + "}"
		}
		cases = append(cases, capacityCase{fmt.Sprintf("size/%d", size), raw, size >= len(base)})
	}
	for name, raw := range map[string]string{
		"malformed": "{", "agent": `{"swarma":{"agent":{"landlord":"id/example"}}}`,
		"empty-holders":   strings.Replace(base, `"}}}`, `","holders":[]}}}`, 1),
		"present-holders": strings.Replace(base, `"}}}`, `","holders":["02`+key+`"]}}}`, 1),
		"oversize":        base[:len(base)-1] + strings.Repeat(" ", 521-len(base)) + "}",
		"leading":         " " + base, "trailing": base + " ",
		"alias":           strings.Replace(base, "swarma", "Swarma", 1),
		"duplicate":       `{"swarma":{},` + base[1:],
		"noncompact":      strings.Replace(base, `"grant":`, `"grant": `, 1),
		"bad-key":         strings.Replace(base, key, strings.Repeat("0", 64), 1),
		"missing-binding": "{}", "not-object": "[]",
		"extra-binding": strings.Replace(base, `"}}}`, `","other":0}}}`, 1),
		"invalid-utf8":  "{\"unused\":\"\xff\"," + base[1:],
	} {
		cases = append(cases, capacityCase{"invalid/" + name, raw, false})
	}
	cases = append(cases, capacityCase{"utf8", `{"padding":"é",` + base[1:], true})
	for _, row := range cases {
		t.Run(row.name, func(t *testing.T) {
			input := []byte(row.raw)
			before := bytes.Clone(input)
			most, with, more, err := HoldersCapacity(input)
			if !bytes.Equal(input, before) {
				t.Fatal("capacity changed input")
			}
			if !row.valid {
				if err != ErrR1Value || most != 0 || with != 0 || more != 0 {
					t.Fatalf("capacity refusal leaked result: %d/%d/%d %v", most, with, more, err)
				}
				r1Record(t, "a4-capacity/"+row.name, map[string]any{"outcome": "refused", "most": most, "with": with, "more": more})
				return
			}
			size, wantMost, wantWith := len(input), 0, len(input)
			for count := 1; size+12+69*count <= 520; count++ {
				wantMost, wantWith = count, size+12+69*count
			}
			wantMore := size + 12 + 69*(wantMost+1)
			if err != nil || most != wantMost || with != wantWith || more != wantMore || with > 520 || more <= 520 {
				t.Fatalf("capacity range: %d/%d/%d %v, want %d/%d/%d", most, with, more, err, wantMost, wantWith, wantMore)
			}
			r1Record(t, "a4-capacity/"+row.name, map[string]int{"without": size, "most": most, "with": with, "more": more})
		})
	}
}

// R8.1 precedes R9.1 on standalone templates in both profiles and draft parent
// and child composition. In-force composition remains unavailable by contract;
// its gate is checked explicitly rather than claiming template evaluation.
func TestR1ExecutorRecipientOrder(t *testing.T) {
	for _, profile := range []struct {
		name  string
		value R1Profile
	}{{"draft", R1DraftLab}, {"in-force-051", R1InForce051}} {
		for _, path := range []string{"template", "parent", "child"} {
			for _, defect := range []string{"valid", "executor", "recipient", "both"} {
				t.Run(profile.name+"/"+path+"/"+defect, func(t *testing.T) {
					p, c, o := r1FullParent(t)
					template := &p.Rows.Groups[0].Template
					if defect == "executor" || defect == "both" {
						template.Executor.Name = ""
					}
					if defect == "recipient" || defect == "both" {
						key := "request-key"
						template.Recipient.Key = &key // Compound with the existing class mode.
					}
					var err error
					switch path {
					case "template":
						err = CheckRowTemplate(profile.value, p.Issuer, p.Notaries, *template)
					case "parent":
						err = CheckR1Parent(profile.value, p)
					case "child":
						var result RowRecipientResult
						result, err = CheckR1Child(profile.value, p, c, o)
						if err != nil && result != (RowRecipientResult{}) {
							t.Fatal("composed refusal leaked result")
						}
					}
					want := "valid"
					if profile.value == R1InForce051 && path != "template" {
						want = ErrR1DraftRule.Error()
					} else if defect == "executor" || defect == "both" {
						want = "R8.1"
					} else if defect == "recipient" {
						want = "R9.1"
					}
					got := "valid"
					if err != nil {
						got = err.Error()
					}
					r1Equal(t, "a4-order/"+profile.name+"/"+path+"/"+defect, got, want)
				})
			}
		}
	}
}

// Standalone no-certifier admission rechecks the template (including R8.1)
// before node facts; the valid neighbouring template still admits its recipient.
func TestR1NoCertifierExecutorRecheck(t *testing.T) {
	for _, profile := range []R1Profile{R1DraftLab, R1InForce051} {
		p, c, o := r1FullParent(t)
		template := p.Rows.Groups[0].Template
		template.Certifier = ""
		for i := range o.Landlords {
			o.Landlords[i].Checkpoint = At(500) // Same explicit checkpoint as the profile fixture.
		}
		if result, err := CheckRowRecipient(profile, p.Issuer, template, c.Recipient, o); err != nil || result.Key == "" || result.AttestationRequired {
			t.Fatalf("no-certifier positive: %+v %v", result, err)
		}
		template.Executor.Name = ""
		if result, err := CheckRowRecipient(profile, p.Issuer, template, c.Recipient, ClassObservation{}); err != R1RuleError("R8.1") || result != (RowRecipientResult{}) {
			t.Fatalf("no-certifier executor recheck: %+v %v", result, err)
		}
	}
}
