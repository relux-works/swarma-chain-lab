package identity

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// R8.1 executor shape is reachable without draft whole-parent composition.
// Each malformed executor refuses beside a valid template under both profiles.
// These checks establish shape only, not the executor's authority or a signature.
func TestR1ExecutorShape(t *testing.T) {
	p, _, _ := r1FullParent(t)
	valid := p.Rows.Groups[0].Template
	for _, profile := range []struct {
		name  string
		value R1Profile
	}{{"draft", R1DraftLab}, {"in-force-051", R1InForce051}} {
		t.Run(profile.name, func(t *testing.T) {
			for _, row := range []struct {
				name     string
				executor RowExecutor
				want     string
			}{
				{"valid", valid.Executor, "valid"},
				{"empty-name", RowExecutor{"", valid.Executor.Key}, "R8.1"},
				{"empty-key", RowExecutor{valid.Executor.Name, ""}, "R8.1"},
				{"short-key", RowExecutor{valid.Executor.Name, valid.Executor.Key[1:]}, "R8.1"},
				{"uppercase-key", RowExecutor{valid.Executor.Name, strings.ToUpper(valid.Executor.Key)}, "R8.1"},
				{"off-curve-key", RowExecutor{valid.Executor.Name, strings.Repeat("0", 64)}, "R8.1"},
				{"nonhex-key", RowExecutor{valid.Executor.Name, strings.Repeat("g", 64)}, "R8.1"},
			} {
				t.Run(row.name, func(t *testing.T) {
					if err := CheckRowTemplate(profile.value, p.Issuer, p.Notaries, valid); err != nil {
						t.Fatalf("executor positive: %v", err)
					}
					candidate := valid
					candidate.Executor = row.executor
					before := candidate.Executor
					got := "valid"
					if err := CheckRowTemplate(profile.value, p.Issuer, p.Notaries, candidate); err != nil {
						got = err.Error()
					}
					r1Equal(t, "a3-executor/"+profile.name+"/"+row.name, got, row.want)
					if candidate.Executor != before {
						t.Fatal("executor check changed input")
					}
				})
			}
		})
	}
}

// Rule 8's byte budget is computed by the product, including UTF-8 owner data.
// Zero holders preserves the absent member; one more must exceed 520 bytes.
// Invalid shape, an existing holders member and oversize values return no result
// and preserve the input. These six boundary rows include an exact 520-byte fit.
func TestR1HoldersCapacity(t *testing.T) {
	key := "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
	base := `{"swarma":{"landlord":{"grant":"` + key + `"}}}`
	padded := func(size int) string {
		prefix, suffix := `{"padding":"é`, `",`+base[1:]
		return prefix + strings.Repeat("x", size-len(prefix)-len(suffix)) + suffix
	}
	check := func(t *testing.T, raw string, wantMost, wantWith, wantMore int) {
		t.Helper()
		input := []byte(raw)
		before := bytes.Clone(input)
		most, with, more, err := HoldersCapacity(input)
		if err != nil || most != wantMost || with != wantWith || more != wantMore || with > 520 || more <= 520 {
			t.Fatalf("capacity got %d/%d/%d %v, want %d/%d/%d", most, with, more, err, wantMost, wantWith, wantMore)
		}
		if !bytes.Equal(input, before) {
			t.Fatal("capacity changed input")
		}
	}
	for _, row := range []struct{ size, most, with, more int }{
		{438, 1, 519, 588}, {439, 1, 520, 589}, {440, 0, 440, 521},
		{507, 0, 507, 588}, {508, 0, 508, 589}, {520, 0, 520, 601},
	} {
		t.Run(fmt.Sprint(row.size), func(t *testing.T) {
			// Include a multibyte character; counts must be octets, not runes.
			raw := padded(row.size)
			if len(raw) != row.size {
				t.Fatal("capacity fixture size")
			}
			check(t, raw, row.most, row.with, row.more)
		})
	}
	for name, raw := range map[string]string{
		"empty": "", "malformed": "{", "agent": `{"swarma":{"agent":{"landlord":"id/example"}}}`,
		"empty-holders":   strings.Replace(base, `"}}}`, `","holders":[]}}}`, 1),
		"present-holders": strings.Replace(base, `"}}}`, `","holders":["02`+key+`"]}}}`, 1),
		"oversize":        padded(521),
	} {
		t.Run(name, func(t *testing.T) {
			check(t, base, 5, 457, 526)
			input := []byte(raw)
			before := bytes.Clone(input)
			most, with, more, err := HoldersCapacity(input)
			if err != ErrR1Value || most != 0 || with != 0 || more != 0 {
				t.Fatalf("invalid capacity leaked result: %d/%d/%d %v", most, with, more, err)
			}
			if !bytes.Equal(input, before) {
				t.Fatal("capacity refusal changed input")
			}
		})
	}
}
