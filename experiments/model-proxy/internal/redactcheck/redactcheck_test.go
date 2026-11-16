package redactcheck

import (
	"fmt"
	"io"
	"testing"
)

type inlineControl [32]byte

func (inlineControl) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, "[redacted]") }

// The actual battery detects inline bytes despite Format, specifically in %p,
// %w and a hidden container, while a nonmatching public control remains accepted.
func TestInlineControl(t *testing.T) {
	var value inlineControl
	copy(value[:], "0123456789abcdefFEDCBA9876543210!?")
	forbidden := SecretForms(value[:])
	want := map[string]bool{"value/fmt/%p": false, "value/fmt/%w": false, "hidden-value/fmt/%v": false}
	for _, output := range Outputs(value) {
		if _, ok := want[output.Name]; ok {
			want[output.Name] = Contains(output.Text, forbidden)
		}
	}
	for name, detected := range want {
		if !detected {
			t.Errorf("inline control undetected: %s", name)
		}
	}
	if Contains("public metadata [redacted]", forbidden) {
		t.Fatal("public control falsely flagged")
	}
}

// A scalar-pointer holder remains safe when its methods are bypassed.
func TestScalarPointerControl(t *testing.T) {
	raw := "cf3489d14ab625e98b701cda46f30972"
	Check(t, struct{ value *string }{&raw}, SecretForms([]byte(raw))...)
}
