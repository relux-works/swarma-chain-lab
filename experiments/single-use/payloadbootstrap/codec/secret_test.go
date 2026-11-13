package codec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// Both input and output slices are isolated; copying a wrapper and replacing
// that copy also cannot change the original credential.
func TestSecretCopies(t *testing.T) {
	input := bytes.Repeat([]byte("x"), 32)
	secret := NewSecret(input)
	input[0] = 'y'
	revealed := secret.Reveal()
	if !bytes.Equal(revealed, bytes.Repeat([]byte("x"), 32)) {
		t.Fatal("constructor retained mutable input")
	}
	revealed[0] = 'z'
	copy := secret
	copy = NewSecret(bytes.Repeat([]byte("y"), 32))
	if !bytes.Equal(secret.Reveal(), bytes.Repeat([]byte("x"), 32)) || !bytes.Equal(copy.Reveal(), bytes.Repeat([]byte("y"), 32)) {
		t.Fatal("credential changed through an accessor or wrapper copy")
	}
}

// JSON remains an explicit private-wire operation. Zero wrappers retain the
// old raw zero encodings, and failed unmarshalling clears previously held bytes.
func TestSecretJSON(t *testing.T) {
	channel := NewSecret([]byte("synthetic-channel"))
	bearer := NewSecret("synthetic-bearer")
	for _, value := range []any{channel, bearer} {
		raw, err := json.Marshal(value)
		if err != nil || !strings.Contains(string(raw), "synthetic") && !strings.Contains(string(raw), "c3ludGhldGljLWNoYW5uZWw=") {
			t.Fatal("private wire credential unavailable")
		}
	}
	if json.Unmarshal([]byte(`{}`), &channel) == nil || !channel.IsZero() || channel.Reveal() != nil {
		t.Fatal("failed channel decode retained credential")
	}
	if json.Unmarshal([]byte(`[]`), &bearer) == nil || !bearer.IsZero() || bearer.Reveal() != "" {
		t.Fatal("failed bearer decode retained credential")
	}
	for _, tc := range []struct {
		value any
		want  string
	}{{Secret[[]byte]{}, "null"}, {Secret[string]{}, `""`}, {NewSecret([]byte{}), "null"}, {NewSecret(""), `""`}} {
		raw, err := json.Marshal(tc.value)
		if err != nil || string(raw) != tc.want {
			t.Fatal("zero credential JSON changed")
		}
	}
}

// A wrapper itself and an embedded wrapper stay opaque for unsupported verbs;
// notably a pointer to a slice would leak through some of these diagnostics.
func TestSecretFormattingAllVerbs(t *testing.T) {
	const marker = "N1opaque0123456789syntheticX"
	for _, secret := range []any{NewSecret(marker), NewSecret([]byte(marker))} {
		for _, value := range []any{secret, &secret, struct{ Secret any }{secret}} {
			for _, format := range []string{"%p", "%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%b", "%o", "%O", "%c", "%U", "%e", "%E", "%f", "%F", "%g", "%G", "%t", "%T", "%10v", "%-8s", "%#x", "%+p", "%#p", "%020p", "%.8v", "%#20.8x", "%w"} {
				out := fmt.Sprintf(format, value)
				for i := 0; i+8 <= len(marker); i++ {
					if strings.Contains(out, marker[i:i+8]) || strings.Contains(out, "115 121 110") {
						t.Fatalf("wrapper disclosed credential with %s", format)
					}
				}
			}
		}
	}
}
