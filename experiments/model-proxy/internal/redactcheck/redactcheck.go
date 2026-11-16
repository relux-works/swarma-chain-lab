// Package redactcheck exercises generic output sinks with synthetic secrets.
// It is a test helper, not a runtime secret scanner or a wire encoder.
package redactcheck

import (
	"bytes"
	"context"
	"encoding"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// Output identifies a shape and sink without putting the secret in test names.
type Output struct {
	Name, Text string
	Err        error
}

// SecretForms detects eight-byte fragments in raw, hex, base64 and reflected
// decimal/Go-hex element lists. Callers may instead pass exact forbidden strings.
// This bounded detector does not claim arbitrary encoding or partial-byte coverage.
func SecretForms(raw []byte) []string {
	if len(raw) < 8 {
		panic("redactcheck: synthetic secret must have at least eight bytes")
	}
	var forms []string
	for i := 0; i+8 <= len(raw); i++ {
		part := raw[i : i+8]
		forms = append(forms, string(part), hex.EncodeToString(part), strings.ToUpper(hex.EncodeToString(part)),
			strings.Trim(fmt.Sprint(part), "[]"))
		goHex := fmt.Sprintf("%#v", part)
		forms = append(forms, goHex[strings.IndexByte(goHex, '{')+1:len(goHex)-1])
	}
	// Encoding alignment differs for fragments, so scan the complete encodings too.
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		encoded := enc.EncodeToString(raw)
		for i := 0; i+12 <= len(encoded); i += 4 {
			forms = append(forms, encoded[i:i+12])
		}
	}
	return forms
}

// Contains reports the presence of one of the caller's forbidden substrings.
func Contains(output string, forbidden []string) bool {
	for _, secret := range forbidden {
		if secret != "" && strings.Contains(output, secret) {
			return true
		}
	}
	return false
}

// Outputs uses concrete generic types in hidden fields: an interface-only
// wrapper would miss some reflection paths. Both holders and containers are
// exercised by value and pointer, including fmtPointer restarts on bad verbs.
func Outputs[T any](value T) []Output {
	hiddenValue := struct{ t T }{value}
	hiddenPointer := struct{ t *T }{&value}
	exported := struct{ Value T }{value}
	shapes := []struct {
		name  string
		value any
	}{
		{"value", value}, {"pointer", &value},
		{"hidden-value", hiddenValue}, {"hidden-value-pointer", &hiddenValue},
		{"hidden-pointer", hiddenPointer}, {"hidden-pointer-pointer", &hiddenPointer},
		{"exported", exported}, {"exported-pointer", &exported},
		{"array", [1]T{value}}, {"slice", []T{value}}, {"map", map[string]T{"value": value}},
	}
	var outputs []Output
	for _, shape := range shapes {
		for _, format := range []string{"%p", "%+p", "%#p", "%020p", "%w", "%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%t", "%b", "%c", "%o", "%U", "%f", "%.8s", "%032x"} {
			outputs = append(outputs, Output{Name: shape.name + "/fmt/" + format, Text: fmt.Sprintf(format, shape.value)})
		}
		format := "%w" // Dynamic format intentionally exercises bad-verb handling.
		outputs = append(outputs, Output{Name: shape.name + "/Errorf/%w", Text: fmt.Errorf(format, shape.value).Error()},
			Output{Name: shape.name + "/Sprint", Text: fmt.Sprint(shape.value)})
		encoded, err := json.Marshal(shape.value)
		outputs = append(outputs, Output{Name: shape.name + "/json", Text: string(encoded), Err: err})
		if marshaler, ok := shape.value.(encoding.TextMarshaler); ok {
			encoded, err := marshaler.MarshalText()
			outputs = append(outputs, Output{Name: shape.name + "/text", Text: string(encoded), Err: err})
		}
		for _, jsonHandler := range []bool{false, true} {
			var buf bytes.Buffer
			var handler slog.Handler = slog.NewTextHandler(&buf, nil)
			name := "slog-text"
			if jsonHandler {
				handler = slog.NewJSONHandler(&buf, nil)
				name = "slog-json"
			}
			slog.New(handler).LogAttrs(context.Background(), slog.LevelInfo, "redaction check", slog.Any("value", shape.value))
			outputs = append(outputs, Output{Name: shape.name + "/" + name, Text: buf.String()})
		}
	}
	return outputs
}

// Check fails a named subtest for every output containing a forbidden substring.
// Errors are failures too, so an encoder that rejects everything cannot pass.
func Check[T any](t *testing.T, value T, forbidden ...string) {
	t.Helper()
	if len(forbidden) == 0 {
		t.Fatal("redactcheck: missing forbidden substrings")
	}
	for _, output := range Outputs(value) {
		t.Run(output.Name, func(t *testing.T) {
			if output.Err != nil {
				t.Fatal("redaction sink failed")
			}
			if Contains(output.Text, forbidden) {
				t.Fatal("secret disclosed by output sink")
			}
		})
	}
}

// CheckPointer includes the concrete value form of a quiescent holder without
// requiring a caller to copy a mutex. Never use it on a concurrently used value.
func CheckPointer[T any](t *testing.T, value *T, forbidden ...string) {
	t.Helper()
	Check(t, *value, forbidden...)
}
