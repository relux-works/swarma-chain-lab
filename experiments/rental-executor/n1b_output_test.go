package executor

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"reflect"
	"strings"
	"testing"
)

type n1bError struct{ Value any }

func (v n1bError) Error() string { return fmt.Sprintf("credential context: %v", v.Value) }
func n1bLeaks(text, secret string) bool {
	// Eight original bytes remain the bound after encoding: sixteen hex digits
	// or twelve base64 characters (nine original bytes), not eight hex digits.
	for start := 0; start+8 <= len(secret); start++ {
		if strings.Contains(text, secret[start:start+8]) {
			return true
		}
	}
	for _, encoded := range []string{hex.EncodeToString([]byte(secret)), strings.ToUpper(hex.EncodeToString([]byte(secret)))} {
		for start := 0; start+16 <= len(encoded); start += 2 {
			if strings.Contains(text, encoded[start:start+16]) {
				return true
			}
		}
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(secret))
	for start := 0; start+12 <= len(encoded); start += 4 {
		if strings.Contains(text, encoded[start:start+12]) {
			return true
		}
	}
	return false
}

// Adapted from rev232/rev234: these synthetic roots exercise every fmt verb,
// bad verbs, flags/widths, formatted and unformatted sinks, generic JSON and
// nested JSON/text slog. Explicit authentication/private wire is checked separately.
func n1bOutputMatrix(t *testing.T, roots []any, secret string) {
	t.Helper()
	if !n1bLeaks(secret, secret) || n1bLeaks("public redacted metadata", secret) {
		t.Fatal("leak detector calibration failed")
	}
	formats := []string{}
	for _, verb := range "vTtbcdoOxXUeEfFgGspqwz!?" {
		for _, flags := range []string{"", "+", "#", "-", " ", "0", "+#", "-#", "+ #0"} {
			for _, width := range []string{"", "1", "8", "65", ".0", ".7", ".16", "32.8"} {
				formats = append(formats, "%"+flags+width+string(verb))
			}
		}
	}
	formats = append(formats, "%", "%[2]v", "%[0]v", "%*v", "%.*v", "%[1]*.[1]*[1]v", "%[2]*[1]v", "public-only", "%10v", "%-8s", "%#x", "%w")
	formatted, structured, generic, refused := 0, 0, 0, 0
	for rootIndex, root := range roots {
		pointer := &root
		shapes := []any{root, pointer, &pointer, struct{ Value any }{root}, struct{ hidden any }{root}, []any{root}, [1]any{root}, map[string]any{"value": root}, reflect.ValueOf(root), n1bError{root}, errors.Join(n1bError{root}, errors.New("public"))}
		for shapeIndex, shape := range shapes {
			name := fmt.Sprintf("root-%d/shape-%d", rootIndex, shapeIndex)
			t.Run(name+"/fmt", func(t *testing.T) {
				for formatIndex, format := range formats {
					outputs := []string{fmt.Sprintf(format, shape), fmt.Errorf(format, shape).Error(), string(fmt.Appendf(nil, format, shape))}
					var out bytes.Buffer
					fmt.Fprintf(&out, format, shape)
					outputs = append(outputs, out.String())
					out.Reset()
					log.New(&out, "", 0).Printf(format, shape)
					outputs = append(outputs, out.String())
					for sink, text := range outputs {
						formatted++
						if n1bLeaks(text, secret) {
							t.Fatalf("credential disclosed: format-index=%d sink=%d", formatIndex, sink)
						}
					}
				}
				for _, text := range []string{fmt.Sprint(shape), fmt.Sprintln(shape), string(fmt.Append(nil, shape)), string(fmt.Appendln(nil, shape))} {
					formatted++
					if n1bLeaks(text, secret) {
						t.Fatal("credential disclosed by unformatted sink")
					}
				}
			})
			t.Run(name+"/json", func(t *testing.T) {
				encoded, err := json.Marshal(shape)
				generic++
				if err != nil {
					refused++
				}
				if err != nil && !strings.Contains(err.Error(), "unsupported type: func(") {
					t.Fatal("public JSON carrier encoding failed")
				}
				if n1bLeaks(string(encoded), secret) {
					t.Error("credential disclosed by generic JSON encoding")
				}
			})
			t.Run(name+"/slog", func(t *testing.T) {
				for _, jsonHandler := range []bool{false, true} {
					for _, group := range []bool{false, true} {
						var out bytes.Buffer
						var handler slog.Handler = slog.NewTextHandler(&out, nil)
						if jsonHandler {
							handler = slog.NewJSONHandler(&out, nil)
						}
						attr := slog.Any("value", shape)
						if group {
							attr = slog.Group("context", attr)
						}
						slog.New(handler).LogAttrs(context.Background(), slog.LevelInfo, "credential audit", attr)
						structured++
						if n1bLeaks(out.String(), secret) {
							t.Errorf("credential disclosed: slog handler-json=%t group=%t", jsonHandler, group)
						}
					}
				}
			})
		}
	}
	t.Logf("roots=%d shapes-per-root=11 formats=%d fmt-checks=%d slog-checks=%d generic-json-checks=%d safe-json-refusals=%d detector-controls=2", len(roots), len(formats), formatted, structured, generic, refused)
}

func TestN1bMintedTokenOutput(t *testing.T) {
	b, e := OpenTrackB(rootDir(t), "regtest", prizes())
	if e != nil {
		t.Fatal("token fixture refused")
	}
	defer b.Close()
	token, e := b.Mint(strings.Repeat("1", 64))
	if e != nil {
		t.Fatal("mint control refused")
	}
	n1bOutputMatrix(t, []any{token, b.state, b, trackBClaimRequest{Slot: strings.Repeat("1", 64), Token: token}}, token.Reveal())
}
