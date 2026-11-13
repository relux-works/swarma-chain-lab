// Regression probes adopted from rev232; explicit private JSON is the positive control.
package codec_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/relux-works/swarma-chain-lab/experiments/single-use/payloadbootstrap/codec"
)

type reviewBootstrap = codec.Bootstrap[[]byte, string]
type reviewRawBootstrap reviewBootstrap
type reviewError struct{ Document reviewBootstrap }

func (value reviewError) Error() string { return fmt.Sprintf("review: %v", value.Document) }

func reviewFixture(t *testing.T) (reviewBootstrap, []string) {
	t.Helper()
	channel := make([]byte, 32)
	bearerBytes := make([]byte, 32)
	if _, err := rand.Read(channel); err != nil {
		t.Fatal("random fixture unavailable")
	}
	if _, err := rand.Read(bearerBytes); err != nil {
		t.Fatal("random fixture unavailable")
	}
	bearer := base64.RawURLEncoding.EncodeToString(bearerBytes)
	document := reviewBootstrap{V: 2, BookingID: strings.Repeat("a", 64), StationName: "id/review", ChannelSecret: codec.NewSecret(channel), ModelBearer: codec.NewSecret(bearer), ModelEndpoint: "https://review.example", ModelCertSHA256: strings.Repeat("b", 64)}
	needles := []string{string(channel), bearer, base64.StdEncoding.EncodeToString(channel), hex.EncodeToString(channel)}
	for _, format := range []string{"%v", "%#v", "%x", "%X", "%q", "%d", "%b", "%o", "%O", "%c", "%U"} {
		needles = append(needles, fmt.Sprintf(format, channel))
	}
	return document, needles
}
func reviewLeaks(output string, needles []string) bool {
	for needleIndex, needle := range needles {
		if strings.Contains(output, needle) {
			return true
		}
		for start := 0; needleIndex < 4 && start+8 <= len(needle); start++ {
			if strings.Contains(output, needle[start:start+8]) {
				return true
			}
		}
	}
	return false
}
func reviewShapes(document reviewBootstrap) []struct {
	Name  string
	Value any
} {
	pointer := &document
	double := &pointer
	copied := document
	secret := document.ModelBearer
	channel := document.ChannelSecret
	secretPointer := &secret
	secretDouble := &secretPointer
	interfaceValue := any(document)
	type hidden struct {
		document   reviewBootstrap
		credential codec.Secret[string]
	}
	type embedded struct{ reviewBootstrap }
	shapes := []struct {
		Name  string
		Value any
	}{
		{"document", document}, {"pointer", pointer}, {"double-pointer", double}, {"triple-pointer", &double}, {"copy", copied},
		{"interface-pointer", &interfaceValue}, {"secret", secret}, {"secret-pointer", secretPointer}, {"secret-double", secretDouble}, {"secret-triple", &secretDouble},
		{"channel", channel}, {"channel-pointer", &channel}, {"raw-bootstrap", reviewRawBootstrap(document)}, {"hidden-fields", hidden{document, secret}}, {"promoted-method", embedded{document}},
		{"array", [2]reviewBootstrap{document, document}}, {"array-of-interface", [2]any{document, secret}}, {"slice", []reviewBootstrap{document}},
		{"map-values", map[string]reviewBootstrap{"document": document}}, {"map-secret-keys", map[codec.Secret[string]]reviewBootstrap{secret: document}},
		{"map-bootstrap-keys", map[reviewBootstrap]codec.Secret[[]byte]{document: channel}}, {"map-interface-both", map[any]any{document: secret}},
		{"nested-map-array", map[string][2]any{"nested": {[]any{document}, map[any]any{secret: document}}}},
		{"reflection", reflect.ValueOf(document)}, {"reflection-pointer", reflect.ValueOf(pointer)}, {"reflection-secret", reflect.ValueOf(secret)},
		{"reflection-unexported-pointer", reflect.ValueOf(secret).Field(0)}, {"reflection-interface", reflect.ValueOf(&interfaceValue).Elem()},
		{"error", reviewError{document}}, {"error-pointer", &reviewError{document}}, {"join", errors.Join(reviewError{document}, errors.New("public failure"))},
		{"errorf-wrap", fmt.Errorf("context: %w", reviewError{document})}, {"errorf-multiple", fmt.Errorf("first %w second %w", reviewError{document}, errors.New("public failure"))},
	}
	var nested any = document
	for depth := 1; depth <= 6; depth++ {
		nested = struct {
			Public any
			hidden any
		}{nested, nested}
		shapes = append(shapes, struct {
			Name  string
			Value any
		}{fmt.Sprintf("nested-depth-%d", depth), nested})
	}
	return shapes
}

// Standard fmt sinks cannot reveal credentials across the reviewed shapes and verbs.
func TestReviewFmtAllPaths(t *testing.T) {
	document, needles := reviewFixture(t)
	if !reviewLeaks(document.ModelBearer.Reveal(), needles) {
		t.Fatal("leak detector positive control failed")
	}
	if reviewLeaks("[redacted] public metadata", needles) {
		t.Fatal("leak detector negative control failed")
	}
	formats := []string{}
	for _, verb := range "vTtbcdoOxXUeEfFgGspqwz!?" {
		for _, flags := range []string{"", "+", "#", "-", " ", "0", "+#", "-#", "+ #0"} {
			for _, width := range []string{"", "1", "8", "65", ".0", ".7", ".16", "32.8"} {
				formats = append(formats, "%"+flags+width+string(verb))
			}
		}
	}
	formats = append(formats, "%", "%[2]v", "%[0]v", "%*v", "%.*v", "%[1]*.[1]*[1]v", "%[2]*[1]v", "public-only")
	checks := 0
	for _, shape := range reviewShapes(document) {
		t.Run(shape.Name, func(t *testing.T) {
			for index, format := range formats {
				outputs := []string{fmt.Sprintf(format, shape.Value), fmt.Errorf(format, shape.Value).Error(), string(fmt.Appendf(nil, format, shape.Value))}
				var output bytes.Buffer
				fmt.Fprintf(&output, format, shape.Value)
				outputs = append(outputs, output.String())
				output.Reset()
				log.New(&output, "", 0).Printf(format, shape.Value)
				outputs = append(outputs, output.String())
				for sink, text := range outputs {
					checks++
					if reviewLeaks(text, needles) {
						t.Fatalf("credential disclosed: format-index=%d sink=%d", index, sink)
					}
				}
			}
			for sink, text := range []string{fmt.Sprint(shape.Value), fmt.Sprintln(shape.Value), string(fmt.Append(nil, shape.Value)), string(fmt.Appendln(nil, shape.Value))} {
				checks++
				if reviewLeaks(text, needles) {
					t.Fatalf("credential disclosed: unformatted-sink=%d", sink)
				}
			}
		})
	}
	t.Logf("shapes=%d formats=%d output-checks=%d detector-controls=2", len(reviewShapes(document)), len(formats), checks)
}

// Generic serialization and nested slog remain safe beside an explicit private-wire positive control.
func TestReviewSerializationAndSlog(t *testing.T) {
	gob.Register(reviewBootstrap{})
	document, needles := reviewFixture(t)
	shapes := []struct {
		Name  string
		Value any
	}{
		{"bootstrap", document}, {"secret", document.ModelBearer}, {"channel", document.ChannelSecret},
		{"nested-struct", struct{ Document reviewBootstrap }{document}}, {"nested-map", map[string]any{"document": document}},
		{"array", [1]reviewBootstrap{document}}, {"pointer", &document},
	}
	for _, shape := range shapes {
		t.Run(shape.Name, func(t *testing.T) {
			private, err := codec.Encode(document)
			if err != nil || !reviewLeaks(string(private), needles) {
				t.Error("private JSON positive control did not carry credential")
			}
			raw, err := json.Marshal(shape.Value)
			if err != nil || reviewLeaks(string(raw), needles) {
				t.Error("credential disclosed by generic JSON encoding")
			}
			var encoded bytes.Buffer
			err = gob.NewEncoder(&encoded).Encode(shape.Value)
			expectedGobRefusal := err != nil && strings.Contains(err.Error(), "has no exported fields") && strings.Contains(err.Error(), "codec.Secret[")
			t.Logf("gob refused-for-opaque-fields=%t contains-credential=%t", expectedGobRefusal, reviewLeaks(encoded.String(), needles))
			if !expectedGobRefusal || reviewLeaks(encoded.String(), needles) {
				t.Error("gob did not safely refuse opaque credential")
			}
			for _, kind := range []string{"text", "json"} {
				for _, group := range []bool{false, true} {
					var output bytes.Buffer
					var handler slog.Handler
					if kind == "text" {
						handler = slog.NewTextHandler(&output, nil)
					} else {
						handler = slog.NewJSONHandler(&output, nil)
					}
					logger := slog.New(handler)
					attribute := slog.Any("document", shape.Value)
					if group {
						attribute = slog.Group("context", attribute)
					}
					logger.LogAttrs(context.Background(), slog.LevelInfo, "review", attribute)
					if reviewLeaks(output.String(), needles) {
						t.Errorf("credential disclosed: slog handler=%s group=%t", kind, group)
					}
				}
			}
		})
	}
}

// Input/accessor mutation and failed decode cannot alter a copied credential holder.
func TestReviewWrapperCopy(t *testing.T) {
	document, needles := reviewFixture(t)
	original := document.ChannelSecret.Reveal()
	wrapped := codec.NewSecret(original)
	copied := wrapped
	original[0] ^= 0xff
	accessor := wrapped.Reveal()
	accessor[1] ^= 0xff
	if !bytes.Equal(copied.Reveal(), document.ChannelSecret.Reveal()) {
		t.Fatal("copy or accessor mutated credential")
	}
	if err := json.Unmarshal([]byte(`123`), &wrapped); err == nil || len(wrapped.Reveal()) != 0 {
		t.Fatal("invalid unmarshal did not clear destination")
	}
	if !bytes.Equal(copied.Reveal(), document.ChannelSecret.Reveal()) {
		t.Fatal("reset propagated into copied wrapper")
	}
	for _, value := range []any{wrapped, copied, document.ModelBearer} {
		for _, format := range []string{"%p", "%#v", "%+v", "%q", "%w"} {
			if reviewLeaks(fmt.Sprintf(format, value), needles) {
				t.Fatal("copied wrapper leaked")
			}
		}
	}
}
