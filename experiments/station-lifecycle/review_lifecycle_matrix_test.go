package lifecycle

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

type reviewLifecycleError struct{ Value any }

func (value reviewLifecycleError) Error() string { return fmt.Sprintf("review: %v", value.Value) }

type reviewRawLifecycleSlot Slot
type reviewRawBrokerRecord brokerRecord

func reviewLifecycleLeak(text string, needles []string) bool {
	for _, needle := range needles {
		if len(needle) > 7 && strings.Contains(text, needle) {
			return true
		}
	}
	return false
}

// Allocate real retained authority and exercise every standard fmt verb/flag/width used in the prior review,
// five formatting sinks, four unformatted sinks, and nested JSON/text slog without emitting any fixture bytes.
func TestReviewLifecycleAllOutput(t *testing.T) {
	now := int64(100)
	broker, _ := brokerFixture(t, &now)
	key := hash([]byte("review-lifecycle"))
	slot, err := broker.Allocate(key, hash([]byte("review-grant")), 90, 200)
	if err != nil {
		t.Fatal("allocation fixture refused")
	}
	raw, err := broker.Credential(key)
	if err != nil {
		t.Fatal("credential control refused")
	}
	needles := []string{string(raw), base64.StdEncoding.EncodeToString(raw), hex.EncodeToString(raw)}
	for _, format := range []string{"%v", "%#v", "%x", "%X", "%q", "%d", "%b", "%o", "%O", "%c", "%U"} {
		needles = append(needles, fmt.Sprintf(format, []byte(raw)))
	}
	if !reviewLifecycleLeak(base64.StdEncoding.EncodeToString(raw), needles) || reviewLifecycleLeak("public redacted value", needles) {
		t.Fatal("leak detector calibration failed")
	}
	retained := broker.state.Records[key]
	rootValues := []struct {
		Name  string
		Value any
	}{
		{"slot", slot}, {"raw-slot", reviewRawLifecycleSlot(slot)}, {"bootstrap-holder", slot.Bootstrap},
		{"broker-record", retained}, {"raw-broker-record", reviewRawBrokerRecord(retained)}, {"broker-credential-holder", retained.Credential},
		{"broker-state", broker.state}, {"broker-pointer", broker},
		{"manager-record", record{ID: slot.ID, Slot: &slot}},
		{"manager-state", state{Records: map[string]record{slot.ID: {ID: slot.ID, Slot: &slot}}}},
		{"command", Command{Op: "start", Slot: slot, Binding: retained.Binding}},
		{"poll-response", PollResponse{Version: 1, Commands: []Command{{Op: "start", Slot: slot, Binding: retained.Binding}}}},
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
	checks, structured := 0, 0
	for _, root := range rootValues {
		t.Run(root.Name, func(t *testing.T) {
			pointer := &root.Value
			shapes := []any{root.Value, pointer, &pointer, struct{ Value any }{root.Value}, struct{ hidden any }{root.Value}, []any{root.Value}, [1]any{root.Value}, map[string]any{"value": root.Value}, reflect.ValueOf(root.Value), reviewLifecycleError{root.Value}, errors.Join(reviewLifecycleError{root.Value}, errors.New("public"))}
			for shapeIndex, shape := range shapes {
				for formatIndex, format := range formats {
					outputs := []string{fmt.Sprintf(format, shape), fmt.Errorf(format, shape).Error(), string(fmt.Appendf(nil, format, shape))}
					var output bytes.Buffer
					fmt.Fprintf(&output, format, shape)
					outputs = append(outputs, output.String())
					output.Reset()
					log.New(&output, "", 0).Printf(format, shape)
					outputs = append(outputs, output.String())
					for sinkIndex, text := range outputs {
						checks++
						if reviewLifecycleLeak(text, needles) {
							t.Fatalf("lifecycle credential disclosure: shape=%d format=%d sink=%d", shapeIndex, formatIndex, sinkIndex)
						}
					}
				}
				for _, text := range []string{fmt.Sprint(shape), fmt.Sprintln(shape), string(fmt.Append(nil, shape)), string(fmt.Appendln(nil, shape))} {
					checks++
					if reviewLifecycleLeak(text, needles) {
						t.Fatal("lifecycle unformatted credential disclosure")
					}
				}
				encoded, err := json.Marshal(shape)
				if err != nil {
					t.Fatal("public JSON carrier encoding failed")
				}
				if reviewLifecycleLeak(string(encoded), needles) {
					t.Fatal("lifecycle generic JSON credential disclosure")
				}
				for _, jsonHandler := range []bool{false, true} {
					for _, group := range []bool{false, true} {
						var output bytes.Buffer
						var handler slog.Handler = slog.NewTextHandler(&output, nil)
						if jsonHandler {
							handler = slog.NewJSONHandler(&output, nil)
						}
						attribute := slog.Any("value", shape)
						if group {
							attribute = slog.Group("context", attribute)
						}
						slog.New(handler).LogAttrs(context.Background(), slog.LevelInfo, "review", attribute)
						structured++
						if reviewLifecycleLeak(output.String(), needles) {
							t.Fatal("lifecycle structured logging credential disclosure")
						}
					}
				}
			}
		})
	}
	t.Logf("roots=%d shapes-per-root=11 formats=%d formatting-checks=%d structured-checks=%d calibration-controls=2", len(rootValues), len(formats), checks, structured)
}
