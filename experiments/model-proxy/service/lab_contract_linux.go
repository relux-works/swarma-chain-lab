//go:build linux && gateway_lab

package service

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"io"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/model-proxy/service/internal/wire"
)

//go:embed testdata/lab-v0/surfaces.json
var labSurfaces []byte

//go:embed testdata/lab-v0/wire-fixtures.json
var labWireFixtures []byte

type labShape struct {
	Fields   map[string]string `json:"fields"`
	Format   string            `json:"format"`
	MaxBytes int               `json:"max_bytes"`
}
type labGrammar struct {
	Structures map[string]labShape `json:"structures"`
	Surfaces   []labShape          `json:"surfaces"`
}

var labRules = func() labGrammar {
	var rules labGrammar
	if json.Unmarshal(labSurfaces, &rules) != nil {
		panic("invalid lab contract")
	}
	return rules
}()

func labDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func labRecord(raw []byte, format string) (map[string]any, error) {
	for _, shape := range labRules.Surfaces {
		if shape.Format != format {
			continue
		}
		if !labPayloadValid(raw, shape.MaxBytes) {
			return nil, ErrFrame
		}
		object, err := wire.Parse(raw)
		if err != nil || labFields(object, shape) != nil {
			return nil, ErrFrame
		}
		return object, nil
	}
	return nil, ErrFrame
}

func labFields(object map[string]any, shape labShape) error {
	if len(object) != len(shape.Fields) {
		return ErrFrame
	}
	for name, kind := range shape.Fields {
		value, present := object[name]
		if !present || value == nil || labValue(value, kind) != nil {
			return ErrFrame
		}
	}
	return nil
}

func labValue(value any, kind string) error {
	if strings.HasPrefix(kind, "[]") {
		values, ok := value.([]any)
		if !ok || len(values) > 256 {
			return ErrFrame
		}
		for _, child := range values {
			if labValue(child, kind[2:]) != nil {
				return ErrFrame
			}
		}
		return nil
	}
	if strings.HasPrefix(kind, "@") {
		object, ok := value.(map[string]any)
		shape, exists := labRules.Structures[kind[1:]]
		if !ok || !exists {
			return ErrFrame
		}
		return labFields(object, shape)
	}
	if strings.HasPrefix(kind, "=") {
		if value != kind[1:] {
			return ErrFrame
		}
		return nil
	}
	if strings.Contains(kind, "|") {
		text, ok := value.(string)
		if !ok || !slices.Contains(strings.Split(kind, "|"), text) {
			return ErrFrame
		}
		return nil
	}
	if kind == "time" {
		text, ok := value.(string)
		parsed, err := time.Parse(time.RFC3339Nano, text)
		if !ok || err != nil || parsed.UTC().Format(time.RFC3339Nano) != text || !parsed.After(time.Unix(0, 0)) {
			return ErrFrame
		}
		return nil
	}
	if kind == "bool" {
		if _, ok := value.(bool); !ok {
			return ErrFrame
		}
		return nil
	}
	if pattern, exists := labPatterns[kind]; exists {
		text, ok := value.(string)
		if !ok || kind == "material" && len(text) > 4096 || !pattern.MatchString(text) {
			return ErrFrame
		}
		return nil
	}
	number, ok := value.(int64)
	if !ok {
		return ErrFrame
	}
	minimum, maximum := int64(0), int64(9007199254740991)
	switch kind {
	case "uint":
	case "positive":
		minimum = 1
	case "root":
		maximum = 0
	case "lifetime":
		minimum, maximum = 1, 900
	case "alignment":
		maximum = 2
	case "exit":
		maximum = 255
	case "poll":
		minimum, maximum = 250, 250
	case "capture-timeout":
		minimum, maximum = 300, 300
	default:
		return ErrFrame
	}
	if number < minimum || number > maximum {
		return ErrFrame
	}
	return nil
}

func labJSON(raw []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, err := labJSONValue(decoder, 0)
	if err != nil {
		return nil, ErrFrame
	}
	if _, err = decoder.Token(); err != io.EOF {
		return nil, ErrFrame
	}
	return value, nil
}
func labJSONValue(decoder *json.Decoder, depth int) (any, error) {
	if depth > 64 {
		return nil, ErrFrame
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, ErrFrame
	}
	if delimiter, ok := token.(json.Delim); ok {
		switch delimiter {
		case '{':
			object := map[string]any{}
			for decoder.More() {
				if len(object) >= 256 {
					return nil, ErrFrame
				}
				key, err := decoder.Token()
				if err != nil {
					return nil, ErrFrame
				}
				name, ok := key.(string)
				if !ok {
					return nil, ErrFrame
				}
				if _, exists := object[name]; exists {
					return nil, ErrFrame
				}
				child, err := labJSONValue(decoder, depth+1)
				if err != nil {
					return nil, err
				}
				object[name] = child
			}
			if end, err := decoder.Token(); err != nil || end != json.Delim('}') {
				return nil, ErrFrame
			}
			return object, nil
		case '[':
			array := []any{}
			for decoder.More() {
				if len(array) >= 256 {
					return nil, ErrFrame
				}
				child, err := labJSONValue(decoder, depth+1)
				if err != nil {
					return nil, err
				}
				array = append(array, child)
			}
			if end, err := decoder.Token(); err != nil || end != json.Delim(']') {
				return nil, ErrFrame
			}
			return array, nil
		}
		return nil, ErrFrame
	}
	if token == nil {
		return nil, ErrFrame
	}
	return token, nil
}

func labHeaderName(name string) (string, bool) {
	if name == "" {
		return "", false
	}
	lower := []byte(name)
	for index, value := range lower {
		if value >= 'A' && value <= 'Z' {
			lower[index] += 'a' - 'A'
		} else if !(value >= 'a' && value <= 'z' || value >= '0' && value <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(value))) {
			return "", false
		}
	}
	return string(lower), true
}

const labBeta = "claude-code-20250219,interleaved-thinking-2025-05-14,context-management-2025-06-27,prompt-caching-scope-2026-01-05,per-turn-control-2026-07-01,mid-conversation-tool-changes-2026-07-01,thinking-token-count-2026-05-13,mid-conversation-system-clear-at-2026-08-21,effort-2025-11-24,thinking-binding-controls-2026-08-01,cache-diagnosis-2026-04-07"

func labBetaValid(value string) bool {
	for _, char := range []byte(value) {
		if char != '\t' && (char < 32 || char >= 127) {
			return false
		}
	}
	wanted := strings.Split(labBeta, ",")
	seen := map[string]bool{}
	for _, flag := range strings.Split(value, ",") {
		flag = strings.Trim(flag, " \t")
		if seen[flag] || !slices.Contains(wanted, flag) {
			return false
		}
		seen[flag] = true
	}
	return len(seen) == len(wanted)
}

var labBodyTemplate = func() any {
	var fixtures struct {
		Cases []struct {
			Name    string `json:"name"`
			Request struct {
				Body json.RawMessage `json:"body"`
			} `json:"request"`
		} `json:"cases"`
	}
	if json.Unmarshal(labWireFixtures, &fixtures) != nil {
		panic("invalid lab fixture")
	}
	for _, fixture := range fixtures.Cases {
		if fixture.Name == "messages-valid" {
			body, err := labJSON(fixture.Request.Body)
			if err != nil {
				panic("invalid lab body")
			}
			return body
		}
	}
	panic("missing lab body")
}()

func labBodyValid(raw []byte) bool {
	value, err := labJSON(raw)
	if err != nil {
		return false
	}
	caches := []string{}
	var visit func(any, any, string) bool
	visit = func(value, control any, path string) bool {
		switch expected := control.(type) {
		case map[string]any:
			object, ok := value.(map[string]any)
			if !ok {
				return false
			}
			if strings.HasSuffix(path, ".cache_control") {
				if len(object) < 1 || len(object) > 2 || object["type"] != "ephemeral" {
					return false
				}
				for key, child := range object {
					if key != "type" && (key != "scope" || child != "global") {
						return false
					}
				}
				encoded, _ := json.Marshal(object)
				caches = append(caches, string(encoded))
				return true
			}
			if len(object) != len(expected) {
				return false
			}
			for key, child := range expected {
				candidate, present := object[key]
				if !present || !visit(candidate, child, path+"."+key) {
					return false
				}
			}
			return true
		case []any:
			items, ok := value.([]any)
			if !ok || len(items) != len(expected) {
				return false
			}
			for index, child := range expected {
				if !visit(items[index], child, path+"[]") {
					return false
				}
			}
			return true
		case string:
			if strings.HasSuffix(path, ".text") || path == ".metadata.user_id" || path == ".diagnostics.previous_message_id" {
				_, ok := value.(string)
				return ok
			}
		case json.Number:
			actual, ok := value.(json.Number)
			if !ok {
				return false
			}
			parsed, err := actual.Int64()
			expectedNumber, _ := expected.Int64()
			return err == nil && parsed == expectedNumber
		}
		return reflect.DeepEqual(value, control)
	}
	if !visit(value, labBodyTemplate, "") {
		return false
	}
	slices.Sort(caches)
	return slices.Equal(caches, []string{`{"scope":"global","type":"ephemeral"}`, `{"type":"ephemeral"}`, `{"type":"ephemeral"}`})
}

func labEqual(left, right any) bool { return reflect.DeepEqual(left, right) }
func labTime(value any) time.Time {
	text, _ := value.(string)
	parsed, _ := time.Parse(time.RFC3339Nano, text)
	return parsed
}
func labObject(value any) map[string]any { object, _ := value.(map[string]any); return object }

var labPatternText = map[string]string{"id": `^[\x21-\x7e]{1,128}$`, "digest": `^sha256:[0-9a-f]{64}$`, "operation": `^[0-9a-f]{32}$`, "uuid": `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`, "commit": `^[0-9a-f]{40}$`, "material": `^[\x21-\x7e]+$`}
var labPatterns = func() map[string]*regexp.Regexp {
	result := map[string]*regexp.Regexp{}
	for name, pattern := range labPatternText {
		result[name] = regexp.MustCompile(pattern)
	}
	return result
}()

func labPayloadValid(raw []byte, maximum int) bool { return len(raw) > 0 && len(raw) <= maximum }
