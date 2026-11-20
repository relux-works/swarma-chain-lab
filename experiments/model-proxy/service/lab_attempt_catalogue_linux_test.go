//go:build linux && gateway_lab

package service

import (
	"encoding/json"
	"fmt"
	"github.com/relux-works/swarma-chain-lab/experiments/model-proxy/service/internal/wire"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func labAttemptFixtures(test *testing.T) map[string]map[string]any {
	test.Helper()
	raw, err := os.ReadFile("testdata/lab-v0-c0e/fixtures.json")
	if err != nil {
		test.Fatal(err)
	}
	var fixtures struct {
		Cases []struct {
			Surface string
			Valid   json.RawMessage
		}
	}
	if json.Unmarshal(raw, &fixtures) != nil {
		test.Fatal("fixtures")
	}
	result := map[string]map[string]any{}
	for _, row := range fixtures.Cases {
		object, err := wire.Parse(row.Valid)
		if err != nil {
			test.Fatal(err)
		}
		result[row.Surface] = object
	}
	return result
}
func labAttemptScalarMutations(kind string) []grammarMutation {
	if bounds, ok := map[string][2]int64{"invocation-count": {1, 256}, "output-tokens": {1, 128000}, "wall-ms": {1, 900000}}[kind]; ok {
		var result []grammarMutation
		for _, value := range []int64{bounds[0] - 1, bounds[0], bounds[0] + 1, bounds[1] - 1, bounds[1], bounds[1] + 1} {
			result = append(result, grammarMutation{fmt.Sprint(value), value, value >= bounds[0] && value <= bounds[1]})
		}
		return result
	}
	if kind == "usd" {
		var result []grammarMutation
		for _, value := range []string{"0.000000", "0.000001", "0.000002", "1.000000", "9007199254.740990", "9007199254.740991", "9007199254.740992", "01.000000", "1.00000", "1.0000000", "+1.000000", "-1.000000", "1e0", "1.000000e0"} {
			expected := value == "0.000001" || value == "0.000002" || value == "1.000000" || value == "9007199254.740990" || value == "9007199254.740991"
			result = append(result, grammarMutation{value, value, expected})
		}
		for _, seed := range []string{"0.000001", "1.000001", "9007199254.740991"} {
			for _, mutation := range literalMutations(seed) {
				text := mutation.Value.(string)
				micros, err := strconv.ParseUint(strings.ReplaceAll(text, ".", ""), 10, 64)
				mutation.Admit = regexp.MustCompile(`^(0|[1-9][0-9]*)\.[0-9]{6}$`).MatchString(text) && err == nil && micros >= 1 && micros <= 9007199254740991
				result = append(result, mutation)
			}
		}
		return result
	}
	if kind == "native-id" || kind == "native-executor" {
		maximum := 64
		if kind == "native-executor" {
			maximum = 32
		}
		var result []grammarMutation
		for _, length := range []int{0, 1, 2, maximum - 1, maximum, maximum + 1} {
			result = append(result, grammarMutation{fmt.Sprint(length), strings.Repeat("a", length), length >= 1 && length <= maximum})
		}
		for _, value := range []string{"a-b", "A.b_1", "-a", "_a", "a b", "a/b", "é", "a\n", "a\t"} {
			admit := value == "a-b" || value == "A.b_1" && kind == "native-id"
			result = append(result, grammarMutation{value, value, admit})
		}
		pattern := `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`
		if kind == "native-executor" {
			pattern = `^[a-z0-9][a-z0-9-]{0,31}$`
		}
		expected := regexp.MustCompile(pattern)
		for _, mutation := range literalMutations("fixture-native-id") {
			mutation.Admit = expected.MatchString(mutation.Value.(string))
			result = append(result, mutation)
		}
		return result
	}
	return scalarMutations(kind)
}

// TestLabAttemptFrozenCatalogue applies C0 operators to every instantiated node/member of the nine formats G1b actually consumes; it tests the runtime parser, not forwarding or native authority.
func TestLabAttemptFrozenCatalogue(test *testing.T) {
	fixtures := labAttemptFixtures(test)
	consumed := map[string]bool{"swarma-broker-lab-bounded-invocation/1": true, "swarma-broker-lab-off-vm-approval/1": true, "swarma-lab-release-set/1": true, "swarma-broker-lab-launch-plan/1": true, "swarma-broker-lab-model-price/1": true, "swarma-broker-lab-access-attestation/1": true, "swarma-broker-lab-observation-response/1": true, labAttemptGroupFormat: true, labAttemptLedgerFormat: true}
	for format, control := range fixtures {
		if !consumed[format] {
			continue
		}
		test.Run(format, func(test *testing.T) {
			var shape labShape
			for _, candidate := range labAttemptRules.Surfaces {
				if candidate.Format == format {
					shape = candidate
				}
			}
			baseline := labBytes(test, control)
			check := func(candidate map[string]any, admit bool, name string) {
				test.Helper()
				if _, err := labAttemptRecord(baseline, format); err != nil {
					test.Fatal("valid control", err)
				}
				raw := labCandidate(candidate)
				admit = admit && len(raw) <= shape.MaxBytes
				_, err := labAttemptRecord(raw, format)
				if (err == nil) != admit {
					test.Fatalf("catalogue %s admission=%t", name, err == nil)
				}
			}
			var visit func(map[string]any, labShape)
			visit = func(object map[string]any, shape labShape) {
				for name, kind := range shape.Fields {
					saved := object[name]
					delete(object, name)
					check(control, false, "missing-"+name)
					object[name] = saved
					for _, label := range literalMutations(name) {
						changed := label.Value.(string)
						if changed == name {
							continue
						}
						if _, exists := object[changed]; exists {
							continue
						}
						delete(object, name)
						object[changed] = saved
						check(control, false, "label-"+name+"-"+label.Name)
						delete(object, changed)
						object[name] = saved
						object[changed] = saved
						check(control, false, "extra-label-"+name+"-"+label.Name)
						delete(object, changed)
					}
					object[name+"́"] = saved
					check(control, false, "combining-label")
					delete(object, name+"́")
					fullwidth := strings.Map(func(char rune) rune {
						if char >= 33 && char <= 126 {
							return char + 0xfee0
						}
						return char
					}, name)
					object[fullwidth] = saved
					check(control, false, "fullwidth-label")
					delete(object, fullwidth)
					for _, mutation := range wrongTypes(saved) {
						object[name] = mutation.Value
						check(control, false, "wrong-type-"+name)
						object[name] = saved
					}
					switch {
					case strings.HasPrefix(kind, "@"):
						visit(labObject(saved), labAttemptRules.Structures[kind[1:]])
					case strings.HasPrefix(kind, "[]"):
						array := saved.([]any)
						element := kind[2:]
						if strings.HasPrefix(element, "@") {
							for _, item := range array {
								visit(labObject(item), labAttemptRules.Structures[element[1:]])
							}
						}
						if len(array) > 0 {
							for _, count := range []int{0, 1, 255, 256, 257} {
								expanded := make([]any, count)
								for index := range expanded {
									expanded[index] = array[0]
								}
								object[name] = expanded
								check(control, count <= 256, "array-bound")
								object[name] = saved
							}
						}
					default:
						for _, mutation := range labAttemptScalarMutations(kind) {
							object[name] = mutation.Value
							check(control, mutation.Admit, name+"-"+mutation.Name)
							object[name] = saved
						}
					}
				}
			}
			visit(control, shape)
			raw := labBytes(test, control)
			if _, err := labAttemptRecord(append(raw, '\n'), format); err == nil {
				test.Fatal("noncanonical newline")
			}
			duplicate := append([]byte(`{"format":"`+format+`",`), raw[1:]...)
			if _, err := labAttemptRecord(duplicate, format); err == nil {
				test.Fatal("duplicate root member")
			}
		})
	}
}
