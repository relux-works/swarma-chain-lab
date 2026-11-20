//go:build linux && gateway_lab

package service

import (
	"fmt"
	"slices"
	"strings"
)

type grammarMutation struct {
	Name  string
	Value any
	Admit bool
}

func literalMutations(text string) []grammarMutation {
	result := []grammarMutation{{"literal-valid", text, true}, {"literal-empty", "", false}, {"literal-suffix", text + "x", false}, {"literal-prefix", "x" + text, false}}
	for name, changed := range map[string]string{"whole-upper": strings.ToUpper(text), "whole-lower": strings.ToLower(text), "whole-flip": flipASCII(text)} {
		if changed != text {
			result = append(result, grammarMutation{name, changed, false})
		}
	}
	for index, pair := range [][2]string{{"\"", "\""}, {"[", "]"}, {"{", "}"}, {"(", ")"}, {" ", " "}, {"\t", "\t"}, {"\r\n", "\r\n"}, {"'", "'"}, {"\v", "\v"}, {"\f", "\f"}} {
		result = append(result, grammarMutation{fmt.Sprintf("wrapper-%d", index), pair[0] + text + pair[1], false})
		result = append(result, grammarMutation{fmt.Sprintf("leading-wrapper-%d", index), pair[0] + text, false}, grammarMutation{fmt.Sprintf("trailing-wrapper-%d", index), text + pair[1], false})
	}
	for offset, char := range []byte(text) {
		replacement := byte('x')
		if char == replacement {
			replacement = 'y'
		}
		result = append(result, grammarMutation{fmt.Sprintf("literal-%d-altered", offset), text[:offset] + string(replacement) + text[offset+1:], false}, grammarMutation{fmt.Sprintf("literal-%d-removed", offset), text[:offset] + text[offset+1:], false})
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' {
			result = append(result, grammarMutation{fmt.Sprintf("case-%d", offset), text[:offset] + string(char^32) + text[offset+1:], false})
		}
		if strings.ContainsRune(separatorAlphabet, rune(char)) {
			result = append(result, separatorMutations(text, offset)...)
		}
	}
	return result
}

const separatorAlphabet = "TZ_,.-:/;= ?&()[]{}\\\"\t\r\n"

func flipASCII(text string) string {
	result := []byte(text)
	for index, char := range result {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' {
			result[index] = char ^ 32
		}
	}
	return string(result)
}

func separatorMutations(text string, offset int) []grammarMutation {
	char := text[offset : offset+1]
	result := []grammarMutation{}
	for index, replacement := range append([]string{"", char + char, " " + char + " ", "\t" + char + "\t", "\r\n" + char + "\r\n"}, strings.Split(separatorAlphabet, "")...) {
		if replacement != char {
			result = append(result, grammarMutation{fmt.Sprintf("separator-%d-op-%d", offset, index), text[:offset] + replacement + text[offset+1:], false})
		}
	}
	return result
}

func hexMutations(kind string) []grammarMutation {
	prefix, groups := "", []int{32}
	switch kind {
	case "digest":
		prefix, groups = "sha256:", []int{64}
	case "commit":
		groups = []int{40}
	case "uuid":
		groups = []int{8, 4, 4, 4, 12}
	}
	parts := make([]string, len(groups))
	for index, count := range groups {
		parts[index] = strings.Repeat("a", count)
	}
	valid := prefix + strings.Join(parts, "-")
	result := []grammarMutation{{"hex-valid", valid, true}}
	for _, mutation := range literalMutations(valid) {
		if !mutation.Admit {
			result = append(result, mutation)
		}
	}
	if kind == "uuid" {
		result = append(result, grammarMutation{"uuid-urn-prefix", "urn:uuid:" + valid, false})
	}
	if prefix != "" {
		for _, mutation := range literalMutations(prefix) {
			if !mutation.Admit {
				result = append(result, grammarMutation{"prefix-" + mutation.Name, mutation.Value.(string) + strings.Join(parts, "-"), false})
			}
		}
	}
	for group, count := range groups {
		for _, char := range []byte{'0', '9', 'a', 'f', '/', ':', '`', 'g', 'A'} {
			changed := slices.Clone(parts)
			changed[group] = strings.Repeat(string(char), count)
			result = append(result, grammarMutation{fmt.Sprintf("group-%d-alphabet-%d", group, char), prefix + strings.Join(changed, "-"), strings.ContainsRune("09af", rune(char))})
		}
		for _, delta := range []int{-1, 1} {
			changed := slices.Clone(parts)
			changed[group] = strings.Repeat("a", count+delta)
			result = append(result, grammarMutation{fmt.Sprintf("group-%d-length-%d", group, delta), prefix + strings.Join(changed, "-"), false})
		}
	}
	for offset, char := range []byte(valid[len(prefix):]) {
		if char != '-' {
			continue
		}
		offset += len(prefix)
		for _, separator := range []string{"", "_", ".", "a", "--"} {
			result = append(result, grammarMutation{fmt.Sprintf("separator-%d-%q", offset, separator), valid[:offset] + separator + valid[offset+1:], false})
		}
		shifted := []byte(valid)
		shifted[offset], shifted[offset+1] = shifted[offset+1], shifted[offset]
		result = append(result, grammarMutation{fmt.Sprintf("separator-%d-shift", offset), string(shifted), false})
	}
	return result
}

func scalarMutations(kind string) []grammarMutation {
	if strings.HasPrefix(kind, "=") || strings.Contains(kind, "|") {
		members := []string{strings.TrimPrefix(kind, "=")}
		if strings.Contains(kind, "|") {
			members = strings.Split(kind, "|")
		}
		var result []grammarMutation
		for member, text := range members {
			for _, mutation := range literalMutations(text) {
				mutation.Name = fmt.Sprintf("member-%d-%s", member, mutation.Name)
				mutation.Admit = slices.Contains(members, mutation.Value.(string))
				result = append(result, mutation)
			}
		}
		return result
	}
	if slices.Contains([]string{"digest", "operation", "commit", "uuid"}, kind) {
		return hexMutations(kind)
	}
	if kind == "id" || kind == "material" {
		maximum := 128
		if kind == "material" {
			maximum = 4096
		}
		var result []grammarMutation
		for _, count := range []int{0, 1, 2, maximum - 1, maximum, maximum + 1} {
			result = append(result, grammarMutation{fmt.Sprintf("length-%d", count), strings.Repeat("x", count), count >= 1 && count <= maximum})
		}
		for _, char := range []byte{0x20, 0x21, 0x22, 0x7d, 0x7e, 0x7f} {
			result = append(result, grammarMutation{fmt.Sprintf("ascii-%d", char), string(char), char >= 0x21 && char <= 0x7e})
		}
		return append(result, grammarMutation{"non-ascii", "é", false})
	}
	bounds := map[string][2]int64{"uint": {0, 9007199254740991}, "positive": {1, 9007199254740991}, "root": {0, 0}, "lifetime": {1, 900}, "alignment": {0, 2}, "exit": {0, 255}, "poll": {250, 250}, "capture-timeout": {300, 300}}
	if bound, exists := bounds[kind]; exists {
		var result []grammarMutation
		for _, value := range []int64{bound[0] - 1, bound[0], bound[0] + 1, bound[1] - 1, bound[1], bound[1] + 1} {
			result = append(result, grammarMutation{fmt.Sprintf("integer-%d", value), value, value >= bound[0] && value <= bound[1]})
		}
		return append(result, grammarMutation{"fractional-number", float64(1.5), false})
	}
	if kind == "bool" {
		return []grammarMutation{{"false", false, true}, {"true", true, true}}
	}
	if kind == "time" {
		result := []grammarMutation{{"epoch-minus-one-ns", "1969-12-31T23:59:59.999999999Z", false}, {"epoch", "1970-01-01T00:00:00Z", false}, {"epoch-plus-one-ns", "1970-01-01T00:00:00.000000001Z", true}, {"epoch-plus-two-ns", "1970-01-01T00:00:00.000000002Z", true}, {"maximum-minus-one-ns", "9999-12-31T23:59:59.999999998Z", true}, {"maximum", "9999-12-31T23:59:59.999999999Z", true}, {"maximum-plus-one-ns", "10000-01-01T00:00:00Z", false}, {"offset", "2027-01-01T00:00:00+00:00", false}, {"redundant-fraction", "2027-01-01T00:00:00.000Z", false}}
		for _, mutation := range timeCanonicalMutations() {
			result = append(result, mutation)
		}
		text := "2027-01-01T00:00:00.123456789Z"
		result = append(result, grammarMutation{"time-valid", text, true})
		for _, mutation := range literalMutations(text) {
			name := mutation.Name
			if strings.HasPrefix(name, "separator-") || strings.HasPrefix(name, "case-") || strings.HasPrefix(name, "whole-") || strings.Contains(name, "wrapper-") || name == "literal-prefix" || name == "literal-suffix" || strings.HasPrefix(name, "literal-") && (strings.Contains(name, "removed") || strings.Contains(name, "altered")) && strings.ContainsAny(string(textOffset(text, name)), "-T:.Z") {
				result = append(result, mutation)
			}
		}
		for _, positions := range [][3]int{{5, 7, 12}, {8, 10, 31}, {11, 13, 23}, {14, 16, 59}, {17, 19, 59}} {
			for _, value := range []int{-1, 0, 1, positions[2] - 1, positions[2], positions[2] + 1} {
				changed := text[:positions[0]] + fmt.Sprintf("%02d", value) + text[positions[1]:]
				result = append(result, grammarMutation{fmt.Sprintf("component-%d-%d", positions[0], value), changed, value >= 0 && value <= positions[2] && ((positions[0] != 5 && positions[0] != 8) || value >= 1)})
			}
		}
		for _, digits := range []int{0, 1, 8, 9, 10} {
			fraction := ""
			if digits != 0 {
				fraction = "." + strings.Repeat("1", digits)
			}
			result = append(result, grammarMutation{fmt.Sprintf("fraction-count-%d", digits), "2027-01-01T00:00:00" + fraction + "Z", digits <= 9})
		}
		return result
	}
	panic("uncovered grammar: " + kind)
}

func textOffset(text, name string) byte {
	var offset int
	if _, err := fmt.Sscanf(name, "literal-%d-", &offset); err != nil {
		panic(err)
	}
	return text[offset]
}

func jsonKind(value any) string {
	switch value.(type) {
	case nil:
		return "null"
	case bool:
		return "bool"
	case int64, float64:
		return "number"
	case string:
		return "string"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	default:
		panic("unknown JSON type")
	}
}

func wrongTypes(control any) []grammarMutation {
	values := []any{nil, false, int64(1), "PUBLIC-TYPE", []any{}, map[string]any{}}
	var result []grammarMutation
	for _, value := range values {
		if jsonKind(value) != jsonKind(control) {
			result = append(result, grammarMutation{"type-" + jsonKind(value), value, false})
		}
	}
	return result
}

func timeCanonicalMutations() []grammarMutation {
	base := "2027-01-01T00:00:00"
	result := []grammarMutation{}
	for count := 1; count <= 10; count++ {
		result = append(result, grammarMutation{fmt.Sprintf("all-zero-fraction-%d", count), base + "." + strings.Repeat("0", count) + "Z", false})
		if count <= 9 {
			digits := strings.Repeat("1", count)
			result = append(result, grammarMutation{fmt.Sprintf("nonzero-fraction-%d-valid", count), base + "." + digits + "Z", true}, grammarMutation{fmt.Sprintf("nonzero-fraction-%d-trailing-zero", count), base + "." + digits + "0Z", false})
			if count > 1 {
				result = append(result, grammarMutation{fmt.Sprintf("fraction-leading-zero-%d-valid", count), base + "." + strings.Repeat("0", count-1) + "1Z", true}, grammarMutation{fmt.Sprintf("fraction-leading-zero-%d-redundant", count), base + "." + strings.Repeat("0", count-1) + "10Z", false})
			}
		}
	}
	for _, value := range []string{base + ".120Z", base + ".100000000Z", base + ".000000010Z", "02027-01-01T00:00:00Z", "+2027-01-01T00:00:00Z", "-2027-01-01T00:00:00Z", base + ".1e1Z", base + ".1E+1Z", base + ".+1Z", base + ".-1Z"} {
		result = append(result, grammarMutation{fmt.Sprintf("canonical-%q", value), value, false})
	}
	for _, marker := range []string{"e", "E"} {
		for _, sign := range []string{"", "+", "-"} {
			result = append(result, grammarMutation{"fraction-exponent-" + marker + fmt.Sprintf("%q", sign), base + ".1" + marker + sign + "1Z", false})
		}
	}
	for _, offset := range []int{4, 7, 10, 13, 16, 19, 29} {
		for _, mutation := range separatorMutations(base+".123456789Z", offset) {
			result = append(result, mutation)
		}
	}
	return result
}

func asciiHeaderCaseEqual(candidate, measured string) bool {
	if len(candidate) != len(measured) {
		return false
	}
	for index := range measured {
		if candidate[index] != measured[index] && !(measured[index] >= 'a' && measured[index] <= 'z' && candidate[index] == measured[index]-('a'-'A')) {
			return false
		}
	}
	return true
}
