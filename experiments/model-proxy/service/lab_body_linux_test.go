//go:build linux && gateway_lab

package service

import (
	"bytes"
	"encoding/json"
	"testing"
)

// TestLabBodyCachePositions proves both observed cache placements work while a duplicated global scope violates the frozen multiset.
func TestLabBodyCachePositions(test *testing.T) {
	var body map[string]any
	if json.Unmarshal(labWireCases(test)[0].Request.Body, &body) != nil {
		test.Fatal("fixture")
	}
	control, _ := json.Marshal(body)
	if !labBodyValid(control) {
		test.Fatal("original control")
	}
	system := body["system"].([]any)
	first, second := system[0].(map[string]any), system[1].(map[string]any)
	first["cache_control"], second["cache_control"] = second["cache_control"], first["cache_control"]
	swapped, _ := json.Marshal(body)
	if !labBodyValid(swapped) {
		test.Fatal("cache multiset was pinned to placement")
	}
	second["cache_control"] = first["cache_control"]
	duplicated, _ := json.Marshal(body)
	if labBodyValid(duplicated) {
		test.Fatal("two global scopes admitted")
	}
}

// TestLabBodyDuplicateMembers proves duplicate HTTP JSON members refuse at root and nested object shapes beside the unchanged valid control.
func TestLabBodyDuplicateMembers(test *testing.T) {
	var body any
	if json.Unmarshal(labWireCases(test)[0].Request.Body, &body) != nil {
		test.Fatal("fixture")
	}
	control, _ := json.Marshal(body)
	if !labBodyValid(control) {
		test.Fatal("valid control")
	}
	var visit func(any)
	visit = func(value any) {
		switch object := value.(type) {
		case map[string]any:
			encoded, _ := json.Marshal(object)
			for name, child := range object {
				key, _ := json.Marshal(name)
				raw, _ := json.Marshal(child)
				duplicate := []byte("{" + string(key) + ":" + string(raw) + "," + string(encoded[1:]))
				changed := bytes.Replace(control, encoded, duplicate, 1)
				if bytes.Equal(changed, control) {
					test.Fatal("duplicate operator not applied")
				}
				if labBodyValid(changed) {
					test.Fatal("duplicate JSON member admitted")
				}
				visit(child)
			}
		case []any:
			for _, child := range object {
				visit(child)
			}
		}
	}
	visit(body)
}
