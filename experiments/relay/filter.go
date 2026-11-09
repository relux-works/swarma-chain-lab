package relay

import (
	"encoding/json"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
)

type filter struct {
	IDs     []string `json:"ids,omitempty"`
	Authors []string `json:"authors,omitempty"`
	Kinds   []int    `json:"kinds,omitempty"`
	P       []string `json:"#p,omitempty"`
	E       []string `json:"#e,omitempty"`
	Since   *int64   `json:"since,omitempty"`
	Until   *int64   `json:"until,omitempty"`
	Limit   *int     `json:"limit,omitempty"`
}

func parseFilter(raw []byte) (filter, error) {
	var f filter
	if len(raw) > maxFilterBytes || strict(raw, &f) != nil {
		return f, fail("FILTER")
	}
	// Objects only: decoding another JSON type into a struct is not a filter.
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil || obj == nil {
		return f, fail("FILTER")
	}
	for _, a := range [][]string{f.IDs, f.Authors, f.P, f.E} {
		if len(a) > 128 {
			return f, fail("FILTER")
		}
		for _, s := range a {
			if !hex(s, 64) {
				return f, fail("FILTER")
			}
		}
	}
	if len(f.Kinds) > 16 {
		return f, fail("FILTER")
	}
	for _, k := range f.Kinds {
		if k < 0 || k > 65535 {
			return f, fail("FILTER")
		}
	}
	if f.Since != nil && *f.Since < 0 || f.Until != nil && *f.Until < 0 || f.Since != nil && f.Until != nil && *f.Since > *f.Until || f.Limit != nil && (*f.Limit < 0 || *f.Limit > 4096) {
		return f, fail("FILTER")
	}
	return f, nil
}
func contains[T comparable](a []T, v T) bool {
	for _, x := range a {
		if x == v {
			return true
		}
	}
	return false
}
func (f filter) match(e *nostr.Event) bool {
	if f.IDs != nil && !contains(f.IDs, e.ID) || f.Authors != nil && !contains(f.Authors, e.PubKey) || f.Kinds != nil && !contains(f.Kinds, e.Kind) || f.Since != nil && e.CreatedAt < *f.Since || f.Until != nil && e.CreatedAt > *f.Until {
		return false
	}
	for name, list := range map[string][]string{"p": f.P, "e": f.E} {
		if list == nil {
			continue
		}
		found := false
		for _, tag := range e.Tags {
			if len(tag) >= 2 && tag[0] == name && contains(list, tag[1]) {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}
func matches(filters []filter, e *nostr.Event) bool {
	for _, f := range filters {
		if f.match(e) {
			return true
		}
	}
	return false
}
