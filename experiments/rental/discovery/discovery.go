// Package discovery checks a local social-identity mirror. It does not resolve
// names, check chain freshness, or provide authority to a grant consumer.
package discovery

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

type value struct {
	Nostr struct {
		Names map[string]string `json:"names"`
	} `json:"nostr"`
}
type Agent struct {
	Label string `json:"label"`
	Name  string `json:"name"`
	Value string `json:"value"`
}
type Inventory struct {
	Landlord string  `json:"landlord"`
	Value    string  `json:"value"`
	Agents   []Agent `json:"agents"`
}
type Record struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type Drift struct {
	OK         bool     `json:"ok"`
	Missing    []string `json:"missing"`
	Extra      []string `json:"extra"`
	Mismatched []string `json:"mismatched"`
}

func fail(s string) error { return errors.New(s) }
func key(s string) bool {
	b, e := hex.DecodeString(s)
	if e != nil || len(b) != 32 || hex.EncodeToString(b) != s {
		return false
	}
	_, e = schnorr.ParsePubKey(b)
	return e == nil
}

// Flat, lowercase ASCII labels avoid wildcard, case-fold and subdomain ambiguity.
func label(s string) bool {
	if len(s) < 1 || len(s) > 63 || strings.HasPrefix(s, "-") || strings.HasSuffix(s, "-") {
		return false
	}
	for _, b := range []byte(s) {
		if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-') {
			return false
		}
	}
	return !strings.Contains(s, "--")
}
func validID(s string) bool {
	if !strings.HasPrefix(s, "id/") || len(s) <= 3 || len(s) > 255 {
		return false
	}
	for _, b := range []byte(s[3:]) {
		if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-' || b == '_' || b == '.') {
			return false
		}
	}
	return true
}
func validate(v value) error {
	if v.Nostr.Names == nil || !key(v.Nostr.Names["_"]) {
		return fail("DISCOVERY_ROOT")
	}
	for name, k := range v.Nostr.Names {
		if name != "_" && !label(name) {
			return fail("DISCOVERY_LABEL")
		}
		if !key(k) {
			return fail("DISCOVERY_KEY")
		}
	}
	return nil
}

// Build emits a complete d/ social value; it never creates a K1 authority value.
func Build(root string, agents map[string]string) (string, error) {
	var v value
	v.Nostr.Names = map[string]string{"_": root}
	for name, k := range agents {
		if name == "_" {
			return "", fail("DISCOVERY_LABEL")
		}
		v.Nostr.Names[name] = k
	}
	if e := validate(v); e != nil {
		return "", e
	}
	raw, e := json.Marshal(v)
	if e != nil {
		return "", e
	}
	if len(raw) > 520 {
		return "", fail("DISCOVERY_SIZE")
	}
	return string(raw), nil
}
func Parse(raw string) (map[string]string, error) {
	var v value
	if len(raw) > 520 || len(raw) == 0 || su.StrictInput([]byte(raw), &v) != nil {
		return nil, fail("DISCOVERY_SCHEMA")
	}
	encoded, e := json.Marshal(v)
	if e != nil || !bytes.Equal(encoded, []byte(raw)) {
		return nil, fail("DISCOVERY_CANONICAL")
	}
	if e = validate(v); e != nil {
		return nil, e
	}
	return v.Nostr.Names, nil
}

// Expected verifies every supplied id/ record and its landlord pointer. Callers
// must supply a complete, fresh inventory; an offline checker cannot infer that.
func Expected(i Inventory) (Record, error) {
	if !strings.HasPrefix(i.Landlord, "id/") || !label(strings.TrimPrefix(i.Landlord, "id/")) || i.Agents == nil || len(i.Agents) > 32 {
		return Record{}, fail("INVENTORY_SCHEMA")
	}
	_, social, e := rental.ParseLandlordIdentity(i.Value)
	if e != nil || social == nil {
		return Record{}, fail("INVENTORY_LANDLORD")
	}
	agents := map[string]string{}
	seen := map[string]bool{}
	for _, a := range i.Agents {
		if !label(a.Label) || !validID(a.Name) || a.Name == i.Landlord || seen[a.Name] {
			return Record{}, fail("INVENTORY_AGENT")
		}
		if _, ok := agents[a.Label]; ok {
			return Record{}, fail("INVENTORY_LABEL")
		}
		seen[a.Name] = true
		binding, desc, e := rental.ParseAgentIdentity(a.Value)
		if e != nil || desc == nil || binding.Landlord != i.Landlord {
			return Record{}, fail("INVENTORY_BINDING")
		}
		agents[a.Label] = binding.Nostr
	}
	raw, e := Build(social.Names.Root, agents)
	if e != nil {
		return Record{}, e
	}
	return Record{"d/" + strings.TrimPrefix(i.Landlord, "id/"), raw}, nil
}
func Check(record Record, i Inventory) (Drift, error) {
	out := Drift{Missing: []string{}, Extra: []string{}, Mismatched: []string{}}
	expected, e := Expected(i)
	if e != nil {
		return out, e
	}
	if record.Name != expected.Name {
		return out, fail("DISCOVERY_NAME")
	}
	want, e := Parse(expected.Value)
	if e != nil {
		return out, e
	}
	got, e := Parse(record.Value)
	if e != nil {
		return out, e
	}
	for label, k := range want {
		if other, ok := got[label]; !ok {
			out.Missing = append(out.Missing, label)
		} else if other != k {
			out.Mismatched = append(out.Mismatched, label)
		}
	}
	for label := range got {
		if _, ok := want[label]; !ok {
			out.Extra = append(out.Extra, label)
		}
	}
	slices.Sort(out.Missing)
	slices.Sort(out.Extra)
	slices.Sort(out.Mismatched)
	out.OK = len(out.Missing) == 0 && len(out.Extra) == 0 && len(out.Mismatched) == 0
	return out, nil
}
