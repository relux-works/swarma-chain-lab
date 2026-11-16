package identity

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"unicode/utf8"
)

// R1Profile selects a stated-fact experiment, never production grant admission.
// At v0.1.49 J10/J11/J12 are pending; neither zero nor R1InForce enables them.
type R1Profile uint8

const (
	R1InForce R1Profile = iota + 1
	R1DraftLab
)

var (
	ErrR1Profile = errors.New("identity: R1 draft lab profile required")
	ErrR1Value   = errors.New("identity: invalid R1 name value")
)

// R1Value is a parsed LIP-0010 binding. Holders grants no signing authority.
// ChannelKey is derived from the same value, not supplied by a presenter.
type R1Value struct {
	Landlord   string
	Grant      string
	Holders    []Pin
	ChannelKey string
	Swarma     []byte
}

// objectMembers preserves duplicate names and exact RawMessage spans.
func objectMembers(raw []byte) ([]string, []json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return nil, nil, ErrR1Value
	}
	var keys []string
	var values []json.RawMessage
	for d.More() {
		t, err = d.Token()
		key, ok := t.(string)
		if err != nil || !ok {
			return nil, nil, ErrR1Value
		}
		var value json.RawMessage
		if err = d.Decode(&value); err != nil {
			return nil, nil, ErrR1Value
		}
		keys = append(keys, key)
		values = append(values, value)
	}
	if _, err = d.Token(); err != nil {
		return nil, nil, ErrR1Value
	}
	// Token skips JSON whitespace. Only the raw end offset proves that no byte
	// follows this object (LIP-0010 section 2.1), including space/TAB/LF/CRLF.
	if d.InputOffset() != int64(len(raw)) {
		return nil, nil, ErrR1Value
	}
	return keys, values, nil
}

func compactR1(v any) []byte {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if e.Encode(v) != nil {
		return nil
	}
	return bytes.TrimSuffix(b.Bytes(), []byte{'\n'})
}

func r1Channel(raw []byte) string {
	var key string
	if json.Unmarshal(raw, &key) == nil && validSigningKey(key) {
		return key
	}
	keys, values, err := objectMembers(raw)
	if err != nil {
		return ""
	}
	names := 0
	key = ""
	for i, k := range keys {
		if k != "names" {
			continue
		}
		names++
		nk, nv, e := objectMembers(values[i])
		if e != nil {
			return ""
		}
		count := 0
		for j, n := range nk {
			if n == "_" {
				count++
				if json.Unmarshal(nv[j], &key) != nil {
					return ""
				}
			}
		}
		if count != 1 {
			return ""
		}
	}
	if names != 1 || !validSigningKey(key) {
		return ""
	}
	return key
}

// ReadR1Value implements LIP-0010 §§2-5,10 for the explicit draft lab.
// Legacy agent shapes are left to the existing v3 reader, never mixed here.
// Refusal returns no partially parsed key, holder list or binding.
func ReadR1Value(profile R1Profile, raw []byte) (R1Value, error) {
	fail := func() (R1Value, error) { return R1Value{}, ErrR1Value }
	if profile != R1DraftLab {
		return R1Value{}, ErrR1Profile
	}
	swarma, nostr, err := r1ValueMembers(raw)
	if err != nil {
		return fail()
	}
	sk, sv, err := objectMembers(swarma)
	if err != nil || len(sk) != 1 {
		return fail()
	}
	result := R1Value{ChannelKey: r1Channel(nostr), Swarma: bytes.Clone(swarma)}
	var expected []byte
	switch sk[0] {
	case "agent":
		var a struct {
			Landlord string `json:"landlord"`
		}
		if json.Unmarshal(sv[0], &a) != nil || a.Landlord == "" {
			return fail()
		}
		result.Landlord = a.Landlord
		expected = compactR1(struct {
			Agent any `json:"agent"`
		}{a})
	case "landlord":
		lk, lv, e := objectMembers(sv[0])
		if e != nil || len(lk) < 1 || len(lk) > 2 || lk[0] != "grant" {
			return fail()
		}
		if json.Unmarshal(lv[0], &result.Grant) != nil || !validSigningKey(result.Grant) {
			return fail()
		}
		if len(lk) == 2 {
			if lk[1] != "holders" || len(lv[1]) == 0 || lv[1][0] != '[' {
				return fail()
			}
			var pins []string
			if json.Unmarshal(lv[1], &pins) != nil {
				return fail()
			}
			for i, p := range pins {
				pin, e := ParsePin(p)
				if e != nil || (i > 0 && pins[i-1] >= p) {
					return fail()
				}
				result.Holders = append(result.Holders, pin)
			}
			expected = compactR1(struct {
				Landlord any `json:"landlord"`
			}{struct {
				Grant   string   `json:"grant"`
				Holders []string `json:"holders"`
			}{result.Grant, pins}})
		} else {
			expected = compactR1(struct {
				Landlord any `json:"landlord"`
			}{struct {
				Grant string `json:"grant"`
			}{result.Grant}})
		}
	default:
		return fail()
	}
	if !bytes.Equal(swarma, expected) {
		return fail()
	}
	return result, nil
}

// r1ValueMembers reads only the top-level members the channel/binding profiles
// consume. A certified exact-name recipient need not carry a Link binding.
func r1ValueMembers(raw []byte) ([]byte, []byte, error) {
	if len(raw) > 520 || !utf8.Valid(raw) {
		return nil, nil, ErrR1Value
	}
	keys, values, err := objectMembers(raw)
	if err != nil {
		return nil, nil, ErrR1Value
	}
	var swarma, nostr []byte
	for i, key := range keys {
		if strings.EqualFold(key, "swarma") {
			if key != "swarma" || swarma != nil {
				return nil, nil, ErrR1Value
			}
			swarma = values[i]
		}
		if strings.EqualFold(key, "nostr") {
			if key != "nostr" || nostr != nil {
				return nil, nil, ErrR1Value
			}
			nostr = values[i]
		}
	}
	return swarma, nostr, nil
}
