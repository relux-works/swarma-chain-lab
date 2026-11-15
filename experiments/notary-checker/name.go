package notarycheck

import (
	"bytes"
	"encoding/json"
	"strings"
	"unicode/utf8"
)

// notaryKey follows LIP-0010 sections 2, 3 and 9: top-level extensions are
// skipped (regardless of type), but the exact authority span remains strict.
func notaryKey(raw []byte) (string, error) {
	bad := func() (string, error) { return "", refuse("NOTARY_KEY") }
	if len(raw) > 520 || !utf8.Valid(raw) {
		return bad()
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	first, e := d.Token()
	if e != nil || first != json.Delim('{') {
		return bad()
	}
	var authority json.RawMessage
	seenS, seenN := false, false
	for d.More() {
		t, e := d.Token()
		if e != nil {
			return bad()
		}
		name, ok := t.(string)
		if !ok {
			return bad()
		}
		if strings.EqualFold(name, "swarma") {
			if name != "swarma" || seenS {
				return bad()
			}
			seenS = true
		}
		if strings.EqualFold(name, "nostr") {
			if name != "nostr" || seenN {
				return bad()
			}
			seenN = true
		}
		var span json.RawMessage
		if e := d.Decode(&span); e != nil {
			return bad()
		}
		if name == "swarma" {
			authority = span
		}
	}
	end, e := d.Token()
	if e != nil || end != json.Delim('}') || d.InputOffset() != int64(len(raw)) || !seenS {
		return bad()
	}
	var binding struct {
		Notary struct {
			Attest string `json:"attest"`
		} `json:"notary"`
	}
	if !decode(authority, &binding, 520) || !key(binding.Notary.Attest) {
		return bad()
	}
	return binding.Notary.Attest, nil
}
