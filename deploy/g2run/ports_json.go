package g2run

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// decodePortJSON accepts ordinary JSON evidence, but never ambiguous duplicate
// keys, invalid UTF-8, trailing values, or excessive nesting. Parameters continue
// to use E1's stricter StrictJSON decoder.
func decodePortJSON(raw []byte, dst any) error {
	if len(raw) > 16<<20 || !utf8.Valid(raw) {
		return errors.New("JSON_ENCODING")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 128 {
			return errors.New("JSON_DEPTH")
		}
		tok, e := d.Token()
		if e != nil {
			return errors.New("JSON_SYNTAX")
		}
		delim, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return errors.New("JSON_SYNTAX")
				}
				key, ok := k.(string)
				if !ok || seen[key] {
					return errors.New("JSON_DUPLICATE_KEY")
				}
				seen[key] = true
				if e = walk(depth + 1); e != nil {
					return e
				}
			}
		case '[':
			for d.More() {
				if e := walk(depth + 1); e != nil {
					return e
				}
			}
		default:
			return errors.New("JSON_SYNTAX")
		}
		end, e := d.Token()
		if e != nil || (delim == '{' && end != json.Delim('}')) || (delim == '[' && end != json.Delim(']')) {
			return errors.New("JSON_SYNTAX")
		}
		return nil
	}
	if e := walk(0); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return errors.New("JSON_TRAILING")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if dec.Decode(dst) != nil {
		return errors.New("JSON_SCHEMA")
	}
	return nil
}

func portObject(v any) (map[string]any, bool) { m, ok := v.(map[string]any); return m, ok }
func portUint(v any, max uint64) (uint64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	s := n.String()
	if s == "" || strings.Trim(s, "0123456789") != "" {
		return 0, false
	}
	u, e := strconv.ParseUint(s, 10, 64)
	return u, e == nil && u <= max
}
func portInt(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, e := n.Int64()
	return i, e == nil
}

func portHex(s string, n int) bool { return len(s) == n && strings.Trim(s, "0123456789abcdef") == "" }

// ParsePortMode parses permissions as base 8; special bits and expressions are refused.
func ParsePortMode(s string) (uint32, error) {
	n, e := strconv.ParseUint(s, 8, 32)
	if e != nil || s == "" || strings.Trim(s, "01234567") != "" || n > 0777 {
		return 0, errors.New("MODE_OCTAL_RANGE")
	}
	return uint32(n), nil
}

// ParsePortCount accepts decimal digits only, bounded by the caller's contract.
func ParsePortCount(s string, max uint64) (uint64, error) {
	n, e := strconv.ParseUint(s, 10, 64)
	if e != nil || s == "" || strings.Trim(s, "0123456789") != "" || n > max {
		return 0, errors.New("COUNT_DECIMAL_RANGE")
	}
	return n, nil
}

// LandlordPin carries instance values supplied by the signed parameters.
type LandlordPin struct{ Name, Grant, Seal string }

// CheckLandlord is the g2-landlord-check port. Errors contain only fixed labels;
// the success line contains validated values and cannot inject extra records.
func CheckLandlord(showRaw, pendingRaw []byte, p LandlordPin) (string, error) {
	fail := func(s string) (string, error) { return "", errors.New("LANDLORD_" + s) }
	if !ValidOperand(p.Name) || strings.ContainsAny(p.Name, "\t ") {
		return fail("NAME_PIN")
	}
	if !portHex(p.Grant, 64) {
		return fail("GRANT_PIN")
	}
	if len(p.Seal) != 50 || !strings.HasPrefix(p.Seal, "76a914") || !strings.HasSuffix(p.Seal, "88ac") || !portHex(p.Seal, 50) {
		return fail("SEAL_PIN")
	}
	var show, pending any
	if decodePortJSON(showRaw, &show) != nil {
		return fail("NAME_SHOW_JSON")
	}
	if decodePortJSON(pendingRaw, &pending) != nil {
		return fail("NAME_PENDING_JSON")
	}
	m, ok := portObject(show)
	if !ok {
		return fail("NAME_SHOW_OBJECT")
	}
	if m["name"] != p.Name {
		return fail("NAME")
	}
	if m["expired"] != false {
		return fail("EXPIRED")
	}
	a, ok := pending.([]any)
	if !ok {
		return fail("PENDING_ARRAY")
	}
	if len(a) != 0 {
		return fail("PENDING")
	}
	raw, ok := m["value"].(string)
	if !ok {
		return fail("VALUE_STRING")
	}
	var value any
	if decodePortJSON([]byte(raw), &value) != nil {
		return fail("VALUE_JSON")
	}
	v, ok := portObject(value)
	if !ok {
		return fail("VALUE_OBJECT")
	}
	sw, ok := portObject(v["swarma"])
	if !ok {
		return fail("SWARMA_OBJECT")
	}
	ll, ok := portObject(sw["landlord"])
	if !ok {
		return fail("LANDLORD_OBJECT")
	}
	grant, ok := ll["grant"].(string)
	if !ok {
		return fail("GRANT_STRING")
	}
	if grant != p.Grant {
		return fail("GRANT_CHANGED")
	}
	height, ok := portUint(m["height"], 1<<63-1)
	if !ok {
		return fail("HEIGHT")
	}
	txid, ok := m["txid"].(string)
	if !ok || !portHex(txid, 64) {
		return fail("TXID")
	}
	return fmt.Sprintf("LANDLORD_GRANT_OK height=%d txid=%s grant=%s seal=%s\n", height, txid, p.Grant, p.Seal), nil
}

// CheckNodeRestarted returns the readback of the restarted node. The original
// script did no type checks; this port refuses malformed fields before output.
func CheckNodeRestarted(raw []byte) (string, error) {
	var m map[string]any
	if decodePortJSON(raw, &m) != nil || m == nil {
		return "", errors.New("NODE_RESTARTED_JSON")
	}
	chain, ok := m["chain"].(string)
	if !ok || !ValidOperand(chain) || strings.Trim(chain, "abcdefghijklmnopqrstuvwxyz0123456789-_") != "" {
		return "", errors.New("NODE_RESTARTED_CHAIN")
	}
	blocks, ok := portUint(m["blocks"], 1<<63-1)
	if !ok {
		return "", errors.New("NODE_RESTARTED_BLOCKS")
	}
	ibd, ok := m["initialblockdownload"].(bool)
	if !ok {
		return "", errors.New("NODE_RESTARTED_IBD")
	}
	b := "False"
	if ibd {
		b = "True"
	}
	return fmt.Sprintf("NODE_RESTARTED chain=%s blocks=%d ibd=%s\n", chain, blocks, b), nil
}
