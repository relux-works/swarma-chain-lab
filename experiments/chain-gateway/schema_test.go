package chaingateway_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Test-only executable schema. It has no socket, node, credential or helper code.
const maxInteger = uint64(9007199254740991)

var namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9/._-]*$`)
var hashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var integerPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
var codes = []string{"unavailable", "not_found", "malformed", "rate_limited", "unauthorized", "tip_moved"}

func bad(s string) error { return errors.New(s) }

// parse rejects ambiguous keys before constructing maps and then compares all
// canonical bytes. Depth counts objects/arrays, with the root at one.
func parse(raw []byte, limit int) (map[string]any, error) {
	if !payloadSize(raw, limit) || !utf8.Valid(raw) {
		return nil, bad("size or UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func(int) (any, error)
	walk = func(depth int) (any, error) {
		t, e := d.Token()
		if e != nil {
			return nil, e
		}
		switch t {
		case json.Delim('{'):
			if depth > 8 {
				return nil, bad("depth")
			}
			m := map[string]any{}
			for d.More() {
				keyStart := d.InputOffset()
				kt, e := d.Token()
				if e != nil {
					return nil, e
				}
				k, ok := kt.(string)
				if !ok {
					return nil, bad("key type")
				}
				keyRaw := raw[keyStart:d.InputOffset()]
				if bytes.ContainsRune(keyRaw, '\\') {
					return nil, bad("escaped key")
				}
				for _, r := range k {
					if r < 0x20 || r > 0x7e {
						return nil, bad("non-ASCII key")
					}
				}
				for old := range m {
					if strings.EqualFold(old, k) {
						return nil, bad("duplicate or folded key")
					}
				}
				v, e := walk(depth + 1)
				if e != nil {
					return nil, e
				}
				m[k] = v
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return nil, bad("object end")
			}
			return m, nil
		case json.Delim('['):
			if depth > 8 {
				return nil, bad("depth")
			}
			a := []any{}
			for d.More() {
				v, e := walk(depth + 1)
				if e != nil {
					return nil, e
				}
				a = append(a, v)
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return nil, bad("array end")
			}
			return a, nil
		case nil:
			return nil, bad("null")
		default:
			switch t.(type) {
			case string, bool, json.Number:
				return t, nil
			}
			return nil, bad("token")
		}
	}
	v, e := walk(1)
	if e != nil {
		return nil, e
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, bad("trailing data")
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if e = enc.Encode(v); e != nil {
		return nil, e
	}
	if !bytes.Equal(bytes.TrimSuffix(b.Bytes(), []byte{'\n'}), raw) {
		return nil, bad("noncanonical")
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, bad("root object")
	}
	return m, nil
}

func fields(v any, keys ...string) (map[string]any, error) {
	m, ok := v.(map[string]any)
	if !ok || len(m) != len(keys) {
		return nil, bad("object fields")
	}
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			return nil, fmt.Errorf("missing exact field %s", k)
		}
	}
	return m, nil
}
func integer(v any, max uint64) bool {
	n, ok := v.(json.Number)
	if !ok || !integerPattern.MatchString(string(n)) {
		return false
	}
	u, e := strconv.ParseUint(string(n), 10, 64)
	return e == nil && u <= max
}
func str(v any) string       { s, _ := v.(string); return s }
func hash(v any) bool        { return hashPattern.MatchString(str(v)) }
func name(v any) bool        { s := str(v); return len(s) >= 1 && len(s) <= 255 && namePattern.MatchString(s) }
func network(v any) bool     { return v == "main" || v == "regtest" }
func boolean(v any) bool     { _, ok := v.(bool); return ok }
func uintValue(v any) uint64 { u, _ := strconv.ParseUint(fmt.Sprint(v), 10, 64); return u }
func tip(v any) error {
	m, e := fields(v, "hash", "height", "time")
	if e != nil {
		return e
	}
	if !hash(m["hash"]) || !integer(m["height"], maxInteger) || !integer(m["time"], maxInteger) {
		return bad("tip")
	}
	return nil
}
func outpoint(m map[string]any) bool { return hash(m["txid"]) && integer(m["vout"], 4294967295) }
func nameRecord(v any, at map[string]any) error {
	m, e := fields(v, "expired", "height", "name", "name_block_hash", "txid", "value_b64", "vout")
	if e != nil {
		return e
	}
	if !boolean(m["expired"]) || !integer(m["height"], maxInteger) || !name(m["name"]) || !hash(m["name_block_hash"]) || !outpoint(m) {
		return bad("name record")
	}
	if uintValue(m["height"]) > uintValue(at["height"]) {
		return bad("future name height")
	}
	if m["height"] == at["height"] && m["name_block_hash"] != at["hash"] {
		return bad("name block mismatch at tip")
	}
	s, ok := m["value_b64"].(string)
	if !ok {
		return bad("value type")
	}
	b, e := base64.StdEncoding.Strict().DecodeString(s)
	if e != nil || len(b) > 520 || base64.StdEncoding.EncodeToString(b) != s {
		return bad("value encoding or size")
	}
	return nil
}
func sealRecord(v any) error {
	m, e := fields(v, "state", "txid", "vout")
	if e != nil {
		return e
	}
	if !outpoint(m) || (m["state"] != "unspent" && m["state"] != "not_in_utxo_set") {
		return bad("seal record")
	}
	return nil
}
func request(m map[string]any) error {
	m, e := fields(m, "method", "params", "v")
	if e != nil {
		return e
	}
	if m["v"] != json.Number("1") {
		return bad("version")
	}
	switch m["method"] {
	case "getblockcount":
		_, e = fields(m["params"])
	case "name_show":
		var p map[string]any
		p, e = fields(m["params"], "name")
		if e == nil && !name(p["name"]) {
			e = bad("name")
		}
	case "gettxout":
		var p map[string]any
		p, e = fields(m["params"], "txid", "vout")
		if e == nil && !outpoint(p) {
			e = bad("outpoint")
		}
	default:
		e = bad("closed method set")
	}
	return e
}
func response(m map[string]any) error {
	if m["ok"] == false {
		m, e := fields(m, "error", "ok", "v")
		if e != nil {
			return e
		}
		if m["v"] != json.Number("1") {
			return bad("version")
		}
		p, e := fields(m["error"], "code")
		if e != nil {
			return e
		}
		if !slices.Contains(codes, str(p["code"])) {
			return bad("closed refusal set")
		}
		return nil
	}
	m, e := fields(m, "method", "network", "ok", "result", "tip", "v")
	if e != nil {
		return e
	}
	if m["ok"] != true || m["v"] != json.Number("1") || !network(m["network"]) {
		return bad("success envelope")
	}
	if e = tip(m["tip"]); e != nil {
		return e
	}
	at := m["tip"].(map[string]any)
	switch m["method"] {
	case "getblockcount":
		_, e = fields(m["result"])
	case "name_show":
		e = nameRecord(m["result"], at)
	case "gettxout":
		e = sealRecord(m["result"])
	default:
		e = bad("closed method set")
	}
	return e
}
func snapshot(m map[string]any) error {
	m, e := fields(m, "consistency", "mode", "names", "network", "seals", "tip", "v", "written_at")
	if e != nil {
		return e
	}
	if m["consistency"] != "bracketed" || m["mode"] != "observe_only" || m["v"] != json.Number("1") || !network(m["network"]) || !integer(m["written_at"], maxInteger) {
		return bad("snapshot envelope")
	}
	if e = tip(m["tip"]); e != nil {
		return e
	}
	at := m["tip"].(map[string]any)
	ns, ok := m["names"].([]any)
	if !ok || len(ns) < 1 || len(ns) > 16 {
		return bad("names capacity")
	}
	prev := ""
	for _, n := range ns {
		if e = nameRecord(n, at); e != nil {
			return e
		}
		s := str(n.(map[string]any)["name"])
		if s <= prev {
			return bad("name order or duplicate")
		}
		prev = s
	}
	ss, ok := m["seals"].([]any)
	if !ok || len(ss) < 1 || len(ss) > 256 {
		return bad("seals capacity")
	}
	var previous map[string]any
	for _, s := range ss {
		if e = sealRecord(s); e != nil {
			return e
		}
		cur := s.(map[string]any)
		if previous != nil && (str(cur["txid"]) < str(previous["txid"]) || (cur["txid"] == previous["txid"] && uintValue(cur["vout"]) <= uintValue(previous["vout"]))) {
			return bad("seal order or duplicate")
		}
		previous = cur
	}
	return nil
}
func validate(kind string, raw []byte) error {
	limit := 4096
	switch kind {
	case "snapshot_size":
		if !payloadSize(raw, 65536) {
			return bad("snapshot size")
		}
		return nil
	case "frame_request", "frame_response":
		if kind == "frame_request" {
			limit = 1024
		}
		if len(raw) < 2 || raw[len(raw)-1] != '\n' || len(raw)-1 > limit || bytes.ContainsRune(raw[:len(raw)-1], '\n') {
			return bad("frame")
		}
		return nil
	case "request":
		limit = 1024
	case "response":
	case "snapshot":
		limit = 65536
	default:
		return bad("unknown fixture kind")
	}
	m, e := parse(raw, limit)
	if e != nil {
		return e
	}
	switch kind {
	case "request":
		return request(m)
	case "response":
		return response(m)
	default:
		return snapshot(m)
	}
}
