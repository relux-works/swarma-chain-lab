package chaingateway

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"unicode/utf8"
)

// Shared bounded upstream profile. Fixture expectations remain in the contract corpus.
type upstreamInput struct {
	Method string `json:"method"`
	Status int    `json:"status"`
	ID     string `json:"id"`
	Body   string `json:"body"`
}

type upstreamBound struct{ bytes, depth int }

var upstreamBounds = map[string]upstreamBound{
	"getblockchaininfo": {8192, 4}, "getblockhash": {256, 1}, "getblockheader": {4096, 4},
	"name_show": {4096, 4}, "gettxout": {32768, 5},
}

// Bounded readers stop at cap+1 even if the sender has more bytes available.
func upstreamRead(r io.Reader, cap int) ([]byte, error) {
	b, e := io.ReadAll(io.LimitReader(r, int64(cap)+1))
	if e != nil || len(b) > cap {
		return nil, bad("upstream bytes")
	}
	return b, nil
}

// SJ1 is enforced during bounded tokenization, not after a map has lost duplicate keys.
func upstreamParse(raw []byte, depthLimit int) (map[string]any, error) {
	if !utf8.Valid(raw) {
		return nil, bad("upstream UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func(int) (any, error)
	walk = func(depth int) (any, error) {
		token, e := d.Token()
		if e != nil {
			return nil, e
		}
		switch token {
		case json.Delim('{'):
			if depth > depthLimit {
				return nil, bad("upstream depth")
			}
			m := map[string]any{}
			for d.More() {
				start := d.InputOffset()
				key, e := d.Token()
				if e != nil {
					return nil, e
				}
				k, ok := key.(string)
				if !ok || bytes.ContainsRune(raw[start:d.InputOffset()], '\\') {
					return nil, bad("upstream key")
				}
				for old := range m {
					if strings.EqualFold(old, k) {
						return nil, bad("upstream duplicate")
					}
				}
				m[k], e = walk(depth + 1)
				if e != nil {
					return nil, e
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return nil, bad("upstream object")
			}
			return m, nil
		case json.Delim('['):
			if depth > depthLimit {
				return nil, bad("upstream depth")
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
				return nil, bad("upstream array")
			}
			return a, nil
		default:
			return token, nil
		}
	}
	v, e := walk(1)
	if e != nil {
		return nil, e
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, bad("upstream trailing")
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, bad("upstream envelope")
	}
	return m, nil
}

func upstreamClass(u upstreamInput) string {
	bound, ok := upstreamBounds[u.Method]
	if !ok || u.ID == "" {
		return "unavailable"
	}
	raw, e := upstreamRead(strings.NewReader(u.Body), bound.bytes)
	if e != nil {
		return "unavailable"
	}
	m, e := upstreamParse(raw, bound.depth)
	if e != nil {
		return "unavailable"
	}
	m, e = fields(m, "result", "error", "id")
	if e != nil || m["id"] != u.ID {
		return "unavailable"
	}
	if m["error"] != nil {
		err, e := fields(m["error"], "code", "message")
		if e != nil || m["result"] != nil {
			return "unavailable"
		}
		if _, ok := err["message"].(string); !ok {
			return "unavailable"
		}
		if u.Status == 500 && u.Method == "name_show" && err["code"] == json.Number("-4") {
			return "not_found"
		}
		return "unavailable"
	}
	if u.Status != 200 {
		return "unavailable"
	}
	r := m["result"]
	if u.Method == "getblockhash" {
		if hash(r) {
			return "ok"
		}
		return "unavailable"
	}
	if u.Method == "gettxout" && r == nil {
		return "absent"
	}
	obj, ok := r.(map[string]any)
	if !ok {
		return "unavailable"
	}
	// Selected names are exact; unrelated extension fields remain permitted within the caps.
	selected := map[string][]string{
		"getblockchaininfo": {"chain", "initialblockdownload", "bestblockhash", "blocks"},
		"getblockheader":    {"hash", "height", "time"},
		"name_show":         {"name", "value", "txid", "vout", "height", "expired"},
		"gettxout":          {"bestblock", "confirmations", "scriptPubKey"},
	}[u.Method]
	for _, k := range selected {
		if _, ok := obj[k]; !ok {
			return "unavailable"
		}
		for actual := range obj {
			if actual != k && strings.EqualFold(actual, k) {
				return "unavailable"
			}
		}
	}
	switch u.Method {
	case "getblockchaininfo":
		if !network(obj["chain"]) || obj["initialblockdownload"] != false || !hash(obj["bestblockhash"]) || !integer(obj["blocks"], maxInteger) {
			return "unavailable"
		}
	case "getblockheader":
		if tip(map[string]any{"hash": obj["hash"], "height": obj["height"], "time": obj["time"]}) != nil {
			return "unavailable"
		}
	case "name_show":
		hexName, nameOK := obj["name"].(string)
		hexValue, valueOK := obj["value"].(string)
		n, ne := decodeHex(hexName, 255)
		_, ve := decodeHex(hexValue, 520)
		if !nameOK || !valueOK || ne != nil || ve != nil || !name(string(n)) || !outpoint(obj) || !integer(obj["height"], maxInteger) || !boolean(obj["expired"]) {
			return "unavailable"
		}
	case "gettxout":
		script, ok := obj["scriptPubKey"].(map[string]any)
		if !ok || !hash(obj["bestblock"]) || !integer(obj["confirmations"], maxInteger) {
			return "unavailable"
		}
		for k := range script {
			if k != "hex" && strings.EqualFold(k, "hex") {
				return "unavailable"
			}
		}
		x, ok := script["hex"].(string)
		if !ok {
			return "unavailable"
		}
		if _, e := decodeHex(x, 10000); e != nil {
			return "unavailable"
		}
	}
	return "ok"
}

func decodeHex(s string, cap int) ([]byte, error) {
	if len(s) > 2*cap || len(s)%2 != 0 {
		return nil, bad("hex size")
	}
	out := make([]byte, len(s)/2)
	for i := range out {
		var x byte
		for _, c := range []byte(s[2*i : 2*i+2]) {
			x *= 16
			switch {
			case c >= '0' && c <= '9':
				x += c - '0'
			case c >= 'a' && c <= 'f':
				x += c - 'a' + 10
			default:
				return nil, bad("hex")
			}
		}
		out[i] = x
	}
	return out, nil
}
