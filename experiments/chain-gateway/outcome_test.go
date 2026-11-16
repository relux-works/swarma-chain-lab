package chaingateway_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"unicode/utf8"
)

// All oracles in this file model contract decisions, not operating-system or node qualification.
type qualificationInput struct {
	Platform       string   `json:"platform"`
	EndpointProof  bool     `json:"endpoint_proof"`
	DumpProtected  bool     `json:"dump_protected"`
	NodeUID        uint32   `json:"node_uid"`
	ServerUID      uint32   `json:"server_uid"`
	AllowedUIDs    []uint32 `json:"allowed_uids"`
	WorkloadUIDs   []uint32 `json:"workload_uids"`
	Dedicated      bool     `json:"dedicated"`
	InitialUser    bool     `json:"initial_user"`
	InitialNetwork bool     `json:"initial_network"`
	LoopbackBind   bool     `json:"loopback_bind"`
	LoopbackAllow  bool     `json:"loopback_allow"`
}

func qualificationOracle(q qualificationInput) bool {
	if q.Platform != "linux" || !q.EndpointProof || !q.DumpProtected {
		return false
	}
	if !q.Dedicated || !q.InitialUser || !q.InitialNetwork || !q.LoopbackBind || !q.LoopbackAllow {
		return false
	}
	if slices.Contains([]uint32{0, 65534, 65535, 4294967295}, q.NodeUID) || q.NodeUID == q.ServerUID {
		return false
	}
	return !slices.Contains(q.AllowedUIDs, q.NodeUID) && !slices.Contains(q.WorkloadUIDs, q.NodeUID)
}

type snapshotAttempt struct {
	Before     map[string]any   `json:"before"`
	After      map[string]any   `json:"after"`
	Replies    []map[string]any `json:"replies,omitempty"`
	Bestblocks []string         `json:"bestblocks,omitempty"`
	Failure    string           `json:"failure,omitempty"`
}

func fixtureTip() map[string]any {
	return map[string]any{"hash": strings.Repeat("1", 64), "height": json.Number("100"), "time": json.Number("1699999990")}
}

var publicationStages = []string{"lock", "config", "serialize", "cleanup", "ancestor_sync", "temp_create", "temp_write", "temp_validate", "temp_metadata", "file_sync", "file_close", "rename", "directory_open", "directory_sync", "directory_close", "own_temp_cleanup"}

func snapshotOutcome(attempts []snapshotAttempt, stage string) map[string]any {
	result := func(code int, renamed bool) map[string]any {
		previous := "unchanged"
		if renamed {
			previous = "replaced"
		}
		return map[string]any{"exit": json.Number(fmt.Sprint(code)), "write": renamed, "previous": previous}
	}
	if stage != "" {
		if !slices.Contains(publicationStages, stage) {
			return result(11, false)
		}
		// Only directory operations after a successful rename may leave a new file visible.
		return result(11, strings.HasPrefix(stage, "directory_"))
	}
	if len(attempts) < 1 || len(attempts) > 3 {
		return result(11, false)
	}
	for i, a := range attempts {
		moved, limited, failed := false, false, a.Failure != ""
		tips := []map[string]any{a.Before, a.After}
		for _, r := range a.Replies {
			if response(r) != nil {
				failed = true
				continue
			}
			if r["ok"] == true {
				tips = append(tips, r["tip"].(map[string]any))
				continue
			}
			switch r["error"].(map[string]any)["code"] {
			case "tip_moved":
				moved = true
			case "rate_limited":
				limited = true
			default:
				failed = true
			}
		}
		byHash := map[string]map[string]any{}
		for _, at := range tips {
			if tip(at) != nil {
				failed = true
				continue
			}
			h := str(at["hash"])
			if old, ok := byHash[h]; ok && !same(old, at) {
				failed = true
			}
			byHash[h] = at
			if !same(at, a.Before) {
				moved = true
			}
		}
		for _, h := range a.Bestblocks {
			if !hash(h) {
				failed = true
			} else if h != a.Before["hash"] {
				moved = true
			}
		}
		if failed {
			return result(11, false)
		}
		if !moved && !limited {
			return result(0, true)
		}
		if i == 2 {
			if limited {
				return result(11, false)
			}
			return result(12, false)
		}
	}
	// A fixture may not claim exhaustion after only one or two retryable attempts.
	return result(11, false)
}

// Wire inputs traverse the canonical response gate before any projection is used.
func responseInputs(objects []map[string]any, wires []string) []map[string]any {
	if wires == nil {
		return objects
	}
	out := make([]map[string]any, 0, len(wires))
	for _, w := range wires {
		if validate("response", []byte(w)) != nil {
			out = append(out, nil)
			continue
		}
		m, _ := parse([]byte(w), 4096)
		out = append(out, m)
	}
	return out
}

type reflectionInput struct {
	Mode   string `json:"mode"`
	User   string `json:"user"`
	Secret string `json:"secret"`
	Value  string `json:"value"`
}

func reflectionOracle(r reflectionInput) string {
	raw := r.User + ":" + r.Secret
	encoded := base64.StdEncoding.EncodeToString([]byte(raw))
	entries := []string{raw, encoded, "Basic " + encoded, r.Secret}
	if slices.Contains(entries, r.Value) {
		return "unavailable"
	}
	return "ok"
}

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

func upstreamOracle(u upstreamInput) string {
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
