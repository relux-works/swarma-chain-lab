package modelproxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"unicode/utf8"
)

type Prepared struct {
	Model     string
	MaxTokens uint64
	Stream    bool
	Body      []byte
}
type StreamDecoder interface {
	Event(string, []byte) (*Usage, bool, error)
}
type Dialect interface {
	Profile() string
	Parse([]byte) (Prepared, error)
	Headers(http.Header, Secret)
	Complete([]byte, Prepared) (Usage, error)
	Stream(Prepared) StreamDecoder
}
type Messages struct{}

func (Messages) Profile() string { return "anthropic-messages-text-global-standard-2026-10-21" }
func (Messages) Headers(h http.Header, key Secret) {
	h.Set("Content-Type", "application/json")
	h.Set("x-api-key", string(key))
	h.Set("anthropic-version", "2026-10-21")
}

// Reject duplicate keys at every depth before decoding; never expose parser text.
func unique(raw []byte) error {
	if !utf8.Valid(raw) {
		return fail("JSON")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 32 {
			return fail("JSON")
		}
		t, e := d.Token()
		if e != nil {
			return fail("JSON")
		}
		if delim, ok := t.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					k, e := d.Token()
					s, ok := k.(string)
					if e != nil || !ok || seen[s] {
						return fail("JSON")
					}
					seen[s] = true
					if e = value(depth + 1); e != nil {
						return e
					}
				}
				end, e := d.Token()
				if e != nil || end != json.Delim('}') {
					return fail("JSON")
				}
			case '[':
				for d.More() {
					if e = value(depth + 1); e != nil {
						return e
					}
				}
				end, e := d.Token()
				if e != nil || end != json.Delim(']') {
					return fail("JSON")
				}
			default:
				return fail("JSON")
			}
		}
		return nil
	}
	if e := value(0); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return fail("JSON")
	}
	return nil
}
func object(raw []byte) (map[string]json.RawMessage, error) {
	var m map[string]json.RawMessage
	if unique(raw) != nil || json.Unmarshal(raw, &m) != nil || m == nil {
		return nil, fail("JSON")
	}
	return m, nil
}
func only(m map[string]json.RawMessage, keys ...string) bool {
	for k := range m {
		ok := false
		for _, a := range keys {
			if k == a {
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	return true
}
func str(raw []byte) (string, bool) {
	var v string
	e := json.Unmarshal(raw, &v)
	return v, e == nil && len(raw) > 0 && !bytes.Equal(raw, []byte("null"))
}
func integer(raw []byte) (uint64, bool) {
	n, e := strconv.ParseUint(string(raw), 10, 64)
	return n, e == nil && strconv.FormatUint(n, 10) == string(raw)
}
func textContent(raw []byte) bool {
	if _, ok := str(raw); ok {
		return true
	}
	var blocks []json.RawMessage
	if json.Unmarshal(raw, &blocks) != nil || len(blocks) == 0 || len(blocks) > 128 {
		return false
	}
	for _, b := range blocks {
		m, e := object(b)
		typ, ok := str(m["type"])
		_, text := str(m["text"])
		if e != nil || !only(m, "type", "text") || !ok || typ != "text" || !text {
			return false
		}
	}
	return true
}
func (Messages) Parse(raw []byte) (Prepared, error) {
	var p Prepared
	if len(raw) == 0 || len(raw) > MaxBody {
		return p, fail("BODY")
	}
	m, e := object(raw)
	if e != nil || !only(m, "model", "max_tokens", "stream", "messages", "system") {
		return p, fail("REQUEST")
	}
	var ok bool
	p.Model, ok = str(m["model"])
	if !ok {
		return p, fail("REQUEST")
	}
	p.MaxTokens, ok = integer(m["max_tokens"])
	if !ok || p.MaxTokens == 0 {
		return p, fail("REQUEST")
	}
	if v, exists := m["stream"]; exists {
		if string(v) != "true" && string(v) != "false" {
			return p, fail("REQUEST")
		}
		p.Stream = string(v) == "true"
	}
	if v, exists := m["system"]; exists && !textContent(v) {
		return p, fail("REQUEST")
	}
	var msgs []json.RawMessage
	if json.Unmarshal(m["messages"], &msgs) != nil || len(msgs) == 0 || len(msgs) > 128 {
		return p, fail("REQUEST")
	}
	for _, raw := range msgs {
		msg, e := object(raw)
		role, ok := str(msg["role"])
		if e != nil || !only(msg, "role", "content") || !ok || (role != "user" && role != "assistant") || !textContent(msg["content"]) {
			return p, fail("REQUEST")
		}
	}
	// The priced profile never inherits workspace priority or regional defaults.
	m["service_tier"] = json.RawMessage(`"standard_only"`)
	m["inference_geo"] = json.RawMessage(`"global"`)
	p.Body = canonical(m)
	if len(p.Body) > MaxBody {
		return Prepared{}, fail("BODY")
	}
	return p, nil
}
func readUsage(raw []byte, prior *Usage) (Usage, error) {
	var u Usage
	if prior != nil {
		u = *prior
	}
	m, e := object(raw)
	if e != nil || !only(m, "input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens", "cache_creation", "server_tool_use", "service_tier", "speed", "inference_geo", "output_tokens_details") {
		return u, fail("USAGE")
	}
	if v, ok := m["input_tokens"]; ok {
		n, valid := integer(v)
		if !valid || (prior != nil && n < prior.Input) {
			return u, fail("USAGE")
		}
		u.Input = n
	} else if prior == nil {
		return u, fail("USAGE")
	}
	n, ok := integer(m["output_tokens"])
	if !ok || (prior != nil && n < prior.Output) {
		return u, fail("USAGE")
	}
	u.Output = n
	for _, k := range []string{"cache_creation_input_tokens", "cache_read_input_tokens"} {
		if v, ok := m[k]; ok && string(v) != "null" {
			n, valid := integer(v)
			if !valid || n != 0 {
				return u, fail("USAGE")
			}
		}
	}
	for _, k := range []string{"cache_creation", "server_tool_use", "output_tokens_details"} {
		if v, ok := m[k]; ok && string(v) != "null" {
			fields, e := object(v)
			if e != nil {
				return u, fail("USAGE")
			}
			for _, v := range fields {
				n, ok := integer(v)
				if !ok || n != 0 {
					return u, fail("USAGE")
				}
			}
		}
	}
	for _, k := range []string{"service_tier", "speed"} {
		if v, ok := m[k]; ok {
			value, valid := str(v)
			if !valid || value != "standard" {
				return u, fail("USAGE")
			}
		}
	}
	if v, ok := m["inference_geo"]; ok {
		value, valid := str(v)
		if !valid || value != "global" {
			return u, fail("USAGE")
		}
	}
	return u, nil
}
func stopReason(raw []byte) bool {
	v, ok := str(raw)
	return ok && (v == "end_turn" || v == "max_tokens" || v == "stop_sequence" || v == "refusal" || v == "model_context_window_exceeded")
}
func message(raw []byte, p Prepared, start bool) (Usage, error) {
	m, e := object(raw)
	typ, _ := str(m["type"])
	role, _ := str(m["role"])
	model, _ := str(m["model"])
	if e != nil || typ != "message" || role != "assistant" || model != p.Model {
		return Usage{}, fail("UPSTREAM")
	}
	var blocks []json.RawMessage
	if json.Unmarshal(m["content"], &blocks) != nil || blocks == nil || len(blocks) > 128 {
		return Usage{}, fail("UPSTREAM")
	}
	if start {
		if len(blocks) != 0 || string(m["stop_reason"]) != "null" {
			return Usage{}, fail("UPSTREAM")
		}
	} else {
		if !stopReason(m["stop_reason"]) {
			return Usage{}, fail("UPSTREAM")
		}
		for _, raw := range blocks {
			b, e := object(raw)
			typ, _ := str(b["type"])
			_, ok := str(b["text"])
			if e != nil || typ != "text" || !ok || !only(b, "type", "text", "citations") {
				return Usage{}, fail("UPSTREAM")
			}
			if v, ok := b["citations"]; ok && string(v) != "null" && string(v) != "[]" {
				return Usage{}, fail("UPSTREAM")
			}
		}
	}
	return readUsage(m["usage"], nil)
}
func (Messages) Complete(raw []byte, p Prepared) (Usage, error) { return message(raw, p, false) }
func (Messages) Stream(p Prepared) StreamDecoder                { return &messageStream{p: p} }

type messageStream struct {
	p                           Prepared
	begun, ended, delta, reason bool
	index                       uint64
	block                       bool
	usage                       Usage
}

func (s *messageStream) Event(name string, raw []byte) (*Usage, bool, error) {
	bad := func() (*Usage, bool, error) { return nil, false, fail("STREAM") }
	m, e := object(raw)
	typ, _ := str(m["type"])
	if e != nil || typ != name || s.ended {
		return bad()
	}
	switch name {
	case "ping":
		if !only(m, "type") {
			return bad()
		}
		return nil, false, nil
	case "message_start":
		if s.begun || !only(m, "type", "message") {
			return bad()
		}
		u, e := message(m["message"], s.p, true)
		if e != nil {
			return bad()
		}
		s.usage = u
		s.begun = true
	case "content_block_start":
		idx, ok := integer(m["index"])
		b, e := object(m["content_block"])
		typ, _ := str(b["type"])
		_, txt := str(b["text"])
		if !s.begun || s.block || s.delta || !ok || idx != s.index || s.index >= 128 || e != nil || typ != "text" || !txt || !only(m, "type", "index", "content_block") || !only(b, "type", "text", "citations") {
			return bad()
		}
		if v, ok := b["citations"]; ok && string(v) != "null" && string(v) != "[]" {
			return bad()
		}
		s.block = true
	case "content_block_delta":
		idx, ok := integer(m["index"])
		d, e := object(m["delta"])
		typ, _ := str(d["type"])
		_, txt := str(d["text"])
		if !s.block || !ok || idx != s.index || e != nil || typ != "text_delta" || !txt || !only(m, "type", "index", "delta") || !only(d, "type", "text") {
			return bad()
		}
	case "content_block_stop":
		idx, ok := integer(m["index"])
		if !s.block || !ok || idx != s.index || !only(m, "type", "index") {
			return bad()
		}
		s.block = false
		s.index++
	case "message_delta":
		if !s.begun || s.block || !only(m, "type", "delta", "usage") {
			return bad()
		}
		d, e := object(m["delta"])
		if e != nil || !only(d, "stop_reason", "stop_sequence") {
			return bad()
		}
		if v, ok := d["stop_reason"]; ok && string(v) != "null" {
			if !stopReason(v) {
				return bad()
			}
			s.reason = true
		}
		u, e := readUsage(m["usage"], &s.usage)
		if e != nil {
			return bad()
		}
		s.usage = u
		s.delta = true
	case "message_stop":
		if !s.begun || s.block || !s.delta || !s.reason || !only(m, "type") {
			return bad()
		}
		s.ended = true
		u := s.usage
		return &u, true, nil
	default:
		return bad()
	}
	return nil, false, nil
}
