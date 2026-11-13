package modelproxy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/relux-works/swarma-chain-lab/experiments/single-use/modelprofile"
)

const OpenAIResponsesProfile = modelprofile.OpenAIResponsesProfile
const MaxResponsesBody = 2 << 20
const MaxResponsesEvent = 256 << 10

// ModelProfile is keyed by an existing exact model ID. It never supplies price
// defaults or accepts client-selected endpoints. Omission retains legacy bytes.
type ModelProfile = modelprofile.ModelProfile

func validateProfiles(c Config) (map[string]ModelProfile, error) {
	out := make(map[string]ModelProfile, len(c.ModelProfiles))
	for id, p := range c.ModelProfiles {
		_, exists := c.Models[id]
		u, e := url.Parse(p.Upstream)
		if !exists || p.Profile != OpenAIResponsesProfile || !validURL(p.Upstream) || e != nil || !strings.HasSuffix(u.Path, "/v1/responses") {
			return nil, fail("CONFIG_PROFILE")
		}
		out[id] = p
	}
	if len(out) > 0 {
		u, _ := url.Parse(c.Upstream)
		if len(out) == len(c.Models) {
			if !strings.HasSuffix(u.Path, "/v1/responses") {
				return nil, fail("CONFIG_PROFILE")
			}
		} else if u.Path != "/v1/messages" {
			return nil, fail("CONFIG_PROFILE")
		}
	}
	return out, nil
}

type Responses struct{}

func (Responses) Profile() string { return OpenAIResponsesProfile }
func (Responses) Headers(h http.Header, key Secret) {
	h.Set("Content-Type", "application/json")
	h.Set("Authorization", "Bearer "+string(key))
}

func word(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
func textField(m map[string]json.RawMessage, key string) (string, bool) {
	v, ok := str(m[key])
	return v, ok
}
func array(raw []byte, max int, empty bool) ([]json.RawMessage, bool) {
	var a []json.RawMessage
	e := json.Unmarshal(raw, &a)
	return a, e == nil && a != nil && len(a) <= max && (empty || len(a) > 0)
}
func optionalString(m map[string]json.RawMessage, key string) bool {
	v, found := m[key]
	if !found {
		return true
	}
	_, ok := str(v)
	return ok
}
func optionalBool(m map[string]json.RawMessage, key string) bool {
	v, found := m[key]
	return !found || string(v) == "true" || string(v) == "false"
}
func toolNames(raw []byte) (map[string]bool, bool) {
	names := map[string]bool{}
	if raw == nil {
		return names, true
	}
	a, ok := array(raw, 128, true)
	if !ok {
		return nil, false
	}
	for _, b := range a {
		m, e := object(b)
		typ, _ := str(m["type"])
		name, valid := str(m["name"])
		_, params := object(m["parameters"])
		if e != nil || !only(m, "type", "name", "parameters", "description", "strict") || typ != "function" || !valid || !word(name) || names[name] || params != nil || !optionalString(m, "description") || !optionalBool(m, "strict") {
			return nil, false
		}
		names[name] = true
	}
	return names, true
}
func inputText(raw []byte, assistant bool) bool {
	if _, ok := str(raw); ok {
		return true
	}
	a, ok := array(raw, 128, false)
	if !ok {
		return false
	}
	for _, raw := range a {
		m, e := object(raw)
		typ, _ := str(m["type"])
		_, txt := str(m["text"])
		if e != nil || !txt {
			return false
		}
		if typ == "input_text" && only(m, "type", "text") {
			continue
		}
		if assistant && typ == "output_text" && validPart(raw, false) {
			continue
		}
		return false
	}
	return true
}
func inputItems(raw []byte, tools map[string]bool) bool {
	if _, ok := str(raw); ok {
		return true
	}
	a, ok := array(raw, 1024, false)
	if !ok {
		return false
	}
	calls, outputs := map[string]bool{}, map[string]bool{}
	for _, b := range a {
		m, e := object(b)
		if e != nil {
			return false
		}
		typ, _ := str(m["type"])
		switch typ {
		case "", "message":
			if typ == "" && m["type"] != nil {
				return false
			}
			role, _ := str(m["role"])
			if !only(m, "type", "role", "content", "id", "status") || (role != "user" && role != "system" && role != "developer" && role != "assistant") || !inputText(m["content"], role == "assistant") {
				return false
			}
			if v, exists := m["id"]; exists {
				id, ok := str(v)
				if !ok || !word(id) || role != "assistant" {
					return false
				}
			}
			if v, exists := m["status"]; exists {
				if string(v) != `"completed"` || role != "assistant" {
					return false
				}
			}
		case "function_call":
			id, _ := str(m["call_id"])
			name, _ := str(m["name"])
			args, ok := str(m["arguments"])
			_, e := object([]byte(args))
			if !only(m, "type", "call_id", "name", "arguments", "id", "status") || !word(id) || calls[id] || !tools[name] || !ok || e != nil {
				return false
			}
			if v, exists := m["id"]; exists {
				id, ok := str(v)
				if !ok || !word(id) {
					return false
				}
			}
			if v, exists := m["status"]; exists && string(v) != `"completed"` {
				return false
			}
			calls[id] = true
		case "function_call_output":
			id, _ := str(m["call_id"])
			_, ok := str(m["output"])
			if !only(m, "type", "call_id", "output") || !calls[id] || outputs[id] || !ok {
				return false
			}
			outputs[id] = true
		default:
			return false
		}
	}
	return true
}

func (Responses) Parse(raw []byte) (Prepared, error) {
	var p Prepared
	if len(raw) == 0 || len(raw) > MaxResponsesBody {
		return p, fail("BODY")
	}
	m, e := object(raw)
	if e != nil || !only(m, "model", "input", "instructions", "tools", "stream", "max_output_tokens") {
		return p, fail("REQUEST")
	}
	var ok bool
	p.Model, ok = str(m["model"])
	if !ok || len(p.Model) < 1 || len(p.Model) > 128 {
		return p, fail("REQUEST")
	}
	p.MaxTokens, ok = integer(m["max_output_tokens"])
	if !ok || p.MaxTokens == 0 || !optionalBool(m, "stream") || !optionalString(m, "instructions") {
		return p, fail("REQUEST")
	}
	tools, ok := toolNames(m["tools"])
	if !ok || !inputItems(m["input"], tools) {
		return p, fail("REQUEST")
	}
	p.Stream = string(m["stream"]) == "true"
	m["store"] = json.RawMessage("false")
	m["background"] = json.RawMessage("false")
	m["service_tier"] = json.RawMessage(`"default"`)
	p.Body = privateCanonical(m)
	if len(p.Body) > MaxResponsesBody {
		return Prepared{}, fail("BODY")
	}
	return p, nil
}

func responseUsage(raw []byte) (Usage, error) {
	m, e := object(raw)
	i, a := integer(m["input_tokens"])
	o, b := integer(m["output_tokens"])
	t, c := integer(m["total_tokens"])
	total, fits := add(i, o)
	if e != nil || !only(m, "input_tokens", "output_tokens", "total_tokens", "input_tokens_details", "output_tokens_details") || !a || !b || !c || !fits || total != t {
		return Usage{}, fail("USAGE")
	}
	for _, d := range []struct {
		name, field string
		limit       uint64
	}{{"input_tokens_details", "cached_tokens", i}, {"output_tokens_details", "reasoning_tokens", o}} {
		if raw, exists := m[d.name]; exists {
			fields, e := object(raw)
			n, ok := integer(fields[d.field])
			if e != nil || !only(fields, d.field) || !ok || n > d.limit {
				return Usage{}, fail("USAGE")
			}
		}
	}
	return Usage{i, o}, nil
}

func emptyArray(m map[string]json.RawMessage, key string) bool {
	v, exists := m[key]
	if !exists {
		return true
	}
	a, ok := array(v, 0, true)
	return ok && len(a) == 0
}
func validPart(raw []byte, start bool) bool {
	m, e := object(raw)
	typ, _ := str(m["type"])
	if e != nil {
		return false
	}
	field := "text"
	if typ == "refusal" {
		field = "refusal"
	} else if typ != "output_text" {
		return false
	}
	txt, ok := str(m[field])
	return ok && (!start || txt == "") && only(m, "type", field, "annotations", "logprobs") && emptyArray(m, "annotations") && emptyArray(m, "logprobs")
}
func validOutput(raw []byte, tools map[string]bool, start bool) bool {
	m, e := object(raw)
	id, _ := str(m["id"])
	typ, _ := str(m["type"])
	status, _ := str(m["status"])
	if e != nil || !word(id) || (start && status != "in_progress") || (!start && status != "completed") {
		return false
	}
	switch typ {
	case "message":
		role, _ := str(m["role"])
		a, ok := array(m["content"], 128, start)
		if !only(m, "id", "type", "role", "content", "status") || role != "assistant" || !ok || (start && len(a) != 0) {
			return false
		}
		for _, b := range a {
			if !validPart(b, false) {
				return false
			}
		}
	case "function_call":
		call, _ := str(m["call_id"])
		name, _ := str(m["name"])
		args, ok := str(m["arguments"])
		if !only(m, "id", "type", "call_id", "name", "arguments", "status") || !word(call) || !tools[name] || !ok {
			return false
		}
		if start {
			return args == ""
		}
		if _, e := object([]byte(args)); e != nil {
			return false
		}
	default:
		return false
	}
	return true
}
func responseObject(raw []byte, p Prepared, start bool) (string, []json.RawMessage, Usage, error) {
	m, e := object(raw)
	id, _ := str(m["id"])
	typ, _ := str(m["object"])
	model, _ := str(m["model"])
	status, _ := str(m["status"])
	if e != nil || !word(id) || typ != "response" || model != p.Model || (start && status != "in_progress") || (!start && status != "completed") {
		return "", nil, Usage{}, fail("RESPONSE")
	}
	// Metadata is not projected into authority. Billing/storage dimensions and
	// executable output types are validated independently below.
	for _, key := range []string{"error", "incomplete_details", "previous_response_id"} {
		if v, exists := m[key]; exists && string(v) != "null" {
			return "", nil, Usage{}, fail("RESPONSE")
		}
	}
	for _, key := range []string{"store", "background"} {
		if v, exists := m[key]; exists && string(v) != "false" {
			return "", nil, Usage{}, fail("RESPONSE")
		}
	}
	if v, exists := m["service_tier"]; exists && string(v) != `"default"` {
		return "", nil, Usage{}, fail("RESPONSE")
	}
	if v, exists := m["max_output_tokens"]; exists {
		n, ok := integer(v)
		if !ok || n != p.MaxTokens {
			return "", nil, Usage{}, fail("RESPONSE")
		}
	}
	request, _ := object(p.Body)
	tools, _ := toolNames(request["tools"])
	if v, exists := m["tools"]; exists {
		echo, ok := toolNames(v)
		if !ok || len(echo) != len(tools) {
			return "", nil, Usage{}, fail("RESPONSE")
		}
		for name := range echo {
			if !tools[name] {
				return "", nil, Usage{}, fail("RESPONSE")
			}
		}
	}
	out, ok := array(m["output"], 128, true)
	if !ok || (start && len(out) != 0) {
		return "", nil, Usage{}, fail("RESPONSE")
	}
	ids, calls := map[string]bool{}, map[string]bool{}
	for _, b := range out {
		if !validOutput(b, tools, false) {
			return "", nil, Usage{}, fail("RESPONSE")
		}
		o, _ := object(b)
		id, _ := str(o["id"])
		call, _ := str(o["call_id"])
		if ids[id] || (call != "" && calls[call]) {
			return "", nil, Usage{}, fail("RESPONSE")
		}
		ids[id] = true
		if call != "" {
			calls[call] = true
		}
	}
	if start {
		if v, exists := m["usage"]; exists && string(v) != "null" {
			return "", nil, Usage{}, fail("USAGE")
		}
		return id, out, Usage{}, nil
	}
	u, e := responseUsage(m["usage"])
	return id, out, u, e
}
func (Responses) Complete(raw []byte, p Prepared) (Usage, error) {
	_, _, u, e := responseObject(raw, p, false)
	return u, e
}
func (Responses) Stream(p Prepared) StreamDecoder {
	m, _ := object(p.Body)
	tools, _ := toolNames(m["tools"])
	return &responsesStream{p: p, tools: tools, ids: map[string]bool{}, calls: map[string]bool{}}
}
func sameValue(a, b []byte) bool {
	var x, y any
	da, db := json.NewDecoder(bytes.NewReader(a)), json.NewDecoder(bytes.NewReader(b))
	da.UseNumber()
	db.UseNumber()
	return da.Decode(&x) == nil && db.Decode(&y) == nil && bytes.Equal(privateCanonical(x), privateCanonical(y))
}

var _ Dialect = Responses{}
