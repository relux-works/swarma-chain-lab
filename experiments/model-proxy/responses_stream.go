package modelproxy

import "encoding/json"

type responsePart struct {
	kind, text     string
	textDone, done bool
}
type responseItem struct {
	id, kind, call, name, arguments string
	argumentsDone                   bool
	parts                           []*responsePart
	final                           json.RawMessage
}
type responsesStream struct {
	p                      Prepared
	tools, ids, calls      map[string]bool
	begun, progress, ended bool
	sequence               uint64
	id                     string
	items                  []*responseItem
}

func (s *responsesStream) Event(name string, raw []byte) (*Usage, bool, error) {
	bad := func() (*Usage, bool, error) { return nil, false, fail("STREAM") }
	m, e := object(raw)
	typ, _ := str(m["type"])
	seq, ok := integer(m["sequence_number"])
	if e != nil || name != typ || !ok || s.ended || (s.begun && seq <= s.sequence) {
		return bad()
	}
	if !s.begun && name != "response.created" {
		return bad()
	}
	s.sequence = seq
	switch name {
	case "response.created", "response.in_progress":
		if !only(m, "type", "sequence_number", "response") || (name == "response.created" && s.begun) || (name == "response.in_progress" && (s.progress || len(s.items) != 0)) {
			return bad()
		}
		id, _, _, e := responseObject(m["response"], s.p, true)
		if e != nil || (s.begun && id != s.id) {
			return bad()
		}
		s.id, s.begun = id, true
		if name == "response.in_progress" {
			s.progress = true
		}
	case "response.completed":
		if !only(m, "type", "sequence_number", "response") {
			return bad()
		}
		id, out, u, e := responseObject(m["response"], s.p, false)
		if e != nil || id != s.id || len(out) != len(s.items) {
			return bad()
		}
		for i, item := range s.items {
			if item.final == nil || !sameValue(out[i], item.final) {
				return bad()
			}
		}
		s.ended = true
		return &u, true, nil
	case "response.output_item.added":
		index, ok := integer(m["output_index"])
		if !only(m, "type", "sequence_number", "output_index", "item") || !ok || index != uint64(len(s.items)) || index >= 128 || !validOutput(m["item"], s.tools, true) {
			return bad()
		}
		o, _ := object(m["item"])
		id, _ := str(o["id"])
		kind, _ := str(o["type"])
		call, _ := str(o["call_id"])
		fn, _ := str(o["name"])
		if s.ids[id] || (call != "" && s.calls[call]) {
			return bad()
		}
		s.ids[id] = true
		if call != "" {
			s.calls[call] = true
		}
		s.items = append(s.items, &responseItem{id: id, kind: kind, call: call, name: fn})
	default:
		index, ok := integer(m["output_index"])
		if !ok || index >= uint64(len(s.items)) {
			return bad()
		}
		item := s.items[index]
		if item.final != nil {
			return bad()
		}
		if name == "response.output_item.done" {
			if !only(m, "type", "sequence_number", "output_index", "item") || !validOutput(m["item"], s.tools, false) {
				return bad()
			}
			o, _ := object(m["item"])
			id, _ := str(o["id"])
			kind, _ := str(o["type"])
			if id != item.id || kind != item.kind {
				return bad()
			}
			if kind == "function_call" {
				call, _ := str(o["call_id"])
				fn, _ := str(o["name"])
				args, _ := str(o["arguments"])
				if !item.argumentsDone || call != item.call || fn != item.name || args != item.arguments {
					return bad()
				}
			} else {
				parts, _ := array(o["content"], 128, false)
				if len(parts) != len(item.parts) {
					return bad()
				}
				for i, raw := range parts {
					p, _ := object(raw)
					typ, _ := str(p["type"])
					field := "text"
					if typ == "refusal" {
						field = "refusal"
					}
					txt, _ := str(p[field])
					if !item.parts[i].done || typ != item.parts[i].kind || txt != item.parts[i].text {
						return bad()
					}
				}
			}
			item.final = append(json.RawMessage(nil), m["item"]...)
			return nil, false, nil
		}
		id, _ := str(m["item_id"])
		if id != item.id {
			return bad()
		}
		if name == "response.function_call_arguments.delta" || name == "response.function_call_arguments.done" {
			if item.kind != "function_call" || item.argumentsDone {
				return bad()
			}
			field := "delta"
			if name == "response.function_call_arguments.done" {
				field = "arguments"
			}
			v, ok := str(m[field])
			if !ok || !only(m, "type", "sequence_number", "item_id", "output_index", field) {
				return bad()
			}
			if field == "delta" {
				if len(item.arguments)+len(v) > MaxResponse {
					return bad()
				}
				item.arguments += v
			} else {
				if _, e := object([]byte(v)); e != nil || v != item.arguments {
					return bad()
				}
				item.argumentsDone = true
			}
			return nil, false, nil
		}
		if item.kind != "message" {
			return bad()
		}
		ci, ok := integer(m["content_index"])
		if !ok {
			return bad()
		}
		if name == "response.content_part.added" {
			if !only(m, "type", "sequence_number", "item_id", "output_index", "content_index", "part") || ci != uint64(len(item.parts)) || ci >= 128 || !validPart(m["part"], true) {
				return bad()
			}
			p, _ := object(m["part"])
			typ, _ := str(p["type"])
			item.parts = append(item.parts, &responsePart{kind: typ})
			return nil, false, nil
		}
		if ci >= uint64(len(item.parts)) {
			return bad()
		}
		part := item.parts[ci]
		if part.done {
			return bad()
		}
		if name == "response.content_part.done" {
			if !only(m, "type", "sequence_number", "item_id", "output_index", "content_index", "part") || !part.textDone || !validPart(m["part"], false) {
				return bad()
			}
			p, _ := object(m["part"])
			typ, _ := str(p["type"])
			field := "text"
			if typ == "refusal" {
				field = "refusal"
			}
			txt, _ := str(p[field])
			if typ != part.kind || txt != part.text {
				return bad()
			}
			part.done = true
			return nil, false, nil
		}
		prefix := "response.output_text."
		if part.kind == "refusal" {
			prefix = "response.refusal."
		}
		if part.textDone || (name != prefix+"delta" && name != prefix+"done") {
			return bad()
		}
		field := "delta"
		if name == prefix+"done" {
			field = "text"
			if part.kind == "refusal" {
				field = "refusal"
			}
		}
		v, ok := str(m[field])
		if !ok || !only(m, "type", "sequence_number", "item_id", "output_index", "content_index", field, "logprobs") || !emptyArray(m, "logprobs") {
			return bad()
		}
		if field == "delta" {
			if len(part.text)+len(v) > MaxResponse {
				return bad()
			}
			part.text += v
		} else {
			if v != part.text {
				return bad()
			}
			part.textDone = true
		}
	}
	return nil, false, nil
}
