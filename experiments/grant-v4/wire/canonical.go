package wire

import (
	"bytes"
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const MaxNumber uint64 = 9007199254740991
const MaxDepth = 16

// Document holds a parsed canonical object; its representation is immutable.
type Document struct{ root *value }
type member struct {
	name  string
	value *value
}
type value struct {
	kind     byte
	text     string
	members  []member
	elements []*value
}

func (v *value) get(name string) *value {
	if v == nil || v.kind != '{' {
		return nil
	}
	for _, m := range v.members {
		if m.name == name {
			return m.value
		}
	}
	return nil
}
func (v *value) stringValue() string {
	if v != nil && v.kind == 's' {
		return v.text
	}
	return ""
}
func (d *Document) Bytes() []byte { return serialize(d.root) }

// ParseDocument applies W9.2, including whole-document refusal precedence.
// limit is the size of the object expected by the caller's place.
func ParseDocument(b []byte, limit int) (*Document, error) {
	v, err := parseDocument(b, limit)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(b, serialize(v)) {
		return nil, WireNotCanonical
	}
	return &Document{v}, nil
}

// ParseInteger reads the string form directly from its digits, without floats.
func ParseInteger(s string, bound uint64) (uint64, error) {
	if s == "" || (len(s) > 1 && s[0] == '0') {
		return 0, WireInteger
	}
	var n uint64
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return 0, WireInteger
		}
		d := uint64(s[i] - '0')
		if d > bound || n > (bound-d)/10 {
			return 0, WireInteger
		}
		n = n*10 + d
	}
	return n, nil
}

// EncodeDocument encodes the restricted value set. Accepted Go values are
// map[string]any, []any, string, bool, uint64, uint32, int and json.Number.
// Floats and nil are refused; the result is checked against the same limits.
func EncodeDocument(input any, limit int) ([]byte, error) {
	v, err := fromGo(input, 1)
	if err != nil {
		return nil, err
	}
	if v.kind != '{' {
		return nil, WireJSON
	}
	b := serialize(v)
	if len(b) > limit {
		return nil, WireSize
	}
	return b, nil
}
func validString(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 {
			return false
		}
	}
	return true
}
func fromGo(x any, depth int) (*value, error) {
	switch x := x.(type) {
	case map[string]any:
		if depth > MaxDepth {
			return nil, WireSize
		}
		v := &value{kind: '{'}
		for k, x := range x {
			if !validString(k) {
				return nil, WireString
			}
			child, err := fromGo(x, depth+1)
			if err != nil {
				return nil, err
			}
			v.members = append(v.members, member{k, child})
		}
		return v, nil
	case []any:
		if depth > MaxDepth {
			return nil, WireSize
		}
		v := &value{kind: '['}
		for _, x := range x {
			child, err := fromGo(x, depth+1)
			if err != nil {
				return nil, err
			}
			v.elements = append(v.elements, child)
		}
		return v, nil
	case string:
		if !validString(x) {
			return nil, WireString
		}
		return &value{kind: 's', text: x}, nil
	case bool:
		if x {
			return &value{kind: 't'}, nil
		}
		return &value{kind: 'f'}, nil
	case uint64:
		return numberValue(strconv.FormatUint(x, 10))
	case uint32:
		return numberValue(strconv.FormatUint(uint64(x), 10))
	case int:
		return numberValue(strconv.Itoa(x))
	case json.Number:
		return numberValue(string(x))
	default:
		return nil, WireValue
	}
}
func numberValue(s string) (*value, error) {
	if _, err := ParseInteger(s, MaxNumber); err != nil {
		return nil, WireNumber
	}
	return &value{kind: 'd', text: s}, nil
}

// The parser defers duplicate/value/number/string failures until syntax is
// known for the entire document. Syntax and excessive depth fail at their
// first byte, so malformed UTF-8 before a deep subtree wins over that subtree.
type parser struct {
	b                                  []byte
	i                                  int
	duplicate, null, number, badString bool
}

func parseDocument(b []byte, limit int) (*value, error) {
	if len(b) > limit {
		return nil, WireSize
	}
	p := parser{b: b}
	p.space()
	if p.i >= len(b) || b[p.i] != '{' {
		return nil, WireJSON
	}
	v, err := p.read(1)
	if err != nil {
		return nil, err
	}
	p.space()
	if p.i != len(b) {
		return nil, WireJSON
	}
	switch {
	case p.duplicate:
		return nil, WireDuplicate
	case p.null:
		return nil, WireValue
	case p.number:
		return nil, WireNumber
	case p.badString:
		return nil, WireString
	}
	return v, nil
}
func (p *parser) space() {
	for p.i < len(p.b) && strings.ContainsRune(" \t\r\n", rune(p.b[p.i])) {
		p.i++
	}
}
func (p *parser) take(c byte) bool {
	if p.i < len(p.b) && p.b[p.i] == c {
		p.i++
		return true
	}
	return false
}
func (p *parser) read(depth int) (*value, error) {
	p.space()
	if p.i >= len(p.b) {
		return nil, WireJSON
	}
	c := p.b[p.i]
	if c == '{' || c == '[' {
		if depth > MaxDepth {
			return nil, WireSize
		}
		p.i++
		v := &value{kind: c}
		p.space()
		end := byte('}')
		if c == '[' {
			end = ']'
		}
		if p.take(end) {
			return v, nil
		}
		seen := map[string]bool{}
		for {
			var name string
			if c == '{' {
				var err error
				name, err = p.readString()
				if err != nil {
					return nil, err
				}
				if seen[name] {
					p.duplicate = true
				}
				seen[name] = true
				p.space()
				if !p.take(':') {
					return nil, WireJSON
				}
			}
			child, err := p.read(depth + 1)
			if err != nil {
				return nil, err
			}
			if c == '{' {
				v.members = append(v.members, member{name, child})
			} else {
				v.elements = append(v.elements, child)
			}
			p.space()
			if p.take(end) {
				return v, nil
			}
			if !p.take(',') {
				return nil, WireJSON
			}
			p.space()
		}
	}
	if c == '"' {
		s, err := p.readString()
		return &value{kind: 's', text: s}, err
	}
	for _, word := range []string{"true", "false", "null"} {
		if bytes.HasPrefix(p.b[p.i:], []byte(word)) {
			p.i += len(word)
			if word == "null" {
				p.null = true
			}
			return &value{kind: word[0]}, nil
		}
	}
	start := p.i
	p.take('-')
	if !p.take('0') {
		if p.i >= len(p.b) || p.b[p.i] < '1' || p.b[p.i] > '9' {
			return nil, WireJSON
		}
		p.digits()
	}
	if p.take('.') {
		if !p.digits() {
			return nil, WireJSON
		}
	}
	if p.take('e') || p.take('E') {
		if !p.take('+') {
			p.take('-')
		}
		if !p.digits() {
			return nil, WireJSON
		}
	}
	s := string(p.b[start:p.i])
	if _, err := ParseInteger(s, MaxNumber); err != nil {
		p.number = true
	}
	return &value{kind: 'd', text: s}, nil
}
func (p *parser) digits() bool {
	start := p.i
	for p.i < len(p.b) && p.b[p.i] >= '0' && p.b[p.i] <= '9' {
		p.i++
	}
	return p.i > start
}
func (p *parser) hex4() (uint16, error) {
	if len(p.b)-p.i < 4 {
		return 0, WireJSON
	}
	var n uint16
	for range 4 {
		c := p.b[p.i]
		p.i++
		n *= 16
		switch {
		case c >= '0' && c <= '9':
			n += uint16(c - '0')
		case c >= 'a' && c <= 'f':
			n += uint16(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			n += uint16(c - 'A' + 10)
		default:
			return 0, WireJSON
		}
	}
	return n, nil
}
func (p *parser) readString() (string, error) {
	if !p.take('"') {
		return "", WireJSON
	}
	var out strings.Builder
	for p.i < len(p.b) {
		c := p.b[p.i]
		p.i++
		if c == '"' {
			return out.String(), nil
		}
		if c < 0x20 {
			return "", WireJSON
		}
		if c == '\\' {
			if p.i >= len(p.b) {
				return "", WireJSON
			}
			c = p.b[p.i]
			p.i++
			switch c {
			case '"', '\\', '/':
				out.WriteByte(c)
			case 'b', 'f', 'n', 'r', 't':
				p.badString = true
				out.WriteByte(map[byte]byte{'b': '\b', 'f': '\f', 'n': '\n', 'r': '\r', 't': '\t'}[c])
			case 'u':
				u, err := p.hex4()
				if err != nil {
					return "", err
				}
				r := rune(u)
				if u >= 0xd800 && u <= 0xdbff {
					if len(p.b)-p.i >= 6 && p.b[p.i] == '\\' && p.b[p.i+1] == 'u' {
						peek := *p
						peek.i += 2
						lo, err := peek.hex4()
						if err == nil && lo >= 0xdc00 && lo <= 0xdfff {
							r = utf16.DecodeRune(r, rune(lo))
							p.i = peek.i
						}
					}
				}
				if r >= 0xd800 && r <= 0xdfff {
					p.badString = true
					// Preserve an invalid code unit's identity for duplicate-name
					// precedence. These internal bytes can never be admitted.
					out.WriteByte(0xe0 | byte(r>>12))
					out.WriteByte(0x80 | byte(r>>6)&0x3f)
					out.WriteByte(0x80 | byte(r)&0x3f)
					continue
				}
				if r < 0x20 {
					p.badString = true
				}
				out.WriteRune(r)
			default:
				return "", WireJSON
			}
		} else if c < utf8.RuneSelf {
			out.WriteByte(c)
		} else {
			p.i--
			r, n := utf8.DecodeRune(p.b[p.i:])
			if r == utf8.RuneError && n == 1 {
				return "", WireJSON
			}
			out.WriteRune(r)
			p.i += n
		}
	}
	return "", WireJSON
}
func utf16Less(a, b string) bool {
	return slices.Compare(utf16.Encode([]rune(a)), utf16.Encode([]rune(b))) < 0
}
func appendString(b []byte, s string) []byte {
	b = append(b, '"')
	for _, r := range s {
		if r == '"' || r == '\\' {
			b = append(b, '\\')
		}
		b = utf8.AppendRune(b, r)
	}
	return append(b, '"')
}
func serialize(v *value) []byte { return appendValue(nil, v) }
func appendValue(b []byte, v *value) []byte {
	switch v.kind {
	case '{':
		ms := slices.Clone(v.members)
		slices.SortFunc(ms, func(a, b member) int {
			if a.name == b.name {
				return 0
			}
			if utf16Less(a.name, b.name) {
				return -1
			}
			return 1
		})
		b = append(b, '{')
		for i, m := range ms {
			if i > 0 {
				b = append(b, ',')
			}
			b = appendString(b, m.name)
			b = append(b, ':')
			b = appendValue(b, m.value)
		}
		return append(b, '}')
	case '[':
		b = append(b, '[')
		for i, x := range v.elements {
			if i > 0 {
				b = append(b, ',')
			}
			b = appendValue(b, x)
		}
		return append(b, ']')
	case 's':
		return appendString(b, v.text)
	case 'd':
		return append(b, v.text...)
	case 't':
		return append(b, "true"...)
	case 'f':
		return append(b, "false"...)
	default:
		panic("unvalidated value")
	}
}
