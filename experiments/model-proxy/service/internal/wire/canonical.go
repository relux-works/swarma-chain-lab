// Package wire implements the unsigned profile envelopes and strict CCJ-1 bytes.
package wire

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strconv"
	"unicode/utf8"
)

var ErrMalformed = errors.New("invalid canonical frame")

// Parse rejects duplicates, non-integers, invalid Unicode and noncanonical bytes.
func Parse(b []byte) (map[string]any, error) {
	v, err := parse(b)
	if err != nil {
		return nil, ErrMalformed
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, ErrMalformed
	}
	canonical, err := appendValue(nil, m)
	if err != nil || !bytes.Equal(b, canonical) {
		return nil, ErrMalformed
	}
	if _, exists := m["sig"]; exists {
		return nil, ErrMalformed
	}
	return m, nil
}

func parse(b []byte) (any, error) {
	if !utf8.Valid(b) || !validEscapes(b) {
		return nil, ErrMalformed
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	v, err := value(d, 0)
	if err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, ErrMalformed
	}
	return v, nil
}
func value(d *json.Decoder, depth int) (any, error) {
	if depth > 64 {
		return nil, ErrMalformed
	}
	t, err := d.Token()
	if err != nil {
		return nil, err
	}
	switch x := t.(type) {
	case json.Delim:
		switch x {
		case '{':
			m := map[string]any{}
			for d.More() {
				k, err := d.Token()
				if err != nil {
					return nil, err
				}
				s, ok := k.(string)
				if !ok {
					return nil, ErrMalformed
				}
				if _, ok = m[s]; ok {
					return nil, ErrMalformed
				}
				v, err := value(d, depth+1)
				if err != nil {
					return nil, err
				}
				m[s] = v
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return nil, ErrMalformed
			}
			return m, nil
		case '[':
			a := []any{}
			for d.More() {
				v, err := value(d, depth+1)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return nil, ErrMalformed
			}
			return a, nil
		}
	case json.Number:
		if string(x) == "-0" {
			return nil, ErrMalformed
		}
		n, err := strconv.ParseInt(string(x), 10, 64)
		if err != nil || n > 9007199254740991 || n < -9007199254740991 {
			return nil, ErrMalformed
		}
		return n, nil
	case string, bool, nil:
		return x, nil
	}
	return nil, ErrMalformed
}

// encoding/json replaces unpaired surrogates; validate escapes before decoding.
func validEscapes(b []byte) bool {
	for i := 0; i < len(b); i++ {
		if b[i] != '"' {
			continue
		}
		i++
		for i < len(b) && b[i] != '"' {
			if b[i] != '\\' {
				i++
				continue
			}
			i++
			if i >= len(b) {
				return false
			}
			if b[i] == 'u' {
				if i+4 >= len(b) {
					return false
				}
				n, e := strconv.ParseUint(string(b[i+1:i+5]), 16, 16)
				if e != nil {
					return false
				}
				i += 4
				if n >= 0xd800 && n <= 0xdbff {
					if i+6 >= len(b) || b[i+1] != '\\' || b[i+2] != 'u' {
						return false
					}
					low, e := strconv.ParseUint(string(b[i+3:i+7]), 16, 16)
					if e != nil || low < 0xdc00 || low > 0xdfff {
						return false
					}
					i += 6
				} else if n >= 0xdc00 && n <= 0xdfff {
					return false
				}
			}
			i++
		}
		if i >= len(b) {
			return false
		}
	}
	return true
}

// Encode emits minimal JSON string escapes, including literal Unicode separators.
func Encode(v any) ([]byte, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return nil, ErrMalformed
	}
	x, e := parse(b)
	if e != nil {
		return nil, ErrMalformed
	}
	return appendValue(nil, x)
}
func quote(b []byte, s string) []byte {
	b = append(b, '"')
	for _, r := range s {
		switch r {
		case '"', '\\':
			b = append(b, '\\', byte(r))
		case '\b':
			b = append(b, '\\', 'b')
		case '\f':
			b = append(b, '\\', 'f')
		case '\n':
			b = append(b, '\\', 'n')
		case '\r':
			b = append(b, '\\', 'r')
		case '\t':
			b = append(b, '\\', 't')
		default:
			if r < 32 {
				const hex = "0123456789abcdef"
				b = append(b, '\\', 'u', '0', '0', hex[byte(r)>>4], hex[byte(r)&15])
			} else {
				b = utf8.AppendRune(b, r)
			}
		}
	}
	return append(b, '"')
}
func appendValue(b []byte, v any) ([]byte, error) {
	switch x := v.(type) {
	case nil:
		return append(b, "null"...), nil
	case bool:
		return strconv.AppendBool(b, x), nil
	case int64:
		return strconv.AppendInt(b, x, 10), nil
	case string:
		return quote(b, x), nil
	case []any:
		b = append(b, '[')
		for i, v := range x {
			if i > 0 {
				b = append(b, ',')
			}
			var e error
			b, e = appendValue(b, v)
			if e != nil {
				return nil, e
			}
		}
		return append(b, ']'), nil
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b = append(b, '{')
		for i, k := range keys {
			if i > 0 {
				b = append(b, ',')
			}
			b = quote(b, k)
			b = append(b, ':')
			var e error
			b, e = appendValue(b, x[k])
			if e != nil {
				return nil, e
			}
		}
		return append(b, '}'), nil
	}
	return nil, ErrMalformed
}
