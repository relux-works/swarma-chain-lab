package service

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
)

var invalidJSON = errors.New("JSON_INVALID")

// Strict rejects unknown, duplicate, aliased and trailing members. Raw protocol
// octets are subsequently checked by the checker's canonical decoders.
func Strict(raw []byte, dst any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	depth := 0
	var walk func() error
	walk = func() error {
		depth++
		defer func() { depth-- }()
		if depth > 64 {
			return invalidJSON
		}
		tok, err := d.Token()
		if err != nil {
			return invalidJSON
		}
		if delim, ok := tok.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					k, err := d.Token()
					if err != nil {
						return invalidJSON
					}
					key, ok := k.(string)
					if !ok || seen[key] {
						return invalidJSON
					}
					seen[key] = true
					if walk() != nil {
						return invalidJSON
					}
				}
				if end, err := d.Token(); err != nil || end != json.Delim('}') {
					return invalidJSON
				}
			case '[':
				for d.More() {
					if walk() != nil {
						return invalidJSON
					}
				}
				if end, err := d.Token(); err != nil || end != json.Delim(']') {
					return invalidJSON
				}
			default:
				return invalidJSON
			}
		}
		return nil
	}
	if walk() != nil {
		return invalidJSON
	}
	if _, err := d.Token(); err != io.EOF {
		return invalidJSON
	}
	var exact func([]byte, reflect.Type) bool
	exact = func(b []byte, t reflect.Type) bool {
		if t == reflect.TypeFor[json.RawMessage]() {
			return true
		}
		if t.Kind() == reflect.Pointer {
			return exact(b, t.Elem())
		}
		if t.Kind() != reflect.Struct {
			return true
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(b, &fields) != nil || fields == nil {
			return false
		}
		allowed := map[string]reflect.Type{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			allowed[strings.Split(f.Tag.Get("json"), ",")[0]] = f.Type
		}
		for key, v := range fields {
			ft, ok := allowed[key]
			if !ok || !exact(v, ft) {
				return false
			}
		}
		return true
	}
	if !exact(raw, reflect.TypeOf(dst).Elem()) {
		return invalidJSON
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(dst) != nil {
		return invalidJSON
	}
	return nil
}
