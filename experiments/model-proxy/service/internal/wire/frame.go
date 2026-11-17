package wire

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"time"
)

const MaxPayload = 65536
const Profile = "codex-refresher-v0"

var ErrTooLarge = errors.New("frame_too_large")

func Read(r io.Reader) ([]byte, error) {
	var header [4]byte
	if _, e := io.ReadFull(r, header[:]); e != nil {
		return nil, e
	}
	n := binary.BigEndian.Uint32(header[:])
	if n > MaxPayload {
		return nil, ErrTooLarge
	}
	if n == 0 {
		return nil, ErrMalformed
	}
	b := make([]byte, n)
	_, e := io.ReadFull(r, b)
	if e != nil {
		clear(b)
		return nil, e
	}
	if _, e = Parse(b); e != nil {
		clear(b)
		return nil, e
	}
	return b, nil
}
func Write(w io.Writer, v any) error {
	b, e := Encode(v)
	if e != nil {
		return e
	}
	if len(b) > MaxPayload {
		return ErrTooLarge
	}
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(b)))
	for _, p := range [][]byte{h[:], b} {
		for len(p) > 0 {
			n, e := w.Write(p)
			if e != nil {
				return e
			}
			if n == 0 {
				return io.ErrShortWrite
			}
			p = p[n:]
		}
	}
	return nil
}

// Decode validates required members and recursively rejects unknown struct fields.
func Decode(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return ErrMalformed
	}
	x, e := parse(b)
	if e != nil {
		return ErrMalformed
	}
	return required(x, reflect.TypeOf(v).Elem())
}
func required(x any, t reflect.Type) error {
	if t == reflect.TypeFor[json.RawMessage]() {
		return nil
	}
	// encoding/json silently maps null primitives to zero values, including
	// array elements. Only explicitly nullable pointers/raw JSON accept null.
	if x == nil {
		if t.Kind() == reflect.Pointer {
			return nil
		}
		return ErrMalformed
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() == reflect.Slice || t.Kind() == reflect.Array {
		if xs, ok := x.([]any); ok {
			for _, item := range xs {
				if e := required(item, t.Elem()); e != nil {
					return e
				}
			}
		}
		return nil
	}
	if t == reflect.TypeFor[time.Time]() {
		return nil
	}
	if t.Kind() != reflect.Struct {
		return nil
	}
	m, ok := x.(map[string]any)
	if !ok {
		return ErrMalformed
	}
	allowed := map[string]bool{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name := strings.Split(f.Tag.Get("json"), ",")[0]
		if name == "" {
			name = f.Name
		}
		allowed[name] = true
	}
	for name := range m {
		if !allowed[name] {
			return ErrMalformed
		}
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := strings.Split(f.Tag.Get("json"), ",")
		if tag[0] == "-" {
			continue
		}
		name := tag[0]
		if name == "" {
			name = f.Name
		}
		v, ok := m[name]
		optional := len(tag) > 1 && tag[1] == "omitempty"
		if !ok {
			if optional {
				continue
			}
			return ErrMalformed
		}
		if v == nil {
			if f.Type.Kind() == reflect.Pointer || f.Type == reflect.TypeFor[json.RawMessage]() {
				continue
			}
			return ErrMalformed
		}
		if e := required(v, f.Type); e != nil {
			return e
		}
	}
	return nil
}
func ASCII(s string, max int) bool {
	if len(s) == 0 || len(s) > max {
		return false
	}
	for i := range len(s) {
		if s[i] > 0x7f {
			return false
		}
	}
	return true
}
