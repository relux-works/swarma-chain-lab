package wire

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"testing"
)

// Adapted from the pinned broker wire tests; request schemas are local fixtures.

type requestEnvelope struct {
	Method string         `json:"method"`
	Params map[string]any `json:"params"`
	ID     string         `json:"request_id"`
}

// Claim: malformed encodings cannot pass CCJ-1; adjacent Unicode/control objects round-trip canonically.
func TestCanonicalRejections(t *testing.T) {
	for name, raw := range map[string]string{"duplicate": `{"a":1,"a":2}`, "fraction": `{"a":1.0}`, "unsafe": `{"a":9007199254740992}`, "negative-zero": `{"a":-0}`, "surrogate": `{"a":"\ud800"}`, "low-surrogate": `{"a":"\udc00"}`, "order": `{"b":1,"a":2}`, "whitespace": `{ "a":1}`, "newline": "{}\n", "signature": `{"sig":null}`, "non-object": `[]`, "invalid-utf8": string([]byte{'{', '"', 'a', '"', ':', '"', 0xff, '"', '}'})} {
		t.Run(name, func(t *testing.T) {
			if _, e := Parse([]byte(raw)); e == nil {
				t.Fatal("invalid canonical object accepted")
			}
		})
	}
	for _, raw := range []string{`{}`, `{"a":[true,null,0,-12],"b":"plain"}`, "{\"a\":\"\u2028😀\",\"b\":\"\\u0000\\n\"}"} {
		m, e := Parse([]byte(raw))
		if e != nil {
			t.Fatal("valid object rejected")
		}
		b, e := Encode(m)
		if e != nil || !bytes.Equal(b, []byte(raw)) {
			t.Fatal("canonical round trip changed bytes")
		}
	}
}

type observedReader struct {
	r io.Reader
	n int
}

func (r *observedReader) Read(p []byte) (int, error) { n, e := r.r.Read(p); r.n += n; return n, e }

// Claim: an oversized prefix consumes only four bytes; zero/truncated/malformed frames fail beside a valid frame.
func TestFrameBounds(t *testing.T) {
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], MaxPayload+1)
	r := &observedReader{r: bytes.NewReader(append(h[:], bytes.Repeat([]byte("x"), 100)...))}
	if _, e := Read(r); !errors.Is(e, ErrTooLarge) || r.n != 4 {
		t.Fatal("oversize read body or wrong error")
	}
	for _, b := range [][]byte{{}, {0, 1}, {0, 0, 0, 0}, {0, 0, 0, 3, '{', '}'}, {0, 0, 0, 2, '[', ']'}} {
		if _, e := Read(bytes.NewReader(b)); e == nil {
			t.Fatal("invalid frame accepted")
		}
	}
	var b bytes.Buffer
	if Write(&b, map[string]any{"ok": true}) != nil {
		t.Fatal("write failed")
	}
	if _, e := Read(&b); e != nil {
		t.Fatal("valid frame rejected")
	}
}

// Claim: request schemas reject missing or extra fields, including nested members.
func TestClosedSchema(t *testing.T) {
	for _, raw := range []string{`{"method":"status","params":{}}`, `{"method":"status","params":{},"request_id":"a","extra":0}`} {
		var r requestEnvelope
		if Decode([]byte(raw), &r) == nil {
			t.Fatal("invalid schema accepted")
		}
	}
	var r requestEnvelope
	if Decode([]byte(`{"method":"status","params":{},"request_id":"a"}`), &r) != nil {
		t.Fatal("valid request rejected")
	}
}

// Claim: closed schemas reject case aliases, duplicate members and missing nested requirements even when a nearby valid envelope decodes.
func TestSchemaAliases(t *testing.T) {
	for _, raw := range []string{`{"METHOD":"hello","method":"status","params":{},"request_id":"a"}`, `{"method":"status","method":"hello","params":{},"request_id":"a"}`, `{"method":"status","params":{},"request_id":null}`} {
		var r requestEnvelope
		if Decode([]byte(raw), &r) == nil {
			t.Fatal("schema alias accepted")
		}
	}
	var r requestEnvelope
	if Decode([]byte(`{"method":"status","params":{},"request_id":"a"}`), &r) != nil {
		t.Fatal("valid schema refused")
	}
}

// bodyCapture retains only the allocation passed to the body read, allowing the
// test to observe its erasure after Read has returned an error.
type bodyCapture struct {
	header   []byte
	body     []byte
	captured []byte
}

func (r *bodyCapture) Read(p []byte) (int, error) {
	if len(r.header) != 0 {
		n := copy(p, r.header)
		r.header = r.header[n:]
		return n, nil
	}
	r.captured = p
	n := copy(p, r.body)
	if n < len(p) {
		return n, io.ErrUnexpectedEOF
	}
	return n, nil
}

// Claim: partial-body and canonical-parse failures erase the mutable wire-owned
// allocation before dropping it; a canonical success transfers its bytes intact.
// This observes that allocation only, not immutable parser/runtime copies.
func TestReadBodyErasure(t *testing.T) {
	for _, mode := range []string{"partial", "malformed", "noncanonical", "valid"} {
		t.Run(mode, func(t *testing.T) {
			body := []byte(`{"fixture":"body-canary"}`)
			n := len(body)
			switch mode {
			case "partial":
				n++
			case "malformed":
				body[len(body)-1] = ':'
			case "noncanonical":
				body = append([]byte(" "), body...)
				n++
			}
			var header [4]byte
			binary.BigEndian.PutUint32(header[:], uint32(n))
			r := &bodyCapture{header: header[:], body: body}
			raw, err := Read(r)
			if len(r.captured) != n {
				t.Fatal("body allocation was not observed")
			}
			if mode == "valid" {
				if err != nil || !bytes.Equal(raw, body) || !bytes.Equal(r.captured, body) {
					t.Fatal("successful body was changed")
				}
				return
			}
			expected := ErrMalformed
			if mode == "partial" {
				expected = io.ErrUnexpectedEOF
			}
			if !errors.Is(err, expected) || raw != nil {
				t.Fatal("wrong failed-read result")
			}
			if !bytes.Equal(r.captured, make([]byte, n)) {
				t.Fatal("failed-read body allocation was not cleared")
			}
		})
	}
}

// Claim: the copied production codec stays byte-identical to the pinned source.
// A changed codec requires a deliberate provenance and digest update.
func TestPinnedCodecHashes(t *testing.T) {
	for name, want := range map[string]string{
		"canonical.go": "11ef191c1ea85cafd7a95a3d37b0923284c3e6ca31b110136de70321baf02592",
		"frame.go":     "c7d735b79534d9d1965fcab22fd3444f61d6d1c541bd537a1dfe848aa2c06d47",
		"types.go":     "4d211115f8610df31c05bfc967c1fe6615ec8f6810bb256fe276d6b4b3c6a3cf",
	} {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal("pinned codec missing")
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != want {
			t.Fatal("pinned codec changed")
		}
	}
}
