package stationlink

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// No parsed frame can reach slot authentication or delivery when its authority
// fields are ambiguous; value escapes remain intact in a valid frame.
func TestSJ1FrameKeys(t *testing.T) {
	frame := func(s string) []byte {
		var b bytes.Buffer
		binary.Write(&b, binary.BigEndian, uint32(len(s)))
		b.WriteString(s)
		return b.Bytes()
	}
	for _, raw := range []string{`{"type":"hello","type":"invalid"}`, `{"type":"invalid","type":"hello"}`, `{"type":"hello","t\u0079pe":"invalid"}`, `{"t\u0079pe":"hello"}`} {
		if f, e := ReadFrame(bytes.NewReader(frame(raw))); e == nil || f != nil {
			t.Fatal("SJ1 ambiguous frame admitted")
		}
		if f, e := ReadFrame(bytes.NewReader(frame(`{"type":"hello","content":"a\nb"}`))); e != nil || f.Content != "a\nb" {
			t.Fatal("valid neighbor refused", e)
		}
	}
}
