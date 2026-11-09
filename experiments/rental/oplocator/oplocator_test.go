package oplocator

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"testing"
)

func golden(action, location byte, n int) []byte {
	b := []byte{0x6a, 3, 0x53, 0x4c, action, byte(34 + n), 1}
	b = append(b, bytes.Repeat([]byte{0x11}, 32)...)
	b = append(b, location)
	return append(b, bytes.Repeat([]byte{0x22}, n)...)
}

// Independent byte fixtures cover both defined actions and all five locations.
// The writer emits exact v1 direct pushes and the reader preserves every byte.
func TestDefinedLocations(t *testing.T) {
	for _, action := range []byte{1, 2} {
		for _, v := range []struct {
			kind byte
			n    int
			size int
		}{{0, 0, 40}, {1, 32, 72}, {2, 32, 72}, {3, 20, 60}, {4, 32, 72}} {
			t.Run(fmt.Sprintf("action%d_type%d", action, v.kind), func(t *testing.T) {
				want := golden(action, v.kind, v.n)
				var commitment [32]byte
				copy(commitment[:], bytes.Repeat([]byte{0x11}, 32))
				loc := Locator{Type: v.kind, Pointer: bytes.Repeat([]byte{0x22}, v.n)}
				script, e := Build(action, commitment, loc)
				if e != nil || len(script) != v.size || !bytes.Equal(script, want) {
					t.Fatalf("builder wire mismatch: %v", e)
				}
				m, e := Parse(want)
				if e != nil || m.Legacy || m.Action != action || m.Version != 1 || m.Commitment != commitment || m.Locator.Type != v.kind || !bytes.Equal(m.Locator.Pointer, loc.Pointer) {
					t.Fatalf("reader wire mismatch: %v", e)
				}
			})
		}
	}
}

// Each malformed frame must be classified as malformed, beside a valid grant
// frame. Alternate push encodings never fall back to the legacy bare parser.
func TestMalformedFrames(t *testing.T) {
	valid := golden(1, 1, 32)
	cases := map[string][]byte{}
	mutate := func(name string, index int, value byte) { v := bytes.Clone(valid); v[index] = value; cases[name] = v }
	for _, p := range []struct {
		name string
		push []byte
	}{{"pushdata1", []byte{0x4c, 3}}, {"pushdata2", []byte{0x4d, 3, 0}}, {"pushdata4", []byte{0x4e, 3, 0, 0, 0}}} {
		cases["header_"+p.name] = append(append([]byte{0x6a}, p.push...), valid[2:]...)
	}
	for _, p := range []struct {
		name string
		push []byte
	}{{"pushdata1", []byte{0x4c, 66}}, {"pushdata2", []byte{0x4d, 66, 0}}, {"pushdata4", []byte{0x4e, 66, 0, 0, 0}}} {
		cases["payload_"+p.name] = append(append(bytes.Clone(valid[:5]), p.push...), valid[6:]...)
	}
	cases["split_id"] = append([]byte{0x6a, 2, 0x53, 0x4c, 1, 1, 66}, valid[6:]...)
	mutate("header_op_1", 1, 0x51)
	mutate("header_op_16", 1, 0x60)
	mutate("payload_op_1", 5, 0x51)
	mutate("payload_op_16", 5, 0x60)
	mutate("wrong_protocol", 2, 0x54)
	mutate("unknown_action", 4, 3)
	mutate("private_action", 4, 0x80)
	mutate("zero_action", 4, 0)
	mutate("unknown_version", 6, 2)
	mutate("unknown_location", 39, 5)
	mutate("private_location", 39, 0x80)
	mutate("short_length", 5, 65)
	mutate("long_length", 5, 67)
	mutate("zero_length", 5, 0)
	mutate("nondirect_length", 5, 76)
	cases["extra_push"] = append(bytes.Clone(valid), 1, 0x01)
	cases["trailing_opcode"] = append(bytes.Clone(valid), 0x00)
	cases["truncated"] = bytes.Clone(valid[:71])
	cases["none_with_pointer"] = golden(1, 0, 32)
	cases["v1_with_32"] = golden(1, 3, 32)
	cases["v2_with_20"] = golden(1, 2, 20)
	cases["blob_without_pointer"] = golden(1, 1, 0)
	cases["unknown_without_pointer"] = golden(1, 5, 0)
	cases["too_short_payload"] = []byte{0x6a, 3, 0x53, 0x4c, 1, 1, 1}
	cases["legacy_trailing"] = append([]byte{0x6a, 32}, bytes.Repeat([]byte{0x11}, 33)...)
	cases["legacy_pushdata1"] = append([]byte{0x6a, 0x4c, 32}, bytes.Repeat([]byte{0x11}, 32)...)
	cases["legacy_wrong_push"] = append([]byte{0x6a, 31}, bytes.Repeat([]byte{0x11}, 32)...)
	for name, script := range cases {
		t.Run(name, func(t *testing.T) {
			m, e := Parse(script)
			if !errors.Is(e, ErrMalformed) || !reflect.DeepEqual(m, Message{}) {
				t.Fatal("malformed framing admitted")
			}
			if _, e = Parse(valid); e != nil {
				t.Fatal("valid frame refused")
			}
		})
	}
}

// Exact bare commitments remain distinguishable from v1 frames; Memo and
// non-OP_RETURN data are non-Link, and returned pointer bytes do not alias input.
func TestLegacyMemoAndOwnership(t *testing.T) {
	legacy := append([]byte{0x6a, 32}, bytes.Repeat([]byte{0x6d}, 32)...)
	m, e := Parse(legacy)
	if e != nil || !m.Legacy || m.Action != 0 || m.Locator.Type != 0 || !bytes.Equal(m.Commitment[:], legacy[2:]) {
		t.Fatal("bare legacy refused")
	}
	for _, script := range [][]byte{nil, {0x51}, {0x6a, 2, 0x6d, 2, 3, 'h', 'i', '!'}} {
		if _, e = Parse(script); !errors.Is(e, ErrNotLink) {
			t.Fatal("non-Link data treated as commitment")
		}
	}
	script := golden(1, 1, 32)
	m, e = Parse(script)
	if e != nil {
		t.Fatal(e)
	}
	script[40] = 0x33
	if m.Locator.Pointer[0] != 0x22 {
		t.Fatal("parsed pointer aliases input")
	}
}

// Writers reject undefined actions/types and every wrong pointer length without
// returning partial bytes; known neighbors remain within the 83-byte relay bound.
func TestBuilderRejects(t *testing.T) {
	var commit [32]byte
	for _, v := range []struct {
		name         string
		action, kind byte
		n            int
	}{{"action", 3, 1, 32}, {"private_action", 0xff, 1, 32}, {"type", 1, 5, 32}, {"unknown_empty", 1, 5, 0}, {"private_type", 1, 0xff, 32}, {"none_extra", 1, 0, 1}, {"blob_short", 1, 1, 31}, {"blob_long", 1, 1, 33}, {"v1_short", 1, 3, 19}, {"v1_long", 1, 3, 21}, {"v2_short", 1, 2, 31}, {"swarm_long", 1, 4, 33}} {
		t.Run(v.name, func(t *testing.T) {
			b, e := Build(v.action, commit, Locator{Type: v.kind, Pointer: make([]byte, v.n)})
			if !errors.Is(e, ErrMalformed) || len(b) != 0 {
				t.Fatal("invalid builder input accepted")
			}
			b, e = Build(1, commit, Locator{Type: 1, Pointer: make([]byte, 32)})
			if e != nil || len(b) != 72 || len(b) > 83 {
				t.Fatal("valid builder neighbor refused")
			}
		})
	}
}

// This exact public vector fixes byte offsets independently of Build/Parse.
func TestIssuanceGolden(t *testing.T) {
	raw, e := hex.DecodeString("6a03534c014201" + "1111111111111111111111111111111111111111111111111111111111111111" + "01" + "2222222222222222222222222222222222222222222222222222222222222222")
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(raw, golden(1, 1, 32)) {
		t.Fatal("golden fixture drift")
	}
}
