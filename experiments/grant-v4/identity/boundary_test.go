package identity

import (
	"bytes"
	"errors"
	"math"
	"strconv"
	"strings"
	"testing"
)

// TestV4PinBoundary proves field-bound and zero-pin refusal beside valid pins; this is point parsing, not proof of possession.
func TestV4PinBoundary(t *testing.T) {
	v := loadVectors(t)
	p := pin(t, v.Pins.Valid[0].Value)
	for _, x := range []string{"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", strings.Repeat("f", 64)} {
		if bad, err := ParsePin("02" + x); err == nil || bad.Valid() {
			t.Fatal("out-of-field pin accepted")
		}
	}
	if same, err := SameKeyAsSigning(Pin{}, p.String()[2:]); same || !errors.Is(err, ErrNoPin) {
		t.Fatal("zero pin compared")
	}
	for _, bad := range []struct {
		key string
		err error
	}{
		{"", ErrSigningKeyForm}, {strings.ToUpper(p.String()[2:]), ErrSigningKeyForm},
		{v.Pins.Invalid[7].Value[2:], ErrSigningKeyPoint},
	} {
		if same, err := SameKeyAsSigning(p, bad.key); same || !errors.Is(err, bad.err) {
			t.Fatalf("signing-key refusal: %v", err)
		}
	}
	if same, err := SameKeyAsSigning(p, p.String()[2:]); !same || err != nil {
		t.Fatal("valid comparison refused")
	}
	copyKey := p.Bytes()
	copyKey[0] ^= 1
	if p.String() != v.Pins.Valid[0].Value {
		t.Fatal("returned bytes changed the pin")
	}
}

// TestV4PushBoundary proves shortest length pushes at encoding boundaries and rejects truncation/nonminimal forms; these are profile octets, not consensus validation.
func TestV4PushBoundary(t *testing.T) {
	for _, n := range []int{0, 1, 75, 76, 255, 256, 65535} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			data := bytes.Repeat([]byte{0x01}, n)
			var head []byte
			switch {
			case n == 0:
				head = []byte{0}
			case n <= 75:
				head = []byte{byte(n)}
			case n <= 255:
				head = []byte{0x4c, byte(n)}
			default:
				head = []byte{0x4d, byte(n), byte(n >> 8)}
			}
			encoded := append(head, data...)
			got, rest, ok := readPush(encoded)
			if !ok || len(rest) != 0 || !bytes.Equal(got, data) {
				t.Fatal("shortest push rejected")
			}
			if _, _, ok := readPush(encoded[:len(encoded)-1]); ok {
				t.Fatal("truncated push accepted")
			}
		})
	}
	for _, bad := range [][]byte{nil, {0x4c}, {0x4d}, {0x4d, 0}, {0x4c, 0}, {0x4d, 1, 0, 1}, {0x4e, 0, 0, 0, 0}, {0x51}, {0x81}} {
		if _, _, ok := readPush(bad); ok {
			t.Fatalf("non-profile push %x", bad)
		}
	}
}

// TestV4ScriptMalformed proves truncations and missing witness facts cannot pass beside the exact valid script; it performs no node reads.
func TestV4ScriptMalformed(t *testing.T) {
	v := loadVectors(t)
	p, c := pin(t, v.Pins.Valid[0].Value), chain(t, v.Parameters.WitnessFrom)
	s := octets(t, v.Scripts[0].Script)
	if r, _ := ReadOutput(s, p, Height{}, c); r != Controlled {
		t.Fatal("positive control")
	}
	for cut := 0; cut < len(s); cut++ {
		if r, _ := ReadOutput(s[:cut], p, Height{}, c); r != Unsupported {
			t.Fatalf("truncation %d passed", cut)
		}
	}
	if r, _ := ReadOutput(s, Pin{}, Height{}, c); r != Unsupported {
		t.Fatal("zero pin passed")
	}
	w := octets(t, v.Scripts[8].Script)
	for _, facts := range []struct {
		h Height
		c Chain
	}{{Height{}, c}, {At(-1), c}, {At(475000), Chain{}}} {
		if r, _ := ReadOutput(w, p, facts.h, facts.c); r != Unsupported {
			t.Fatal("missing witness facts passed")
		}
	}
	if r, _ := ReadOutput(w, p, At(475000), c); r != Controlled {
		t.Fatal("witness boundary control")
	}
	if _, err := NewChain(-1); !errors.Is(err, ErrChainWitnessHeight) {
		t.Fatal("negative activation accepted")
	}
}

// TestV4WriterMalformed proves ambiguous/missing name inputs and malformed unlock/witness refuse beside their valid spends; no signature verification is claimed.
func TestV4WriterMalformed(t *testing.T) {
	v := loadVectors(t)
	p, c := pin(t, v.Pins.Valid[0].Value), chain(t, v.Parameters.WitnessFrom)
	name := []byte(v.Writers[0].Created.Name)
	_, ordinary := writerInput(t, v.Writers[0])
	_, witness := writerInput(t, v.Writers[3])
	keyInput, witnessInput := ordinary[1], witness[1]
	for _, in := range []Input{keyInput, witnessInput} {
		if CheckWriter(OpUpdate, name, []Input{in}, p, c) != WrittenByOwner {
			t.Fatal("positive control")
		}
		if CheckWriter(OpUpdate, name, []Input{in, in}, p, c) != WriterUnsupported {
			t.Fatal("ambiguous input passed")
		}
	}
	if CheckWriter(OpUpdate, name, ordinary[:1], p, c) != WriterUnsupported {
		t.Fatal("fee input substituted")
	}
	if CheckWriter(OpNone, name, ordinary, p, c) != WriterUnsupported || CheckWriter(OpUpdate, name, ordinary, Pin{}, c) != WriterUnsupported {
		t.Fatal("absent authority passed")
	}
	for cut := 0; cut < len(keyInput.Unlocking); cut++ {
		in := keyInput
		in.Unlocking = in.Unlocking[:cut]
		if CheckWriter(OpUpdate, name, []Input{in}, p, c) != WriterUnsupported {
			t.Fatalf("unlock truncation %d passed", cut)
		}
	}
	other := pin(t, v.Pins.Valid[2].Value)
	for _, items := range [][][]byte{nil, {witnessInput.Witness[0]}, {nil, p.Bytes()}, {witnessInput.Witness[0], nil}, {witnessInput.Witness[0], other.Bytes()}, {p.Bytes(), witnessInput.Witness[0]}} {
		in := witnessInput
		in.Witness = items
		if CheckWriter(OpUpdate, name, []Input{in}, p, c) != WriterUnsupported {
			t.Fatal("malformed witness passed")
		}
	}
	in := witnessInput
	in.Unlocking = []byte{0}
	if CheckWriter(OpUpdate, name, []Input{in}, p, c) != WriterUnsupported {
		t.Fatal("nonempty witness unlocking passed")
	}
}

// TestV4LiveBoundary proves invalid height refusal and overflow-safe exclusive expiry beside valid extremes; depth remains caller supplied.
func TestV4LiveBoundary(t *testing.T) {
	for _, in := range [][3]int64{{-1, 1, 1}, {2, 1, 1}, {0, 0, 0}, {0, 0, -1}} {
		if l, err := CheckLive(in[0], in[1], in[2]); l != Expired || !errors.Is(err, ErrLiveInput) {
			t.Fatal("invalid heights passed")
		}
	}
	for _, tc := range []struct {
		h, H, d int64
		want    Liveness
	}{
		{math.MaxInt64, math.MaxInt64, 1, Live}, {math.MaxInt64 - 1, math.MaxInt64, 1, Expired},
		{0, math.MaxInt64 - 1, math.MaxInt64, Live}, {0, math.MaxInt64, math.MaxInt64, Expired},
	} {
		if l, err := CheckLive(tc.h, tc.H, tc.d); err != nil || l != tc.want {
			t.Fatalf("height comparison %v %v", l, err)
		}
	}
}
