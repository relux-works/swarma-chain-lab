package identity

import (
	"bytes"
	"errors"
)

// Prefix is the operation of a supported name prefix (O3.2).
type Prefix int

const (
	// PrefixNone: the script starts with none of the three supported
	// prefixes. It is the zero value.
	PrefixNone Prefix = iota
	// PrefixUpdate: name_update, 53 P(name) P(value) 6d 75.
	PrefixUpdate
	// PrefixRegistration: name_firstupdate, 52 P(name) P(rand) P(value) 6d 6d.
	PrefixRegistration
	// PrefixReservation: name_new, 51 P(hash) 6d with a hash of 20 octets.
	PrefixReservation
)

func (p Prefix) String() string {
	switch p {
	case PrefixUpdate:
		return "update"
	case PrefixRegistration:
		return "registration"
	case PrefixReservation:
		return "reservation"
	}
	return "none"
}

// Reading is the outcome of O3.4. The zero value is Unsupported, so a reading
// that was never made proves nothing.
type Reading int

const (
	// Unsupported: every script that is not Controlled or AnotherKey. It is
	// no evidence of a change of owner and none against one (O3.5).
	Unsupported Reading = iota
	// Controlled: a supported prefix and a supported address script with
	// the 20 octets of the pin.
	Controlled
	// AnotherKey: a supported prefix and a supported address script with
	// other 20 octets.
	AnotherKey
)

func (r Reading) String() string {
	switch r {
	case Controlled:
		return "controlled"
	case AnotherKey:
		return "another key"
	}
	return "unsupported"
}

// Height is a stated block height, or the absence of one. The zero value is
// unknown.
type Height struct {
	h     int64
	known bool
}

// At states a height. A negative height is no height and stays unknown.
func At(h int64) Height {
	if h < 0 {
		return Height{}
	}
	return Height{h: h, known: true}
}

// Value returns the height and whether one was stated.
func (h Height) Value() (int64, bool) { return h.h, h.known }

// Chain holds the chain parameter that O3.3 needs: the height from which the
// pinned chain enforces the witness rules. The value is the caller's; this
// module carries no production value. The zero value is no chain, and under
// it every witness key hash reads as unsupported.
type Chain struct {
	witnessFrom int64
	set         bool
}

// ErrChainWitnessHeight reports a negative witness height.
var ErrChainWitnessHeight = errors.New("identity: witness height is negative")

// NewChain states the height from which the chain enforces the witness rules.
func NewChain(witnessFromHeight int64) (Chain, error) {
	if witnessFromHeight < 0 {
		return Chain{}, ErrChainWitnessHeight
	}
	return Chain{witnessFrom: witnessFromHeight, set: true}, nil
}

// NameScript is the split of an output script under O3.2. Only the octets of
// the pushes are kept; the opcodes are fixed by the prefix.
type NameScript struct {
	Prefix        Prefix
	Name          []byte // update and registration
	Rand          []byte // registration
	Value         []byte // update and registration
	Hash          []byte // reservation, 20 octets
	AddressScript []byte // the octets after the prefix
}

// readPush reads one push at s[0:] in the shortest form P(x) of section 3
// and returns the pushed octets and the rest. Any other spelling, including a
// longer form than needed, a 4e push and a truncated push, is no push.
func readPush(s []byte) (data, rest []byte, ok bool) {
	if len(s) == 0 {
		return nil, nil, false
	}
	op := s[0]
	var n, head int
	switch {
	case op == 0x00:
		return []byte{}, s[1:], true
	case op >= 0x01 && op <= 0x4b:
		n, head = int(op), 1
	case op == 0x4c:
		if len(s) < 2 {
			return nil, nil, false
		}
		n, head = int(s[1]), 2
		if n < 76 {
			return nil, nil, false
		}
	case op == 0x4d:
		if len(s) < 3 {
			return nil, nil, false
		}
		n, head = int(s[1])|int(s[2])<<8, 3
		if n < 256 {
			return nil, nil, false
		}
	default:
		return nil, nil, false
	}
	if len(s)-head < n {
		return nil, nil, false
	}
	return s[head : head+n], s[head+n:], true
}

// ParseNameScript splits an output script under O3.2. It returns false when
// the script starts with no supported prefix; it never follows the wider
// parser of the node (no skipped OP_NOP or drop runs, no longer pushes).
func ParseNameScript(script []byte) (NameScript, bool) {
	if len(script) == 0 {
		return NameScript{}, false
	}
	var pushes [][]byte
	var tail []byte
	var want int
	var prefix Prefix
	switch script[0] {
	case 0x53:
		prefix, want, tail = PrefixUpdate, 2, []byte{0x6d, 0x75}
	case 0x52:
		prefix, want, tail = PrefixRegistration, 3, []byte{0x6d, 0x6d}
	case 0x51:
		prefix, want, tail = PrefixReservation, 1, []byte{0x6d}
	default:
		return NameScript{}, false
	}
	rest := script[1:]
	for i := 0; i < want; i++ {
		d, r, ok := readPush(rest)
		if !ok {
			return NameScript{}, false
		}
		pushes, rest = append(pushes, d), r
	}
	if !bytes.HasPrefix(rest, tail) {
		return NameScript{}, false
	}
	rest = rest[len(tail):]
	ns := NameScript{Prefix: prefix, AddressScript: bytes.Clone(rest)}
	switch prefix {
	case PrefixUpdate:
		ns.Name, ns.Value = bytes.Clone(pushes[0]), bytes.Clone(pushes[1])
	case PrefixRegistration:
		ns.Name, ns.Rand, ns.Value = bytes.Clone(pushes[0]), bytes.Clone(pushes[1]), bytes.Clone(pushes[2])
	case PrefixReservation:
		if len(pushes[0]) != 20 {
			return NameScript{}, false
		}
		ns.Hash = bytes.Clone(pushes[0])
	}
	return ns, true
}

// addressKind is the address script kind of O3.3.
type addressKind int

const (
	addrUnsupported addressKind = iota
	addrKeyHash
	addrWitnessKeyHash
)

// splitAddress recognises exactly the two address scripts of O3.3 and
// returns their 20 octets. Any other octets, including a trailing opcode,
// are unsupported.
func splitAddress(a []byte) (addressKind, []byte) {
	if len(a) == 25 && a[0] == 0x76 && a[1] == 0xa9 && a[2] == 0x14 && a[23] == 0x88 && a[24] == 0xac {
		return addrKeyHash, a[3:23]
	}
	if len(a) == 22 && a[0] == 0x00 && a[1] == 0x14 {
		return addrWitnessKeyHash, a[2:22]
	}
	return addrUnsupported, nil
}

// readAddress applies O3.3 and O3.4 to an address script that follows a
// supported prefix. confirmedAt is the height of the block that holds the
// output; it decides only for a witness key hash.
func readAddress(addr []byte, p Pin, confirmedAt Height, c Chain) Reading {
	kind, h := splitAddress(addr)
	switch kind {
	case addrKeyHash:
	case addrWitnessKeyHash:
		at, known := confirmedAt.Value()
		if !c.set || !known || at < c.witnessFrom {
			return Unsupported
		}
	default:
		return Unsupported
	}
	ph := p.Hash160()
	if bytes.Equal(h, ph[:]) {
		return Controlled
	}
	return AnotherKey
}

// ReadOutput reads the octets of an output script against a pin under O3.2
// to O3.4. It returns the reading and, where the prefix is supported, the
// split of the script. A zero Pin reads every script as unsupported.
func ReadOutput(script []byte, p Pin, confirmedAt Height, c Chain) (Reading, NameScript) {
	ns, ok := ParseNameScript(script)
	if !ok {
		return Unsupported, NameScript{}
	}
	if !p.ok {
		return Unsupported, ns
	}
	return readAddress(ns.AddressScript, p, confirmedAt, c), ns
}
