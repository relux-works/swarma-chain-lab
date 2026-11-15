package identity

import "bytes"

// Operation is the kind of operation whose writer is asked (O4.1).
type Operation int

const (
	// OpNone is no operation; the writer check of it is unsupported.
	OpNone Operation = iota
	// OpUpdate is name_update.
	OpUpdate
	// OpRegistration is name_firstupdate.
	OpRegistration
)

// Writer is the outcome of the writer check (O4.4). The zero value is
// WriterUnsupported, which is no evidence of either other outcome.
type Writer int

const (
	// WriterUnsupported: every case that is not one of the two others.
	WriterUnsupported Writer = iota
	// WrittenByOwner: O4.2 holds, read as O4.3 says.
	WrittenByOwner
	// WrittenByAnother: the output that the name input spends reads as
	// another key.
	WrittenByAnother
)

func (w Writer) String() string {
	switch w {
	case WrittenByOwner:
		return "written by the owner"
	case WrittenByAnother:
		return "written by another"
	}
	return "unsupported"
}

// Input is one input of an operation, as stated octets: the script of the
// output that it spends with the height of the block that holds that output,
// its unlocking script and the items of its witness (none for no witness).
type Input struct {
	SpentScript      []byte
	SpentConfirmedAt Height
	Unlocking        []byte
	Witness          [][]byte
}

// sighashAll is the only hash type that O4.2 admits: SIGHASH_ALL without
// ANYONECANPAY.
const sighashAll = 0x01

// isNameInput applies O4.1 to the spent script of one input.
func isNameInput(op Operation, name []byte, spent []byte) bool {
	ns, ok := ParseNameScript(spent)
	if !ok {
		return false
	}
	switch op {
	case OpUpdate:
		return (ns.Prefix == PrefixUpdate || ns.Prefix == PrefixRegistration) && bytes.Equal(ns.Name, name)
	case OpRegistration:
		return ns.Prefix == PrefixReservation
	}
	return false
}

// signedAll reports whether s is a signature whose last octet is the hash
// type 01 and k is the 33 octets of the pin (O4.3).
func signedAll(s, k []byte, p Pin) bool {
	return len(s) > 0 && s[len(s)-1] == sighashAll && bytes.Equal(k, p.key[:])
}

// keyHashSpendOK applies O4.3 to the spend of a key hash: the unlocking
// script is exactly P(s) P(k) and the input has no witness.
func keyHashSpendOK(in Input, p Pin) bool {
	if len(in.Witness) != 0 {
		return false
	}
	s, rest, ok := readPush(in.Unlocking)
	if !ok {
		return false
	}
	k, rest, ok := readPush(rest)
	if !ok || len(rest) != 0 {
		return false
	}
	return signedAll(s, k, p)
}

// witnessSpendOK applies O4.3 to the spend of a witness key hash: the
// unlocking script is empty and the witness has exactly two items, s then k.
func witnessSpendOK(in Input, p Pin) bool {
	if len(in.Unlocking) != 0 || len(in.Witness) != 2 {
		return false
	}
	return signedAll(in.Witness[0], in.Witness[1], p)
}

// CheckWriter applies O4.1 to O4.4 to the inputs of an operation that
// created an output of the named name. It does not verify a signature again:
// the node that validated the transaction is outside this module.
func CheckWriter(op Operation, name []byte, inputs []Input, p Pin, c Chain) Writer {
	if !p.ok || (op != OpUpdate && op != OpRegistration) {
		return WriterUnsupported
	}
	idx := -1
	for i, in := range inputs {
		if isNameInput(op, name, in.SpentScript) {
			if idx >= 0 {
				// Two candidates: no guessing which one is the name input.
				return WriterUnsupported
			}
			idx = i
		}
	}
	if idx < 0 {
		return WriterUnsupported
	}
	in := inputs[idx]
	reading, ns := ReadOutput(in.SpentScript, p, in.SpentConfirmedAt, c)
	switch reading {
	case AnotherKey:
		return WrittenByAnother
	case Controlled:
	default:
		return WriterUnsupported
	}
	kind, _ := splitAddress(ns.AddressScript)
	var ok bool
	switch kind {
	case addrKeyHash:
		ok = keyHashSpendOK(in, p)
	case addrWitnessKeyHash:
		ok = witnessSpendOK(in, p)
	}
	if ok {
		return WrittenByOwner
	}
	return WriterUnsupported
}
