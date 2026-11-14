package wire

import (
	"bytes"
	"encoding/hex"
)

// Outpoint is evidence named by the unsigned preparation. Its source and
// ownership are not established by the wire module.
type Outpoint struct {
	TxID string
	Vout uint64
}

// PreparationParts supplies the values of separately checked parts. This is
// an arithmetic input, deliberately not a representation of a verified grant.
// No grant schema or composed-issuance admission is supplied by LIP-0020.
type PreparationParts struct {
	Mode                                                      RecipientMode
	Genesis, Contract, GrantID, GrantSignature                string
	AssentParty, AssentSignature, ConsentID, ConsentSignature string
	NameOutput                                                *Outpoint
}

func BuildPreparation(p PreparationParts) (*Preparation, error) {
	if p.Mode != ByKey && p.Mode != ByName || p.Mode == ByKey && p.NameOutput != nil || p.Mode == ByName && p.NameOutput == nil {
		return nil, IssuanceMode
	}
	consent := map[string]any{"event_id": p.ConsentID, "signature": p.ConsentSignature}
	if p.NameOutput != nil {
		consent["name_output"] = map[string]any{"txid": p.NameOutput.TxID, "vout": p.NameOutput.Vout}
	}
	b, err := EncodeDocument(map[string]any{"type": string(Issuance), "genesis": p.Genesis, "contract": p.Contract, "grant_id": p.GrantID, "grant_signature": p.GrantSignature, "issuer_assent": map[string]any{"party": p.AssentParty, "signature": p.AssentSignature}, "recipient_consent": consent}, MaxPreparationSize)
	if err != nil {
		return nil, err
	}
	return ReadUnsigned(b, Issuance)
}

// Frame describes only the issuance output and its transaction-level count.
// The caller must supply the actual output value and OP_RETURN count; this
// type does not read or establish a transaction's confirmation or inputs.
type Frame struct {
	Script        []byte
	Value         uint64
	OpReturnCount int
}

func EncodeIssuanceFrame(commitment [32]byte, contentAddress string) ([]byte, error) {
	if !hexForm(contentAddress, 32) {
		return nil, IssuanceFrame
	}
	pointer, _ := hex.DecodeString(contentAddress)
	b := []byte{0x6a, 0x03, 0x53, 0x4c, 0x01, 0x42, 0x02}
	b = append(b, commitment[:]...)
	b = append(b, 0x01)
	return append(b, pointer...), nil
}

// CheckIssuanceAnchor evaluates W8.4-W8.6 after independently checked parts.
// It does NOT implement W9.1's composed pipeline or choose a first refusal
// between invalid parts. In particular it cannot admit the stand-in grants
// used for arithmetic in the public vectors as real grants.
func CheckIssuanceAnchor(p PreparationParts, contentAddress string, frame Frame) (*Preparation, error) {
	prep, err := BuildPreparation(p)
	if err != nil {
		return nil, err
	}
	expected, err := EncodeIssuanceFrame(prep.Commitment(), contentAddress)
	if err != nil {
		return nil, err
	}
	if frame.Value != 0 || frame.OpReturnCount != 1 || len(frame.Script) != 72 {
		return nil, IssuanceFrame
	}
	if !bytes.Equal(frame.Script[:7], expected[:7]) || frame.Script[39] != 1 || !bytes.Equal(frame.Script[40:], expected[40:]) {
		return nil, IssuanceFrame
	}
	if !bytes.Equal(frame.Script[7:39], expected[7:39]) {
		return nil, IssuanceCommitment
	}
	return prep, nil
}

// Class is selected by a reader's place, never by untrusted input octets.
type Class uint8

const (
	SignedClass Class = iota + 1
	UnsignedClass
	ConsentClass
	IssuanceClass
)

type ReadContext struct {
	Expected Type
	Assent   AssentContext
	Consent  ConsentContext
}

// Read dispatches wire documents to their class pipeline. The issuance class
// fails closed: its grant still has no schema, so no presentation is admitted.
// CheckIssuanceAnchor is separately exposed as arithmetic on stated inputs.
func Read(class Class, b []byte, ctx ReadContext) (any, error) {
	switch class {
	case SignedClass:
		if ctx.Expected != ContractAssent {
			return nil, WireType
		}
		o, err := ReadAssent(b, ctx.Assent)
		if err != nil {
			return nil, err
		}
		return o, nil
	case UnsignedClass:
		o, err := ReadUnsigned(b, ctx.Expected)
		if err != nil {
			return nil, err
		}
		return o, nil
	case ConsentClass:
		o, err := ReadConsent(b, ctx.Consent)
		if err != nil {
			return nil, err
		}
		return o, nil
	case IssuanceClass:
		return nil, WireType
	default:
		return nil, WireType
	}
}
