package singleuse

import (
	"encoding/hex"
)

// WitnessConstruction is observed from this pinned node, not from a caller's
// claimed input roles. Signing-time confirmation is enforced by the producer;
// a later verifier checks ordinary parents precede the spender's block.
type WitnessConstruction struct {
	SealTransaction   *WTransaction
	AnchorTransaction *WTransaction
	Linkage           Point
}

type witnessObserved struct {
	view   TransactionView
	body   *Transaction
	height int64
}

func (r *ReadObservation) witnessObserved(id string, allowCoinbase bool) (witnessObserved, error) {
	var out witnessObserved
	if !digestHex(id) {
		return out, fail("W_TXID")
	}
	if e := r.o.call("getrawtransaction", &out.view, id, true); e != nil {
		return out, e
	}
	v := out.view
	raw, e := hex.DecodeString(v.Hex)
	if e != nil || hex.EncodeToString(raw) != v.Hex || v.TxID != id {
		return out, fail("W_TXID")
	}
	tx, e := DecodePaymentTransaction(raw)
	if e != nil || tx.ID() != id || len(tx.Inputs) != len(v.Vin) || len(tx.Outputs) != len(v.Vout) {
		return out, fail("W_BODY_BINDING")
	}
	for i, in := range tx.Inputs {
		projected := v.Vin[i]
		if projected.Coinbase != "" {
			if !allowCoinbase || len(tx.Inputs) != 1 || in.TxID != zeroHash || in.Vout != 0xffffffff || hex.EncodeToString(in.Script) != projected.Coinbase {
				return out, fail("W_COINBASE_INPUT")
			}
		} else if in.TxID != projected.TxID || in.Vout != projected.Vout || hex.EncodeToString(in.Script) != projected.Script.Hex {
			return out, fail("W_BODY_BINDING")
		}
	}
	for i, o := range tx.Outputs {
		p := v.Vout[i]
		if p.N != uint32(i) || int64(p.Value) != o.Value || p.Script.Hex != hex.EncodeToString(o.Script) {
			return out, fail("W_BODY_BINDING")
		}
	}
	if v.Block != "" {
		if v.Confirmations < 1 {
			return out, fail("W_PARENT_STATE")
		}
		h, e := r.Confirmed(v)
		if e != nil {
			return out, e
		}
		out.height = h.Height
	} else if v.Confirmations != 0 {
		return out, fail("W_PARENT_STATE")
	}
	out.body = tx
	return out, nil
}

// FundingTransaction binds a funding candidate to this node's exact raw body,
// including coinbase candidates. It does not admit W or an unconfirmed funding
// role: callers separately require confirmation or authenticate exact T:L.
func (r *ReadObservation) FundingTransaction(id string) (TransactionView, *Transaction, error) {
	observed, e := r.witnessObserved(id, true)
	if e != nil {
		return TransactionView{}, nil, e
	}
	return observed.view, observed.body, nil
}

const zeroHash = "0000000000000000000000000000000000000000000000000000000000000000"

func (r *ReadObservation) witnessInputs(tx witnessObserved, linkage *Point) (*WTransaction, error) {
	raw, _ := hex.DecodeString(tx.view.Hex)
	w, e := DecodeWitnessTransaction(raw)
	if e != nil {
		return nil, e
	}
	prevs := make([]Output, len(w.Body.Inputs))
	for i, in := range w.Body.Inputs {
		parent, e := r.witnessObserved(in.TxID, true)
		if e != nil {
			return nil, e
		}
		if uint64(in.Vout) >= uint64(len(parent.body.Outputs)) {
			return nil, fail("W_PREVOUT")
		}
		prevs[i] = parent.body.Outputs[in.Vout]
		if linkage != nil && in.Point == *linkage {
			continue
		}
		// Height zero is mempool; equal height was unconfirmed at block entry.
		if parent.height == 0 || (tx.height > 0 && parent.height >= tx.height) {
			return nil, fail("W_UNCONFIRMED_NON_LINKAGE_PARENT")
		}
	}
	if e := VerifyWitnessInputs(w, prevs); e != nil {
		return nil, e
	}
	return w, nil
}

// WitnessCreation binds T to the seal's exact txid and verifies every funding
// prevout and every signature. T may be unconfirmed, its funding may not.
func (r *ReadObservation) WitnessCreation(profile string, seal Point) (*WTransaction, error) {
	if e := RequireWitnessProfile(profile); e != nil {
		return nil, e
	}
	tx, e := r.witnessObserved(seal.TxID, false)
	if e != nil {
		return nil, e
	}
	if uint64(seal.Vout) >= uint64(len(tx.body.Outputs)) {
		return nil, fail("W_SEAL_OUTPUT")
	}
	return r.witnessInputs(tx, nil)
}

// WitnessIssuance implements the linkage-only W subset. At most one A input
// may reference a non-seal output of T; an unconfirmed T requires that link. No payment or other unconfirmed parent
// exception exists here; SW1b requires a separately authenticated proof contract.
func (r *ReadObservation) WitnessIssuance(profile string, seal Point, anchorID string) (WitnessConstruction, error) {
	var out WitnessConstruction
	if e := RequireWitnessProfile(profile); e != nil {
		return out, e
	}
	t, e := r.witnessObserved(seal.TxID, false)
	if e != nil {
		return out, e
	}
	if uint64(seal.Vout) >= uint64(len(t.body.Outputs)) {
		return out, fail("W_SEAL_OUTPUT")
	}
	out.SealTransaction, e = r.witnessInputs(t, nil)
	if e != nil {
		return WitnessConstruction{}, e
	}
	a, e := r.witnessObserved(anchorID, false)
	if e != nil {
		return WitnessConstruction{}, e
	}
	links := 0
	for _, in := range a.body.Inputs {
		if in.Point == seal {
			return WitnessConstruction{}, fail("W_ISSUANCE_SPENDS_SEAL")
		}
		if in.TxID == seal.TxID {
			if uint64(in.Vout) >= uint64(len(t.body.Outputs)) || !NativeP2WPKH(t.body.Outputs[in.Vout].Script) {
				return WitnessConstruction{}, fail("W_LINKAGE_SCRIPT")
			}
			links++
			out.Linkage = in.Point
		}
	}
	if links > 1 || (links == 0 && (t.height == 0 || t.height == a.height)) {
		return WitnessConstruction{}, fail("W_LINKAGE_REQUIRED")
	}
	if a.height > 0 {
		if t.height == 0 || t.height > a.height {
			return WitnessConstruction{}, fail("W_DEPENDENCY_ORDER")
		}
		if t.height == a.height {
			if t.view.Block != a.view.Block {
				return WitnessConstruction{}, fail("W_DEPENDENCY_ORDER")
			}
			b, e := r.o.block(a.view.Block, a.height)
			if e != nil {
				return WitnessConstruction{}, e
			}
			ti, ai := -1, -1
			for i, id := range b.Tx {
				if id == seal.TxID {
					ti = i
				}
				if id == anchorID {
					ai = i
				}
			}
			if ti < 0 || ai < 0 || ti >= ai {
				return WitnessConstruction{}, fail("W_DEPENDENCY_ORDER")
			}
		}
	}
	var link *Point
	if links == 1 {
		link = &out.Linkage
	}
	out.AnchorTransaction, e = r.witnessInputs(a, link)
	if e != nil {
		return WitnessConstruction{}, e
	}
	return out, nil
}
