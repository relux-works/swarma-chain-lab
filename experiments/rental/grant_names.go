package rental

import (
	"encoding/json"
	sw "github.com/relux-works/swarma-chain-lab/experiments/sealwatch"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"slices"
)

func pendingIdentityTransition(o *su.ReadObservation, n su.NameView, changed func(string) (bool, error)) (bool, []string, error) {
	var ids []string
	if e := o.Call("getrawmempool", &ids); e != nil {
		return false, nil, e
	}
	slices.Sort(ids)
	for i, id := range ids {
		if !digest(id) || (i > 0 && id == ids[i-1]) {
			return false, nil, bad("MEMPOOL_PROJECTION")
		}
		var raw json.RawMessage
		if e := o.Call("getrawtransaction", &raw, id, true); e != nil {
			return false, nil, e
		}
		var txid string
		var vin []json.RawMessage
		if sw.ProjectJSON(raw, map[string]any{"txid": &txid, "vin": &vin}, nil) != nil || txid != id || len(vin) == 0 {
			return false, nil, bad("MEMPOOL_PROJECTION")
		}
		candidate := false
		for _, b := range vin {
			var point su.Point
			if sw.ProjectJSON(b, map[string]any{"txid": &point.TxID, "vout": &point.Vout}, nil) != nil || !digest(point.TxID) {
				return false, nil, bad("MEMPOOL_PROJECTION")
			}
			if point == (su.Point{TxID: n.TxID, Vout: n.Vout}) {
				candidate = true
			}
		}
		if !candidate {
			continue
		}
		// Only a name-spend candidate enters the full decoder. Unrelated witness
		// or large-input traffic is projected, not fed to the legacy decoder.
		v, tx, e := o.PaymentTransaction(id)
		if e != nil {
			return false, nil, e
		}
		bound := false
		for _, input := range tx.Inputs {
			if input.Point == (su.Point{TxID: n.TxID, Vout: n.Vout}) {
				bound = true
			}
		}
		if !bound {
			return false, nil, bad("PENDING_INPUT_BINDING")
		}
		matches := 0
		pending := false
		for _, out := range v.Vout {
			op := out.Script.Name
			if op == nil || op.Name != n.Name {
				continue
			}
			matches++
			if e := bindAgentNameOutput(n.Name, op.Value, out.N, v, tx); e != nil {
				return false, nil, e
			}
			different, e := changed(op.Value)
			if e != nil {
				return false, nil, bad("PENDING_NAME_VALUE")
			}
			if different {
				pending = true
			}
		}
		if matches != 1 {
			return false, nil, bad("PENDING_NAME_TRANSITION")
		}
		if pending {
			return true, ids, nil
		}
	}
	return false, ids, nil
}

// readNameGeneration binds either exact name role to its confirmed raw output;
// role-specific value parsing follows, without assuming cold owner custody.
func readNameGeneration(o *su.ReadObservation, name string) (su.NameView, Anchor, error) {
	n, e := currentName(o, name)
	if e != nil {
		return n, Anchor{}, e
	}
	v, tx, e := o.PaymentTransaction(n.TxID)
	if e != nil {
		return n, Anchor{}, e
	}
	if v.Block == "" || v.Confirmations <= 0 {
		return n, Anchor{}, bad("NAME_UNCONFIRMED")
	}
	h, e := o.Confirmed(v)
	if e != nil {
		return n, Anchor{}, e
	}
	if n.Height != h.Height || uint64(n.Vout) >= uint64(len(tx.Outputs)) {
		return n, Anchor{}, bad("NAME_GENERATION_BINDING")
	}
	if e = bindAgentNameOutput(n.Name, n.Value, n.Vout, v, tx); e != nil {
		return n, Anchor{}, e
	}
	return n, Anchor{n.TxID, n.Vout, v.Block, h.Height}, nil
}

func pendingGrantBinding(o *su.ReadObservation, agent, landlord su.NameView, landlordName, grantKey string) ([]string, error) {
	a, ids, e := pendingIdentityTransition(o, agent, func(v string) (bool, error) { b, e := ParseAgentBinding(v); return b.Landlord != landlordName, e })
	if e != nil {
		return nil, e
	}
	if a {
		return nil, bad("PENDING_LANDLORD_POINTER")
	}
	l, more, e := pendingIdentityTransition(o, landlord, func(v string) (bool, error) { b, e := ParseLandlordValue(v); return b.Grant != grantKey, e })
	if e != nil {
		return nil, e
	}
	if l {
		return nil, bad("PENDING_LANDLORD_ROTATION")
	}
	if !sameJSON(ids, more) {
		return nil, bad("MEMPOOL_CHANGED")
	}
	return ids, nil
}
