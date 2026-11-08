package sealwatch

import (
	"bytes"
	"encoding/json"
	"strings"
	"unicode"
)

// Project only official Core spellings. Unknown extension fields remain valid;
// aliases of projected fields do not. uniqueJSON has already rejected exact
// and fold-equal duplicates throughout the complete bounded reply.
// Optional fields describe context-dependent transaction members: an unmined
// transaction has no block binding, and coinbase has no previous outpoint.
// The existing state-machine schema checks determine which values are needed.
func exactProjection(raw []byte, required, optional map[string]any) error {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return failure("JSON_PROJECTION")
	}
	for _, projection := range []map[string]any{required, optional} {
		for supplied := range fields {
			for official := range projection {
				if supplied != official && strings.EqualFold(supplied, official) {
					return failure("JSON_PROJECTION")
				}
			}
		}
	}
	for key, dst := range required {
		value, ok := fields[key]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) || json.Unmarshal(value, dst) != nil {
			return failure("JSON_PROJECTION")
		}
	}
	for key, dst := range optional {
		if value, ok := fields[key]; ok && json.Unmarshal(value, dst) != nil {
			return failure("JSON_PROJECTION")
		}
	}
	return nil
}

func (v *info) UnmarshalJSON(raw []byte) error {
	*v = info{}
	return exactProjection(raw, map[string]any{"chain": &v.Chain, "blocks": &v.Blocks,
		"headers": &v.Headers, "bestblockhash": &v.Best, "initialblockdownload": &v.IBD}, nil)
}

func (v *input) UnmarshalJSON(raw []byte) error {
	*v = input{}
	return exactProjection(raw, nil, map[string]any{"txid": &v.TxID, "vout": &v.Vout, "coinbase": &v.Coinbase})
}

type scriptPubKey struct {
	Hex string `json:"hex"`
}

func (v *scriptPubKey) UnmarshalJSON(raw []byte) error {
	*v = scriptPubKey{}
	// A non-commitment output need not contribute a script proof. Missing hex
	// cannot match either the nonempty seal script or certificate commitment;
	// if supplied, its spelling/type must still be exact on every output.
	return exactProjection(raw, nil, map[string]any{"hex": &v.Hex})
}

func (v *output) UnmarshalJSON(raw []byte) error {
	*v = output{}
	return exactProjection(raw, map[string]any{"scriptPubKey": &v.Script}, map[string]any{"n": &v.N})
}

func (v *tx) UnmarshalJSON(raw []byte) error {
	*v = tx{}
	return exactProjection(raw, map[string]any{"txid": &v.TxID}, map[string]any{
		"blockhash": &v.BlockHash, "confirmations": &v.Confirmations, "vin": &v.Vin, "vout": &v.Vout})
}

func (v *block) UnmarshalJSON(raw []byte) error {
	*v = block{}
	return exactProjection(raw, map[string]any{"hash": &v.Hash, "height": &v.Height, "tx": &v.Tx}, nil)
}

func (v *utxo) UnmarshalJSON(raw []byte) error {
	*v = utxo{}
	return exactProjection(raw, map[string]any{"bestblock": &v.Best, "confirmations": &v.Confirmations, "scriptPubKey": &v.Script}, nil)
}

// Canonicalize Unicode simple-fold classes, not merely lowercase spelling.
// This also rejects ambiguous unknown extensions without quadratic key scans.
func foldJSONKey(s string) string {
	return strings.Map(func(r rune) rune {
		least := r
		for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
			if next < least {
				least = next
			}
		}
		return least
	}, s)
}
