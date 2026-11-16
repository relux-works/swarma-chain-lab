package identity

import (
	"bytes"
	"math/big"
)

// R1RuleError identifies a refused parent rule; the draft has no parent code.
type R1RuleError string

func (r R1RuleError) Error() string { return string(r) }

// RowOutpoint and the following types are stated facts, not grant wire members.
type RowOutpoint struct {
	TxID string
	Vout uint32
}
type RowRange struct {
	TxID         string
	First, Count uint64
	Script       []byte
}
type RowLimitKey struct{ Kind, Resource, Unit, Period string }

// Amount is a nonnegative canonical decimal integer, with no machine-word bound.
// Period is an opaque, independently established typed-period identity.
type RowLimit struct {
	Key    RowLimitKey
	Amount string
}
type RowExecutor struct{ Name, Key string }
type LandlordPin struct {
	Name         string
	Registration RowOutpoint
	Owner        Pin
}

// RowRecipient is an exclusive union. A non-nil empty Class is invalid.
// Key is an opaque, independently validated request-key identity for R2.3
// equality. This layer does not choose a channel or validate its key encoding.
type RowRecipient struct {
	Key   *string
	Name  *NameRecipient
	Class []LandlordPin
}
type RowTemplate struct {
	Executor  RowExecutor
	Recipient RowRecipient
	Limits    []RowLimit
	Certifier string // empty explicitly means no certifier
	StopCoin  *RowOutpoint
}
type RowGroup struct {
	Template RowTemplate
	Ranges   []RowRange
}
type RowGroups struct {
	Seal   RowOutpoint
	Pools  []RowLimit
	Groups []RowGroup
}
type SelectedRow struct {
	Group, Range int
	Coin         RowOutpoint
	Script       []byte
}

func rowTxID(s string) bool { return len(s) == 64 && isLowerHex(s) }
func rowAmount(s string) (*big.Int, bool) {
	if s == "" || (len(s) > 1 && s[0] == '0') {
		return nil, false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return nil, false
		}
	}
	n, ok := new(big.Int).SetString(s, 10)
	return n, ok
}
func limitMap(limits []RowLimit) (map[RowLimitKey]*big.Int, bool) {
	out := make(map[RowLimitKey]*big.Int)
	for _, l := range limits {
		n, ok := rowAmount(l.Amount)
		if !ok || l.Key.Kind == "" || l.Key.Resource == "" || l.Key.Unit == "" || out[l.Key] != nil {
			return nil, false
		}
		out[l.Key] = n
	}
	return out, true
}

// CheckRowGroups checks the decided range/pool/disjointness predicates.
// R1DraftLab additionally enforces R8.4 and witness-key-hash scripts. It deliberately
// does not check templates or a parent size: use CheckR1Parent for templates;
// size awaits parent octets. It never expands every coin or reads a node.
func CheckRowGroups(profile R1Profile, p RowGroups) (uint64, error) {
	if profile != R1DraftLab && profile != R1InForce051 {
		return 0, ErrR1Profile
	}
	if len(p.Groups) < 1 && profile == R1DraftLab || profile == R1DraftLab && len(p.Groups) > 16 {
		return 0, R1RuleError("R8.4")
	}
	if !rowTxID(p.Seal.TxID) {
		return 0, R1RuleError("R8.6")
	}
	pools, ok := limitMap(p.Pools)
	if !ok {
		return 0, R1RuleError("R8.5")
	}
	sums := make(map[RowLimitKey]*big.Int)
	var ranges []RowRange
	var total uint64
	for _, g := range p.Groups {
		if profile == R1DraftLab && (len(g.Ranges) < 1 || len(g.Ranges) > 16) {
			return 0, R1RuleError("R8.4")
		}
		limits, ok := limitMap(g.Template.Limits)
		if !ok {
			return 0, R1RuleError("R8.5")
		}
		var rows uint64
		for _, r := range g.Ranges {
			if profile == R1DraftLab && r.Count > 4096 {
				return 0, R1RuleError("R8.4")
			}
			if !rowTxID(r.TxID) || r.Count == 0 || r.First > 4294967295 || r.Count-1 > 4294967295-r.First || (profile == R1DraftLab && (len(r.Script) != 22 || !bytes.Equal(r.Script[:2], []byte{0, 20}))) {
				return 0, R1RuleError("R8.2")
			}
			end := r.First + r.Count - 1
			if r.TxID == p.Seal.TxID && uint64(p.Seal.Vout) >= r.First && uint64(p.Seal.Vout) <= end {
				return 0, R1RuleError("R8.6")
			}
			for _, prior := range ranges {
				if r.TxID == prior.TxID && r.First <= prior.First+prior.Count-1 && prior.First <= end {
					return 0, R1RuleError("R8.6")
				}
			}
			ranges = append(ranges, r)
			if ^uint64(0)-rows < r.Count {
				return 0, ErrR1FactRange
			}
			rows += r.Count
		}
		if ^uint64(0)-total < rows {
			return 0, ErrR1FactRange
		}
		total += rows
		for key, amount := range limits {
			if sums[key] == nil {
				sums[key] = new(big.Int)
			}
			sums[key].Add(sums[key], new(big.Int).Mul(amount, new(big.Int).SetUint64(rows)))
		}
	}
	if len(sums) != len(pools) {
		return 0, R1RuleError("R8.5")
	}
	for key, sum := range sums {
		if pools[key] == nil || sum.Cmp(pools[key]) > 0 {
			return 0, R1RuleError("R8.5")
		}
	}
	return total, nil
}

// SelectRow checks the one-based ordinal before reading a selected template.
// The returned script is a copy. Invalid parents return no selected row.
func SelectRow(profile R1Profile, p RowGroups, ordinal uint64) (SelectedRow, error) {
	if err := RequireR1Rule(profile, R1OrdinalOrder); err != nil {
		return SelectedRow{}, err
	}
	total, err := CheckRowGroups(profile, p)
	if err != nil {
		return SelectedRow{}, err
	}
	if ordinal < 1 || ordinal > total {
		return SelectedRow{}, ChildOrdinal
	}
	remaining := ordinal - 1
	for gi, g := range p.Groups {
		for ri, r := range g.Ranges {
			if remaining < r.Count {
				return SelectedRow{gi + 1, ri + 1, RowOutpoint{r.TxID, uint32(r.First + remaining)}, bytes.Clone(r.Script)}, nil
			}
			remaining -= r.Count
		}
	}
	return SelectedRow{}, ChildOrdinal
}
