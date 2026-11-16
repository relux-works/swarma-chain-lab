package wire

import (
	"bytes"
	"math"
	"math/bits"
	"strings"
)

func grantNumber(v *value) uint64 {
	n, _ := ParseInteger(v.text, math.MaxUint64) // The schema already proved the bound.
	return n
}
func grantAscending(v *value, member string) bool {
	last := ""
	for i, x := range v.elements {
		if member != "" {
			x = x.get(member)
		}
		if i > 0 && last >= x.text {
			return false
		}
		last = x.text
	}
	return true
}
func grantLimitKey(v *value) string {
	key := &value{kind: '{'}
	for _, m := range v.members {
		if m.name != "amount" {
			key.members = append(key.members, m)
		}
	}
	return string(serialize(key))
}
func grantDistinct(v *value, key func(*value) string) bool {
	seen := map[string]bool{}
	for _, x := range v.elements {
		k := key(x)
		if seen[k] {
			return false
		}
		seen[k] = true
	}
	return true
}
func grantName(v *value) string { return v.get("name").text }

func grantShapeRule(p *value) int {
	if grantNumber(p.get("not_before_height")) >= grantNumber(p.get("not_after_height")) {
		return 1
	}
	if !grantAscending(p.get("actions"), "") {
		return 2
	}
	if !grantDistinct(p.get("limits"), grantLimitKey) {
		return 3
	}
	return 0
}

type grantRun struct {
	txid        string
	first, last uint64
}

func (a grantRun) meets(b grantRun) bool {
	return a.txid == b.txid && a.first <= b.last && b.first <= a.last
}
func grantWitnessScript(v *value) bool {
	return len(v.text) == 44 && strings.HasPrefix(v.text, "0014")
}
func grantDelegateRule(p *value, proposals bool) int {
	d := p.get("delegate")
	if d == nil {
		return 0
	}
	if !grantAscending(d.get("actions"), "") {
		return 1
	}
	if !grantDistinct(d.get("pools"), grantLimitKey) {
		return 2
	}
	if !grantAscending(d.get("notaries"), "name") {
		return 3
	}
	notaries := map[string]bool{}
	for _, n := range d.get("notaries").elements {
		notaries[grantName(n)] = true
	}
	var coins, stops []grantRun
	for _, g := range d.get("groups").elements {
		t := g.get("template")
		if !grantDistinct(t.get("limits"), grantLimitKey) {
			return 4
		}
		r := t.get("recipient")
		if class := r.get("class"); class != nil && !grantDistinct(class, grantName) {
			return 4
		}
		certified := t.get("certifier") != nil
		if certified {
			if !notaries[t.get("certifier").text] {
				return 4
			}
		} else {
			if r.get("key") != nil {
				return 4
			}
			if class := r.get("class"); class != nil {
				if len(class.elements) != 1 {
					return 4
				}
				landlord, issuer := class.elements[0], p.get("issuer")
				for _, k := range []string{"name", "registration", "owner"} {
					if !bytes.Equal(serialize(landlord.get(k)), serialize(issuer.get(k))) {
						return 4
					}
				}
			}
		}
		for _, rng := range g.get("ranges").elements {
			count, first := grantNumber(rng.get("count")), grantNumber(rng.get("first"))
			last := first + count - 1 // Both operands are schema-bounded, below 2^33.
			if last > math.MaxUint32 || proposals && !grantWitnessScript(rng.get("script")) {
				return 5
			}
			stop := rng.get("stop")
			if (stop != nil) != certified {
				return 5
			}
			coins = append(coins, grantRun{rng.get("txid").text, first, last})
			if stop != nil {
				first = grantNumber(stop.get("first"))
				last = first + count - 1
				if last > math.MaxUint32 || proposals && !grantWitnessScript(stop.get("script")) {
					return 5
				}
				stops = append(stops, grantRun{stop.get("txid").text, first, last})
			}
		}
	}
	pools, sums := map[string]uint64{}, map[string]uint64{}
	for _, x := range d.get("pools").elements {
		pools[grantLimitKey(x)] = grantNumber(x.get("amount"))
	}
	for _, g := range d.get("groups").elements {
		var count uint64
		for _, rng := range g.get("ranges").elements {
			count += grantNumber(rng.get("count"))
		}
		for _, x := range g.get("template").get("limits").elements {
			key := grantLimitKey(x)
			// Overflow of either operation already exceeds every possible pool.
			hi, lo := bits.Mul64(count, grantNumber(x.get("amount")))
			sum, carry := bits.Add64(sums[key], lo, 0)
			if hi != 0 || carry != 0 {
				return 6
			}
			sums[key] = sum
		}
	}
	if len(sums) != len(pools) {
		return 6
	}
	for key, sum := range sums {
		pool, exists := pools[key]
		if !exists || sum > pool {
			return 6
		}
	}
	seal := p.get("seal").get("outpoint")
	vout := grantNumber(seal.get("vout"))
	sealRun := grantRun{seal.get("txid").text, vout, vout}
	for i, a := range coins {
		if a.meets(sealRun) {
			return 7
		}
		for _, b := range coins[:i] {
			if a.meets(b) {
				return 7
			}
		}
	}
	for i, a := range stops {
		for _, b := range stops[:i] {
			if a.meets(b) {
				return 8
			}
		}
	}
	if proposals {
		afterSeal := grantRun{sealRun.txid, vout + 1, vout + 1}
		for _, a := range stops {
			if a.meets(sealRun) || a.meets(afterSeal) {
				return 8
			}
			for _, b := range coins {
				if a.meets(b) {
					return 8
				}
			}
		}
	}
	return 0
}
