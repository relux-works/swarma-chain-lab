//go:build ignore

// Regenerate: go run scripts/generate-child-v4.go > testdata/child-v4.json
// All scalars and zero auxiliary randomness are PUBLIC test material, exactly
// the scalars 1, 2, 3 declared by experiments/grant-v4/vectors/vectors.json.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	wire "github.com/relux-works/swarma-chain-lab/experiments/grant-v4/wire"
)

type obj = map[string]any

func hash(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func key(n int) *btcec.PrivateKey {
	if n < 1 || n > 3 {
		panic("public scalars 1,2,3 only")
	}
	b := make([]byte, 32)
	b[31] = byte(n)
	k, _ := btcec.PrivKeyFromBytes(b)
	return k
}
func signing(n int) string { return hex.EncodeToString(schnorr.SerializePubKey(key(n).PubKey())) }
func output(n int) string  { return hex.EncodeToString(key(n).PubKey().SerializeCompressed()) }
func opposite(k string) string {
	if k[:2] == "02" {
		return "03" + k[2:]
	}
	return "02" + k[2:]
}
func point(s string, v int) obj { return obj{"txid": hash(s), "vout": v} }
func pin(s string) obj          { return obj{"name": s, "owner": output(1), "registration": point(s, 0)} }
func limit(amount string) obj {
	return obj{"kind": "example/count", "resource": "example/resource", "unit": "example/unit", "amount": amount}
}
func template(p obj) obj { return p["delegate"].(obj)["groups"].([]any)[0].(obj)["template"].(obj) }
func parent() obj {
	issuer := pin("id/example-issuer")
	issuer["grant_key"] = signing(1)
	return obj{"type": "swarma-grant/4", "genesis": hash("example-genesis"), "contract": hash("example-contract"), "issuer": issuer,
		"recipient": obj{"key": signing(1)}, "executor": obj{"name": "id/example-executor", "key": signing(1)}, "actions": []any{"example/a"}, "limits": []any{},
		"not_before_height": 10, "not_after_height": 20, "recent_block": hash("example-recent"),
		"seal": obj{"construction": "W", "kind": "revocable-only", "key": output(1), "outpoint": point("example-parent-seal", 0)},
		"delegate": obj{"key": signing(2), "child_seal_key": output(3), "actions": []any{"example/a", "example/b"}, "pools": []any{}, "notaries": []any{pin("id/example-notary")},
			"groups": []any{obj{"template": obj{"executor": obj{"name": "id/example-executor", "key": signing(1)}, "recipient": obj{"key": signing(1)}, "limits": []any{}, "certifier": "id/example-notary"},
				"ranges": []any{obj{"txid": hash("example-coins"), "first": 7, "count": 2, "script": "0014" + fmt.Sprintf("%040x", 1), "stop": obj{"txid": hash("example-stops"), "first": 0, "script": "0014" + fmt.Sprintf("%040x", 2)}}}}}}}
}
func child() obj {
	return obj{"type": "swarma-grant/4", "genesis": hash("example-genesis"), "contract": hash("example-contract"), "ordinal": 1, "parent": "", "recipient": obj{"key": signing(1)}, "executor": obj{"name": "id/example-executor", "key": signing(1)}, "actions": []any{"example/a"}, "limits": []any{}, "not_before_height": 10, "not_after_height": 20, "recent_block": hash("example-child-recent"), "seal": obj{"construction": "W", "kind": "revocable-only", "key": output(3), "outpoint": point("example-child-seal", 0)}}
}
func signed(p obj, n int) (json.RawMessage, string) {
	b, e := json.Marshal(p)
	must(e)
	d, e := wire.TypedDigest(b)
	must(e)
	id, e := wire.PayloadID(b)
	must(e)
	sig, e := schnorr.Sign(key(n), d[:], schnorr.CustomNonce([32]byte{}))
	must(e)
	out, e := json.Marshal(obj{"payload": p, "signature": hex.EncodeToString(sig.Serialize())})
	must(e)
	return out, id
}
func must(e error) {
	if e != nil {
		panic(e)
	}
}

type fixture struct {
	ID          string                           `json:"id"`
	Mode        string                           `json:"mode"`
	Parent      json.RawMessage                  `json:"parent"`
	Child       json.RawMessage                  `json:"child"`
	Expect      string                           `json:"expect"`
	Step        int                              `json:"step"`
	Neighbour   string                           `json:"valid_neighbour"`
	Spec        string                           `json:"spec_case"`
	Ancestor    json.RawMessage                  `json:"ancestor,omitempty"`
	Observation *wire.ParentNameObservation      `json:"observation,omitempty"`
	InputIndex  int                              `json:"input_index,omitempty"`
	Selected    *wire.ChildAttenuationEvaluation `json:"selected,omitempty"`
}

func main() {
	var cases []fixture
	add := func(id, mode, want string, step int, spec string, mutate func(obj, obj)) {
		if want == "ok" {
			step = 0
		}
		p, c := parent(), child()
		if mutate != nil {
			mutate(p, c)
		}
		parentScalar := 1
		for n := 1; n <= 3; n++ {
			if signing(n) == p["issuer"].(obj)["grant_key"] {
				parentScalar = n
			}
		}
		pb, pid := signed(p, parentScalar)
		c["parent"] = pid
		scalar := 2
		for n := 1; n <= 3; n++ {
			if signing(n) == p["delegate"].(obj)["key"] {
				scalar = n
			}
		}
		cb, _ := signed(c, scalar)
		neighbour := "prefix-open"
		if mode == "template" {
			neighbour = "template-valid"
		}
		cases = append(cases, fixture{ID: id, Mode: mode, Parent: pb, Child: cb, Expect: want, Step: step, Neighbour: neighbour, Spec: spec})
	}
	prefix := func(id, want string, step int, spec string, f func(obj, obj)) { add(id, "prefix", want, step, spec, f) }
	row := func(id, want string, step int, spec string, f func(obj, obj)) {
		add(id, "template", want, step, spec, f)
	}
	prefix("prefix-open", "ok", 13, "F1/F2 preconditions; evaluated F5, F8 to F12, F13(a), F14 to F18 slice", nil)
	prefix("contract", "CHILD_CONTRACT_DIFFERS", 5, "step-i-01", func(p, c obj) { c["contract"] = hash("other-contract") })
	prefix("genesis", "SUBJECT_MISMATCH", 8, "step-i-02", func(p, c obj) { c["genesis"] = hash("other-genesis") })
	prefix("contract-before-genesis", "CHILD_CONTRACT_DIFFERS", 5, "step-c-01", func(p, c obj) { c["contract"] = hash("other-contract"); c["genesis"] = hash("other-genesis") })
	roles := []string{"grant", "issuer-owner", "recipient", "seal", "notary-owner"}
	for _, role := range roles {
		for _, odd := range []bool{false, true} {
			mutate := func(p, c obj) {
				d := p["delegate"].(obj)
				k := output(2)
				if odd {
					k = opposite(k)
				}
				switch role {
				case "grant":
					p["issuer"].(obj)["grant_key"] = signing(2)
				case "issuer-owner":
					p["issuer"].(obj)["owner"] = k
				case "recipient":
					p["recipient"] = obj{"name": "id/example-parent", "owner": k}
				case "seal":
					p["seal"].(obj)["key"] = k
				case "notary-owner":
					d["notaries"].([]any)[0].(obj)["owner"] = k
				}
			}
			prefix(fmt.Sprintf("delegation-%s-parity-%t", role, odd), "DELEGATE_KEY_REUSE", 9, "step-i-03..08", mutate)
		}
	}
	for _, role := range append(roles, "delegation") {
		for _, odd := range []bool{false, true} {
			prefix(fmt.Sprintf("childseal-%s-parity-%t", role, odd), "DELEGATE_KEY_REUSE", 10, "step-i-10..16", func(p, c obj) {
				d := p["delegate"].(obj)
				k := output(3)
				switch role {
				case "grant":
					p["issuer"].(obj)["grant_key"] = signing(3)
				case "issuer-owner":
					p["issuer"].(obj)["owner"] = output(3)
				case "recipient":
					p["recipient"] = obj{"key": signing(3)}
				case "seal":
					p["seal"].(obj)["key"] = output(3)
				case "notary-owner":
					d["notaries"].([]any)[0].(obj)["owner"] = output(3)
				case "delegation":
					k = output(2)
				}
				if odd {
					k = opposite(k)
				}
				d["child_seal_key"] = k
			})
		}
	}
	prefix("missing-childseal", "CHILD_SEAL_KEY", 10, "step-i-09", func(p, c obj) { delete(p["delegate"].(obj), "child_seal_key") })
	prefix("reuse-before-missing", "DELEGATE_KEY_REUSE", 9, "step-c-03", func(p, c obj) { d := p["delegate"].(obj); d["key"] = signing(1); delete(d, "child_seal_key") })
	prefix("genesis-before-reuse", "SUBJECT_MISMATCH", 8, "step-c-02", func(p, c obj) { c["genesis"] = hash("other"); p["delegate"].(obj)["key"] = signing(1) })
	for _, odd := range []bool{false, true} {
		prefix(fmt.Sprintf("child-seal-reuses-delegation-%t", odd), "DELEGATE_KEY_REUSE", 11, "step-c-04", func(p, c obj) {
			k := output(2)
			if odd {
				k = opposite(k)
			}
			c["seal"].(obj)["key"] = k
		})
	}
	prefix("missing-childseal-before-delegation-reuse", "CHILD_SEAL_KEY", 10, "Q9: F10 before F11", func(p, c obj) {
		delete(p["delegate"].(obj), "child_seal_key")
		c["seal"].(obj)["key"] = output(2)
	})
	prefix("child-recipient-key-reuse", "DELEGATE_KEY_REUSE", 11, "step-i-17", func(p, c obj) { c["recipient"] = obj{"key": signing(2)} })
	for _, odd := range []bool{false, true} {
		prefix(fmt.Sprintf("child-recipient-owner-reuse-%t", odd), "DELEGATE_KEY_REUSE", 11, "J4.3(b)", func(p, c obj) {
			k := output(2)
			if odd {
				k = opposite(k)
			}
			c["recipient"] = obj{"name": "id/example-agent", "owner": k}
		})
	}
	prefix("parent-name-open", "implementation:", 11, "F11 missing caller facts, unset not no-key", func(p, c obj) { p["recipient"] = obj{"name": "id/example-parent", "owner": output(1)} })
	prefix("wrong-seal", "CHILD_SEAL_KEY", 12, "step-i-18", func(p, c obj) { c["seal"].(obj)["key"] = output(1) })
	prefix("seal-parity", "CHILD_SEAL_KEY", 12, "step-i-19", func(p, c obj) { c["seal"].(obj)["key"] = opposite(output(3)) })
	for _, n := range []int{0, 1, 2, 3, 9007199254740991} {
		want, step := "ok", 13
		if n == 0 || n > 2 {
			want = "CHILD_ORDINAL"
		}
		prefix(fmt.Sprintf("ordinal-%d", n), want, step, "step-i-20/21; bounds", func(p, c obj) { c["ordinal"] = n })
	}

	for _, n := range []int{4096, 4097} {
		want := "ok"
		if n > 4096 {
			want = "CHILD_ORDINAL"
		}
		prefix(fmt.Sprintf("ordinal-range-bound-%d", n), want, 13, "R8.4 range bound", func(p, c obj) {
			p["delegate"].(obj)["groups"].([]any)[0].(obj)["ranges"].([]any)[0].(obj)["count"] = 4096
			c["ordinal"] = n
		})
	}
	for _, n := range []int{5, 9, 10} {
		want := "ok"
		if n > 9 {
			want = "CHILD_ORDINAL"
		}
		prefix(fmt.Sprintf("ordinal-groups-ranges-%d", n), want, 13, "LIP-0026 section 8 nine-row counts", func(p, c obj) {
			d := p["delegate"].(obj)
			g := d["groups"].([]any)[0].(obj)
			g["ranges"].([]any)[0].(obj)["count"] = 3
			makeRange := func(label string, count int) obj {
				return obj{"txid": hash(label), "first": 0, "count": count, "script": "0014" + fmt.Sprintf("%040x", 1), "stop": obj{"txid": hash(label + "-stop"), "first": 0, "script": "0014" + fmt.Sprintf("%040x", 2)}}
			}
			g["ranges"] = append(g["ranges"].([]any), makeRange("example-range-two", 2))
			d["groups"] = append(d["groups"].([]any), obj{"template": g["template"], "ranges": []any{makeRange("example-range-three", 4)}})
			c["ordinal"] = n
		})
	}
	prefix("seal-before-ordinal", "CHILD_SEAL_KEY", 12, "step-c-06", func(p, c obj) { c["seal"].(obj)["key"] = output(1); c["ordinal"] = 0 })
	prefix("missing-before-ordinal", "CHILD_SEAL_KEY", 10, "step-c-05", func(p, c obj) { delete(p["delegate"].(obj), "child_seal_key"); c["ordinal"] = 0 })
	prefix("ordinal-before-executor", "CHILD_ORDINAL", 13, "step-c-07", func(p, c obj) { c["ordinal"] = 3; c["executor"].(obj)["name"] = "id/example-other" })
	// F11 observations are caller facts, never signed grant members. Every
	// negative is generated beside a by-name valid neighbour, not hand-edited.
	observe := func(id, want string, step, index int, mutate func(obj, obj, *wire.ParentNameObservation)) {
		o := &wire.ParentNameObservation{Name: "id/example-parent", Genesis: hash("example-genesis"), TipHash: hash("example-observed-tip"), TipHeight: 12, ValueState: wire.ParentNameValueKeys, ChannelKeys: []string{signing(1)}}
		add(id, "observation", want, step, "F11; F7.3 stated observation", func(p, c obj) {
			p["recipient"] = obj{"name": o.Name, "owner": output(1)}
			if mutate != nil {
				mutate(p, c, o)
			}
		})
		v := &cases[len(cases)-1]
		v.Observation, v.InputIndex, v.Neighbour = o, index, "name-valid-neighbour"
	}
	observe("name-valid-neighbour", "ok", 13, -1, nil)
	for _, state := range []wire.ParentNameValueState{wire.ParentNameValueNoKey, wire.ParentNameValueRefused, ""} {
		id := string(state)
		if id == "" {
			id = "unset"
		}
		observe("value-"+id, "implementation:"+string(state), 11, -1, func(p, c obj, o *wire.ParentNameObservation) {
			o.ValueState, o.ChannelKeys = state, nil
		})
		for _, role := range []string{"seal", "key", "owner"} {
			observe("value-"+id+"-"+role+"-reuse", "DELEGATE_KEY_REUSE", 11, -1, func(p, c obj, o *wire.ParentNameObservation) {
				o.ValueState, o.ChannelKeys = state, nil
				switch role {
				case "seal":
					c["seal"].(obj)["key"] = opposite(output(2))
				case "key":
					c["recipient"] = obj{"key": signing(2)}
				case "owner":
					c["recipient"] = obj{"name": "id/example-child", "owner": opposite(output(2))}
				}
			})
		}
	}
	observe("delegation-not-in-set", "ok", 13, -1, func(p, c obj, o *wire.ParentNameObservation) { o.ChannelKeys = []string{signing(3), signing(1)} })
	observe("value-unset-with-keys", "implementation:", 11, -1, func(p, c obj, o *wire.ParentNameObservation) { o.ValueState = "" })
	observe("value-unknown", "implementation:unknown", 11, -1, func(p, c obj, o *wire.ParentNameObservation) { o.ValueState = "unknown" })
	observe("value-no-key-empty-list", "implementation:no-key", 11, -1, func(p, c obj, o *wire.ParentNameObservation) {
		o.ValueState, o.ChannelKeys = wire.ParentNameValueNoKey, []string{}
	})
	observe("value-refused-with-keys", "implementation:refused", 11, -1, func(p, c obj, o *wire.ParentNameObservation) {
		o.ValueState, o.ChannelKeys = wire.ParentNameValueRefused, []string{signing(2)}
	})
	observe("child-key-not-in-set", "ok", 13, -1, func(p, c obj, o *wire.ParentNameObservation) { o.ChannelKeys = []string{signing(3)} })
	observe("delegation-in-set", "DELEGATE_KEY_REUSE", 11, -1, func(p, c obj, o *wire.ParentNameObservation) { o.ChannelKeys = []string{signing(2)} })
	observe("delegation-first-in-set", "DELEGATE_KEY_REUSE", 11, -1, func(p, c obj, o *wire.ParentNameObservation) { o.ChannelKeys = []string{signing(2), signing(1)} })
	observe("delegation-last-in-set", "DELEGATE_KEY_REUSE", 11, -1, func(p, c obj, o *wire.ParentNameObservation) {
		o.ChannelKeys = []string{signing(1), signing(3), signing(2)}
	})
	observe("different-name", "input:name", 11, -1, func(p, c obj, o *wire.ParentNameObservation) { o.Name = "id/example-other" })
	observe("different-name-before-member", "input:name", 11, -1, func(p, c obj, o *wire.ParentNameObservation) {
		o.Name = "id/example-other"
		o.ChannelKeys = []string{signing(2)}
	})
	observe("empty-name", "input:name", 11, -1, func(p, c obj, o *wire.ParentNameObservation) { o.Name = "" })
	observe("empty-set", "input:empty", 11, -1, func(p, c obj, o *wire.ParentNameObservation) { o.ChannelKeys = []string{} })
	observe("nil-set", "input:empty", 11, -1, func(p, c obj, o *wire.ParentNameObservation) { o.ChannelKeys = nil })
	observe("duplicate-set", "input:duplicate", 11, 1, func(p, c obj, o *wire.ParentNameObservation) { o.ChannelKeys = []string{signing(1), signing(1)} })
	observe("duplicate-after-member", "input:duplicate", 11, 2, func(p, c obj, o *wire.ParentNameObservation) {
		o.ChannelKeys = []string{signing(2), signing(1), signing(1)}
	})
	for _, bad := range []struct{ id, key string }{
		{"empty-key", ""}, {"short-key", "01"}, {"uppercase-key", "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"},
		{"compressed-key", output(1)}, {"nonhex-key", fmt.Sprintf("%064s", "z")},
		{"offcurve-key", fmt.Sprintf("%064x", 0)}, {"out-of-field-key", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
	} {
		observe(bad.id, "input:key", 11, 0, func(p, c obj, o *wire.ParentNameObservation) { o.ChannelKeys = []string{bad.key} })
	}
	observe("malformed-after-member", "input:key", 11, 1, func(p, c obj, o *wire.ParentNameObservation) { o.ChannelKeys = []string{signing(2), "bad"} })
	observe("missing-tip", "input:identity", 11, -1, func(p, c obj, o *wire.ParentNameObservation) { o.TipHash = "" })
	observe("malformed-tip", "input:identity", 11, -1, func(p, c obj, o *wire.ParentNameObservation) { o.TipHash = "BAD" })
	observe("malformed-genesis", "input:identity", 11, -1, func(p, c obj, o *wire.ParentNameObservation) { o.Genesis = "bad" })
	observe("different-chain", "input:chain", 11, -1, func(p, c obj, o *wire.ParentNameObservation) { o.Genesis = hash("other-chain") })
	observe("genesis-tip-identity", "ok", 13, -1, func(p, c obj, o *wire.ParentNameObservation) { o.TipHeight = 0; o.TipHash = o.Genesis })
	observe("later-tip-identity", "ok", 13, -1, func(p, c obj, o *wire.ParentNameObservation) { o.TipHeight = 100; o.TipHash = hash("later-tip") })
	observe("by-key-unexpected-observation", "input:unexpected", 11, -1, func(p, c obj, o *wire.ParentNameObservation) { p["recipient"] = obj{"key": signing(1)} })
	// Earlier signed-octet rows retain precedence even with invalid facts and a
	// forbidden channel key; nearby existing cases witness each defect alone.
	for _, earlier := range []struct {
		id, want string
		step     int
		change   func(obj, obj)
	}{
		{"contract-before-observation", "CHILD_CONTRACT_DIFFERS", 5, func(p, c obj) { c["contract"] = hash("other-contract") }},
		{"genesis-before-observation", "SUBJECT_MISMATCH", 8, func(p, c obj) { c["genesis"] = hash("other-genesis") }},
		{"parent-key-before-observation", "DELEGATE_KEY_REUSE", 9, func(p, c obj) { p["issuer"].(obj)["grant_key"] = signing(2) }},
		{"missing-childseal-before-observation", "CHILD_SEAL_KEY", 10, func(p, c obj) { delete(p["delegate"].(obj), "child_seal_key") }},
		{"childseal-reuse-before-observation", "DELEGATE_KEY_REUSE", 10, func(p, c obj) { p["delegate"].(obj)["child_seal_key"] = output(2) }},
		{"child-seal-before-observation", "DELEGATE_KEY_REUSE", 11, func(p, c obj) { c["seal"].(obj)["key"] = opposite(output(2)) }},
		{"child-key-before-observation", "DELEGATE_KEY_REUSE", 11, func(p, c obj) { c["recipient"] = obj{"key": signing(2)} }},
		{"child-owner-before-observation", "DELEGATE_KEY_REUSE", 11, func(p, c obj) { c["recipient"] = obj{"name": "id/example-child", "owner": opposite(output(2))} }},
	} {
		observe(earlier.id, earlier.want, earlier.step, -1, func(p, c obj, o *wire.ParentNameObservation) {
			o.Name = "id/example-other"
			o.ChannelKeys = []string{signing(2)}
			earlier.change(p, c)
		})
	}
	observe("membership-before-f12", "DELEGATE_KEY_REUSE", 11, -1, func(p, c obj, o *wire.ParentNameObservation) {
		o.ChannelKeys = []string{signing(2)}
		c["seal"].(obj)["key"] = output(1)
	})
	observe("input-before-f12", "input:name", 11, -1, func(p, c obj, o *wire.ParentNameObservation) {
		o.Name = "id/example-other"
		c["seal"].(obj)["key"] = output(1)
	})
	observe("valid-f11-then-f12", "CHILD_SEAL_KEY", 12, -1, func(p, c obj, o *wire.ParentNameObservation) { c["seal"].(obj)["key"] = output(1) })
	observe("valid-f11-then-f13-bound", "CHILD_ORDINAL", 13, -1, func(p, c obj, o *wire.ParentNameObservation) { c["ordinal"] = 3 })

	row("template-valid", "ok", 0, "F14-F18 no limits, equal window", nil)
	row("executor-name", "CHILD_AGENT_NOT_ALLOWED", 14, "step-i-22", func(p, c obj) { c["executor"].(obj)["name"] = "id/example-other" })
	row("executor-key", "CHILD_AGENT_NOT_ALLOWED", 14, "R2.2 pinned key", func(p, c obj) { c["executor"].(obj)["key"] = signing(3) })
	row("recipient-key", "CHILD_GRANTEE_NOT_ALLOWED", 15, "step-i-23", func(p, c obj) { c["recipient"] = obj{"key": signing(3)} })
	row("recipient-mode", "CHILD_GRANTEE_NOT_ALLOWED", 15, "R2.3", func(p, c obj) { c["recipient"] = obj{"name": "id/example-agent", "owner": output(1)} })
	for _, part := range []string{"valid", "name", "owner", "parity", "mode"} {
		want, step := "CHILD_GRANTEE_NOT_ALLOWED", 15
		if part == "valid" {
			want, step = "ok", 0
		}
		row("by-name-"+part, want, step, "R2.3 exact name/owner", func(p, c obj) {
			template(p)["recipient"] = obj{"name": "id/example-agent", "owner": output(1)}
			c["recipient"] = obj{"name": "id/example-agent", "owner": output(1)}
			r := c["recipient"].(obj)
			switch part {
			case "name":
				r["name"] = "id/example-other"
			case "owner":
				r["owner"] = output(3)
			case "parity":
				r["owner"] = opposite(output(1))
			case "mode":
				c["recipient"] = obj{"key": signing(1)}
			}
		})
	}
	for _, byName := range []bool{false, true} {
		want, step := "CHILD_GRANTEE_NOT_ALLOWED", 15
		if byName {
			want, step = "ok", 0
		}
		row(fmt.Sprintf("class-by-name-%t", byName), want, step, "R9.3; F19 not claimed", func(p, c obj) {
			template(p)["recipient"] = obj{"class": []any{pin("id/example-landlord")}}
			if byName {
				c["recipient"] = obj{"name": "id/example-agent", "owner": output(1)}
			}
		})
	}
	row("j9-name", "ok", 0, "J9 exact-name; node owner facts deferred", func(p, c obj) {
		t := template(p)
		delete(t, "certifier")
		t["no_certifier"] = true
		t["recipient"] = obj{"name": "id/example-agent", "owner": output(1)}
		c["recipient"] = obj{"name": "id/example-agent", "owner": output(1)}
		delete(p["delegate"].(obj)["groups"].([]any)[0].(obj)["ranges"].([]any)[0].(obj), "stop")
	})
	row("actions-empty", "ok", 0, "step-v-02", func(p, c obj) { c["actions"] = []any{} })
	row("actions-equal", "ok", 0, "F16 equal set", func(p, c obj) { c["actions"] = []any{"example/a", "example/b"} })
	row("actions-wider", "CHILD_ACTIONS_WIDER", 16, "step-i-25", func(p, c obj) { c["actions"] = []any{"example/c"} })
	row("actions-use-delegate", "ok", 0, "F16 delegate.actions, not own actions", func(p, c obj) { c["actions"] = []any{"example/b"} })
	for _, amount := range []string{"0", "4", "5", "6", "18446744073709551615"} {
		row("limit-"+amount, "LIMIT_KIND_UNDEFINED", 17, "T9; step-i-30 (no profile)", func(p, c obj) {
			template(p)["limits"] = []any{limit("5")}
			p["delegate"].(obj)["pools"] = []any{limit("10")}
			c["limits"] = []any{limit(amount)}
		})
	}
	row("template-only-kind", "LIMIT_KIND_UNDEFINED", 17, "W11.14 both template and child", func(p, c obj) {
		template(p)["limits"] = []any{limit("5")}
		p["delegate"].(obj)["pools"] = []any{limit("10")}
	})
	row("new-key-zero", "CHILD_BUDGET_OVER", 17, "step-i-27; step-c-12", func(p, c obj) { c["limits"] = []any{limit("0")} })
	for _, multiple := range []bool{false, true} {
		row(fmt.Sprintf("limit-later-missing-key-%t", multiple), "CHILD_BUDGET_OVER", 17, "F17(a): every limit before kind lookup", func(p, c obj) {
			template(p)["limits"] = []any{limit("5")}
			p["delegate"].(obj)["pools"] = []any{limit("10")}
			missing := limit("0")
			missing["resource"] = "example/other"
			c["limits"] = []any{missing}
			if multiple {
				c["limits"] = []any{limit("1"), missing}
			}
		})
	}
	row("policy", "LIMIT_KIND_UNDEFINED", 17, "step-i-31", func(p, c obj) {
		a, b := limit("5"), limit("10")
		a["kind"] = "policy"
		b["kind"] = "policy"
		template(p)["limits"] = []any{a}
		p["delegate"].(obj)["pools"] = []any{b}
		c["limits"] = []any{a}
	})
	for _, part := range []string{"kind", "resource", "unit", "period"} {
		row("limit-key-"+part, "CHILD_BUDGET_OVER", 17, "F17(a); period presence matters", func(p, c obj) {
			template(p)["limits"] = []any{limit("5")}
			p["delegate"].(obj)["pools"] = []any{limit("10")}
			a := limit("0")
			a[part] = "example/other"
			c["limits"] = []any{a}
		})
	}
	for _, w := range [][2]int{{10, 20}, {11, 19}, {10, 11}, {19, 20}, {9, 20}, {10, 21}, {0, 20}, {10, 9007199254740991}} {
		want, step := "ok", 0
		if w[0] < 10 || w[1] > 20 {
			want, step = "CHILD_WINDOW_NOT_NESTED", 18
		}
		row(fmt.Sprintf("window-%d-%d", w[0], w[1]), want, step, "F18; step-i-28/29", func(p, c obj) { c["not_before_height"], c["not_after_height"] = w[0], w[1] })
	}
	row("executor-before-recipient", "CHILD_AGENT_NOT_ALLOWED", 14, "F14 before F15", func(p, c obj) {
		c["executor"].(obj)["name"] = "id/example-other"
		c["recipient"] = obj{"key": signing(3)}
	})
	row("recipient-before-actions", "CHILD_GRANTEE_NOT_ALLOWED", 15, "step-c-09", func(p, c obj) { c["recipient"] = obj{"key": signing(3)}; c["actions"] = []any{"example/c"} })
	row("actions-before-key", "CHILD_ACTIONS_WIDER", 16, "step-c-10", func(p, c obj) { c["actions"] = []any{"example/c"}; c["limits"] = []any{limit("0")} })
	row("key-before-kind", "CHILD_BUDGET_OVER", 17, "step-c-12", func(p, c obj) {
		template(p)["limits"] = []any{limit("5")}
		p["delegate"].(obj)["pools"] = []any{limit("10")}
		a := limit("0")
		a["resource"] = "example/other"
		c["limits"] = []any{a}
	})
	row("kind-before-amount-and-window", "LIMIT_KIND_UNDEFINED", 17, "T9; step-i-30", func(p, c obj) {
		template(p)["limits"] = []any{limit("5")}
		p["delegate"].(obj)["pools"] = []any{limit("10")}
		c["limits"] = []any{limit("6")}
		c["not_after_height"] = 21
	})
	row("key-before-window", "CHILD_BUDGET_OVER", 17, "step-c-11 without stand-in profile", func(p, c obj) { c["limits"] = []any{limit("0")}; c["not_after_height"] = 21 })
	// J12: the first group has ranges of three and two, the second four.
	// These signed fixtures instantiate the exact example's relative positions.
	nineRows := func(parent, child obj) {
		delegation := parent["delegate"].(obj)
		firstGroup := delegation["groups"].([]any)[0].(obj)
		makeRange := func(label string, first, count int) obj {
			return obj{"txid": hash(label), "first": first, "count": count, "script": "0014" + fmt.Sprintf("%040x", 1),
				"stop": obj{"txid": hash(label + "-stop"), "first": first, "script": "0014" + fmt.Sprintf("%040x", 2)}}
		}
		firstGroup["ranges"] = []any{makeRange("example-j12-first", 9, 3), makeRange("example-j12-second", 20, 2)}
		secondTemplate := obj{"executor": obj{"name": "id/example-second-executor", "key": signing(3)},
			"recipient": obj{"key": signing(3)}, "limits": []any{}, "certifier": "id/example-notary"}
		delegation["groups"] = []any{firstGroup, obj{"template": secondTemplate, "ranges": []any{makeRange("example-j12-third", 30, 4)}}}
	}
	positions := []struct {
		ordinal, group, span, index int
		label                       string
	}{
		{1, 0, 0, 9, "example-j12-first"}, {2, 0, 0, 10, "example-j12-first"}, {3, 0, 0, 11, "example-j12-first"},
		{4, 0, 1, 20, "example-j12-second"}, {5, 0, 1, 21, "example-j12-second"},
		{6, 1, 0, 30, "example-j12-third"}, {7, 1, 0, 31, "example-j12-third"}, {8, 1, 0, 32, "example-j12-third"}, {9, 1, 0, 33, "example-j12-third"},
	}
	for _, position := range positions {
		add(fmt.Sprintf("selection-%d", position.ordinal), "selection", "ok", 0, "LIP-0026 section 8 J12 nine-row example; F13", func(parent, child obj) {
			nineRows(parent, child)
			child["ordinal"] = position.ordinal
			if position.group == 1 {
				child["executor"] = obj{"name": "id/example-second-executor", "key": signing(3)}
				child["recipient"] = obj{"key": signing(3)}
			}
		})
		cases[len(cases)-1].Selected = &wire.ChildAttenuationEvaluation{GroupIndex: position.group, RangeIndex: position.span,
			RowCoin: wire.Outpoint{TxID: hash(position.label), Vout: uint64(position.index)}}
		cases[len(cases)-1].Neighbour = fmt.Sprintf("selection-%d", position.ordinal)
	}
	selectCase := func(id, want string, step int, mutate func(obj, obj)) {
		add(id, "selection", want, step, "F13 selected row; F12-F18 precedence", func(parent, child obj) {
			nineRows(parent, child)
			child["ordinal"] = 6
			child["executor"] = obj{"name": "id/example-second-executor", "key": signing(3)}
			child["recipient"] = obj{"key": signing(3)}
			mutate(parent, child)
		})
		cases[len(cases)-1].Neighbour = "selection-6"
	}
	selectCase("selection-zero", "CHILD_ORDINAL", 13, func(parent, child obj) { child["ordinal"] = 0 })
	selectCase("selection-ten", "CHILD_ORDINAL", 13, func(parent, child obj) { child["ordinal"] = 10 })
	selectCase("selection-other-template", "CHILD_AGENT_NOT_ALLOWED", 14, func(parent, child obj) { child["ordinal"] = 1 })
	selectCase("selection-executor", "CHILD_AGENT_NOT_ALLOWED", 14, func(parent, child obj) { child["executor"].(obj)["key"] = signing(1) })
	selectCase("selection-recipient", "CHILD_GRANTEE_NOT_ALLOWED", 15, func(parent, child obj) { child["recipient"] = obj{"key": signing(1)} })
	selectCase("selection-actions", "CHILD_ACTIONS_WIDER", 16, func(parent, child obj) { child["actions"] = []any{"example/c"} })
	selectCase("selection-budget", "CHILD_BUDGET_OVER", 17, func(parent, child obj) { child["limits"] = []any{limit("0")} })
	selectCase("selection-window", "CHILD_WINDOW_NOT_NESTED", 18, func(parent, child obj) { child["not_after_height"] = 21 })
	selectCase("selection-seal-before-bound", "CHILD_SEAL_KEY", 12, func(parent, child obj) { child["seal"].(obj)["key"] = output(1); child["ordinal"] = 0 })
	selectCase("selection-bound-before-executor", "CHILD_ORDINAL", 13, func(parent, child obj) { child["ordinal"] = 10; child["executor"].(obj)["key"] = signing(1) })
	selectCase("selection-executor-before-recipient", "CHILD_AGENT_NOT_ALLOWED", 14, func(parent, child obj) {
		child["executor"].(obj)["key"] = signing(1)
		child["recipient"] = obj{"key": signing(1)}
	})
	selectCase("selection-recipient-before-actions", "CHILD_GRANTEE_NOT_ALLOWED", 15, func(parent, child obj) {
		child["recipient"] = obj{"key": signing(1)}
		child["actions"] = []any{"example/c"}
	})
	selectCase("selection-actions-before-budget", "CHILD_ACTIONS_WIDER", 16, func(parent, child obj) { child["actions"] = []any{"example/c"}; child["limits"] = []any{limit("0")} })
	selectCase("selection-budget-before-window", "CHILD_BUDGET_OVER", 17, func(parent, child obj) { child["limits"] = []any{limit("0")}; child["not_after_height"] = 21 })
	for _, kind := range []string{"swarma/coins", "swarma/model-cost", "swarma/model-tokens"} {
		selectCase("selection-no-profile-"+kind, "LIMIT_KIND_UNDEFINED", 17, func(parent, child obj) {
			rowLimit, pool := limit("5"), limit("20")
			rowLimit["kind"], pool["kind"] = kind, kind
			delegation := parent["delegate"].(obj)
			delegation["groups"].([]any)[1].(obj)["template"].(obj)["limits"] = []any{rowLimit}
			delegation["pools"] = []any{pool}
			child["limits"] = []any{rowLimit}
			child["not_after_height"] = 21
		})
	}
	// These pipeline boundaries cannot be reached by two already verified matching
	// documents: the reader rejects the attempted extra link before returning one.
	p := parent()
	pb, pid := signed(p, 1)
	c := child()
	c["parent"] = pid
	cb, cid := signed(c, 2)
	grand := child()
	grand["parent"] = cid
	gb, _ := signed(grand, 2)
	cases = append(cases, fixture{ID: "depth-three", Mode: "reader", Parent: cb, Child: gb, Ancestor: pb, Expect: "CHAIN_DEPTH", Step: 2, Neighbour: "prefix-open", Spec: "D7; W11.8 step 6"})
	p = parent()
	delete(p, "delegate")
	pb, pid = signed(p, 1)
	c = child()
	c["parent"] = pid
	cb, _ = signed(c, 2)
	cases = append(cases, fixture{ID: "not-delegable", Mode: "reader", Parent: pb, Child: cb, Expect: "NOT_DELEGABLE", Step: 2, Neighbour: "prefix-open", Spec: "W11.8 step 6"})
	// These composed vectors pin the declared post-pipeline S8-29 divergence,
	// not the admission outcomes deferred with O7 / LIP-0026 Q1.
	for _, listed := range []bool{false, true} {
		for _, variant := range []string{"valid", "ordinal-zero", "wrong-signer"} {
			parentDoc, childDoc := parent(), child()
			template(parentDoc)["certifier"] = "id/example-other-notary"
			if listed {
				parentDoc["delegate"].(obj)["notaries"] = []any{pin("id/example-other-notary")}
			}
			parentBytes, parentID := signed(parentDoc, 1)
			childDoc["parent"] = parentID
			childScalar := 2
			want, step := "ok", 0
			if variant == "ordinal-zero" {
				childDoc["ordinal"] = 0
				want, step = "CHILD_ORDINAL", 13
			}
			if variant == "wrong-signer" {
				childScalar = 1
				want, step = "CHILD_SIGNER", 2
			}
			if !listed {
				want, step = "GRANT_DELEGATE", 1
			}
			childBytes, _ := signed(childDoc, childScalar)
			cases = append(cases, fixture{ID: fmt.Sprintf("composition-notary-%t-%s", listed, variant), Mode: "composition",
				Parent: parentBytes, Child: childBytes, Expect: want, Step: step,
				Neighbour: "composition-notary-true-valid", Spec: "S8-29; section 8.7 document precondition, not F13(b)"})
		}
	}
	// Keep compact signed-form objects: the restricted canonical reader does not
	// accept indentation inside their bytes.
	var buf bytes.Buffer
	e := json.NewEncoder(&buf)
	e.SetEscapeHTML(false)
	must(e.Encode(obj{"spec_commit": "464c445fd52ce0ec8bdc52c0ead8a866a7b77f56", "public_test_scalars": []int{1, 2, 3}, "aux_rand": fmt.Sprintf("%064x", 0), "j12_example": "Take a parent with two groups. The first has ranges of three and of two coins,\nthe second one range of four. The parent has nine rows. The ordinals 1 to 3 are\nthe coins of the first range in the order of their output indices, 4 and 5\nthose of the second, and 6 to 9 those of the second group. A child with the\nordinal 5 is checked against the template of the first group and against the\nsecond coin of its second range, and a child with the ordinal 10 refuses as\n`CHILD_ORDINAL` before any row is read.", "vectors": cases}))
	_, err := os.Stdout.Write(buf.Bytes())
	must(err)
}
