package rental

import (
	"encoding/json"
	"strings"
	"testing"
)

func n1Descriptor(key string) NostrDescriptor { return NostrDescriptor{Names: NostrNames{Root: key}} }

// Historical bytes/bindings survive; social metadata never substitutes a grant key.
func TestN1Values(t *testing.T) {
	_, k := testKey(1)
	_, n := testKey(3)
	a := AgentBinding{n, "id/landlord"}
	l := LandlordBinding{k}
	oldA, _ := AgentBindingValue(a)
	oldL, _ := LandlordValue(l)
	if oldA != `{"swarma":{"agent":{"nostr":"`+n+`","landlord":"id/landlord"}}}` || oldL != `{"swarma":{"landlord":{"grant":"`+k+`"}}}` {
		t.Fatal("historical bytes changed")
	}
	for _, relays := range []bool{false, true} {
		d := n1Descriptor(n)
		if relays {
			d.Relays = map[string][]string{n: {"wss://relay.example/", "ws://localhost:1234/"}}
		}
		av, e := CombinedAgentBindingValue(a, d)
		if e != nil {
			t.Fatal(e)
		}
		lv, e := CombinedLandlordValue(l, d)
		if e != nil {
			t.Fatal(e)
		}
		for _, raw := range []string{oldA, av} {
			got, e := ParseAgentBinding(raw)
			if e != nil || got != a {
				t.Fatal("agent neighbor", e)
			}
		}
		for _, raw := range []string{oldL, lv} {
			got, e := ParseLandlordValue(raw)
			if e != nil || got != l {
				t.Fatal("landlord neighbor", e)
			}
		}
		_, desc, e := ParseAgentIdentity(av)
		if e != nil || desc == nil || desc.Names.Root != n {
			t.Fatal("agent descriptor lost")
		}
		_, desc, e = ParseLandlordIdentity(lv)
		if e != nil || desc == nil || desc.Names.Root != n {
			t.Fatal("landlord descriptor lost")
		}
	}
	if _, e := CombinedLandlordValue(l, n1Descriptor(k)); e != nil {
		t.Fatal("equal landlord keys refused")
	}
	if _, e := CombinedAgentBindingValue(a, n1Descriptor(k)); e == nil {
		t.Fatal("agent mismatch builder accepted")
	}
}

// Malformed descriptors return zero bindings; each rejection has a valid neighbor.
func TestN1Refusals(t *testing.T) {
	_, k := testKey(1)
	_, n := testKey(3)
	valid := `{"names":{"_":"` + n + `"}}`
	cases := map[string]string{"null": "null", "empty": "{}", "scalar": `"` + n + `"`, "array": "[]", "missing_names": `{"relays":{"` + n + `":["wss://relay.example/"]}}`, "missing_root": `{"names":{}}`, "null_names": `{"names":null}`, "null_root": `{"names":{"_":null}}`, "extra_name": `{"names":{"_":"` + n + `","other":"` + n + `"}}`, "legacy_pubkey": `{"pubkey":"` + n + `"}`, "extra": `{"names":{"_":"` + n + `"},"extra":0}`, "alias": `{"Names":{"_":"` + n + `"}}`, "import": `{"names":{"_":"` + n + `"},"import":[]}`, "duplicate_root": `{"names":{"_":"` + n + `","_":"` + n + `"}}`, "escaped_duplicate": `{"names":{"_":"` + n + `","\u005f":"` + n + `"}}`, "duplicate_names": `{"names":{"_":"` + n + `"},"names":{"_":"` + n + `"}}`, "case_duplicate": `{"names":{"_":"` + n + `"},"Names":{"_":"` + n + `"}}`}
	relays := map[string]string{"other_key": `{"` + k + `":["wss://relay.example/"]}`, "empty_map": "{}", "null_map": "null", "null_array": `{"` + n + `":null}`, "empty_array": `{"` + n + `":[]}`, "null_url": `{"` + n + `":[null]}`, "numeric_url": `{"` + n + `":[42]}`, "wrong_scheme": `{"` + n + `":["https://relay.example/"]}`, "no_host": `{"` + n + `":["wss:///path"]}`, "relative": `{"` + n + `":["relay.example"]}`, "duplicate_url": `{"` + n + `":["wss://relay.example/","wss://relay.example/"]}`, "duplicate_key": `{"` + n + `":["wss://a.example/"],"` + n + `":["wss://b.example/"]}`}
	for name, r := range relays {
		cases["relay_"+name] = `{"names":{"_":"` + n + `"},"relays":` + r + `}`
	}
	for name, key := range map[string]string{"uppercase": strings.ToUpper(n), "short": n[:63], "long": n + "0", "invalid_point": strings.Repeat("f", 64), "nonhex": strings.Repeat("z", 64)} {
		cases["key_"+name] = `{"names":{"_":"` + key + `"}}`
	}
	for name, d := range cases {
		t.Run(name, func(t *testing.T) {
			a := `{"nostr":` + d + `,"swarma":{"agent":{"nostr":"` + n + `","landlord":"id/landlord"}}}`
			l := `{"nostr":` + d + `,"swarma":{"landlord":{"grant":"` + k + `"}}}`
			if got, e := ParseAgentBinding(a); e == nil || got != (AgentBinding{}) {
				t.Fatal("N1 invalid agent accepted", name)
			}
			if got, e := ParseLandlordValue(l); e == nil || got != (LandlordBinding{}) {
				t.Fatal("N1 invalid landlord accepted", name)
			}
			if _, e := ParseAgentBinding(strings.Replace(a, d, valid, 1)); e != nil {
				t.Fatal("positive agent neighbor", e)
			}
			if _, e := ParseLandlordValue(strings.Replace(l, d, valid, 1)); e != nil {
				t.Fatal("positive landlord neighbor", e)
			}
		})
	}
	av, _ := CombinedAgentBindingValue(AgentBinding{n, "id/landlord"}, n1Descriptor(n))
	if _, e := ParseAgentBinding(strings.Replace(av, `"_":"`+n+`"`, `"_":"`+k+`"`, 1)); e == nil || e.Error() != "AGENT_NOSTR_MISMATCH" {
		t.Fatal("N1 cross-key guard", e)
	}
	for _, raw := range []string{av + " ", av + "{}", strings.Replace(av, `"nostr":`, `"Nostr":`, 1), strings.Replace(av, `"nostr":`, `"extra":0,"nostr":`, 1), strings.Replace(av, `"nostr":`, `"nostr":null,"nostr":`, 1), strings.Replace(av, `"landlord":`, `"landlord":"id/landlord","landlord":`, 1), strings.Replace(av, "id/landlord", "d/landlord", 1)} {
		if got, e := ParseAgentBinding(raw); e == nil || got != (AgentBinding{}) {
			t.Fatal("N1 root/canonical guard")
		}
	}
	var v agentBindingValue
	json.Unmarshal([]byte(av), &v)
	reversed, _ := json.Marshal(struct {
		Swarma any `json:"swarma"`
		Nostr  any `json:"nostr"`
	}{v.Swarma, v.Nostr})
	if _, e := ParseAgentBinding(string(reversed)); e == nil {
		t.Fatal("N1 order guard")
	}
	if _, e := ParseAgentBinding(`{"nostr":` + valid + `}`); e == nil {
		t.Fatal("discovery accepted as agent authority")
	}
	if _, e := ParseLandlordValue(`{"nostr":` + valid + `}`); e == nil {
		t.Fatal("discovery accepted as landlord authority")
	}
}

// Serialized 520-byte canonical values pass; 521-byte neighbors fail in both directions.
func TestN1ByteBoundary(t *testing.T) {
	_, k := testKey(1)
	_, n := testKey(3)
	for _, role := range []string{"agent", "landlord"} {
		t.Run(role, func(t *testing.T) {
			build := func(d NostrDescriptor) (string, error) {
				if role == "agent" {
					return CombinedAgentBindingValue(AgentBinding{n, "id/landlord"}, d)
				}
				return CombinedLandlordValue(LandlordBinding{k}, d)
			}
			parse := func(s string) error {
				if role == "agent" {
					_, e := ParseAgentBinding(s)
					return e
				}
				_, e := ParseLandlordValue(s)
				return e
			}
			d := n1Descriptor(n)
			d.Relays = map[string][]string{n: {"wss://relay.example/"}}
			s, e := build(d)
			if e != nil {
				t.Fatal(e)
			}
			d.Relays[n][0] += strings.Repeat("x", 520-len(s))
			s, e = build(d)
			if e != nil || len(s) != 520 || parse(s) != nil {
				t.Fatal("N1 520 neighbor", len(s), e)
			}
			larger := strings.Replace(s, "wss://relay.example/", "wss://relay.example/x", 1)
			if len(larger) != 521 || parse(larger) == nil {
				t.Fatal("N1 521 parser guard")
			}
			d.Relays[n][0] += "x"
			if got, e := build(d); e == nil || got != "" {
				t.Fatal("N1 521 builder guard")
			}
		})
	}
}

// Builders reject malformed descriptors before producing bytes; relay key-set
// checks and URL checks are exercised independently of canonical decoding.
func TestN1DescriptorGuards(t *testing.T) {
	_, n := testKey(3)
	_, k := testKey(1)
	cases := map[string]NostrDescriptor{
		"key":         n1Descriptor(strings.Repeat("f", 64)),
		"relay_arity": {Names: NostrNames{n}, Relays: map[string][]string{n: {"wss://a.example/"}, k: {"wss://b.example/"}}},
		"relay_root":  {Names: NostrNames{n}, Relays: map[string][]string{k: {"wss://a.example/"}}},
		"relay_empty": {Names: NostrNames{n}, Relays: map[string][]string{n: {}}},
	}
	for name, u := range map[string]string{"scheme": "https://a.example/", "host": "wss:///path", "userinfo": "wss://name@a.example/", "fragment": "wss://a.example/#x", "malformed": "wss://a.example/%zz"} {
		cases[name] = NostrDescriptor{Names: NostrNames{n}, Relays: map[string][]string{n: {u}}}
	}
	cases["duplicate"] = NostrDescriptor{Names: NostrNames{n}, Relays: map[string][]string{n: {"wss://a.example/", "wss://a.example/"}}}
	for name, d := range cases {
		t.Run(name, func(t *testing.T) {
			if raw, e := CombinedLandlordValue(LandlordBinding{k}, d); e == nil || raw != "" {
				t.Fatal("N1 descriptor builder guard")
			}
			if raw, e := CombinedAgentBindingValue(AgentBinding{n, "id/example"}, d); e == nil || raw != "" {
				t.Fatal("N1 agent descriptor builder guard")
			}
			var v landlordBindingValue
			v.Nostr = &d
			v.Swarma.Landlord = LandlordBinding{k}
			raw, _ := json.Marshal(v)
			if got, e := ParseLandlordValue(string(raw)); e == nil || got != (LandlordBinding{}) {
				t.Fatal("N1 descriptor parser guard")
			}
			if _, e := CombinedLandlordValue(LandlordBinding{k}, n1Descriptor(n)); e != nil {
				t.Fatal("descriptor neighbor", e)
			}
		})
	}
}

// Canonical field order and UTF-8 size are checked after actual serialization.
func TestN1Encoding(t *testing.T) {
	_, n := testKey(3)
	d := n1Descriptor(n)
	d.Relays = map[string][]string{n: {"wss://a.example/"}}
	raw, e := CombinedAgentBindingValue(AgentBinding{n, "id/example"}, d)
	if e != nil {
		t.Fatal(e)
	}
	nd, _ := json.Marshal(d.Names)
	rd, _ := json.Marshal(d.Relays)
	badOrder := strings.Replace(raw, `"names":`+string(nd)+`,"relays":`+string(rd), `"relays":`+string(rd)+`,"names":`+string(nd), 1)
	if _, e := ParseAgentBinding(badOrder); e == nil {
		t.Fatal("N1 inner order guard")
	}
	d.Relays[n][0] += strings.Repeat("x", 518-len(raw)) + "é"
	raw, e = CombinedAgentBindingValue(AgentBinding{n, "id/example"}, d)
	if e != nil || len(raw) != 520 {
		t.Fatal("N1 multibyte neighbor", len(raw), e)
	}
	d.Relays[n][0] += "x"
	if _, e := CombinedAgentBindingValue(AgentBinding{n, "id/example"}, d); e == nil {
		t.Fatal("N1 multibyte bound")
	}
}
