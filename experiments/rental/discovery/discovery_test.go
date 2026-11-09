package discovery

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
)

func pub(n byte) string {
	b := make([]byte, 32)
	b[31] = n
	k, _ := btcec.PrivKeyFromBytes(b)
	return hex.EncodeToString(schnorr.SerializePubKey(k.PubKey()))
}
func inventory(t *testing.T) Inventory {
	t.Helper()
	l, e := rental.CombinedLandlordValue(rental.LandlordBinding{Grant: pub(1)}, rental.NostrDescriptor{Names: rental.NostrNames{Root: pub(2)}})
	if e != nil {
		t.Fatal(e)
	}
	a, e := rental.CombinedAgentBindingValue(rental.AgentBinding{Nostr: pub(3), Landlord: "id/example"}, rental.NostrDescriptor{Names: rental.NostrNames{Root: pub(3)}})
	if e != nil {
		t.Fatal(e)
	}
	return Inventory{"id/example", l, []Agent{{"cedar", "id/example-cedar", a}}}
}

// Exact inventory mirrors pass; missing/extra/key drift is deterministic and the
// authority parsers never admit the d/ shape, including a valid root-only mirror.
func TestDiscovery(t *testing.T) {
	i := inventory(t)
	r, e := Expected(i)
	if e != nil {
		t.Fatal(e)
	}
	d, e := Check(r, i)
	if e != nil || !d.OK {
		t.Fatal("valid discovery", e)
	}
	tests := []struct {
		name                     string
		agents                   map[string]string
		root                     string
		missing, extra, mismatch string
	}{{"missing", map[string]string{}, pub(2), "cedar", "", ""}, {"extra", map[string]string{"cedar": pub(3), "birch": pub(4)}, pub(2), "", "birch", ""}, {"key", map[string]string{"cedar": pub(4)}, pub(2), "", "", "cedar"}, {"root", map[string]string{"cedar": pub(3)}, pub(4), "", "", "_"}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, e := Build(tt.root, tt.agents)
			if e != nil {
				t.Fatal(e)
			}
			got, e := Check(Record{r.Name, raw}, i)
			if e != nil || got.OK || strings.Join(got.Missing, ",") != tt.missing || strings.Join(got.Extra, ",") != tt.extra || strings.Join(got.Mismatched, ",") != tt.mismatch {
				t.Fatal("discovery drift guard", got, e)
			}
			if got, e := Check(r, i); e != nil || !got.OK {
				t.Fatal("valid neighbor")
			}
		})
	}
	for _, raw := range []string{r.Value, `{"nostr":{"names":{"_":"` + pub(2) + `"}}}`} {
		if _, e := rental.ParseAgentBinding(raw); e == nil {
			t.Fatal("discovery became agent authority")
		}
		if _, e := rental.ParseLandlordValue(raw); e == nil {
			t.Fatal("discovery became landlord authority")
		}
	}
	if _, e := Parse(i.Value); e == nil {
		t.Fatal("authority became discovery")
	}
	if _, e := Check(Record{"id/example", r.Value}, i); e == nil {
		t.Fatal("discovery namespace guard")
	}
}

// Closed schemas/canonical bytes, real curve keys and flat labels reject ambiguity.
func TestDiscoveryRefusals(t *testing.T) {
	i := inventory(t)
	r, _ := Expected(i)
	for _, raw := range []string{r.Value + " ", r.Value + "{}", strings.Replace(r.Value, `"nostr":`, `"nostr":null,"nostr":`, 1), strings.Replace(r.Value, `"names":`, `"extra":0,"names":`, 1), strings.Replace(r.Value, `"_":`, `"_":"`+pub(1)+`","_":`, 1), strings.Replace(r.Value, `"cedar":`, `"Cedar":`, 1), strings.Replace(r.Value, pub(3), strings.Repeat("f", 64), 1), `{"nostr":{"names":null}}`, `{"nostr":{"names":{}}}`, strings.Replace(r.Value, `"cedar":"`+pub(3)+`"`, `"cedar":null`, 1)} {
		if _, e := Parse(raw); e == nil {
			t.Fatal("discovery parser guard")
		}
	}
	for _, label := range []string{"_", "*", "", "Cedar", "a.b", "a--b", "-a", "a-"} {
		if _, e := Build(pub(2), map[string]string{label: pub(3)}); e == nil {
			t.Fatal("discovery label guard")
		}
	}
	for _, mut := range []func(*Inventory){func(i *Inventory) { i.Agents = nil }, func(i *Inventory) { i.Landlord = "d/example" }, func(i *Inventory) { i.Agents[0].Name = "d/example-cedar" }, func(i *Inventory) {
		i.Agents[0].Value = strings.Replace(i.Agents[0].Value, "id/example", "id/foreign", 1)
	}, func(i *Inventory) { i.Agents = append(i.Agents, i.Agents[0]) }, func(i *Inventory) { i.Agents = append(i.Agents, Agent{"birch", i.Agents[0].Name, i.Agents[0].Value}) }, func(i *Inventory) { i.Agents = append(i.Agents, Agent{"cedar", "id/second", i.Agents[0].Value}) }} {
		j := inventory(t)
		mut(&j)
		if _, e := Expected(j); e == nil {
			t.Fatal("inventory guard")
		}
		if _, e := Expected(i); e != nil {
			t.Fatal("inventory valid neighbor", e)
		}
	}
}

// Variable label lengths create actual 520/521-byte canonical neighboring values.
func TestDiscoveryBytes(t *testing.T) {
	agents := map[string]string{}
	for n := 0; n < 5; n++ {
		agents[string(rune('a'+n))] = pub(byte(n + 3))
	}
	raw, e := Build(pub(2), agents)
	if e != nil {
		t.Fatal(e)
	}
	b := agents["b"]
	delete(agents, "b")
	agents["b"+strings.Repeat("x", 30)] = b
	raw, e = Build(pub(2), agents)
	if e != nil {
		t.Fatal(e)
	}
	k := agents["a"]
	delete(agents, "a")
	label := "a" + strings.Repeat("x", 520-len(raw))
	agents[label] = k
	raw, e = Build(pub(2), agents)
	if e != nil || len(raw) != 520 {
		t.Fatal("discovery 520 neighbor", len(raw), e)
	}
	if _, e := Parse(raw); e != nil {
		t.Fatal(e)
	}
	larger := strings.Replace(raw, `"`+label+`":`, `"`+label+`x":`, 1)
	if len(larger) != 521 {
		t.Fatal("fixture size")
	}
	if _, e := Parse(larger); e == nil {
		t.Fatal("discovery 521 parser guard")
	}
	delete(agents, label)
	agents[label+"x"] = k
	if _, e := Build(pub(2), agents); e == nil {
		t.Fatal("discovery 521 builder guard")
	}
}

// Each independent inventory guard refuses its own otherwise valid witness;
// empty (explicit) inventories and hyphenated lowercase labels remain valid.
func TestInventoryGuards(t *testing.T) {
	cases := map[string]func(*Inventory){
		"nil_agents":         func(i *Inventory) { i.Agents = nil },
		"landlord_namespace": func(i *Inventory) { i.Landlord = "d/example"; i.Agents = []Agent{} },
		"landlord_label":     func(i *Inventory) { i.Landlord = "id/Example" },
		"agent_label":        func(i *Inventory) { i.Agents[0].Label = "Cedar" },
		"agent_namespace":    func(i *Inventory) { i.Agents[0].Name = "d/cedar" },
		"agent_same_name":    func(i *Inventory) { i.Agents[0].Name = i.Landlord },
		"duplicate_name":     func(i *Inventory) { i.Agents = append(i.Agents, Agent{"birch", i.Agents[0].Name, i.Agents[0].Value}) },
		"duplicate_label":    func(i *Inventory) { i.Agents = append(i.Agents, Agent{"cedar", "id/second", i.Agents[0].Value}) },
		"pointer": func(i *Inventory) {
			i.Agents[0].Value = strings.Replace(i.Agents[0].Value, "id/example", "id/foreign", 1)
		},
		"landlord_social": func(i *Inventory) { i.Value, _ = rental.LandlordValue(rental.LandlordBinding{Grant: pub(1)}) },
		"agent_social": func(i *Inventory) {
			i.Agents[0].Value, _ = rental.AgentBindingValue(rental.AgentBinding{Nostr: pub(3), Landlord: "id/example"})
		},
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			i := inventory(t)
			mut(&i)
			if _, e := Expected(i); e == nil {
				t.Fatal("inventory independent guard")
			}
			if _, e := Expected(inventory(t)); e != nil {
				t.Fatal("inventory neighbor", e)
			}
		})
	}
	i := inventory(t)
	i.Agents = []Agent{}
	if _, e := Expected(i); e != nil {
		t.Fatal("empty inventory neighbor", e)
	}
	if _, e := Build(pub(2), map[string]string{"cedar-one": pub(3)}); e != nil {
		t.Fatal("label neighbor", e)
	}
}

// Missing root, invalid agent point and reserved labels cannot become discovery.
func TestDiscoverySemanticGuards(t *testing.T) {
	if _, e := Parse(`{"nostr":{"names":{"cedar":"` + pub(3) + `"}}}`); e == nil {
		t.Fatal("discovery root guard")
	}
	if _, e := Build(pub(2), map[string]string{"cedar": strings.Repeat("f", 64)}); e == nil {
		t.Fatal("discovery key guard")
	}
	if _, e := Build(pub(2), map[string]string{"_": pub(3)}); e == nil {
		t.Fatal("discovery reserved guard")
	}
	if _, e := Build(pub(2), map[string]string{"cedar": pub(3)}); e != nil {
		t.Fatal("discovery semantic neighbor", e)
	}
}

// Exact published fixtures are internally consistent; the inventory references
// the separate canonical id/ files and the expected d/ value byte-for-byte.
func TestDiscoveryFixtures(t *testing.T) {
	read := func(name string) []byte {
		t.Helper()
		b, e := os.ReadFile("../testdata/n1-values/" + name + ".json")
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	var i Inventory
	if e := json.Unmarshal(read("inventory"), &i); e != nil {
		t.Fatal(e)
	}
	if i.Value != string(read("landlord")) || len(i.Agents) != 1 || i.Agents[0].Value != string(read("agent")) {
		t.Fatal("id fixture mismatch")
	}
	r, e := Expected(i)
	if e != nil {
		t.Fatal(e)
	}
	if r.Value != string(read("discovery")) {
		t.Fatal("discovery fixture mismatch")
	}
	b, e := json.Marshal(r)
	if e != nil || !bytes.Equal(b, read("record")) {
		t.Fatal("record fixture mismatch", e)
	}
}
