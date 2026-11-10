package rental

import (
	"context"
	"fmt"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"os"
	"path/filepath"
	"testing"
)

// Genuine isolated Core accepts arbitrary name bytes; the real resolver must
// refuse duplicate/escaped authority keys both pending and confirmed, without
// panic, returned authority, state creation or any change to chain/mempool.
// Repairing the name restores resolution for both plain and N1 name documents.
func TestCoreSJ1NameKeys(t *testing.T) {
	l := newCore(t)
	l.grantIdentity()
	_, key := testKey(1)
	_, social := testKey(3)
	plain, e := LandlordValue(LandlordBinding{key})
	if e != nil {
		t.Fatal(e)
	}
	n1, e := CombinedLandlordValue(LandlordBinding{key}, n1Descriptor(social))
	if e != nil {
		t.Fatal(e)
	}
	p := Policy{Network: "regtest", Genesis: su.RegtestGenesis, LandlordName: labLandlord, StateDir: filepath.Join(l.root, "must-not-create")}
	resolve := func(want string) {
		t.Helper()
		before := string(l.rpc("", "getrawmempool"))
		tip := string(l.rpc("", "getbestblockhash"))
		name := string(l.rpc("", "name_show", labLandlord))
		got, generation, e := ResolveLandlordGrantKey(context.Background(), l.observer, p, labLandlord)
		if want == "" {
			if e != nil || got != key || !validGeneration(generation) {
				t.Fatal("valid resolver neighbor", e)
			}
		} else if e == nil || e.Error() != want || got != "" || generation != (Anchor{}) {
			t.Fatalf("resolver key refusal: want %s got %v", want, e)
		}
		if string(l.rpc("", "getrawmempool")) != before || string(l.rpc("", "getbestblockhash")) != tip || string(l.rpc("", "name_show", labLandlord)) != name {
			t.Fatal("resolver mutated chain or name")
		}
		if _, e := os.Stat(p.StateDir); !os.IsNotExist(e) {
			t.Fatal("resolver created state")
		}
	}
	for label, valid := range map[string]string{"plain": plain, "n1": n1} {
		l.rpc("issuer", "name_update", labLandlord, valid)
		l.mine(1)
		resolve("")
		for variant, bad := range sj1Variants(t, []byte(valid), "grant", fmt.Sprintf("%q", key), `"invalid"`) {
			t.Run(label+"/"+variant, func(t *testing.T) {
				l.rpc("issuer", "name_update", labLandlord, string(bad))
				resolve("PENDING_NAME_VALUE")
				l.mine(1)
				resolve("LANDLORD_VALUE")
				l.rpc("issuer", "name_update", labLandlord, valid)
				l.mine(1)
				resolve("")
			})
		}
	}
	l.save("sj1-name-keys.json", map[string]any{"variants": 8, "pending_refusals": 8, "confirmed_refusals": 8, "valid_repairs": 8, "state_created": false, "resolver_chain_mutations": false})
}
