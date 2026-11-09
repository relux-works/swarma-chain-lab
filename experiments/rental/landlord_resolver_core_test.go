package rental

import (
	"context"
	su "relux.works/swarma-chain-lab/experiments/single-use"
	"testing"
)

// The standalone resolver binds the pinned landlord without an agent/seal or
// state store, rejects pending/malformed identity, and returns new/rolled-back
// confirmed generations honestly. Closure memory remains the caller's job.
func TestCoreLandlordResolver(t *testing.T) {
	l := newCore(t)
	l.grantIdentity()
	p := Policy{Network: "regtest", Genesis: su.RegtestGenesis, LandlordName: labLandlord}
	resolve := func(label string, want byte, reason string) Anchor {
		t.Helper()
		key, gen, e := ResolveLandlordGrantKey(context.Background(), l.observer, p, p.LandlordName)
		if reason != "" {
			if e == nil || e.Error() != reason || key != "" || gen != (Anchor{}) {
				t.Fatalf("resolver %s want %s got key=%s generation=%+v err=%v", label, reason, key, gen, e)
			}
			return gen
		}
		_, pub := testKey(want)
		if e != nil || key != pub || !validGeneration(gen) {
			t.Fatalf("resolver %s key/generation: %s %+v %v", label, key, gen, e)
		}
		l.save("resolver-"+label+".json", map[string]any{"key": key, "generation": gen})
		return gen
	}
	initial := resolve("initial", 1, "")
	key, gen, e := ResolveLandlordGrantKey(context.Background(), l.observer, p, "id/foreign")
	if e == nil || e.Error() != "LANDLORD_POLICY" || key != "" || gen != (Anchor{}) {
		t.Fatal("resolver name pin")
	}
	resolve("pin-neighbor", 1, "")
	main := p
	main.Network = "main"
	main.Genesis = su.MainGenesis
	if _, _, e = ResolveLandlordGrantKey(context.Background(), nil, main, main.LandlordName); e == nil || e.Error() != "REGTEST_ONLY" {
		t.Fatal("resolver mainnet")
	}
	l.landlordKey(5, false)
	resolve("pending-key", 0, "PENDING_LANDLORD_ROTATION")
	l.mine(1)
	changed := resolve("changed", 5, "")
	if changed.TxID == initial.TxID || changed.Height <= initial.Height {
		t.Fatal("resolver forward generation")
	}
	o := su.NewReadObservation(context.Background(), l.observer)
	if e = o.Start(p.Network, p.Genesis); e != nil {
		t.Fatal(e)
	}
	if _, e = o.Active(initial.Block); e != nil {
		t.Fatal(e)
	}
	o.Close()
	// Matching old generation remains active on a genuine forward rotation.
	l.landlordKey(1, true)
	back := resolve("back", 1, "")
	l.rpc("", "invalidateblock", back.Block)
	resolve("rollback-pending", 0, "PENDING_LANDLORD_ROTATION")
	l.rpc("", "reconsiderblock", back.Block)
	resolve("restored", 1, "")
	l.rpc("issuer", "name_update", labLandlord, `{}`)
	resolve("malformed-pending", 0, "PENDING_NAME_VALUE")
	l.mine(1)
	resolve("malformed-confirmed", 0, "LANDLORD_VALUE")
	l.landlordKey(1, true)
	resolve("malformed-neighbor", 1, "")
}
