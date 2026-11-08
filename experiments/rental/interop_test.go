package rental

import (
	"context"
	"encoding/json"
	"os"
	"testing"
)

// The independently generated M3 bytes verify without rewriting or resigning.
// Payment fields are synthetic: only wire/signature interoperability is proved.
// Expired holds refuse before RPC and never use miner timestamps as a clock.
func TestM3FrozenInterop(t *testing.T) {
	read := func(name, hash string) []byte {
		t.Helper()
		b, e := os.ReadFile("testdata/m3-wire-v1/" + name)
		if e != nil || Hash(b) != hash {
			t.Fatalf("fixture pin %s: %v", name, e)
		}
		return b
	}
	request := read("issuance-request.json", "994dc903bce06fe4f85a6d97f0900b8cfb978987aa2d8bc892230014a620c515")
	event := read("package-event.json", "5cf98588ee05f01885ec42454212946f89cbe8d25f3f8942a1c7e289a107d416")
	p := unitPolicy(t)
	var r IssuanceRequest
	var e Event
	if json.Unmarshal(request, &r) != nil || json.Unmarshal(event, &e) != nil {
		t.Fatal("fixture decode")
	}
	p.ProviderPubkey = e.Pubkey
	p.Policy.AgentPubkey = r.AgentPubkey
	p.Policy.StationName = r.StationName
	if _, _, err := VerifyIssuancePackage(p, request, event, 2000000001); err != nil {
		t.Fatal(err)
	}
	for _, now := range []int64{2000001200, 2000001201} {
		a := AdmitIssuance(context.Background(), nil, p, request, event, now)
		if a.Verdict != "refused" || a.Reason != "hold_expired_at_admission" || a.Calls != 0 {
			t.Fatal(a)
		}
	}
	if _, _, err := VerifyIssuancePackage(p, request, event, 2000001199); err != nil {
		t.Fatal("valid boundary neighbor", err)
	}
}
