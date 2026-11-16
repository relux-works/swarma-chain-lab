package grantcheck

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-chain-lab/experiments/rental"
)

// R1 is a v4 lab delta. Existing v3 name readers keep rejecting holders and
// new agent shapes, beside valid legacy controls. No node read is involved.
func TestR1V3NameCompatibility(t *testing.T) {
	key := xonly(1)
	landlord, err := rental.LandlordValue(rental.LandlordBinding{Grant: key})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = rental.ParseLandlordValue(landlord); err != nil {
		t.Fatal(err)
	}
	for _, holders := range []string{`[]`, `["02` + key + `"]`} {
		t.Run(holders, func(t *testing.T) {
			value := strings.Replace(landlord, `"grant":"`+key+`"`, `"grant":"`+key+`","holders":`+holders, 1)
			if _, e := rental.ParseLandlordValue(value); e == nil {
				t.Fatal("R1 widened v3 landlord acceptance")
			}
		})
	}
	agent, err := rental.AgentBindingValue(rental.AgentBinding{Nostr: xonly(2), Landlord: "id/example"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = rental.ParseAgentBinding(agent); err != nil {
		t.Fatal(err)
	}
	newAgent := `{"nostr":{"names":{"_":"` + xonly(2) + `"}},"swarma":{"agent":{"landlord":"id/example"}}}`
	if _, err = rental.ParseAgentBinding(newAgent); err == nil {
		t.Fatal("R1 new agent shape admitted as v3")
	}
}

// Additional v4/group/class/no-certifier facts cannot enter the v3 checker,
// reach its backend, replace admitted cache bytes, or change durable state.
// The live unit backend is only a routing control, not chain qualification.
func TestR1V3ProofCompatibility(t *testing.T) {
	c, backend, p := unitChecker(t)
	ctx := context.Background()
	peer := xonly(2)
	assertVerdict(t, c.Inbound(ctx, peer, &p), Live, CodeLive, false, false)
	state := filepath.Join(c.config.StateDir, stateName)
	before, e := os.ReadFile(state)
	if e != nil {
		t.Fatal(e)
	}
	calls := backend.Calls
	for _, test := range []struct{ name, old, new string }{
		{"version", `"version":3`, `"version":4`},
		{"groups", `"grant":{`, `"grant":{"groups":[],`},
		{"class", `"grant":{`, `"grant":{"recipient":{"class":[]},`},
		{"no-certifier", `"grant":{`, `"grant":{"certifier":null,`},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := bytes.Replace(p.Bytes, []byte(test.old), []byte(test.new), 1)
			if bytes.Equal(raw, p.Bytes) {
				t.Fatal("R1 fixture plant not applied")
			}
			assertVerdict(t, c.Inbound(ctx, peer, &Presentation{GrantID: p.GrantID, Bytes: raw}), Refused, CodeInvalidPresentation, false, false)
			after, e := os.ReadFile(state)
			if e != nil {
				t.Fatal(e)
			}
			if backend.Calls != calls || !bytes.Equal(before, after) || !bytes.Equal(cachedBytes(t, c, peer), p.Bytes) {
				t.Fatal("R1 incompatible proof changed v3 state or reached backend")
			}
		})
	}
	assertVerdict(t, c.Outbound(ctx, peer), Live, CodeLive, false, false)
}
