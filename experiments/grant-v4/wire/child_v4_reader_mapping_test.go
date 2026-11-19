package wire

import (
	"testing"

	"github.com/relux-works/swarma-chain-lab/experiments/grant-v4/identity"
)

// Missing swarma with a valid channel key is the section 2 rule 5 / section 4
// rule 6 counterexample: the reader error set is wider than whole-value B.
func TestChildV4ReaderErrorIsNotB(t *testing.T) {
	for _, vector := range childVectorsV4(t) {
		if vector.ID != "name-valid-neighbour" {
			continue
		}
		key := vector.Observation.ChannelKeys[0]
		if err := CheckSigningKey(key); err != nil {
			t.Fatal(err)
		}
		if _, err := identity.ReadR1Value(identity.R1InForce051, []byte(`{"nostr":"`+key+`"}`)); err == nil {
			t.Fatal("missing-swarma counterexample no longer exercises the broader reader error set")
		}
	}
}
