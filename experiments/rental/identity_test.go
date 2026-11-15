package rental

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

type identityNode struct {
	t       *testing.T
	expired bool
	expires int64
}

func (n identityNode) Call(_ context.Context, method string, args ...any) (json.RawMessage, error) {
	n.t.Helper()
	if method != "name_show" || len(args) != 2 {
		n.t.Fatal("unexpected name read")
	}
	options, ok := args[1].(map[string]any)
	if !ok || options["allowExpired"] != true {
		n.t.Fatal("name read omitted allowExpired")
	}
	return json.Marshal(map[string]any{"name": "id/test", "txid": strings.Repeat("a", 64), "vout": 0, "height": 1, "value": "{}", "expired": n.expired, "expires_in": n.expires, "name_encoding": "ascii", "value_encoding": "ascii"})
}

// Claim: the shared current-generation reader requests expired names, returns typed expiry, and never admits a zero-lifetime inconsistent name beside a live control.
func TestCurrentIdentityExpiry(t *testing.T) {
	for _, tc := range []struct {
		expired bool
		expires int64
		reason  string
	}{
		{false, 1, ""}, {true, 0, "IDENTITY_EXPIRED"}, {true, -1, "IDENTITY_EXPIRED"}, {false, 0, "CURRENT_NAME"},
	} {
		o := su.NewReadObservation(context.Background(), identityNode{t, tc.expired, tc.expires})
		_, err := currentName(o, "id/test")
		o.Close()
		if tc.reason == "" {
			if err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err == nil || err.Error() != tc.reason {
			t.Fatalf("wanted %s got %v", tc.reason, err)
		}
		if tc.expired && err != IdentityExpired {
			t.Fatal("expiry lost its type")
		}
	}
}
