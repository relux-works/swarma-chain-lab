package rental

// PX1 FROZEN contract test (owner S0): the rental mirror of terms v2 produces
// the same bytes and contract hash as agent-wallet's frozen golden fixtures.

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// Same frozen values as experiments/agent-wallet/px1_freeze_fixture_test.go.
const (
	px1TermsAllowSHA256 = "8fd808bf05a15ce5bc3d2be0a3086f1d8ccd64c6b4224b66def6e10b22fa28d0"
	px1TermsAnySHA256   = "2479f6741191ca7f318164866ba3d913436367229bb02265d4d6539f68acb039"
	px1ExecutorKey      = "acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe"
)

func px1PayTermsAllow() PayTermsV2 {
	return PayTermsV2{Version: 2, Service: "wallet.nmc", ExecutorKey: px1ExecutorKey, Network: "main", Genesis: su.MainGenesis, RecipientMode: "allow", Recipients: []string{"N35GKXNzPPRWWJipjt3svASBzetRtSNCW6", "N83jRqEXmasbVYh8zHgNv6UPSJLsH73aJ5"}, SpendCap: 500000, TransferCap: 100000, DayCap: 300000, DayCountCap: 5, FeeCap: 100000, DayBasis: "utc-calendar"}
}
func px1PayTermsAny() PayTermsV2 {
	return PayTermsV2{Version: 2, Service: "wallet.nmc", ExecutorKey: px1ExecutorKey, Network: "main", Genesis: su.MainGenesis, RecipientMode: "any", Recipients: []string{}, SpendCap: 100000, TransferCap: 50000, DayCap: 100000, DayCountCap: 10, FeeCap: 50000, DayBasis: "utc-calendar"}
}

// Claim: PayTermsV2 marshals to the frozen golden bytes and contract hash for
// both modes, its member order equals wallet.TermsV2's frozen order, and a
// changed value no longer matches (negative control).
func TestPX1PayTermsV2MirrorGolden(t *testing.T) {
	for _, c := range []struct {
		file, sha string
		terms     PayTermsV2
	}{{"terms-v2-allow.json", px1TermsAllowSHA256, px1PayTermsAllow()}, {"terms-v2-any.json", px1TermsAnySHA256, px1PayTermsAny()}} {
		golden, e := os.ReadFile("testdata/px1/" + c.file)
		if e != nil {
			t.Fatal(e)
		}
		got, _ := json.Marshal(c.terms)
		if !bytes.Equal(got, golden) || Hash(golden) != c.sha {
			t.Fatalf("%s drifted\n got %s\nwant %s", c.file, got, golden)
		}
		bumped := c.terms
		bumped.DayCap--
		if b, _ := json.Marshal(bumped); Hash(b) == c.sha {
			t.Fatal("value change not detected")
		}
	}
	ty := reflect.TypeOf(PayTermsV2{})
	var tags []string
	for i := 0; i < ty.NumField(); i++ {
		tags = append(tags, ty.Field(i).Tag.Get("json"))
	}
	if got := strings.Join(tags, " "); got != "version service executor_key network genesis recipient_mode recipients spend_cap_sat transfer_cap_sat day_cap_sat day_count_cap fee_cap_sat day_basis" {
		t.Fatal("PayTermsV2 member order drifted:", got)
	}
}
