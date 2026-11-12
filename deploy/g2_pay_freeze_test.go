package deploy

// PX1 FROZEN contract test (owner S0): the deploy mirror of the G2 operator
// block marshals to the same bytes agent-wallet pins.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// Bytes of experiments/agent-wallet/testdata/px1/g2-operator.json.
const px1OperatorGolden = `{"require_terms_version":2,"allow_single_use":false,"allow_any_recipients":false,"max_transfer_sat":100000,"max_day_sat":300000,"max_day_count":10,"max_fee_sat":100000,"max_float_sat":2000000,"low_float_sat":500000,"canary":{"outpoint":{"txid":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","vout":0},"value_sat":10000},"confirmations_k":2,"conflict_blocks_n":6,"read_rate_per_hour":60,"journal_spend_capacity":2048}`

func px1OperatorParameters() G2OperatorParameters {
	return G2OperatorParameters{RequireTermsVersion: 2, MaxTransferSat: 100000, MaxDaySat: 300000, MaxDayCount: 10, MaxFeeSat: 100000, MaxFloatSat: 2000000, LowFloatSat: 500000, Canary: G2CanaryParameters{Outpoint: G2Outpoint{TxID: strings.Repeat("c", 64)}, ValueSat: 10000}, ConfirmationsK: 2, ConflictBlocksN: 6, ReadRatePerHour: 60, JournalSpendCapacity: 2048}
}

// Claim: the mirror's bytes and SHA-256 equal agent-wallet's frozen operator
// golden; a changed ceiling no longer matches (negative control).
func TestPX1OperatorMirrorGolden(t *testing.T) {
	got, _ := json.Marshal(px1OperatorParameters())
	sum := sha256.Sum256([]byte(px1OperatorGolden))
	if string(got) != px1OperatorGolden || hex.EncodeToString(sum[:]) != "ed001683d2751865d4b339214bc668edfa977d1d0d50e5e0005354dc07df2dde" {
		t.Fatalf("operator mirror drifted\n got %s\nwant %s", got, px1OperatorGolden)
	}
	bumped := px1OperatorParameters()
	bumped.MaxDaySat++
	if b, _ := json.Marshal(bumped); string(b) == px1OperatorGolden {
		t.Fatal("value change not detected")
	}
}
