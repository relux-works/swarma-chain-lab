package wallet

// PX1 FROZEN shared test fixtures (owner S0). Streams call these helpers and
// never edit them; a change is a freeze amendment.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// Frozen SHA-256 of the golden terms fixtures. These are the contract_sha256
// values a v3 grant commits to when it carries the fixture terms.
const (
	px1TermsAllowSHA256 = "8fd808bf05a15ce5bc3d2be0a3086f1d8ccd64c6b4224b66def6e10b22fa28d0"
	px1TermsAnySHA256   = "2479f6741191ca7f318164866ba3d913436367229bb02265d4d6539f68acb039"
	// px1ExecutorKey is testKey(9)'s x-only key: the fixture receipt key.
	px1ExecutorKey = "acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe"
	// Mainnet P2PKH addresses of testKey(5) and testKey(3), sorted.
	px1AllowA = "N35GKXNzPPRWWJipjt3svASBzetRtSNCW6"
	px1AllowB = "N83jRqEXmasbVYh8zHgNv6UPSJLsH73aJ5"
	// px1Outsider is testKey(4)'s mainnet P2PKH address: never allow-listed.
	px1Outsider = "NETgLquuwG5E3GG2A4g62J1TMiSZ4973st"
)

// px1TermsAllow is the smoke-value allow-mode terms (§3.8 step 2).
func px1TermsAllow() TermsV2 {
	return TermsV2{Version: 2, Service: WalletServiceID, ExecutorKey: px1ExecutorKey, Network: "main", Genesis: su.MainGenesis, RecipientMode: RecipientModeAllow, Recipients: []string{px1AllowA, px1AllowB}, SpendCap: 500000, TransferCap: 100000, DayCap: 300000, DayCountCap: 5, FeeCap: 100000, DayBasis: DayBasisUTCCalendar}
}

// px1TermsAny is the phase-2 any-mode terms with lower caps (Q2).
func px1TermsAny() TermsV2 {
	return TermsV2{Version: 2, Service: WalletServiceID, ExecutorKey: px1ExecutorKey, Network: "main", Genesis: su.MainGenesis, RecipientMode: RecipientModeAny, Recipients: []string{}, SpendCap: 100000, TransferCap: 50000, DayCap: 100000, DayCountCap: 10, FeeCap: 50000, DayBasis: DayBasisUTCCalendar}
}

// px1Operator is the launch operator block: allow-only, single-use disabled.
func px1Operator() G2OperatorConfig {
	return G2OperatorConfig{RequireTermsVersion: 2, AllowSingleUse: false, AllowAnyRecipients: false, MaxTransferSat: 100000, MaxDaySat: 300000, MaxDayCount: 10, MaxFeeSat: 100000, MaxFloatSat: 2000000, LowFloatSat: 500000, Canary: CanaryConfig{Outpoint: su.Point{TxID: strings.Repeat("c", 64), Vout: 0}, ValueSat: 10000}, ConfirmationsK: DefaultConfirmationsK, ConflictBlocksN: DefaultConflictBlocksN, ReadRatePerHour: DefaultReadRatePerHour, JournalSpendCapacity: 2048}
}

// px1Golden reads a frozen fixture from testdata/px1.
func px1Golden(t *testing.T, name string) []byte {
	t.Helper()
	b, e := os.ReadFile(filepath.Join("testdata", "px1", name))
	if e != nil {
		t.Fatal(e)
	}
	return b
}

// px1StatusFixture is the populated status projection behind
// testdata/px1/status-projection-v1.json.
func px1StatusFixture() StatusProjectionV1 {
	pay := TrackedPayment{GrantID: strings.Repeat("a", 64), Nonce: strings.Repeat("b", 64), TxID: strings.Repeat("d", 64), Inputs: []su.Point{{TxID: strings.Repeat("e", 64), Vout: 1}}, ReserveSeq: 3, BroadcastTip: 851300, State: TrackConfirmed, Confirmations: 2, MissingSince: 0}
	return StatusProjectionV1{
		Version: StatusProjectionVersion, Service: WalletServiceID, Network: "main", ReceiptKey: px1ExecutorKey, GeneratedAt: 1794000600, Poisoned: false,
		Tip:      StatusTip{Height: 851302, Hash: strings.Repeat("f", 64), ObservedAt: 1794000590},
		Grants:   []StatusGrant{{GrantID: strings.Repeat("a", 64), TotalCapSat: 500000, SpendCapSat: 500000, TransferCapSat: 100000, DayCapSat: 300000, DayCountCap: 5, SpentSat: 64600, ReservedSat: 64600, UncertainSat: 0, ReleasedSat: 0, TotalRemainingSat: 435400, Day: "2026-11-06", DayUsedSat: 64600, DayCount: 1, DayRemainingSat: 235400, DayCountRemaining: 4, Seal: StatusSealCheck{Verdict: "live", Reason: "LIVE", Height: 851302, At: 1794000590}}},
		Payments: StatusPayments{Pending: 0, Confirmed: 1, Conflicted: 0, Items: []TrackedPayment{pay}},
		Float:    FloatReading{BalanceSat: 1935400, MaxFloatSat: 2000000, LowFloatSat: 500000, State: "ok"},
		Canary:   StatusCanary{Outpoint: su.Point{TxID: strings.Repeat("c", 64), Vout: 0}, ValueSat: 10000, State: CanaryUnspent, At: 1794000590},
		Journal:  StatusJournal{Admitted: 4, SpendCapacity: 2048, PercentUsed: 0, Segments: 1},
		Refusals: []StatusCount{{Code: "ADDRESS_NOT_ALLOWED", Count: 1}, {Code: "TRANSFER_CAP_EXCEEDED", Count: 1}},
		Alerts:   []Alert{},
	}
}
