package wallet

// PX1 FROZEN contract tests (owner S0). They pin byte order and code shape,
// never stub behaviour, so they stay green after every stream lands.

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func px1JSONTags(t reflect.Type) []string {
	var out []string
	for i := 0; i < t.NumField(); i++ {
		out = append(out, strings.Split(t.Field(i).Tag.Get("json"), ",")[0])
	}
	return out
}

// Claim: the TermsV2 struct marshals to exactly the golden bytes whose SHA-256
// is the frozen contract hash, for both recipient modes. Negative controls: the
// same members in another order, or one changed value, do not match.
func TestPX1TermsV2Golden(t *testing.T) {
	for _, c := range []struct {
		name, file, sha string
		terms           TermsV2
	}{{"allow", "terms-v2-allow.json", px1TermsAllowSHA256, px1TermsAllow()}, {"any", "terms-v2-any.json", px1TermsAnySHA256, px1TermsAny()}} {
		golden := px1Golden(t, c.file)
		got := canonical(c.terms)
		if !bytes.Equal(got, golden) || Hash(golden) != c.sha {
			t.Fatalf("%s: terms bytes or hash drifted\n got %s\nwant %s", c.name, got, golden)
		}
		var members map[string]any
		if e := json.Unmarshal(golden, &members); e != nil || len(members) != 13 {
			t.Fatalf("%s: golden is not a 13-member object", c.name)
		}
		if reordered := canonical(members); bytes.Equal(reordered, golden) {
			t.Fatalf("%s: reordered members not detected", c.name)
		}
		bumped := c.terms
		bumped.SpendCap++
		if Hash(canonical(bumped)) == c.sha {
			t.Fatalf("%s: value change not detected", c.name)
		}
	}
	if !strings.Contains(string(px1Golden(t, "terms-v2-any.json")), `"recipients":[]`) {
		t.Fatal("any-mode recipients must encode as [], never null")
	}
}

// Claim: the canonical member order of every frozen wire/journal struct equals
// the order written in PX1-INTERFACES.md and §3.2/§3.4/§3.6.
func TestPX1FieldOrder(t *testing.T) {
	for _, c := range []struct {
		v    any
		want string
	}{
		{TermsV2{}, "version service executor_key network genesis recipient_mode recipients spend_cap_sat transfer_cap_sat day_cap_sat day_count_cap fee_cap_sat day_basis"},
		{G2OperatorConfig{}, "require_terms_version allow_single_use allow_any_recipients max_transfer_sat max_day_sat max_day_count max_fee_sat max_float_sat low_float_sat canary confirmations_k conflict_blocks_n read_rate_per_hour journal_spend_capacity"},
		{JournalRecordV2{}, "seq kind grant_id nonce request_hash action phase reserved_sat fee_sat day inputs txid created last_time service track reconcile"},
		{JournalSegmentV2{}, "header index prev_sha256 first_seq records"},
		{ReconcileRecordV2{}, "target_seq evidence height block_hash conflict_txid released_sat note_sha256 signature"},
		{StatusProjectionV1{}, "v service network receipt_key generated_at poisoned tip grants payments float canary journal refusals alerts"},
	} {
		if got := strings.Join(px1JSONTags(reflect.TypeOf(c.v)), " "); got != c.want {
			t.Fatalf("%T order drifted:\n got %s\nwant %s", c.v, got, c.want)
		}
	}
}

// Claim: the launch operator block marshals to the golden bytes the deploy
// mirror also pins (deploy/g2_pay_freeze_test.go), with Q2/Q7/Q12 values.
func TestPX1OperatorGolden(t *testing.T) {
	golden := px1Golden(t, "g2-operator.json")
	if got := canonical(px1Operator()); !bytes.Equal(got, golden) || Hash(golden) != "ed001683d2751865d4b339214bc668edfa977d1d0d50e5e0005354dc07df2dde" {
		t.Fatalf("operator block drifted\n got %s\nwant %s", got, golden)
	}
	o := px1Operator()
	if o.RequireTermsVersion != 2 || o.AllowSingleUse || o.AllowAnyRecipients || o.ConfirmationsK != 2 {
		t.Fatal("launch decisions Q2/Q7/Q12 not reflected")
	}
}

// Claim: the populated status fixture marshals to the golden bytes, with empty
// lists as [] (never null).
func TestPX1StatusProjectionGolden(t *testing.T) {
	golden := px1Golden(t, "status-projection-v1.json")
	if got := canonical(px1StatusFixture()); !bytes.Equal(got, golden) {
		t.Fatalf("status projection drifted\n got %s\nwant %s", got, golden)
	}
	if !strings.Contains(string(golden), `"alerts":[]`) {
		t.Fatal("empty alerts must encode as []")
	}
}

// Claim: the JSON Schema's required lists equal the Go struct member order for
// the top level and every $def, and every object closes additionalProperties.
// Negative control: a schema list with two members swapped is reported.
func TestPX1StatusSchemaMatchesStructs(t *testing.T) {
	type node struct {
		Required   []string        `json:"required"`
		Additional *bool           `json:"additionalProperties"`
		Defs       map[string]node `json:"$defs"`
	}
	var s node
	if e := json.Unmarshal(px1Golden(t, "status-projection-v1.schema.json"), &s); e != nil {
		t.Fatal(e)
	}
	types := map[string]reflect.Type{
		"": reflect.TypeOf(StatusProjectionV1{}), "tip": reflect.TypeOf(StatusTip{}), "seal": reflect.TypeOf(StatusSealCheck{}),
		"grant": reflect.TypeOf(StatusGrant{}), "payment": reflect.TypeOf(TrackedPayment{}), "payments": reflect.TypeOf(StatusPayments{}),
		"float": reflect.TypeOf(FloatReading{}), "canary": reflect.TypeOf(StatusCanary{}), "journal": reflect.TypeOf(StatusJournal{}),
		"count": reflect.TypeOf(StatusCount{}), "alert": reflect.TypeOf(Alert{}), "point": reflect.TypeOf(struct {
			TxID string `json:"txid"`
			Vout uint32 `json:"vout"`
		}{}),
	}
	same := func(n node, ty reflect.Type) bool {
		return n.Additional != nil && !*n.Additional && slices.Equal(n.Required, px1JSONTags(ty))
	}
	if len(s.Defs) != len(types)-1 {
		t.Fatalf("schema has %d defs, want %d", len(s.Defs), len(types)-1)
	}
	for name, ty := range types {
		n := s
		if name != "" {
			n = s.Defs[name]
		}
		if !same(n, ty) {
			t.Fatalf("schema %q != %s: %v", name, ty, n.Required)
		}
	}
	swapped := s.Defs["tip"]
	swapped.Required = []string{"hash", "height", "observed_at"}
	if same(swapped, types["tip"]) {
		t.Fatal("swapped schema order not detected")
	}
}

// Claim: the stub sentinel and every PX1 refusal/alert code survive safeCode
// unchanged, so a reached stub refuses with PX1_NOT_IMPLEMENTED instead of a
// generic failure. Negative control: a non-bounded error collapses.
func TestPX1CodesBounded(t *testing.T) {
	if safeCode(ErrNotImplemented) != "PX1_NOT_IMPLEMENTED" {
		t.Fatal("sentinel is not a bounded wire code")
	}
	for _, c := range []string{CodeTermsVersionRequired, CodeTermsExecutorMismatch, CodeTermsNetwork, CodeTermsRecipientMode, CodeSingleUseDisabled, CodeAmountDust, CodeTransferCapExceeded, CodeDayCapExceeded, CodeDayCountExceeded, CodeFeeCapExceeded, CodeJournalCapacity, CodeJournalSegment, CodeClockRollback, CodeReadRateLimited, CodeFloatCanarySpent, CodeStateReconcileRequired, CodeReconcileRateLimited, CodeReconcileEvidence, AlertCanarySpent, AlertPaymentConflicted, AlertUncertainVerdict, AlertJournalHighWater, AlertClockRollback, AlertSealClosed, AlertFloatLow, AlertFloatExcess} {
		if safeCode(errors.New(c)) != c {
			t.Fatalf("%s is not bounded", c)
		}
	}
	if safeCode(errors.New("px1 not implemented")) != "SERVICE_FAILURE" {
		t.Fatal("negative control: unbounded text admitted")
	}
}
