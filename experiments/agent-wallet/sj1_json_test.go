package wallet

import (
	"fmt"
	"strings"
	"testing"
)

// sj1Variants preserves the surrounding valid fixture. Invalid duplicate values
// use a different semantic value; reverse order defeats last-key-wins decoders.
func sj1Variants(t *testing.T, raw []byte, key, good, bad string) map[string][]byte {
	t.Helper()
	field := `"` + key + `":` + good
	if !strings.Contains(string(raw), field) {
		t.Fatal("missing mutation target", key)
	}
	escaped := `"\u` + fmt.Sprintf("%04x", key[0]) + key[1:] + `":`
	out := map[string][]byte{}
	for name, value := range map[string]string{
		"left-valid":        field + `,"` + key + `":` + bad,
		"right-valid":       `"` + key + `":` + bad + `,` + field,
		"escaped-duplicate": field + `,` + escaped + bad,
		"escaped-single":    escaped + good,
	} {
		out[name] = []byte(strings.Replace(string(raw), field, value, 1))
	}
	return out
}

// Actual LIP-0006 request parsing refuses ambiguous params and grant keys before
// producing an authenticated action. The valid signed neighbor still verifies.
func TestSJ1ActionKeys(t *testing.T) {
	r := actionFixture(t, "spend")
	raw := actionEnvelope(t, r)
	for _, target := range []struct{ key, good, bad string }{{"v", "1", "9"}, {"amount_sat", fmt.Sprint(actionAmount(t, r)), "0"}, {"kind", `"standing"`, `"invalid"`}} {
		for name, bad := range sj1Variants(t, raw, target.key, target.good, target.bad) {
			t.Run(target.key+"/"+name, func(t *testing.T) {
				got, e := ParseAction(bad, WalletServiceID)
				if e == nil || e.Error() != "ACTION_SCHEMA" || got.Hash != "" {
					t.Fatal("action key guard", e)
				}
				if _, e := ParseAction(raw, WalletServiceID); e != nil {
					t.Fatal("valid neighbor", e)
				}
			})
		}
	}
}
func actionAmount(t *testing.T, r ActionRequest) int64 {
	t.Helper()
	var p SpendParams
	if e := strict(r.Params, &p); e != nil {
		t.Fatal(e)
	}
	return p.Amount
}

// Re-sign each ambiguous Effect so the receipt's recursive JSON guard, rather
// than invalid cryptography, must reject it. No verified receipt is returned.
func TestSJ1ReceiptKeys(t *testing.T) {
	key, pub := testKey(7)
	_, grantee := testKey(2)
	r := ActionReceipt{Version: 1, Service: WalletServiceID, Grantee: grantee, RequestHash: strings.Repeat("a", 64), Verdict: "executed", Reason: "EXECUTED", Effect: []byte(`{"amount_sat":1}`), Sequence: 1, ObservedHeight: 100}
	parse := func(raw []byte) error {
		got, e := ParseActionReceipt(raw, pub, r.RequestHash, grantee)
		if e != nil && got.Signature != "" {
			t.Fatal("refusal populated receipt")
		}
		return e
	}
	valid := canonical(signActionReceipt(r, key))
	for _, effect := range sj1Variants(t, r.Effect, "amount_sat", "1", "0") {
		bad := r
		bad.Effect = effect
		if e := parse(canonical(signActionReceipt(bad, key))); e == nil {
			t.Fatal("SJ1 ambiguous receipt admitted")
		}
		if e := parse(valid); e != nil {
			t.Fatal("valid neighbor", e)
		}
	}
}
