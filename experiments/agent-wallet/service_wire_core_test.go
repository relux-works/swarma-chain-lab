package wallet

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// W1's malformed/unsigned/missing-grant/nonce/amount/fee boundaries cross the
// real W2 socket. W2 schema/object codes intentionally differ from legacy event
// errors. No refused request reserves wallet budget or broadcasts; a valid
// standing payment immediately afterward is the positive control.
func TestCoreActionWireRefusals(t *testing.T) {
	l := newCore(t)
	terms := Terms{Version: 1, Recipients: []string{testAddress(3)}, SpendCap: 1000000}
	raw, c := l.grant(terms, []string{"pay"}, 1000000)
	id := installActionObjects(t, c, raw, terms)
	f := coreSocket(t, l, c)
	s := f.service
	r := actionFixture(t, "spend")
	r.Grant.ID = id
	check := func(raw []byte, want string) {
		t.Helper()
		before, _ := os.ReadFile(filepath.Join(c.StateDir, "wallet.json"))
		pool := string(l.rpc("", "getrawmempool"))
		got, _ := socketRaw(t, s, raw)
		expectAction(t, got, "refused", want)
		after, _ := os.ReadFile(filepath.Join(c.StateDir, "wallet.json"))
		if !bytes.Equal(before, after) || pool != string(l.rpc("", "getrawmempool")) {
			t.Fatal("wire refusal changed wallet/effect")
		}
	}
	check([]byte(`{}`), "ACTION_SCHEMA")
	check(canonical(r), "ACTION_SCHEMA")
	for _, tc := range []struct {
		want string
		edit func(*ActionRequest)
	}{
		{"ACTION_GRANT", func(r *ActionRequest) { r.Grant = ActionGrant{Kind: "none"} }},
		{"ACTION_SCHEMA", func(r *ActionRequest) { r.Nonce = "" }},
		{"PUBLIC_FILE", func(r *ActionRequest) { r.Grant.ID = strings.Repeat("f", 64) }},
		{"ACTION_PARAMS", func(r *ActionRequest) { r.Params = canonical(SpendParams{testAddress(3), 0, 100000}) }},
		{"ACTION_PARAMS", func(r *ActionRequest) { r.Params = canonical(SpendParams{testAddress(3), -1, 100000}) }},
		{"ACTION_PARAMS", func(r *ActionRequest) { r.Params = canonical(SpendParams{testAddress(3), 1, MaxFee + 1}) }},
		{"TOTAL_BUDGET_EXCEEDED", func(r *ActionRequest) { r.Params = canonical(SpendParams{testAddress(3), 1000001, 100000}) }},
	} {
		q := r
		q.Nonce = Hash([]byte(tc.want))[:32]
		tc.edit(&q)
		check(actionEnvelope(t, q), tc.want)
	}
	got, _ := socketRequest(t, s, r)
	expectAction(t, got, "executed", "EXECUTED")
}
