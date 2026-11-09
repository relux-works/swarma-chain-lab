package wallet

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// Fixed public vectors were constructed from literal wire bytes and standard
// SHA256/BIP340, without the product encoders/digests. They lock hash domains,
// field order and service-key pinning; an ASCII-hash signature must not verify.
func TestActionGolden(t *testing.T) {
	raw, e := os.ReadFile("testdata/service-v1/balance-envelope.json")
	if e != nil {
		t.Fatal(e)
	}
	v, e := ParseAction(raw, WalletServiceID)
	if e != nil {
		t.Fatal(e)
	}
	const hash = "f3fb78db4d8324dfc4537b2822c51ae9c44c3554d82ef30666b5779a6aab7763"
	if v.Hash != hash || ActionDigest(v.Envelope.Request) != "fe5351a4aef1ba65173f49dc6d828f83e5bdddd02cd917520df1f4fef4ef9e10" {
		t.Fatal("action golden digest")
	}
	request, e := os.ReadFile("testdata/service-v1/balance.json")
	if e != nil || !bytes.Equal(request, v.RequestBytes) {
		t.Fatal("action golden bytes")
	}
	raw, e = os.ReadFile("testdata/service-v1/receipt.json")
	if e != nil {
		t.Fatal(e)
	}
	r, e := ParseActionReceipt(raw, "5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc", hash, v.Envelope.Request.Grantee)
	if e != nil || receiptDigest(r.Receipt) != "90a94a1cf305f07bb595ae073597baa45c295d34de4a89112af6eeee38049d72" {
		t.Fatal("receipt golden digest", e)
	}
	env := v.Envelope
	env.Signature = signDigest(t, Hash([]byte("swarma-action-v1"+hash)), 2)
	if _, e = ParseAction(canonical(env), WalletServiceID); e == nil {
		t.Fatal("ASCII hash domain accepted")
	}
}

func actionFixture(t *testing.T, action string) ActionRequest {
	t.Helper()
	_, key := testKey(2)
	r := ActionRequest{Version: 1, Service: "wallet.nmc", Action: action, Params: json.RawMessage(`{}`), Grant: ActionGrant{Kind: "none"}, Nonce: strings.Repeat("a", 32), CreatedAt: 500, Grantee: key}
	if action == "spend" {
		r.Params = canonical(SpendParams{To: testAddress(3), Amount: 100000, FeeLimit: 100000})
		r.Grant = ActionGrant{Kind: "standing", ID: strings.Repeat("b", 64)}
	}
	return r
}
func actionEnvelope(t *testing.T, r ActionRequest) []byte {
	t.Helper()
	e := ActionEnvelope{Request: r, Signature: signDigest(t, ActionDigest(r), 2)}
	return canonical(e)
}

// Valid read/spend requests round-trip; closed nested schemas, exact bytes,
// signature/domain/service/role/nonce and action-specific constraints refuse.
func TestActionWire(t *testing.T) {
	for _, action := range []string{"balance", "receive", "history", "spend"} {
		r := actionFixture(t, action)
		raw := actionEnvelope(t, r)
		v, e := ParseAction(raw, "wallet.nmc")
		if e != nil || v.Hash != Hash(canonical(r)) || !bytes.Equal(v.RequestBytes, canonical(r)) {
			t.Fatal("action neighbor", action, e)
		}
	}
	r := actionFixture(t, "spend")
	raw := actionEnvelope(t, r)
	cases := map[string][]byte{
		"trailing":  append(append([]byte{}, raw...), ' '),
		"duplicate": []byte(strings.Replace(string(raw), `"v":1`, `"v":1,"v":1`, 1)),
		"unknown":   []byte(strings.Replace(string(raw), `"v":1`, `"v":1,"extra":0`, 1)),
		"alias":     []byte(strings.Replace(string(raw), `"service":`, `"Service":`, 1)),
		"null":      []byte(strings.Replace(string(raw), `"params":`+string(r.Params), `"params":null`, 1)),
	}
	for name, mut := range map[string]func(*ActionRequest){
		"version": func(r *ActionRequest) { r.Version = 2 }, "service": func(r *ActionRequest) { r.Service = "other" }, "action": func(r *ActionRequest) { r.Action = "name-register" }, "nonce": func(r *ActionRequest) { r.Nonce = "aa" }, "time": func(r *ActionRequest) { r.CreatedAt = 0 }, "no-grant-spend": func(r *ActionRequest) { r.Grant = ActionGrant{Kind: "none"} }, "unknown-params": func(r *ActionRequest) {
			r.Params = []byte(`{"to":"` + testAddress(3) + `","amount_sat":1,"fee_limit_sat":1,"extra":0}`)
		}, "amount": func(r *ActionRequest) { r.Params = canonical(SpendParams{To: testAddress(3), Amount: 0, FeeLimit: 1}) }, "fee": func(r *ActionRequest) { r.Params = canonical(SpendParams{To: testAddress(3), Amount: 1, FeeLimit: 0}) },
	} {
		x := r
		mut(&x)
		cases[name] = actionEnvelope(t, x)
	}
	var bad ActionEnvelope
	json.Unmarshal(raw, &bad)
	bad.Signature = signDigest(t, Hash(canonical(r)), 2)
	cases["domain"] = canonical(bad)
	bad.Signature = signDigest(t, ActionDigest(r), 3)
	cases["signature"] = canonical(bad)
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, e := ParseAction(raw, "wallet.nmc"); e == nil {
				t.Fatal("action wire guard")
			}
			if _, e := ParseAction(actionEnvelope(t, r), "wallet.nmc"); e != nil {
				t.Fatal("action positive neighbor", e)
			}
		})
	}
}

// Proof is a locator outside request_hash, accepted only for single-use spends;
// changing it does not change the verified request or its signature.
func TestActionProof(t *testing.T) {
	r := actionFixture(t, "spend")
	r.Grant.Kind = "single-use"
	var e ActionEnvelope
	json.Unmarshal(actionEnvelope(t, r), &e)
	first, err := ParseAction(canonical(e), "wallet.nmc")
	if err != nil {
		t.Fatal(err)
	}
	e.Proof = &ActionProof{UseTxID: strings.Repeat("c", 64)}
	second, err := ParseAction(canonical(e), "wallet.nmc")
	if err != nil || first.Hash != second.Hash {
		t.Fatal("proof must not enter commitment", err)
	}
	e.Request.Grant.Kind = "standing"
	e.Signature = signDigest(t, ActionDigest(e.Request), 2)
	if _, err := ParseAction(canonical(e), "wallet.nmc"); err == nil {
		t.Fatal("proof kind guard")
	}
}
