package wallet

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
)

func testKey(n byte) (*btcec.PrivateKey, string) {
	b := make([]byte, 32)
	b[31] = n
	k, p := btcec.PrivKeyFromBytes(b)
	return k, hex.EncodeToString(schnorr.SerializePubKey(p))
}
func testAddress(n byte) string {
	k, _ := testKey(n)
	a, _ := btcutil.NewAddressPubKeyHash(btcutil.Hash160(k.PubKey().SerializeCompressed()), &chaincfg.RegressionNetParams)
	return a.EncodeAddress()
}
func testRequest() Request {
	return Request{Version: 1, GrantID: strings.Repeat("a", 64), Action: "pay", Nonce: strings.Repeat("b", 64), Address: testAddress(3), Amount: 10000, FeeLimit: 10000}
}
func signRequest(t *testing.T, r Request, n byte) []byte {
	return signRequestAt(t, r, n, 500)
}
func signRequestAt(t *testing.T, r Request, n byte, now int64) []byte {
	t.Helper()
	k, p := testKey(n)
	e := Event{Pubkey: p, CreatedAt: now, Kind: RequestKind, Tags: [][]string{}, Content: string(canonical(r))}
	e.ID = e.Digest()
	id, _ := hex.DecodeString(e.ID)
	sig, err := schnorr.Sign(k, id)
	if err != nil {
		t.Fatal(err)
	}
	e.Sig = hex.EncodeToString(sig.Serialize())
	return canonical(e)
}

// Valid pay and name payloads parse; independently malformed signed payloads
// refuse specific shape/authority fields rather than passing as another action.
func TestRequestControls(t *testing.T) {
	base := testRequest()
	raw := signRequest(t, base, 2)
	if _, e := ParseRequest(raw); e != nil {
		t.Fatal(e)
	}
	cases := []struct {
		name, want string
		edit       func(*Request)
	}{
		{"action", "REQUEST_ACTION", func(r *Request) { r.Action = "wallet.dump" }},
		{"zero", "REQUEST_PAY", func(r *Request) { r.Amount = 0 }},
		{"negative", "REQUEST_PAY", func(r *Request) { r.Amount = -1 }},
		{"overflow", "REQUEST_PAY", func(r *Request) { r.Amount = MaxMoney + 1 }},
		{"fee-zero", "REQUEST_FIELDS", func(r *Request) { r.FeeLimit = 0 }},
		{"fee-large", "REQUEST_FIELDS", func(r *Request) { r.FeeLimit = MaxFee + 1 }},
		{"nonce", "REQUEST_FIELDS", func(r *Request) { r.Nonce = "a" }},
		{"grant", "REQUEST_FIELDS", func(r *Request) { r.GrantID = "a" }},
		{"foreign-address", "ADDRESS_REGTEST", func(r *Request) { r.Address = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT" }},
		{"pay-name", "REQUEST_PAY", func(r *Request) { r.Name = "d/test" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := base
			c.edit(&r)
			_, e := ParseRequest(signRequest(t, r, 2))
			if e == nil || e.Error() != c.want {
				t.Fatalf("want %s got %v", c.want, e)
			}
		})
	}
	name := base
	name.Action = "names.register"
	name.Amount = 0
	name.Name = "d/lab"
	name.Value = "{}"
	if _, e := ParseRequest(signRequest(t, name, 2)); e != nil {
		t.Fatal(e)
	}
	name.Name = "../../wallet"
	if _, e := ParseRequest(signRequest(t, name, 2)); e == nil || e.Error() != "REQUEST_NAME" {
		t.Fatal("name shape admitted", e)
	}
}

// The event id and signature are separate gates; canonical byte and schema
// controls reject alternate encodings of the same apparent request.
func TestEventControls(t *testing.T) {
	raw := signRequest(t, testRequest(), 2)
	var event Event
	json.Unmarshal(raw, &event)
	cases := []struct {
		name, want string
		data       []byte
	}{
		{"whitespace", "REQUEST_SCHEMA", append(raw, '\n')},
		{"unknown", "REQUEST_SCHEMA", []byte(strings.TrimSuffix(string(raw), "}") + `,"extra":true}`)},
		{"duplicate", "REQUEST_SCHEMA", []byte(strings.Replace(string(raw), `"kind":8184`, `"kind":8184,"kind":8184`, 1))},
		{"null", "REQUEST_SCHEMA", []byte(strings.Replace(string(raw), `"tags":[]`, `"tags":null`, 1))},
	}
	wrong := event
	wrong.ID = strings.Repeat("0", 64)
	cases = append(cases, struct {
		name, want string
		data       []byte
	}{"id", "REQUEST_ID", canonical(wrong)})
	wrong = event
	wrong.Sig = strings.Repeat("0", 128)
	cases = append(cases, struct {
		name, want string
		data       []byte
	}{"signature", "REQUEST_SIGNATURE", canonical(wrong)})
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, e := ParseRequest(c.data)
			if e == nil || e.Error() != c.want {
				t.Fatalf("want %s got %v", c.want, e)
			}
		})
	}
}

// Separate budget caps never exceed the signed total; zero authority is not
// converted into defaults. Recipient allowlists are exact and duplicate-free.
func TestTermsControls(t *testing.T) {
	terms := Terms{Version: 1, Recipients: []string{testAddress(3)}, SpendCap: 10000, NameCap: DefaultNameBudget, NameCount: 3}
	if _, e := ParseTerms(canonical(terms), 3010000); e != nil {
		t.Fatal(e)
	}
	for _, total := range []int64{0, 3009999, -1, MaxMoney + 1} {
		if _, e := ParseTerms(canonical(terms), total); e == nil {
			t.Fatalf("budget accepted total %d", total)
		}
	}
	bad := terms
	bad.Recipients = append(append([]string{}, terms.Recipients...), terms.Recipients[0])
	if _, e := ParseTerms(canonical(bad), 3010000); e == nil {
		t.Fatal("duplicate recipient admitted")
	}
}

// Scope and recipient allowlists
// narrow a valid signed request; a good request alone cannot invent authority.
func TestRequestBinding(t *testing.T) {
	s, e := ParseRequest(signRequest(t, testRequest(), 2))
	if e != nil {
		t.Fatal(e)
	}
	g := Grant{ID: s.Request.GrantID, Grantee: s.Event.Pubkey, Scope: []string{"pay"}, NotBefore: 400, NotAfter: 600}
	terms := Terms{Recipients: []string{s.Request.Address}}
	if e := bindRequest(g, terms, s, 500); e != nil {
		t.Fatal(e)
	}
	g.Scope = []string{}
	if e := bindRequest(g, terms, s, 500); e == nil || e.Error() != "GRANT_SCOPE" {
		t.Fatal("want GRANT_SCOPE", e)
	}
	g.Scope = []string{"pay"}
	terms.Recipients = []string{}
	if e := bindRequest(g, terms, s, 500); e == nil || e.Error() != "ADDRESS_NOT_ALLOWED" {
		t.Fatal("want ADDRESS_NOT_ALLOWED", e)
	}
}
