package rental

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// Frozen public fixture bytes remain stable for downstream interoperability;
// verification and the unsigned digest are checked independently of re-signing.
func TestDetachedFixture(t *testing.T) {
	read := func(name string) []byte {
		t.Helper()
		b, e := os.ReadFile("testdata/detached-v2/" + name)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	raw := read("envelope.json")
	var meta map[string]string
	if e := json.Unmarshal(read("metadata.json"), &meta); e != nil {
		t.Fatal(e)
	}
	env, e := ParseDetachedEnvelope(raw)
	if e != nil {
		t.Fatal(e)
	}
	unsigned, e := env.Certificate.Canonical()
	if e != nil {
		t.Fatal(e)
	}
	if string(unsigned) != string(read("unsigned.json")) || Hash(unsigned) != meta["unsigned_sha256"] || Hash(raw) != meta["id"] {
		t.Fatal("fixture digest drift")
	}
	keys, e := ParseAgentValue(string(read("agent-value.json")))
	if e != nil || keys.Grant != env.Certificate.IssuerKey {
		t.Fatal("fixture identity", e)
	}
	script, e := GrantSealScript(keys.Grant)
	if e != nil || script != meta["seal_script"] {
		t.Fatal("fixture ownership", e)
	}
}

func testDetached() DetachedCertificate {
	_, issuer := testKey(1)
	_, grantee := testKey(2)
	return DetachedCertificate{Version: 2, Network: "regtest", Genesis: su.RegtestGenesis, AgentName: "id/test-agent", IssuerKey: issuer, GranteeKey: grantee, ContractSHA256: strings.Repeat("a", 64), Scope: []string{"deliver", "pay"}, NotBefore: 100, NotAfter: 1000, Seal: Point{strings.Repeat("b", 64), 0}}
}
func signDetachedTest(t *testing.T, c DetachedCertificate, key byte) []byte {
	t.Helper()
	raw, e := c.Canonical()
	if e != nil {
		t.Fatal(e)
	}
	k, _ := testKey(key)
	sig, e := schnorr.Sign(k, mustDecodeKey(Hash(raw)))
	if e != nil {
		t.Fatal(e)
	}
	b, e := json.Marshal(DetachedEnvelope{c, hex.EncodeToString(sig.Serialize())})
	if e != nil {
		t.Fatal(e)
	}
	return b
}

// The exact version-2 wire signs and verifies with both optional-field states;
// absent budget is zero and explicit zero remains distinct signed bytes.
func TestDetachedWire(t *testing.T) {
	c := testDetached()
	raw := signDetachedTest(t, c, 1)
	env, e := ParseDetachedEnvelope(raw)
	if e != nil || env.Certificate.BudgetSat() != 0 {
		t.Fatal("absent budget is not zero", e)
	}
	unsigned, _ := c.Canonical()
	want := `{"version":2,"network":"regtest","genesis":"` + su.RegtestGenesis + `","agent_name":"id/test-agent","issuer_key":"` + c.IssuerKey + `","grantee_key":"` + c.GranteeKey + `","contract_sha256":"` + c.ContractSHA256 + `","scope":["deliver","pay"],"not_before":100,"not_after":1000,"seal":{"txid":"` + c.Seal.TxID + `","vout":0}}`
	if string(unsigned) != want {
		t.Fatal("field order differs from frozen wire")
	}
	zero := int64(0)
	c.Budget = &zero
	c.GranteeName = "id/renter"
	present := signDetachedTest(t, c, 1)
	env, e = ParseDetachedEnvelope(present)
	if e != nil || env.Certificate.Budget == nil || env.Certificate.BudgetSat() != 0 || Hash(present) == Hash(raw) {
		t.Fatal("optional fields collapsed", e)
	}
}

// Alternate JSON, legacy format, signed-field mutation and foreign signatures
// are rejected; no unknown field or null optional becomes a different authority.
func TestDetachedWireRefusals(t *testing.T) {
	c := testDetached()
	good := signDetachedTest(t, c, 1)
	cases := map[string][]byte{
		"legacy":            signTest(t, testCertificate(), 1),
		"wrong-signing-key": signDetachedTest(t, c, 3),
		"extra":             []byte(strings.Replace(string(good), `"version":2`, `"version":2,"extra":0`, 1)),
		"alias":             []byte(strings.Replace(string(good), `"issuer_key":`, `"issuer_pubkey":`, 1)),
		"folded":            []byte(strings.Replace(string(good), `"issuer_key":`, `"Issuer_Key":`, 1)),
		"null-budget":       []byte(strings.Replace(string(good), `"seal":`, `"budget":null,"seal":`, 1)),
		"null-name":         []byte(strings.Replace(string(good), `"contract_sha256":`, `"grantee_name":null,"contract_sha256":`, 1)),
		"duplicate":         []byte(strings.Replace(string(good), `"version":2`, `"version":2,"version":2`, 1)),
		"scope-null":        []byte(strings.Replace(string(good), `["deliver","pay"]`, `null`, 1)),
		"changed-window":    []byte(strings.Replace(string(good), `"not_after":1000`, `"not_after":1001`, 1)),
		"trailing":          append(append([]byte(nil), good...), 10),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, e := ParseDetachedEnvelope(raw); e == nil {
				t.Fatal("invalid envelope accepted")
			}
			if _, e := ParseDetachedEnvelope(good); e != nil {
				t.Fatal("valid neighbor", e)
			}
		})
	}
}

// Key 1 has a published well-known compressed public point and HASH160;
// this pins script bytes independently of the script-building implementation.
func TestGrantSealScript(t *testing.T) {
	_, key := testKey(1)
	got, e := GrantSealScript(key)
	if e != nil || got != "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac" {
		t.Fatal("even-y key script mismatch", e)
	}
	for _, badKey := range []string{"", strings.Repeat("f", 64), strings.ToUpper(key)} {
		if _, e := GrantSealScript(badKey); e == nil || e.Error() != "DETACHED_KEY" {
			t.Fatal("invalid script key accepted")
		}
	}
}
