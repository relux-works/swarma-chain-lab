package kernelbind_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernel"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernelbind"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"os"
	"reflect"
	"strings"
	"testing"
)

func xonly(n byte) string {
	b := make([]byte, 32)
	b[31] = n
	_, p := btcec.PrivKeyFromBytes(b)
	return hex.EncodeToString(schnorr.SerializePubKey(p))
}
func stateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	return dir
}
func newAdapter(t *testing.T) *kernelbind.Adapter {
	t.Helper()
	a, e := kernelbind.New(nil, stateDir(t), "id/test-agent", "id/test-landlord", xonly(1), "W")
	if e != nil {
		t.Fatal(e)
	}
	return a
}
func jsonBytes(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func signHash(t *testing.T, k *btcec.PrivateKey, id string) string {
	t.Helper()
	h, e := hex.DecodeString(id)
	if e != nil {
		t.Fatal(e)
	}
	s, e := schnorr.Sign(k, h)
	if e != nil {
		t.Fatal(e)
	}
	return hex.EncodeToString(s.Serialize())
}
func signEvent(t *testing.T, k *nostr.PrivKey, e rental.Event) rental.Event {
	t.Helper()
	n := nostr.Event{CreatedAt: e.CreatedAt, Kind: e.Kind, Tags: e.Tags, Content: e.Content}
	if err := k.SignEvent(&n); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(jsonBytes(t, n), &e); err != nil {
		t.Fatal(err)
	}
	return e
}
func proofGrant(t *testing.T, raw []byte) rental.SignedGrant {
	t.Helper()
	p, e := rental.ParseGrantPresentation(raw)
	if e != nil {
		t.Fatal(e)
	}
	return p.SignedGrant
}

// Offline cryptographic fixture only. The genuine Core suite creates every
// admitted v3 grant through rental.IssueGrant instead.
func unitGrant(t *testing.T) []byte {
	t.Helper()
	keyBytes := make([]byte, 32)
	keyBytes[31] = 1
	k, _ := btcec.PrivKeyFromBytes(keyBytes)
	keyBytes[31] = 2
	renter, e := nostr.PrivKeyFromBytes(keyBytes)
	if e != nil {
		t.Fatal(e)
	}
	hash := strings.Repeat("a", 64)
	consent := signEvent(t, renter, rental.Event{CreatedAt: 200, Kind: 8181, Tags: [][]string{{"t", "swarma-rental-consent-v1"}, {"contract", hash}, {"booking", strings.Repeat("b", 64)}, {"privacy", strings.Repeat("c", 64)}}})
	g := rental.Grant{Version: 3, Network: "regtest", Genesis: su.RegtestGenesis, AgentName: "id/test-agent", LandlordName: "id/test-landlord", IssuerKey: xonly(1), GranteeKey: renter.PubKeyHex(), ContractSHA256: hash, Scope: []string{"deliver", "pay"}, NotBefore: 100, NotAfter: 1000, Seal: rental.Point{TxID: strings.Repeat("d", 64)}, Consent: rental.GrantConsent{ContractSHA256: hash, ConsentEvent: consent, LandlordSig: signHash(t, k, hash)}}
	digest, e := g.SigningHash()
	if e != nil {
		t.Fatal(e)
	}
	raw, e := rental.PresentIssuedGrant(jsonBytes(t, rental.SignedGrant{Grant: g, Signature: signHash(t, k, digest)}), strings.Repeat("e", 64))
	if e != nil {
		t.Fatal(e)
	}
	return raw
}

// Policy pins include landlord and agent; the gateway never needs funding.
// A malformed seal key is refused locally beside the valid constructor.
func TestNewPinsPolicy(t *testing.T) {
	a := newAdapter(t)
	p := a.Policy
	script, e := rental.GrantSealScript(xonly(1))
	if e != nil {
		t.Fatal(e)
	}
	if p.Network != "regtest" || p.Genesis != su.RegtestGenesis || p.AgentName != "id/test-agent" || p.LandlordName != "id/test-landlord" || p.SealScript != script || p.StateDir == "" || p.FundingScript != "" {
		t.Fatalf("policy pins: %+v", p)
	}
	if _, e = kernelbind.New(nil, t.TempDir(), "id/test-agent", "id/test-landlord", "bad-key", "W"); e == nil {
		t.Fatal("malformed key admitted")
	}
}

// Mapping preserves v3 fields when the node is absent. A foreign sender and
// malformed/v2 objects refuse before chain observation, with no closure.
func TestCheckMapsV3Receipt(t *testing.T) {
	a := newAdapter(t)
	raw := unitGrant(t)
	signed := proofGrant(t, raw)
	r, e := a.Check(context.Background(), raw, a.Policy.AgentName, xonly(2), 500)
	if e != nil || r.Verdict != kernel.Refused || r.Reason != "NODE_UNAVAILABLE" || r.GrantID != signed.ID() || r.AgentName != a.Policy.AgentName || r.LandlordName != a.Policy.LandlordName || r.CheckedAt != 500 || r.Closed || !reflect.DeepEqual(r.Scope, signed.Grant.Scope) {
		t.Fatalf("v3 mapping: %+v %v", r, e)
	}
	foreign, _ := a.Check(context.Background(), raw, a.Policy.AgentName, xonly(3), 500)
	if foreign.Reason != "GRANTEE_MISMATCH" || foreign.Admits() {
		t.Fatalf("foreign: %+v", foreign)
	}
	for _, bad := range [][]byte{[]byte("not JSON"), legacyEnvelope(t, signed.Grant)} {
		got, _ := a.Check(context.Background(), bad, a.Policy.AgentName, xonly(2), 500)
		if got.Verdict != kernel.Refused || got.Reason != "CANONICAL_ENCODING" || got.GrantID != "" || got.Closed {
			t.Fatalf("malformed/v2: %+v", got)
		}
	}
}

// Wrong ID refuses before caching; the correct ID reaches Check and missing
// node refuses without caching. Changing only locator preserves the stable ID.
func TestPresentRejectsBadID(t *testing.T) {
	a := newAdapter(t)
	raw := unitGrant(t)
	signed := proofGrant(t, raw)
	r, e := a.Present(context.Background(), raw, strings.Repeat("0", 64), a.Policy.AgentName, xonly(2), 500)
	if e != nil || r.Verdict != kernel.Refused || r.Reason != "PRESENTATION_ID" {
		t.Fatalf("wrong id: %+v %v", r, e)
	}
	r, e = a.Present(context.Background(), raw, signed.ID(), a.Policy.AgentName, xonly(2), 500)
	if e != nil || r.Reason != "NODE_UNAVAILABLE" || r.Admits() {
		t.Fatalf("correct id without node: %+v %v", r, e)
	}
	if _, e = a.CachedGrant(xonly(2)); !errors.Is(e, kernel.ErrNoPresentation) {
		t.Fatalf("refused cache insertion: %v", e)
	}
	changed, e := rental.PresentIssuedGrant(jsonBytes(t, signed), strings.Repeat("f", 64))
	if e != nil {
		t.Fatal(e)
	}
	for _, proof := range [][]byte{raw, changed} {
		id, e := kernel.PresentationID(proof)
		if e != nil || id != signed.ID() {
			t.Fatalf("locator affected ID: %s %v", id, e)
		}
	}
}

// A valid v2 certificate is a negative fixture only; no compatibility path.
func legacyEnvelope(t *testing.T, g rental.Grant) []byte {
	t.Helper()
	c := rental.DetachedCertificate{Version: 2, Network: g.Network, Genesis: g.Genesis, AgentName: g.AgentName, IssuerKey: g.IssuerKey, GranteeKey: g.GranteeKey, ContractSHA256: g.ContractSHA256, Scope: g.Scope, NotBefore: g.NotBefore, NotAfter: g.NotAfter, Seal: g.Seal}
	b, e := c.Canonical()
	if e != nil {
		t.Fatal(e)
	}
	key := make([]byte, 32)
	key[31] = 1
	k, _ := btcec.PrivKeyFromBytes(key)
	return jsonBytes(t, rental.DetachedEnvelope{Certificate: c, Signature: signHash(t, k, rental.Hash(b))})
}
