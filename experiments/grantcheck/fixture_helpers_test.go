package grantcheck

import (
	"encoding/hex"
	"encoding/json"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"os"
	"path/filepath"
	"relux.works/swarma-chain-lab/experiments/rental"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/nostr"
	su "relux.works/swarma-chain-lab/experiments/single-use"
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
	canonical, e := filepath.EvalSymlinks(dir)
	if e != nil {
		t.Fatal(e)
	}
	return canonical
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
	g := rental.Grant{Version: 3, Network: "regtest", Genesis: su.RegtestGenesis, AgentName: "id/test-agent", LandlordName: "id/test-landlord", IssuerKey: xonly(1), GranteeKey: renter.PubKeyHex(), ContractSHA256: hash, Scope: []string{"deliver", "pay"}, NotBefore: 300, NotAfter: 1000, Seal: rental.Point{TxID: strings.Repeat("d", 64)}, Consent: rental.GrantConsent{ContractSHA256: hash, ConsentEvent: consent, LandlordSig: signHash(t, k, hash)}}
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
