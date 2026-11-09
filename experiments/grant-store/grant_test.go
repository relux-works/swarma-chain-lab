package grantstore

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"relux.works/swarma-chain-lab/experiments/rental"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/nostr"
	su "relux.works/swarma-chain-lab/experiments/single-use"
)

func grantFixture(t *testing.T, l *lab) []byte {
	t.Helper()
	k, _ := btcec.PrivKeyFromBytes(l.writer.Bytes())
	sign := func(id string) string {
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
	hash := Hash([]byte("contract"))
	ev := nostr.Event{CreatedAt: 200, Kind: 8181, Tags: [][]string{{"t", "swarma-rental-consent-v1"}, {"contract", hash}, {"booking", Hash([]byte("booking"))}, {"privacy", Hash([]byte("privacy"))}}}
	if e := l.reader.SignEvent(&ev); e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(ev)
	var consent rental.Event
	if e := json.Unmarshal(b, &consent); e != nil {
		t.Fatal(e)
	}
	g := rental.Grant{Version: 3, Network: "regtest", Genesis: su.RegtestGenesis, AgentName: "id/test-agent", LandlordName: "id/test-landlord", IssuerKey: l.writer.PubKeyHex(), GranteeKey: l.reader.PubKeyHex(), ContractSHA256: hash, Scope: []string{"deliver", "pay"}, NotBefore: 100, NotAfter: 1000, Seal: rental.Point{TxID: strings.Repeat("d", 64)}, Consent: rental.GrantConsent{ContractSHA256: hash, ConsentEvent: consent, LandlordSig: sign(hash)}}
	digest, e := g.SigningHash()
	if e != nil {
		t.Fatal(e)
	}
	b, e = json.Marshal(rental.SignedGrant{Grant: g, Signature: sign(digest)})
	if e != nil {
		t.Fatal(e)
	}
	return b
}

// A cryptographically valid offline K1 fixture round-trips at its canonical ID
// for grantee/landlord/agent. This proves storage glue, not live chain authority.
func TestGrantHelpers(t *testing.T) {
	l := newLab(t)
	l.s.cfg.MaxBlobBytes = 8192
	c := l.client(l.writer)
	c.MaxBytes = 8192
	raw := grantFixture(t, l)
	d, e := c.PutGrant(context.Background(), l.http.URL, raw, l.writer.PubKeyHex(), l.other.PubKeyHex())
	if e != nil || d.SHA256 != Hash(raw) {
		t.Fatalf("put grant: %v", e)
	}
	for _, k := range []*nostr.PrivKey{l.writer, l.reader, l.other} {
		c := l.client(k)
		c.MaxBytes = 8192
		g, e := c.GetGrant(context.Background(), l.http.URL, d.SHA256)
		if e != nil || g.ID() != d.SHA256 {
			t.Fatalf("grant reader: %v", e)
		}
	}
	if _, e = l.client(l.outsider).GetGrant(context.Background(), l.http.URL, d.SHA256); e == nil {
		t.Fatal("outsider fetched grant")
	}
	count := len(l.s.blobs)
	for _, bad := range [][]byte{append(append([]byte{}, raw...), '\n'), []byte(`{}`), []byte(strings.Replace(string(raw), `"signature":"`, `"signature":"00`, 1))} {
		if _, e = c.PutGrant(context.Background(), l.http.URL, bad, l.writer.PubKeyHex(), l.other.PubKeyHex()); e == nil {
			t.Fatal("invalid signed grant uploaded")
		}
	}
	if _, e = c.PutGrant(context.Background(), l.http.URL, raw, "bad", l.other.PubKeyHex()); e == nil {
		t.Fatal("invalid pin uploaded")
	}
	if len(l.s.blobs) != count {
		t.Fatal("invalid grant changed store")
	}
	ordinary := l.put("ordinary")
	if _, e = c.GetGrant(context.Background(), l.http.URL, ordinary); e == nil {
		t.Fatal("ordinary blob accepted as grant")
	}
	l.read(l.writer, ordinary, "ordinary")
}
