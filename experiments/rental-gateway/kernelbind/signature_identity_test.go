package kernelbind_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernel"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernelbind"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
)

// The actual gateway adapter accepts the committed presentation, refuses a
// second valid signature over identical grant content before first admission,
// and never caches it or replaces the original with that different ID.
func TestCoreGatewaySecondSignatureCommitment(t *testing.T) {
	agent, err := nostr.GeneratePrivKey()
	if err != nil {
		t.Fatal(err)
	}
	l := newCoreLab(t, agent.PubKeyHex())
	renter, err := nostr.GeneratePrivKey()
	if err != nil {
		t.Fatal(err)
	}
	raw := l.grant(renter, "signature", l.seal(), true)
	p, err := rental.ParseGrantPresentation(raw)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := p.SignedGrant.Grant.SigningHash()
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := hex.DecodeString(digest)
	original := p.SignedGrant.Signature
	var aux [32]byte
	if _, err = rand.Read(aux[:]); err != nil {
		t.Fatal(err)
	}
	sig, err := schnorr.Sign(l.issuer, hash, schnorr.CustomNonce(aux))
	if err != nil {
		t.Fatal(err)
	}
	p.SignedGrant.Signature = hex.EncodeToString(sig.Serialize())
	if original == p.SignedGrant.Signature || !rental.VerifySignature(l.issuerPub, digest, original) || !rental.VerifySignature(l.issuerPub, digest, p.SignedGrant.Signature) {
		t.Fatal("two valid distinct fixture signatures required")
	}
	second := jsonBytes(t, p)
	if _, err = rental.ParseGrantPresentation(second); err != nil {
		t.Fatal(err)
	}
	firstID, err := kernel.PresentationID(raw)
	if err != nil {
		t.Fatal(err)
	}
	secondID, err := kernel.PresentationID(second)
	if err != nil || secondID == firstID || secondID != p.SignedGrant.ID() {
		t.Fatal("signature-dependent presentation IDs required", err)
	}
	root := filepath.Join(l.root, "kernel-signature")
	if err = os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	adapter, err := kernelbind.New(l.observer, root, e2eAgentName, e2eLandlordName, l.issuerPub, "W")
	if err != nil {
		t.Fatal(err)
	}
	denied, err := adapter.Present(context.Background(), second, secondID, e2eAgentName, renter.PubKeyHex(), 500)
	if err != nil || denied.Admits() || denied.Reason != "ISSUANCE_COMMITMENT" {
		t.Fatal("uncommitted gateway admission", denied, err)
	}
	if cached, err := adapter.CachedGrant(renter.PubKeyHex()); err != kernel.ErrNoPresentation || cached != nil {
		t.Fatal("refused twin cached", err)
	}
	live, err := adapter.Present(context.Background(), raw, firstID, e2eAgentName, renter.PubKeyHex(), 500)
	if err != nil || !live.Admits() {
		t.Fatal("committed original", live, err)
	}
	denied, err = adapter.Present(context.Background(), second, secondID, e2eAgentName, renter.PubKeyHex(), 500)
	if err != nil || denied.Admits() || denied.Reason != "SEAL_ALREADY_SEEN" {
		t.Fatal("twin replaced original", denied, err)
	}
	cached, err := adapter.CachedGrant(renter.PubKeyHex())
	if err != nil || !bytes.Equal(cached, raw) {
		t.Fatal("cache changed on refusal", err)
	}
}
