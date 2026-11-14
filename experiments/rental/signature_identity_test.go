package rental

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// Only public deterministic fixture keys are used. Fresh aux randomness changes
// the signing nonce, not the signed content or its authorization.
func secondFixtureSignature(t *testing.T, digest, original string, key byte) string {
	t.Helper()
	k, pub := testKey(key)
	hash, err := hex.DecodeString(digest)
	if err != nil {
		t.Fatal(err)
	}
	var aux [32]byte
	if _, err = rand.Read(aux[:]); err != nil {
		t.Fatal(err)
	}
	sig, err := schnorr.Sign(k, hash, schnorr.CustomNonce(aux))
	if err != nil {
		t.Fatal(err)
	}
	second := hex.EncodeToString(sig.Serialize())
	if original == second || !VerifySignature(pub, digest, original) || !VerifySignature(pub, digest, second) {
		t.Fatal("fixture must contain two distinct valid signatures over identical content")
	}
	return second
}

func secondSignedGrant(t *testing.T, original []byte) []byte {
	t.Helper()
	s, err := ParseSignedGrant(original)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := s.Grant.SigningHash()
	if err != nil {
		t.Fatal(err)
	}
	s.Signature = secondFixtureSignature(t, digest, s.Signature, 1)
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ParseSignedGrant(raw); err != nil {
		t.Fatal(err)
	}
	return raw
}

// Two valid signatures create different signed-grant IDs and commitments. Both
// historical and framed issuance gates bind exactly the original signed bytes.
// This is a script-gate test; the Core test below covers actual admission.
func TestGrantSecondSignatureCommitment(t *testing.T) {
	raw := signGrantTest(t, testGrant(t), 1)
	second := secondSignedGrant(t, raw)
	a, _ := ParseSignedGrant(raw)
	b, _ := ParseSignedGrant(second)
	ac, _ := a.Grant.Canonical()
	bc, _ := b.Grant.Canonical()
	ca, err := IssuanceCommitment(a)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := IssuanceCommitment(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ac, bc) || a.ID() == b.ID() || ca == cb {
		t.Fatal("signature-dependent identity/commitment fixture")
	}
	for _, script := range [][]byte{append([]byte{0x6a, 32}, mustDecodeKey(ca)...), framedGrantScript(t, raw)} {
		if !issuanceScriptMatches(script, ca, a.ID()) {
			t.Fatal("committed original refused")
		}
		if issuanceScriptMatches(script, cb, b.ID()) {
			t.Fatal("SECOND_SIGNATURE_COMMITMENT: uncommitted signature admitted")
		}
	}
}

// On genuine Core, the alternate signature fails before first admission, cannot
// create a grant record, and cannot replace a live cached presentation. Its own
// separately committed issuance is required even in a fresh observer state.
func TestCoreGrantSecondSignatureCommitment(t *testing.T) {
	l := newCore(t)
	l.grantIdentity()
	p, g, raw := l.grantFixture("signature", l.witnessPool(1, true), 2)
	proof := l.grantProof(p, raw, true)
	original, err := ParseGrantPresentation(proof)
	if err != nil {
		t.Fatal(err)
	}
	second := secondSignedGrant(t, raw)
	alternate, err := PresentIssuedGrant(second, original.Issuance.TxID)
	if err != nil {
		t.Fatal(err)
	}
	twin, _ := ParseGrantPresentation(alternate)
	denied := Check(context.Background(), l.observer, p, alternate, p.AgentName, g.GranteeKey, 500)
	if denied.Verdict != "refused" || denied.Reason != "ISSUANCE_COMMITMENT" {
		t.Fatalf("SECOND_SIGNATURE_COMMITMENT: %+v", denied)
	}
	if _, err = os.Stat(filepath.Join(p.StateDir, "grant-"+twin.SignedGrant.ID()+".json")); !os.IsNotExist(err) {
		t.Fatal("uncommitted grant record written", err)
	}
	admitted := Present(context.Background(), l.observer, p, proof, original.SignedGrant.ID(), p.AgentName, g.GranteeKey, 500)
	if admitted.Verdict != "live" {
		t.Fatal("committed original", admitted)
	}
	before, id, err := CachedGrant(p, g.GranteeKey)
	if err != nil {
		t.Fatal(err)
	}
	denied = Present(context.Background(), l.observer, p, alternate, twin.SignedGrant.ID(), p.AgentName, g.GranteeKey, 500)
	if denied.Verdict != "refused" || denied.Reason != "SEAL_ALREADY_SEEN" {
		t.Fatal("alternate replaced original", denied)
	}
	after, afterID, err := CachedGrant(p, g.GranteeKey)
	if err != nil || id != afterID || !bytes.Equal(before, after) {
		t.Fatal("refusal changed presentation cache", err)
	}
	fresh := p
	fresh.StateDir = l.policy("signature-own-issuance").StateDir
	ownProof := l.grantProof(fresh, second, true)
	l.checkGrant("second-own-issuance", fresh, g, ownProof, 500, "live", "LIVE", false)
}

// A legacy envelope's fresh valid signature cannot reuse the original confirmed
// name value/OP_RETURN commitment or create another certificate state record.
func TestCoreLegacySecondSignatureCommitment(t *testing.T) {
	l := newCore(t)
	p, c, raw, _ := l.fixture("signature-legacy")
	original, err := ParseEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := c.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	alternate := original
	alternate.Signature = secondFixtureSignature(t, Hash(payload), original.Signature, 1)
	second, _ := json.Marshal(alternate)
	if _, err = ParseEnvelope(second); err != nil {
		t.Fatal(err)
	}
	if Hash(raw) == Hash(second) {
		t.Fatal("envelope IDs must differ")
	}
	denied := CheckLegacy(context.Background(), l.observer, p, second, c.StationName, c.GranteePubkey, 500)
	if denied.Verdict != "refused" || denied.Reason != "NAME_VALUE" {
		t.Fatal("uncommitted alternate admitted", denied)
	}
	if _, err = os.Stat(filepath.Join(p.StateDir, "certificate-"+Hash(second)+".json")); !os.IsNotExist(err) {
		t.Fatal("alternate state written", err)
	}
	admitted := CheckLegacy(context.Background(), l.observer, p, raw, c.StationName, c.GranteePubkey, 500)
	if admitted.Verdict != "live" {
		t.Fatal("committed original", admitted)
	}
}

// Detached v2 has NO per-certificate chain commitment. Its first-admitted seal
// index prevents a second signed ID in the same state. A fresh observer accepts
// either valid signature; this explicitly bounds, rather than overclaims, v2.
func TestCoreDetachedSecondSignatureSealBinding(t *testing.T) {
	l := newCore(t)
	l.agentValue(1, 3, true)
	p, c, raw := l.detached("signature-detached", l.detachedPool(1, true), 2)
	original, err := ParseDetachedEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := c.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	alternate := original
	alternate.Signature = secondFixtureSignature(t, Hash(payload), original.Signature, 1)
	second, _ := json.Marshal(alternate)
	if _, err = ParseDetachedEnvelope(second); err != nil {
		t.Fatal(err)
	}
	if Hash(raw) == Hash(second) {
		t.Fatal("envelope IDs must differ")
	}
	admitted := PresentV2(context.Background(), l.observer, p, raw, Hash(raw), p.AgentName, c.GranteeKey, 500)
	if admitted.Verdict != "live" {
		t.Fatal("original detached presentation", admitted)
	}
	denied := PresentV2(context.Background(), l.observer, p, second, Hash(second), p.AgentName, c.GranteeKey, 500)
	if denied.Verdict != "refused" || denied.Reason != "SEAL_ALREADY_SEEN" {
		t.Fatal("alternate detached presentation", denied)
	}
	cached, id, err := CachedCertificateV2(p, c.GranteeKey)
	if err != nil || id != Hash(raw) || !bytes.Equal(cached, raw) {
		t.Fatal("refusal changed detached cache", err)
	}
	if _, err = os.Stat(filepath.Join(p.StateDir, "detached-"+Hash(second)+".json")); !os.IsNotExist(err) {
		t.Fatal("second state record written", err)
	}
	fresh := p
	fresh.StateDir = l.policy("fresh-detached-observer").StateDir
	l.checkDetached("second-first-observation", fresh, c, second, 500, "live", "LIVE", false)
}
