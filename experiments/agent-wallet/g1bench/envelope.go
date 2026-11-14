// Package g1bench is a regtest-only envelope-shaped admission laboratory.
// Its BIP-340 fixture profile is NOT the native swarm-envelope/2 key profile.
package g1bench

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	cg "github.com/relux-works/swarma-chain-lab/experiments/grantcheck"
)

const ContentKey = "works.relux.swarm.envelope"
const version = "swarm-envelope/2"

// A separate domain prevents the fixture algorithm from masquerading as a
// registered native message signature. See README.md for the profile mismatch.
const domain = "g1bench-message/1\n"
const maxEnvelope = 65536

var errEnvelope = errors.New("bench envelope invalid")

type Arguments struct {
	GrantID      string `json:"grant_id"`
	Presentation string `json:"presentation"`
	Terms        string `json:"terms"`
}
type Body struct {
	Type              string    `json:"type"`
	Aud               string    `json:"aud"`
	Nonce             string    `json:"nonce"`
	Iat               string    `json:"iat"`
	Exp               string    `json:"exp"`
	Author            string    `json:"author"`
	AuthorAttestation string    `json:"author_attestation"`
	Action            string    `json:"action"`
	Target            string    `json:"target"`
	Arguments         Arguments `json:"arguments"`
	Room              string    `json:"room"`
	To                string    `json:"to"`
	BodySHA256        string    `json:"body_sha256"`
}
type Signature struct {
	Role string `json:"role"`
	Key  string `json:"key"`
	Sig  string `json:"sig"`
}
type Envelope struct {
	Version    string      `json:"version"`
	Body       Body        `json:"body"`
	ID         string      `json:"id"`
	Signatures []Signature `json:"signatures"`
}

// Canonical implements the bench's narrow all-string message schema. Sorting
// through maps gives scalar key order; floats and arbitrary objects are absent.
func Canonical(v any) []byte {
	raw, _ := json.Marshal(v)
	var tree any
	_ = json.Unmarshal(raw, &tree)
	var out bytes.Buffer
	e := json.NewEncoder(&out)
	e.SetEscapeHTML(false)
	_ = e.Encode(tree)
	return bytes.TrimSuffix(out.Bytes(), []byte{'\n'})
}
func Hash(b []byte) string           { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func Key(k *btcec.PrivateKey) string { return hex.EncodeToString(schnorr.SerializePubKey(k.PubKey())) }
func decode(s string, max int) ([]byte, error) {
	if len(s) > base64.RawURLEncoding.EncodedLen(max) {
		return nil, errEnvelope
	}
	b, e := base64.RawURLEncoding.Strict().DecodeString(s)
	if e != nil || base64.RawURLEncoding.EncodeToString(b) != s {
		return nil, errEnvelope
	}
	return b, nil
}
func record(e Envelope) []byte {
	return append([]byte(domain), Canonical(map[string]any{"body": e.Body, "key": e.Body.Author, "role": "author", "version": version})...)
}

// Sign creates only laboratory messages, with a random 128-bit nonce. No
// attestation trust or platform authority is implied by the synthetic reference.
func Sign(k *btcec.PrivateKey, body Body) ([]byte, error) {
	body.Author = "bip340:" + Key(k)
	e := Envelope{Version: version, Body: body}
	e.ID = "sha256:" + Hash(append([]byte(domain), Canonical(body)...))
	digest := sha256.Sum256(record(e))
	sig, err := schnorr.Sign(k, digest[:])
	if err != nil {
		return nil, errEnvelope
	}
	e.Signatures = []Signature{{Role: "author", Key: body.Author, Sig: base64.RawURLEncoding.EncodeToString(sig.Serialize())}}
	return Canonical(e), nil
}
func Message(p cg.Presentation, terms []byte, room, to, text string, now time.Time) (Body, error) {
	n := make([]byte, 16)
	if _, err := rand.Read(n); err != nil {
		return Body{}, err
	}
	return Body{Type: "message/1", Aud: "regtest.grant-bench", Nonce: base64.RawURLEncoding.EncodeToString(n), Iat: now.UTC().Format(time.RFC3339), Exp: now.Add(120 * time.Second).UTC().Format(time.RFC3339), AuthorAttestation: "sha256:" + strings.Repeat("0", 64), Action: "observe", Target: "regtest.admission", Arguments: Arguments{p.GrantID, base64.RawURLEncoding.EncodeToString(p.Bytes), base64.RawURLEncoding.EncodeToString(terms)}, Room: room, To: to, BodySHA256: Hash([]byte(text))}, nil
}

// verify returns a key only after BIP-340 verification of the protected record.
// Canonical-only input intentionally narrows the native format's wire grammar.
func verify(raw []byte, text, room, to string, now time.Time) (Envelope, string, error) {
	var e Envelope
	if len(raw) == 0 || len(raw) > maxEnvelope || !utf8.Valid(raw) || !utf8.ValidString(text) {
		return e, "", errEnvelope
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&e) != nil || !bytes.Equal(Canonical(e), raw) {
		return e, "", errEnvelope
	}
	b := e.Body
	if e.Version != version || b.Type != "message/1" || b.Aud != "regtest.grant-bench" || b.Action != "observe" || b.Target != "regtest.admission" || b.AuthorAttestation != "sha256:"+strings.Repeat("0", 64) || b.Room != room || b.To != to || b.BodySHA256 != Hash([]byte(text)) {
		return e, "", errEnvelope
	}
	nonce, err := decode(b.Nonce, 16)
	if err != nil || len(nonce) != 16 {
		return e, "", errEnvelope
	}
	iat, e1 := time.Parse(time.RFC3339, b.Iat)
	exp, e2 := time.Parse(time.RFC3339, b.Exp)
	if e1 != nil || e2 != nil || iat.UTC().Format(time.RFC3339) != b.Iat || exp.UTC().Format(time.RFC3339) != b.Exp || !iat.Before(exp) || exp.Sub(iat) > 120*time.Second || now.Before(iat) || !now.Before(exp) {
		return e, "", errEnvelope
	}
	if len(e.Signatures) != 1 || e.Signatures[0].Role != "author" || e.Signatures[0].Key != b.Author || !strings.HasPrefix(b.Author, "bip340:") {
		return e, "", errEnvelope
	}
	key := strings.TrimPrefix(b.Author, "bip340:")
	kb, err := hex.DecodeString(key)
	if err != nil || len(kb) != 32 || hex.EncodeToString(kb) != key {
		return e, "", errEnvelope
	}
	pub, err := schnorr.ParsePubKey(kb)
	if err != nil {
		return e, "", errEnvelope
	}
	sb, err := decode(e.Signatures[0].Sig, 64)
	if err != nil {
		return e, "", errEnvelope
	}
	sig, err := schnorr.ParseSignature(sb)
	digest := sha256.Sum256(record(e))
	if err != nil || !sig.Verify(digest[:], pub) {
		return e, "", errEnvelope
	}
	if e.ID != "sha256:"+Hash(append([]byte(domain), Canonical(b)...)) {
		return e, "", errEnvelope
	}
	return e, key, nil
}
