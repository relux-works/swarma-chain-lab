package g1bench

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	cg "github.com/relux-works/swarma-chain-lab/experiments/grantcheck"
)

// Claim: the fixture codec verifies its signed record and refuses altered
// delivery, duplicate/aliased fields, invalid signatures and noncanonical bytes.
// This is the explicitly separate BIP-340 bench profile, not native conformance.
func TestEnvelopeFixtureProfile(t *testing.T) {
	key, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(2000000000, 0)
	const room = "!codec:example.invalid"
	const to = "@peer:example.invalid"
	body, err := Message(cg.Presentation{GrantID: strings.Repeat("a", 64), Bytes: []byte("proof")}, []byte("terms"), room, to, "work text", now)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Sign(key, body)
	if err != nil {
		t.Fatal(err)
	}
	if _, got, err := verify(raw, "work text", room, to, now); err != nil || got != Key(key) {
		t.Fatal("positive signature control")
	}
	for name, bad := range map[string][]byte{
		"empty":      nil,
		"oversize":   bytes.Repeat([]byte("x"), maxEnvelope+1),
		"trailing":   append(bytes.Clone(raw), ' '),
		"duplicate":  bytes.Replace(raw, []byte(`"version":"swarm-envelope/2"`), []byte(`"version":"swarm-envelope/2","version":"swarm-envelope/2"`), 1),
		"case-alias": bytes.Replace(raw, []byte(`"version":`), []byte(`"Version":`), 1),
		"unknown":    bytes.Replace(raw, []byte(`"version":`), []byte(`"extra":true,"version":`), 1),
		"id":         bytes.Replace(raw, []byte(`"id":"sha256:`), []byte(`"id":"sha256:0`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := verify(bad, "work text", room, to, now); err != errEnvelope {
				t.Fatal("invalid envelope admitted")
			}
		})
	}
	for name, change := range map[string]func(*Body){
		"room":      func(b *Body) { b.Room = "!other:example.invalid" },
		"recipient": func(b *Body) { b.To = "@other:example.invalid" },
		"text":      func(b *Body) { b.BodySHA256 = Hash([]byte("other text")) },
		"nonce":     func(b *Body) { b.Nonce += "=" },
		"audience":  func(b *Body) { b.Aud = "other" },
		"action":    func(b *Body) { b.Action = "execute" },
		"future":    func(b *Body) { b.Iat = now.Add(time.Second).Format(time.RFC3339) },
	} {
		t.Run(name, func(t *testing.T) {
			copy := body
			change(&copy)
			signed, err := Sign(key, copy)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := verify(signed, "work text", room, to, now); err != errEnvelope {
				t.Fatal("invalid signed body admitted")
			}
		})
	}
	// Claim: the unchanged valid lifetime refuses exactly at its exclusive end;
	// iat < exp and the 120-second duration remain valid.
	t.Run("expired", func(t *testing.T) {
		if _, _, err := verify(raw, "work text", room, to, now.Add(120*time.Second)); err != errEnvelope {
			t.Fatal("expired envelope did not return envelope-invalid")
		}
	})
}
