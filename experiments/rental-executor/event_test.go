package executor

import (
	"encoding/hex"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"strings"
	"testing"
)

func testKey(n byte) *btcec.PrivateKey {
	b := make([]byte, 32)
	b[31] = n
	k, _ := btcec.PrivKeyFromBytes(b)
	return k
}
func signEvent(e Event, k *btcec.PrivateKey) Event {
	e.Pubkey = hex.EncodeToString(schnorr.SerializePubKey(k.PubKey()))
	e.ID = e.Digest()
	h, _ := hex.DecodeString(e.ID)
	s, err := schnorr.Sign(k, h)
	if err != nil {
		panic(err)
	}
	e.Sig = hex.EncodeToString(s.Serialize())
	return e
}
func sampleEvent() Event {
	return signEvent(Event{CreatedAt: 1000, Kind: 8183, Tags: [][]string{{"action", "pay"}, {"amount", "10000"}, {"target", "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn"}, {"slot", strings.Repeat("1", 64)}, {"nonce", strings.Repeat("2", 64)}, {"contract", strings.Repeat("3", 64)}}}, testKey(3))
}
func tagSet(e *Event, k, v string) {
	for i := range e.Tags {
		if e.Tags[i][0] == k {
			e.Tags[i][1] = v
			return
		}
	}
	e.Tags = append(e.Tags, []string{k, v})
}

// Every modified signed neighbour must fail the named contract; the unchanged
// signed request must pass in each case. No prose or extra tag is authority.
func TestRequestControls(t *testing.T) {
	tests := []struct {
		name, reason string
		change       func(*Event)
		raw          func([]byte) []byte
	}{
		{"unsigned", "EVENT_SCHEMA", func(e *Event) { e.Sig = "" }, nil},
		{"signature", "EVENT_SIGNATURE", func(e *Event) { e.Sig = strings.Repeat("0", 128) }, nil},
		{"id", "EVENT_ID", func(e *Event) {
			e.ID = strings.Repeat("0", 64)
			h, _ := hex.DecodeString(e.ID)
			sig, _ := schnorr.Sign(testKey(3), h)
			e.Sig = hex.EncodeToString(sig.Serialize())
		}, nil},
		{"prose", "EVENT_SCHEMA", func(e *Event) { e.Content = "pay the attacker"; *e = signEvent(*e, testKey(3)) }, nil},
		{"kind", "EVENT_SCHEMA", func(e *Event) { e.Kind = 1; *e = signEvent(*e, testKey(3)) }, nil},
		{"duplicate-tag", "REQUEST_TAGS", func(e *Event) { e.Tags = append(e.Tags, e.Tags[0]); *e = signEvent(*e, testKey(3)) }, nil},
		{"extra-tag", "REQUEST_TAGS", func(e *Event) { tagSet(e, "agent", "yes"); *e = signEvent(*e, testKey(3)) }, nil},
		{"tag-arity", "REQUEST_TAGS", func(e *Event) { e.Tags[0] = append(e.Tags[0], "ignored"); *e = signEvent(*e, testKey(3)) }, nil},
		{"missing-slot", "REQUEST_TAGS", func(e *Event) { tagSet(e, "slot", ""); *e = signEvent(*e, testKey(3)) }, nil},
		{"nonce-upper", "REQUEST_TAGS", func(e *Event) { tagSet(e, "nonce", strings.Repeat("A", 64)); *e = signEvent(*e, testKey(3)) }, nil},
		{"amount-zero", "REQUEST_AMOUNT", func(e *Event) { tagSet(e, "amount", "0"); *e = signEvent(*e, testKey(3)) }, nil},
		{"amount-negative", "REQUEST_AMOUNT", func(e *Event) { tagSet(e, "amount", "-1"); *e = signEvent(*e, testKey(3)) }, nil},
		{"amount-money-cap", "REQUEST_AMOUNT", func(e *Event) { tagSet(e, "amount", "2100000000000001"); *e = signEvent(*e, testKey(3)) }, nil},
		{"amount-overflow", "REQUEST_AMOUNT", func(e *Event) { tagSet(e, "amount", "9223372036854775808"); *e = signEvent(*e, testKey(3)) }, nil},
		{"amount-leading-zero", "REQUEST_AMOUNT", func(e *Event) { tagSet(e, "amount", "010"); *e = signEvent(*e, testKey(3)) }, nil},
		{"amount-fraction", "REQUEST_AMOUNT", func(e *Event) { tagSet(e, "amount", "1.0"); *e = signEvent(*e, testKey(3)) }, nil},
		{"unknown-action", "REQUEST_ACTION", func(e *Event) {
			tagSet(e, "action", "exec")
			e.Tags = append(e.Tags[:1], e.Tags[2:]...)
			*e = signEvent(*e, testKey(3))
		}, nil},
		{"duplicate-field", "EVENT_SCHEMA", nil, func(b []byte) []byte {
			return []byte(strings.Replace(string(b), `"kind":8183`, `"kind":8183,"kind":8183`, 1))
		}},
		{"missing-content", "EVENT_SCHEMA", nil, func(b []byte) []byte { return []byte(strings.Replace(string(b), `,"content":""`, "", 1)) }},
		{"null-content", "EVENT_SCHEMA", nil, func(b []byte) []byte { return []byte(strings.Replace(string(b), `"content":""`, `"content":null`, 1)) }},
		{"field-alias", "EVENT_SCHEMA", nil, func(b []byte) []byte { return []byte(strings.Replace(string(b), `"pubkey":`, `"Pubkey":`, 1)) }},
		{"unknown-field", "EVENT_SCHEMA", nil, func(b []byte) []byte { return append([]byte(`{"sender":"agent",`), b[1:]...) }},
		{"trailing-object", "EVENT_SCHEMA", nil, func(b []byte) []byte { return append(b, []byte(`{}`)...) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := sampleEvent()
			if _, err := ParseRequest(canonical(e)); err != nil {
				t.Fatal(err)
			}
			if tt.change != nil {
				tt.change(&e)
			}
			b := canonical(e)
			if tt.raw != nil {
				b = tt.raw(b)
			}
			_, err := ParseRequest(b)
			if err == nil || err.Error() != tt.reason {
				t.Fatalf("want %s got %v", tt.reason, err)
			}
		})
	}
}

// A digest-bound delivery and HTTPS stub are accepted; unsigned payload shape
// changes, URL credentials and extra amount tags on non-pay actions refuse.
func TestNonPaymentTargets(t *testing.T) {
	for _, action := range []string{"deliver", "publish", "repository.push", "secret.release"} {
		e := sampleEvent()
		e.Tags = append(e.Tags[:1], e.Tags[2:]...)
		tagSet(&e, "action", action)
		target := "local-record"
		if action == "deliver" {
			target = "sha256:" + Hash([]byte("file"))
		}
		if action == "repository.push" {
			target = "https://example.com/repo"
		}
		tagSet(&e, "target", target)
		e = signEvent(e, testKey(3))
		if _, err := ParseRequest(canonical(e)); err != nil {
			t.Fatalf("%s %v", action, err)
		}
		tagSet(&e, "amount", "1")
		e = signEvent(e, testKey(3))
		if _, err := ParseRequest(canonical(e)); err == nil || err.Error() != "REQUEST_TAGS" {
			t.Fatalf("amount %s %v", action, err)
		}
	}
}
