package session

import (
	"bytes"
	"encoding"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

const tokenMarker = "[session token]"

func outputToken(t *testing.T) (Token, [32]byte) {
	t.Helper()
	// Public synthetic credential; never print its bytes even on failure.
	var token Token
	copy(token[:], "0123456789abcdefFEDCBA9876543210!?")
	raw := token.RevealForOpen()
	if raw == [32]byte{} || Token(raw) != token {
		t.Fatal("token output control is zero or changed")
	}
	return token, raw
}

func noTokenOutput(t *testing.T, output []byte, raw [32]byte) {
	t.Helper()
	for _, forbidden := range []string{
		string(raw[:]), hex.EncodeToString(raw[:]), strings.ToUpper(hex.EncodeToString(raw[:])),
		base64.StdEncoding.EncodeToString(raw[:]), base64.RawStdEncoding.EncodeToString(raw[:]),
		base64.URLEncoding.EncodeToString(raw[:]), base64.RawURLEncoding.EncodeToString(raw[:]),
	} {
		if bytes.Contains(output, []byte(forbidden)) {
			t.Fatal("token disclosed by output sink")
		}
	}
}

// All fmt verbs ignore flags and width for both value/pointer tokens and each
// carrier. Exact marker checks also exclude decimal array and partial disclosure.
func TestTokenOutputFormat(t *testing.T) {
	for _, format := range []string{"%v", "%s", "%d", "%x", "%X", "%q", "%#v", "%+v", "%032x", "%.8s", "%b", "%c", "%o", "%U", "%f", "%p"} {
		t.Run(format, func(t *testing.T) {
			token, raw := outputToken(t) // Non-zero positive control beside each sink.
			for _, value := range []any{token, &token} {
				output := fmt.Sprintf(format, value)
				noTokenOutput(t, []byte(output), raw)
				// fmt reserves %p for pointer addresses; it never renders token bytes.
				if format != "%p" && output != tokenMarker {
					t.Fatal("token formatting did not return the fixed marker")
				}
			}
			for _, value := range []any{Facts{Token: token}, Facts{Random: token}, Result{Code: Admitted, Token: &token}} {
				output := fmt.Sprintf(format, value)
				noTokenOutput(t, []byte(output), raw)
				if format != "%p" && !strings.Contains(output, tokenMarker) {
					t.Fatal("token carrier formatting omitted redaction")
				}
			}
		})
	}
}

// JSON redacts Token itself and each ephemeral carrier independently; exact
// field assertions exclude numeric arrays as well as raw/hex/base64 spellings.
func TestTokenOutputJSON(t *testing.T) {
	for _, name := range []string{"Token", "Facts.Token", "Facts.Random", "Result.Token"} {
		t.Run(name, func(t *testing.T) {
			token, raw := outputToken(t) // Valid non-zero token still explicitly reveals.
			marshaler, ok := any(token).(json.Marshaler)
			if !ok {
				t.Fatal("token lacks json.Marshaler")
			}
			direct, err := marshaler.MarshalJSON()
			if err != nil || string(direct) != `"[session token]"` {
				t.Fatal("token JSON marshaler did not return the fixed marker")
			}
			noTokenOutput(t, direct, raw)
			var value any
			field := ""
			switch name {
			case "Token":
				value = token
			case "Facts.Token":
				value, field = Facts{Token: token}, "Token"
			case "Facts.Random":
				value, field = Facts{Random: token}, "Random"
			case "Result.Token":
				value, field = Result{Code: Admitted, Token: &token}, "Token"
			}
			output, err := json.Marshal(value)
			if err != nil {
				t.Fatal("token JSON encoding failed")
			}
			noTokenOutput(t, output, raw)
			if field != "" {
				var fields map[string]json.RawMessage
				if json.Unmarshal(output, &fields) != nil {
					t.Fatal("token carrier JSON invalid")
				}
				output = fields[field]
			}
			if string(output) != `"[session token]"` {
				t.Fatal("token JSON did not return the fixed marker")
			}
		})
	}
}

// The encoding.TextMarshaler interface redacts values and pointers, including
// JSON map keys. This is an output boundary, not a token wire encoding.
func TestTokenOutputText(t *testing.T) {
	token, raw := outputToken(t) // Non-zero positive control for both text receivers.
	for _, value := range []any{token, &token} {
		marshaler, ok := value.(encoding.TextMarshaler)
		if !ok {
			t.Fatal("token lacks encoding.TextMarshaler")
		}
		output, err := marshaler.MarshalText()
		if err != nil || string(output) != tokenMarker {
			t.Fatal("token text did not return the fixed marker")
		}
		noTokenOutput(t, output, raw)
	}
	output, err := json.Marshal(map[Token]string{token: "public"})
	if err != nil || string(output) != `{"[session token]":"public"}` {
		t.Fatal("token JSON map key is not redacted")
	}
	noTokenOutput(t, output, raw)
}

// Random is the actual opening credential, not a seed for another value. Only
// the explicit accessor returns raw output, and replay has no token to reveal.
func TestTokenExplicitReturn(t *testing.T) {
	v := readVectors(t)
	f := vectorFacts(t, v.Base, vectorStep{Entropy: strings.Repeat("11", 32)}, nil)
	next, reply := Apply(Draft, NewState(v.Executor), f)
	if reply.Code != Admitted || reply.Token == nil || f.Random == (Token{}) {
		t.Fatal("non-zero opening token control failed")
	}
	if *reply.Token != f.Random || Token(reply.Token.RevealForOpen()) != f.Random {
		t.Fatal("explicit token return differs from random carrier")
	}
	if next.sessions[f.RequestID].Digest != tokenDigest(f.Random) {
		t.Fatal("token digest changed at output boundary")
	}
	_, replay := Apply(Draft, next, f)
	if replay.Code != Replay || replay.Token != nil {
		t.Fatal("token returned on replay")
	}
}
