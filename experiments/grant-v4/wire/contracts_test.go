package wire

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// All seven registered domains have pinned distinct digests. Wrong tag,
// untagged and legacy-prefix signatures refuse beside the valid assent.
// Arithmetic for a reserved domain does not make it an admitted schema.
func TestV4TypedDomains(t *testing.T) {
	s := loadVectors(t)
	seen := map[[32]byte]bool{}
	for i := 1; i <= 7; i++ {
		v := s.byID[fmt.Sprintf("prim-type-%02d", i)]
		t.Run(v.str("type"), func(t *testing.T) {
			s.runPrimitive(t, v)
			d, err := TypedDigest(v.octets(t, "octets_hex"))
			wantCode(t, err, "")
			if seen[d] {
				t.Fatal("domains collide")
			}
			seen[d] = true
		})
	}
	for _, id := range []string{"prim-cross-01", "prim-descriptive-01", "assent-v-01", "assent-i-12", "assent-i-13", "assent-i-14"} {
		t.Run(id, func(t *testing.T) { s.run(t, s.byID[id]) })
	}
	for _, bad := range []string{`{"type":"swarma-grant/3"}`, `{"type":"unknown/1"}`, `{"type":1}`, `{}`} {
		d, err := TypedDigest([]byte(bad))
		wantCode(t, err, string(WireType))
		if d != [32]byte{} {
			t.Fatal("rejected domain returned a digest")
		}
	}
}

// Different valid nonces preserve the payload id and change only the content
// address. The wrapper cannot assert an id, and references cannot exchange the
// id with a digest or address. This proves no durable replay prevention.
func TestV4StableObjectID(t *testing.T) {
	s := loadVectors(t)
	a, err := ReadSigned(s.byID["assent-v-01"].octets(t, "signed_form_hex"), ContractAssent)
	wantCode(t, err, "")
	b, err := ReadSigned(s.byID["assent-v-04"].octets(t, "signed_form_hex"), ContractAssent)
	wantCode(t, err, "")
	if a.ID() != b.ID() || a.ContentAddress() == b.ContentAddress() || a.Signature() == b.Signature() {
		t.Fatal("signature changed stable identity or failed to change address")
	}
	id, err := PayloadID(a.Payload())
	wantCode(t, err, "")
	if a.ID() != id || a.ID() == hashHex(a.Bytes()) {
		t.Fatal("identifier hashes wrapper")
	}
	for _, name := range []string{"id-01", "id-02", "id-03", "id-04", "assent-i-23"} {
		t.Run(name, func(t *testing.T) { s.run(t, s.byID[name]) })
	}
	out := a.Payload()
	out[0] = '['
	if bytes.Equal(out, a.Payload()) {
		t.Fatal("mutable payload escaped")
	}
	for _, name := range []string{"issuance-v-01", "issuance-v-03", "issuance-i-03", "issuance-i-08"} {
		t.Run(name, func(t *testing.T) { s.run(t, s.byID[name]) })
	}
}

// A valid high-s signature is accepted. Wrong length, r>=p and s>=n are
// refused before library parsing and return no Signature; odd-Y and infinity
// witnesses fail verification beside the valid assent.
func TestV4StrictBIP340(t *testing.T) {
	s := loadVectors(t)
	g := s.byID["prim-grant-01"]
	raw := g.octets(t, "signature")
	if raw[32] < 0x80 {
		t.Fatal("control is not high-s")
	}
	d, err := TypedDigest(g.octets(t, "octets_hex"))
	wantCode(t, err, "")
	wantCode(t, VerifyBIP340(g.str("public_key"), d, raw), "")
	for _, size := range []int{0, 32, 63, 65, 128} {
		t.Run(fmt.Sprintf("length-%d", size), func(t *testing.T) {
			sig, err := ParseSignature(make([]byte, size))
			wantCode(t, err, string(WireSignatureForm))
			requireNoObject(t, sig, err)
		})
	}
	for _, test := range []struct {
		name   string
		offset int
		bound  [32]byte
	}{{"r=p", 0, fieldPrime}, {"s=n", 32, groupOrder}, {"r>p", 0, [32]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}} {
		t.Run(test.name, func(t *testing.T) {
			bad := bytes.Clone(raw)
			copy(bad[test.offset:test.offset+32], test.bound[:])
			sig, err := ParseSignature(bad)
			wantCode(t, err, string(WireSignature))
			requireNoObject(t, sig, err)
			wantCode(t, VerifyBIP340(g.str("public_key"), d, bad), string(WireSignature))
		})
	}
	for _, id := range []string{"assent-v-01", "assent-v-04", "assent-i-06", "assent-i-16", "assent-i-17", "assent-i-18", "assent-i-19", "assent-i-20", "assent-i-21", "assent-i-22"} {
		t.Run(id, func(t *testing.T) { s.run(t, s.byID[id]) })
	}
	raw[0] ^= 1
	err = VerifyBIP340(g.str("public_key"), d, raw)
	wantCode(t, err, string(WireSignature))
}

// The encoder preserves the restricted canonical forms; floats, null,
// malformed strings, excessive nesting and over-size outputs are refused.
// These supplement the pinned decoder vectors with encoder-side boundaries.
func TestV4CanonicalEncoder(t *testing.T) {
	input := map[string]any{"😀": "<>&/\u2028", "דּ": uint64(9007199254740991), "s": "quote\" and slash\\"}
	b, err := EncodeDocument(input, 1024)
	wantCode(t, err, "")
	d, err := ParseDocument(b, 1024)
	wantCode(t, err, "")
	equalBytes(t, d.Bytes(), b)
	if bytes.Contains(b, []byte(`\u`)) || bytes.Index(b, []byte("😀")) > bytes.Index(b, []byte("דּ")) {
		t.Fatal("wrong Unicode encoding/order")
	}
	for _, tc := range []struct {
		name  string
		input any
		code  Code
	}{
		{"null", map[string]any{"a": nil}, WireValue},
		{"float", map[string]any{"a": float64(1)}, WireValue},
		{"overflow", map[string]any{"a": MaxNumber + 1}, WireNumber},
		{"negative", map[string]any{"a": -1}, WireNumber},
		{"exponent", map[string]any{"a": json.Number("1e0")}, WireNumber},
		{"control-value", map[string]any{"a": "\n"}, WireString},
		{"control-name", map[string]any{"\x1f": "a"}, WireString},
		{"invalid-utf8", map[string]any{"a": string([]byte{0xff})}, WireString},
		{"array-root", []any{}, WireJSON},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := EncodeDocument(tc.input, 1024)
			wantCode(t, err, string(tc.code))
			if b != nil {
				t.Fatal("rejected encoder returned octets")
			}
		})
	}
	var nested any = map[string]any{}
	for range MaxDepth - 1 {
		nested = map[string]any{"a": nested}
	}
	_, err = EncodeDocument(nested, 1024)
	wantCode(t, err, "")
	nested = map[string]any{"a": nested}
	_, err = EncodeDocument(nested, 1024)
	wantCode(t, err, string(WireSize))
	_, err = EncodeDocument(map[string]any{}, 2)
	wantCode(t, err, "")
	_, err = EncodeDocument(map[string]any{}, 1)
	wantCode(t, err, string(WireSize))
	for _, bound := range []uint64{0, 1, 9, 10, 100, ^uint64(0)} {
		s := fmt.Sprint(bound)
		n, err := ParseInteger(s, bound)
		wantCode(t, err, "")
		if n != bound {
			t.Fatal("bound changed")
		}
		if bound > 0 {
			_, err = ParseInteger(s, bound-1)
			wantCode(t, err, string(WireInteger))
		}
	}
}

// Each place selects its own pipeline, never based on input type. The
// unsupported composed issuance place admits no grant stand-in or object.
func TestV4EntryPointDispatch(t *testing.T) {
	s := loadVectors(t)
	assent := s.byID["assent-v-01"].octets(t, "signed_form_hex")
	event := s.byID["consent-v-01"].octets(t, "event_hex")
	prep := s.byID["issuance-s-01"].octets(t, "preparation_hex")
	a, err := ReadSigned(assent, ContractAssent)
	wantCode(t, err, "")
	p := a.payload.root
	bound := ReadContext{Expected: ContractAssent, Assent: AssentContext{
		p.get("genesis").text, p.get("contract").text, p.get("party").text,
	}}
	for _, tc := range []struct {
		class Class
		b     []byte
		ctx   ReadContext
		want  string
	}{
		{SignedClass, assent, bound, ""},
		{SignedClass, assent, ReadContext{Expected: ContractAssent}, string(AssentBinding)},
		{UnsignedClass, prep, ReadContext{Expected: Issuance}, ""},
		{ConsentClass, event, ReadContext{Consent: s.consentContext(t, s.byID["consent-v-01"])}, ""},
		{SignedClass, event, ReadContext{Expected: ContractAssent}, string(WireNotCanonical)},
		{UnsignedClass, assent, ReadContext{Expected: Issuance}, string(WireType)},
		{ConsentClass, assent, ReadContext{}, string(ConsentShape)},
		{SignedClass, assent, ReadContext{Expected: Grant}, string(WireType)},
		{UnsignedClass, prep, ReadContext{Expected: Grant}, string(WireType)},
		{IssuanceClass, prep, ReadContext{}, string(WireType)},
		{Class(0), assent, ReadContext{}, string(WireType)},
	} {
		t.Run(fmt.Sprintf("class-%d/%s", tc.class, tc.want), func(t *testing.T) {
			o, err := Read(tc.class, tc.b, tc.ctx)
			wantCode(t, err, tc.want)
			if err != nil && o != nil {
				t.Fatal("dispatcher admitted refused object")
			}
		})
	}
}

// Frame checks retain the valid anchor and reject wrong transaction value,
// multiple OP_RETURN outputs, all framing octets, truncation and extension.
// Arithmetic on supplied parts proves no real grant or transaction validity.
func TestV4IssuanceFrameBoundary(t *testing.T) {
	s := loadVectors(t)
	v := s.byID["issuance-v-01"]
	parts, pointer := s.parts(t, v)
	script := v.octets(t, "script_hex")
	for _, f := range []Frame{{script, 0, 1}, {script, 1, 1}, {script, 0, 0}, {script, 0, 2}, {script[:71], 0, 1}, {append(bytes.Clone(script), 0), 0, 1}} {
		p, err := CheckIssuanceAnchor(parts, pointer, f)
		if f.Value == 0 && f.OpReturnCount == 1 && len(f.Script) == 72 {
			wantCode(t, err, "")
		} else {
			wantCode(t, err, string(IssuanceFrame))
			requireNoObject(t, p, err)
		}
	}
	for _, i := range []int{0, 1, 2, 3, 4, 5, 6, 39, 40, 71} {
		b := bytes.Clone(script)
		b[i] ^= 1
		p, err := CheckIssuanceAnchor(parts, pointer, Frame{b, 0, 1})
		wantCode(t, err, string(IssuanceFrame))
		requireNoObject(t, p, err)
	}
	b := bytes.Clone(script)
	b[7] ^= 1
	p, err := CheckIssuanceAnchor(parts, pointer, Frame{b, 0, 1})
	wantCode(t, err, string(IssuanceCommitment))
	requireNoObject(t, p, err)
	for _, bad := range []string{strings.Repeat("A", 64), "", strings.Repeat("0", 63)} {
		out, err := EncodeIssuanceFrame([32]byte{}, bad)
		wantCode(t, err, string(IssuanceFrame))
		if out != nil {
			t.Fatal("invalid pointer returned script")
		}
	}
}

// Signing-key syntax is distinct from curve membership, and returned
// signature bytes cannot mutate a parsed signature's retained representation.
func TestV4SigningKeyForms(t *testing.T) {
	s := loadVectors(t)
	g := s.byID["prim-grant-01"]
	key := g.str("public_key")
	wantCode(t, CheckSigningKey(key), "")
	for _, bad := range []string{strings.ToUpper(key), "02" + key, key[:62], ""} {
		wantCode(t, CheckSigningKey(bad), string(WireMember))
	}
	wantCode(t, CheckSigningKey(hex.EncodeToString(fieldPrime[:])), string(WireKey))
	raw := g.octets(t, "signature")
	sig, err := ParseSignature(raw)
	wantCode(t, err, "")
	out := sig.Bytes()
	out[0] ^= 1
	equalBytes(t, sig.Bytes(), raw)
}

// Escapes must retain name identity before W1.5 is reported: distinct control
// or surrogate code units cannot collapse into a false duplicate. Identical
// resolved names still fail W1.3 first, and malformed escapes fail W1.2 first.
func TestV4EscapedNamePrecedence(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  Code
	}{
		{`{"a ":1,"b ":2}`, ""},
		{`{"a\n":1,"a ":2}`, WireString},
		{`{"a\n":1,"a\u000a":2}`, WireDuplicate},
		{`{"\ud800":1,"\ud801":2}`, WireString},
		{`{"\ud800a":1,"\ud800\u0061":2}`, WireDuplicate},
		{`{"\ud800\ud801":1,"\ud800":2}`, WireString},
		{`{"\ud800\uZZZZ":1}`, WireJSON},
		{`{"\ud800":1,"\ud800":2}`, WireDuplicate},
	} {
		t.Run(tc.input, func(t *testing.T) {
			d, err := ParseDocument([]byte(tc.input), 1024)
			wantCode(t, err, string(tc.want))
			requireNoObject(t, d, err)
		})
	}
}
