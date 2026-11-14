package wire

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
)

type objectState struct {
	encoding, payload, id, address, signature, key string
	digest                                         [32]byte
	created                                        uint64
}

func signedState(o *SignedObject) objectState {
	return objectState{encoding: string(o.Bytes()), payload: string(o.Payload()), id: o.ID(), address: o.ContentAddress(), signature: o.Signature(), digest: o.Digest()}
}
func consentState(c *Consent) objectState {
	return objectState{encoding: string(c.Bytes()), id: c.ID(), signature: c.Signature(), key: c.PublicKey(), created: c.CreatedAt()}
}
func preparationState(p *Preparation) objectState {
	return objectState{encoding: string(p.Bytes()), id: hashHex(p.Bytes()), digest: p.Commitment()}
}
func documentState(d *Document) objectState {
	return objectState{encoding: string(d.Bytes()), id: hashHex(d.Bytes())}
}

func mustBytes(t *testing.T, b []byte, err error) []byte {
	t.Helper()
	wantCode(t, err, "")
	return b
}

func detachedBytes(t *testing.T, read func() []byte, state func() objectState) {
	t.Helper()
	original := bytes.Clone(read())
	before := state()
	if len(original) == 0 {
		t.Fatal("empty mutation control")
	}
	for i := range original {
		out := read()
		equalBytes(t, out, original) // Valid control before each single-byte mutation.
		out[i] ^= 1
		if hashHex(out) == hashHex(original) {
			t.Fatalf("byte %d mutation did not change content hash", i)
		}
		if !bytes.Equal(read(), original) || state() != before {
			t.Fatalf("returned bytes alias retained state at byte %d", i)
		}
	}
	out := read()
	out = append(out[:0], bytes.Repeat([]byte{0xff}, len(out)+1)...)
	if bytes.Equal(out, original) || !bytes.Equal(read(), original) || state() != before {
		t.Fatal("reslice/append changed retained state")
	}
}

// Every returned byte is caller-owned; mutating it changes its hash but never later output, canonical bytes or retained identities.
func TestV4ReturnedBytesIsolation(t *testing.T) {
	s := loadVectors(t)
	a, err := ReadSigned(s.byID["assent-v-01"].octets(t, "signed_form_hex"), ContractAssent)
	wantCode(t, err, "")
	v := s.byID["consent-v-01"]
	c, err := ReadConsent(v.octets(t, "event_hex"), s.consentContext(t, v))
	wantCode(t, err, "")
	parts, pointer := s.parts(t, s.byID["issuance-v-01"])
	p, err := BuildPreparation(parts)
	wantCode(t, err, "")
	d, err := ParseDocument(a.Payload(), MaxAssentSize)
	wantCode(t, err, "")
	sig, err := decodeSignature(a.Signature())
	wantCode(t, err, "")
	payload := a.Payload()
	input := map[string]any{"a": []any{map[string]any{"b": "c"}, uint64(1)}}
	var tags [][2]string
	for _, tag := range c.root.get("tags").elements {
		tags = append(tags, [2]string{tag.elements[0].text, tag.elements[1].text})
	}
	ap := a.payload.root
	for _, tc := range []struct {
		name  string
		read  func() []byte
		state func() objectState
	}{
		{"Document.Bytes", d.Bytes, func() objectState { return documentState(d) }},
		{"SignedObject.Bytes", a.Bytes, func() objectState { return signedState(a) }},
		{"SignedObject.Payload", a.Payload, func() objectState { return signedState(a) }},
		{"Consent.Bytes", c.Bytes, func() objectState { return consentState(c) }},
		{"Preparation.Bytes", p.Bytes, func() objectState { return preparationState(p) }},
		{"Signature.Bytes", sig.Bytes, func() objectState { return objectState{encoding: string(sig.Bytes()), id: hashHex(sig.Bytes())} }},
		{"EncodeDocument", func() []byte { b, e := EncodeDocument(input, 1024); return mustBytes(t, b, e) }, func() objectState {
			b, e := json.Marshal(input)
			return objectState{encoding: string(mustBytes(t, b, e))}
		}},
		{"EncodeAssentPayload", func() []byte {
			b, e := EncodeAssentPayload(ap.get("genesis").text, ap.get("contract").text, ap.get("party").text)
			return mustBytes(t, b, e)
		}, func() objectState { return signedState(a) }},
		{"EncodeSignedAssent", func() []byte { b, e := EncodeSignedAssent(payload, a.Signature()); return mustBytes(t, b, e) }, func() objectState { st := signedState(a); st.payload = string(payload); return st }},
		{"EncodeConsentEvent", func() []byte {
			b, e := EncodeConsentEvent(c.PublicKey(), c.CreatedAt(), tags, c.Signature())
			return mustBytes(t, b, e)
		}, func() objectState {
			st := consentState(c)
			b, e := json.Marshal(tags)
			st.payload = string(mustBytes(t, b, e))
			return st
		}},
		{"EncodeIssuanceFrame", func() []byte { b, e := EncodeIssuanceFrame(p.Commitment(), pointer); return mustBytes(t, b, e) }, func() objectState { return preparationState(p) }},
		{"eventBytes", func() []byte { return eventBytes(c.root) }, func() objectState { return consentState(c) }},
		{"eventPreimage", func() []byte { return eventPreimage(c.root) }, func() objectState { return consentState(c) }},
		{"serialize", func() []byte { return serialize(d.root) }, func() objectState { return documentState(d) }},
	} {
		t.Run(tc.name, func(t *testing.T) { detachedBytes(t, tc.read, tc.state) })
	}
}

// Parsed pointers have no exported mutable fields; replacing a caller's object leaves a second read of the original bytes and id intact.
func TestV4ParsedObjectIsolation(t *testing.T) {
	s := loadVectors(t)
	aBytes := s.byID["assent-v-01"].octets(t, "signed_form_hex")
	a, err := ReadSigned(aBytes, ContractAssent)
	wantCode(t, err, "")
	ap := a.payload.root
	ac := AssentContext{ap.get("genesis").text, ap.get("contract").text, ap.get("party").text}
	cv := s.byID["consent-v-01"]
	cc := s.consentContext(t, cv)
	parts, pointer := s.parts(t, s.byID["issuance-v-01"])
	prep, err := BuildPreparation(parts)
	wantCode(t, err, "")
	frame := s.byID["issuance-v-01"].octets(t, "script_hex")
	altDocument, err := ParseDocument([]byte(`{"changed":[{"nested":"value"}]}`), MaxAssentSize)
	wantCode(t, err, "")
	altSigned, err := ReadSigned(s.byID["assent-v-02"].octets(t, "signed_form_hex"), ContractAssent)
	wantCode(t, err, "")
	altConsent, err := parseConsent(s.byID["consent-v-02"].octets(t, "event_hex"))
	wantCode(t, err, "")
	altParts, _ := s.parts(t, s.byID["issuance-v-02"])
	altPreparation, err := BuildPreparation(altParts)
	wantCode(t, err, "")
	altRaw := s.byID["prim-grant-01"].octets(t, "signature")
	altRaw[0] ^= 1
	altSignature, err := ParseSignature(altRaw)
	wantCode(t, err, "")
	alternatives := map[reflect.Type]any{}
	for _, x := range []any{altDocument, altSigned, altConsent, altPreparation, altSignature} {
		alternatives[reflect.TypeOf(x)] = x
	}
	for _, tc := range []struct {
		name  string
		read  func() (any, error)
		state func(any) objectState
	}{
		{"ParseDocument", func() (any, error) { return ParseDocument(a.Payload(), MaxAssentSize) }, func(x any) objectState { return documentState(x.(*Document)) }},
		{"ReadSigned", func() (any, error) { return ReadSigned(aBytes, ContractAssent) }, func(x any) objectState { return signedState(x.(*SignedObject)) }},
		{"ReadAssent", func() (any, error) { return ReadAssent(aBytes, ac, a.ID()) }, func(x any) objectState { return signedState(x.(*SignedObject)) }},
		{"ReadConsent", func() (any, error) { return ReadConsent(cv.octets(t, "event_hex"), cc) }, func(x any) objectState { return consentState(x.(*Consent)) }},
		{"parseConsent", func() (any, error) { return parseConsent(cv.octets(t, "event_hex")) }, func(x any) objectState { return consentState(x.(*Consent)) }},
		{"ReadUnsigned", func() (any, error) { return ReadUnsigned(prep.Bytes(), Issuance) }, func(x any) objectState { return preparationState(x.(*Preparation)) }},
		{"BuildPreparation", func() (any, error) { return BuildPreparation(parts) }, func(x any) objectState { return preparationState(x.(*Preparation)) }},
		{"CheckIssuanceAnchor", func() (any, error) { return CheckIssuanceAnchor(parts, pointer, Frame{frame, 0, 1}) }, func(x any) objectState { return preparationState(x.(*Preparation)) }},
		{"Read/signed", func() (any, error) {
			return Read(SignedClass, aBytes, ReadContext{Expected: ContractAssent, Assent: ac})
		}, func(x any) objectState { return signedState(x.(*SignedObject)) }},
		{"Read/unsigned", func() (any, error) { return Read(UnsignedClass, prep.Bytes(), ReadContext{Expected: Issuance}) }, func(x any) objectState { return preparationState(x.(*Preparation)) }},
		{"Read/consent", func() (any, error) { return Read(ConsentClass, cv.octets(t, "event_hex"), ReadContext{Consent: cc}) }, func(x any) objectState { return consentState(x.(*Consent)) }},
		{"ParseSignature", func() (any, error) { return ParseSignature(s.byID["prim-grant-01"].octets(t, "signature")) }, func(x any) objectState {
			b := x.(*Signature).Bytes()
			return objectState{encoding: string(b), id: hashHex(b)}
		}},
		{"decodeSignature", func() (any, error) { return decodeSignature(s.byID["prim-grant-01"].str("signature")) }, func(x any) objectState {
			b := x.(*Signature).Bytes()
			return objectState{encoding: string(b), id: hashHex(b)}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := tc.read()
			wantCode(t, err, "")
			retained, err := tc.read()
			wantCode(t, err, "")
			before := tc.state(retained)
			if tc.state(out) != before {
				t.Fatal("valid control changed")
			}
			// External callers can replace an opaque object, but cannot reach its private tree.
			typ := reflect.TypeOf(out).Elem()
			for i := range typ.NumField() {
				if typ.Field(i).IsExported() {
					t.Fatal("new exported field needs a field mutation test", typ.Field(i).Name)
				}
			}
			reflect.ValueOf(out).Elem().Set(reflect.ValueOf(alternatives[reflect.TypeOf(out)]).Elem())
			if tc.state(out).id == before.id || tc.state(out).encoding == before.encoding {
				t.Fatal("replacement control did not change the copy's canonical encoding and id")
			}
			again, err := tc.read()
			wantCode(t, err, "")
			if tc.state(again) != before || tc.state(retained) != before {
				t.Fatal("object replacement changed another read or retained identity")
			}
		})
	}
}

// Hash arrays are values: changing each returned byte changes only that value; canonical input, stable id and later digests stay fixed.
func TestV4ReturnedHashIsolation(t *testing.T) {
	s := loadVectors(t)
	a, err := ReadSigned(s.byID["assent-v-01"].octets(t, "signed_form_hex"), ContractAssent)
	wantCode(t, err, "")
	p, err := ReadUnsigned(s.byID["issuance-s-01"].octets(t, "preparation_hex"), Issuance)
	wantCode(t, err, "")
	payload := a.Payload()
	before := signedState(a)
	pb := preparationState(p)
	for _, tc := range []struct {
		name string
		read func() [32]byte
	}{
		{"SignedObject.Digest", a.Digest},
		{"Preparation.Commitment", p.Commitment},
		{"TaggedHash", func() [32]byte { return TaggedHash(string(ContractAssent), payload) }},
		{"TypedDigest", func() [32]byte { d, e := TypedDigest(payload); wantCode(t, e, ""); return d }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := tc.read()
			for i := range original {
				out := tc.read()
				out[i] ^= 1
				if out == original || tc.read() != original || signedState(a) != before || preparationState(p) != pb || !bytes.Equal(payload, a.Payload()) {
					t.Fatal("hash mutation changed retained encoding or identity")
				}
			}
		})
	}
}

// Issuer checks preserve actual decoded inputs on success and rejection, including Name.Height after all deferred work has run.
func TestV4ConsentSnapshotPostReturn(t *testing.T) {
	s := loadVectors(t)
	for i := 1; i <= 12; i++ {
		v := s.byID[fmt.Sprintf("issuer-c-%02d", i)]
		t.Run(v.str("id"), func(t *testing.T) {
			ctx, snapshot, consumed := s.issuerContext(t, v)
			b := v.octets(t, "event_hex")
			// Marshal the live call arguments, not the unrelated raw fixture map.
			capture := func() []byte {
				x, e := json.Marshal([]any{ctx, snapshot, consumed, b})
				return mustBytes(t, x, e)
			}
			before := bytes.Clone(capture())
			for range 2 {
				wantCode(t, CheckIssuerConditions(b, ctx, snapshot, consumed), v.str("expect"))
				if !bytes.Equal(capture(), before) {
					t.Fatal("issuer check mutated live snapshot or context after return")
				}
			}
			if snapshot != nil {
				original := *snapshot
				copy := *snapshot
				copy.Name.Height++
				if copy == original || *snapshot != original {
					t.Fatal("Name.Height value-copy mutation control failed")
				}
				wantCode(t, CheckIssuerConditions(b, ctx, snapshot, consumed), v.str("expect"))
				equalBytes(t, capture(), before)
			}
		})
	}
}

// Mutating each field of a copied snapshot, including Name.Height, leaves the original event bytes/id and next issuer result intact.
func TestV4SnapshotValueCopyIsolation(t *testing.T) {
	s := loadVectors(t)
	v := s.byID["issuer-c-07"]
	ctx, snapshot, consumed := s.issuerContext(t, v)
	b := v.octets(t, "event_hex")
	c, err := parseConsent(b)
	wantCode(t, err, "")
	before, original := consentState(c), *snapshot
	for _, tc := range []struct {
		name   string
		mutate func(*Snapshot)
		want   Code
	}{
		{"RecentBlockHeight", func(s *Snapshot) { s.RecentBlockHeight = s.Name.Height - 1 }, ConsentEvidence},
		{"Name.Confirmed", func(s *Snapshot) { s.Name.Confirmed = false }, ConsentEvidence},
		{"Name.Height", func(s *Snapshot) { s.Name.Height = s.RecentBlockHeight + 1 }, ConsentEvidence},
		{"Name.Live", func(s *Snapshot) { s.Name.Live = false }, ConsentEvidence},
		{"Name.OwnerMatches", func(s *Snapshot) { s.Name.OwnerMatches = false }, ConsentEvidence},
		{"Name.YieldsPublicKey", func(s *Snapshot) { s.Name.YieldsPublicKey = "" }, ConsentKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wantCode(t, CheckIssuerConditions(b, ctx, snapshot, consumed), "")
			copy := *snapshot
			tc.mutate(&copy)
			x, e := json.Marshal(copy)
			changed := mustBytes(t, x, e)
			x, e = json.Marshal(original)
			if hashHex(changed) == hashHex(mustBytes(t, x, e)) {
				t.Fatal("snapshot mutation did not change its content fingerprint")
			}
			wantCode(t, CheckIssuerConditions(b, ctx, &copy, consumed), string(tc.want))
			wantCode(t, CheckIssuerConditions(b, ctx, snapshot, consumed), "")
			next, e := parseConsent(b)
			wantCode(t, e, "")
			if *snapshot != original || consentState(c) != before || consentState(next) != before {
				t.Fatal("copied snapshot mutation changed original snapshot, event encoding or id")
			}
		})
	}
}

// Retained objects detach from every input byte, nested encoder map/slice, context evidence pointer and preparation outpoint.
func TestV4InputOwnership(t *testing.T) {
	s := loadVectors(t)
	for _, tc := range []struct {
		name  string
		input []byte
		read  func([]byte) (any, error)
		state func(any) objectState
	}{
		{"ParseDocument", []byte(`{"nested":[{"a":"b"},1,true]}`), func(b []byte) (any, error) { return ParseDocument(b, 1024) }, func(x any) objectState { return documentState(x.(*Document)) }},
		{"ReadSigned", s.byID["assent-v-01"].octets(t, "signed_form_hex"), func(b []byte) (any, error) { return ReadSigned(b, ContractAssent) }, func(x any) objectState { return signedState(x.(*SignedObject)) }},
		{"ReadConsent", s.byID["consent-v-01"].octets(t, "event_hex"), func(b []byte) (any, error) { return ReadConsent(b, s.consentContext(t, s.byID["consent-v-01"])) }, func(x any) objectState { return consentState(x.(*Consent)) }},
		{"ReadUnsigned", s.byID["issuance-s-01"].octets(t, "preparation_hex"), func(b []byte) (any, error) { return ReadUnsigned(b, Issuance) }, func(x any) objectState { return preparationState(x.(*Preparation)) }},
		{"ParseSignature", s.byID["prim-grant-01"].octets(t, "signature"), func(b []byte) (any, error) { return ParseSignature(b) }, func(x any) objectState {
			b := x.(*Signature).Bytes()
			return objectState{encoding: string(b), id: hashHex(b)}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := bytes.Clone(tc.input)
			o, err := tc.read(input)
			wantCode(t, err, "")
			before := tc.state(o)
			for i := range input {
				input[i] ^= 1
				if tc.state(o) != before {
					t.Fatalf("input byte %d changed retained object", i)
				}
				input[i] ^= 1
			}
			again, err := tc.read(input)
			wantCode(t, err, "")
			if tc.state(again) != before {
				t.Fatal("second read changed original encoding or identity")
			}
		})
	}
	t.Run("nested-map-and-slice", func(t *testing.T) {
		child := map[string]any{"s": "text", "n": uint64(1), "b": true}
		array := []any{child, "tail"}
		input := map[string]any{"array": array}
		b, e := EncodeDocument(input, 1024)
		original := bytes.Clone(mustBytes(t, b, e))
		d, err := ParseDocument(b, 1024)
		wantCode(t, err, "")
		before := documentState(d)
		for _, mutate := range []func(){
			func() { child["s"] = "changed" }, func() { child["n"] = uint64(2) },
			func() { child["b"] = false }, func() { array[1] = "changed" },
			func() { array[0] = "replacement" }, func() { input["array"] = []any{} },
		} {
			mutate()
			changed, e := EncodeDocument(input, 1024)
			wantCode(t, e, "")
			id, e := PayloadID(changed)
			wantCode(t, e, "")
			if id == before.id || documentState(d) != before {
				t.Fatal("nested mutation failed to change copied id or changed retained state")
			}
			equalBytes(t, b, original)
			child["s"], child["n"], child["b"] = "text", uint64(1), true
			array[0], array[1], input["array"] = child, "tail", array
			control, e := EncodeDocument(input, 1024)
			equalBytes(t, mustBytes(t, control, e), original)
		}
	})
	t.Run("evidence-and-outpoint", func(t *testing.T) {
		v := s.byID["consent-v-02"]
		ctx := s.consentContext(t, v)
		spent := ctx.RecentBlockHeight + 1
		ctx.Evidence.SpentAtHeight = &spent
		c, err := ReadConsent(v.octets(t, "event_hex"), ctx)
		wantCode(t, err, "")
		before := consentState(c)
		*ctx.Evidence = Evidence{}
		spent = 0
		if consentState(c) != before {
			t.Fatal("context evidence mutated retained consent")
		}
		parts, _ := s.parts(t, s.byID["issuance-v-02"])
		p, err := BuildPreparation(parts)
		wantCode(t, err, "")
		pb := preparationState(p)
		original := *parts.NameOutput
		for _, mutate := range []func(){func() { parts.NameOutput.TxID = "" }, func() { parts.NameOutput.Vout++ }} {
			mutate()
			if preparationState(p) != pb {
				t.Fatal("outpoint mutation changed preparation encoding or commitment")
			}
			*parts.NameOutput = original
			control, e := BuildPreparation(parts)
			wantCode(t, e, "")
			if preparationState(control) != pb {
				t.Fatal("original outpoint no longer builds the original preparation")
			}
		}
	})
}

// Immutable scalar accessors return values; reassigning each local copy leaves canonical bytes, ids, key forms and later accessors unchanged.
func TestV4ScalarReturnIsolation(t *testing.T) {
	s := loadVectors(t)
	a, err := ReadSigned(s.byID["assent-v-01"].octets(t, "signed_form_hex"), ContractAssent)
	wantCode(t, err, "")
	v := s.byID["consent-v-01"]
	c, err := ReadConsent(v.octets(t, "event_hex"), s.consentContext(t, v))
	wantCode(t, err, "")
	before, cb := signedState(a), consentState(c)
	for _, tc := range []struct {
		name string
		read func() string
	}{
		{"SignedObject.ID", a.ID}, {"SignedObject.ContentAddress", a.ContentAddress},
		{"SignedObject.Signature", a.Signature}, {"Consent.ID", c.ID},
		{"Consent.Signature", c.Signature}, {"Consent.PublicKey", c.PublicKey},
		{"PayloadID", func() string { id, e := PayloadID(a.Payload()); wantCode(t, e, ""); return id }},
		{"Code.Error", WireMember.Error},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := tc.read()
			copy := tc.read() + "changed"
			if copy == original || hashHex([]byte(copy)) == hashHex([]byte(original)) || tc.read() != original || signedState(a) != before || consentState(c) != cb {
				t.Fatal("local scalar mutation changed retained encoding or identity")
			}
		})
	}
	created := c.CreatedAt()
	changed := created + 1
	if changed == created || c.CreatedAt() != created || consentState(c) != cb {
		t.Fatal("created-at value mutation changed consent")
	}
	n, err := ParseInteger("42", 42)
	wantCode(t, err, "")
	n++
	again, err := ParseInteger("42", 42)
	wantCode(t, err, "")
	if n == again || again != 42 {
		t.Fatal("integer value mutation changed next parse")
	}
}
