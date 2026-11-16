// Package vectors derives arithmetic and stated-fact fixtures from the wire lab.
// It defines no grant schema and admits no grant bytes.
package vectors

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	wire "github.com/relux-works/swarma-chain-lab/experiments/grant-v4/wire"
)

type object = map[string]any

type Vector struct {
	ID        string `json:"id"`
	Purpose   string `json:"purpose"`
	Spec      string `json:"spec"`
	Operation string `json:"operation"`
	Input     object `json:"input"`
	Output    object `json:"output"`
}

type Set struct {
	Format        string   `json:"format"`
	Scope         string   `json:"scope"`
	SpecRevision  string   `json:"spec_revision"`
	PublicScalars []int    `json:"public_test_scalars"`
	AuxRand       string   `json:"aux_rand"`
	Vectors       []Vector `json:"vectors"`
}

func hx(b []byte) string   { return hex.EncodeToString(b) }
func hash(b []byte) string { h := sha256.Sum256(b); return hx(h[:]) }
func unhex(s string) []byte {
	b, e := hex.DecodeString(s)
	if e != nil {
		panic(e)
	}
	return b
}
func text(x object, k string) string { s, _ := x[k].(string); return s }
func number(x object, k string) uint64 {
	n, e := strconv.ParseUint(fmt.Sprint(x[k]), 10, 64)
	if e != nil {
		panic(e)
	}
	return n
}
func decode(x any, out any) {
	b, e := json.Marshal(x)
	if e != nil {
		panic(e)
	}
	if e = json.Unmarshal(b, out); e != nil {
		panic(e)
	}
}
func clone(x object) object {
	b, e := json.Marshal(x)
	if e != nil {
		panic(e)
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var y object
	if e = d.Decode(&y); e != nil {
		panic(e)
	}
	return y
}
func code(err error) string {
	if err != nil {
		return err.Error()
	}
	return "ok"
}
func canonical(x any, limit int) []byte {
	b, e := wire.EncodeDocument(x, limit)
	if e != nil {
		panic(e)
	}
	return b
}
func key(scalar int) string {
	b := make([]byte, 32)
	b[31] = byte(scalar)
	_, p := btcec.PrivKeyFromBytes(b)
	return hx(schnorr.SerializePubKey(p))
}
func sign(scalar int, d [32]byte) string {
	b := make([]byte, 32)
	b[31] = byte(scalar)
	sk, _ := btcec.PrivKeyFromBytes(b)
	sig, e := schnorr.Sign(sk, d[:], schnorr.CustomNonce([32]byte{}))
	if e != nil {
		panic(e)
	}
	return hx(sig.Serialize())
}
func digest(b []byte) [32]byte {
	d, e := wire.TypedDigest(b)
	if e != nil {
		panic(e)
	}
	return d
}

// Evaluate computes outputs through exported laboratory APIs. Fixture inputs are
// test transport, never a proposed grant/presentation protocol.
func Evaluate(op string, in object) object {
	out := object{}
	var err error
	switch op {
	case "encode":
		var b []byte
		b, err = wire.EncodeDocument(in["document"], int(number(in, "limit")))
		if err == nil {
			out["canonical_hex"] = hx(b)
		}
	case "parse":
		var d *wire.Document
		d, err = wire.ParseDocument(unhex(text(in, "raw_hex")), int(number(in, "limit")))
		if err == nil {
			out["canonical_hex"] = hx(d.Bytes())
		} else if d != nil {
			panic("refused document escaped")
		}
	case "integer":
		var n uint64
		n, err = wire.ParseInteger(text(in, "value"), number(in, "bound"))
		if err == nil {
			out["value"] = strconv.FormatUint(n, 10)
		} else if n != 0 {
			panic("refused integer escaped")
		}
	case "primitive", "signature":
		b := canonical(in["document"], 1<<20)
		var d [32]byte
		d, err = wire.TypedDigest(b)
		if err == nil {
			var id string
			id, err = wire.PayloadID(b)
			if err != nil {
				break
			}
			tag := in["document"].(map[string]any)["type"].(string)
			th := wire.TaggedHash(tag, b)
			out = object{"canonical_hex": hx(b), "tag_hex": hx([]byte(tag)), "tag_sha256": hash([]byte(tag)), "tagged_hash": hx(th[:]), "typed_digest": hx(d[:]), "payload_id": id}
			if op == "signature" {
				s := int(number(in, "public_test_scalar"))
				sig := sign(s, d)
				err = wire.VerifyBIP340(key(s), d, unhex(sig))
				out["public_key"] = key(s)
				out["signature_hex"] = sig
			}
		}
	case "verify", "signature_form":
		raw := unhex(text(in, "signature_hex"))
		if op == "signature_form" {
			var s *wire.Signature
			s, err = wire.ParseSignature(raw)
			if err == nil {
				out["signature_hex"] = hx(s.Bytes())
			} else if s != nil {
				panic("refused signature escaped")
			}
		} else {
			var d [32]byte
			copy(d[:], unhex(text(in, "digest")))
			err = wire.VerifyBIP340(text(in, "public_key"), d, raw)
		}
	case "key":
		err = wire.CheckSigningKey(text(in, "public_key"))
	case "signed":
		var o *wire.SignedObject
		if in["context"] != nil {
			var ctx wire.AssentContext
			decode(in["context"], &ctx)
			var refs []string
			if in["references"] != nil {
				decode(in["references"], &refs)
			}
			o, err = wire.ReadAssent(unhex(text(in, "raw_hex")), ctx, refs...)
		} else {
			o, err = wire.ReadSigned(unhex(text(in, "raw_hex")), wire.Type(text(in, "expected_type")))
		}
		if err == nil {
			d := o.Digest()
			out = object{"signed_hex": hx(o.Bytes()), "payload_hex": hx(o.Payload()), "payload_id": o.ID(), "content_address": o.ContentAddress(), "typed_digest": hx(d[:]), "signature_hex": o.Signature()}
		} else if o != nil {
			panic("refused assent escaped")
		}
	case "unsigned":
		var p *wire.Preparation
		p, err = wire.ReadUnsigned(unhex(text(in, "raw_hex")), wire.Type(text(in, "expected_type")))
		if err == nil {
			d := p.Commitment()
			out = object{"preparation_hex": hx(p.Bytes()), "commitment": hx(d[:])}
		} else if p != nil {
			panic("refused preparation escaped")
		}
	case "consent_encode":
		var tags [][2]string
		decode(in["tags"], &tags)
		s := int(number(in, "public_test_scalar"))
		created := number(in, "created_at")
		pre := canonicalArray([]any{0, key(s), created, 8181, in["tags"], ""})
		id := sha256.Sum256(pre)
		sig := sign(s, id)
		var b []byte
		b, err = wire.EncodeConsentEvent(key(s), created, tags, sig)
		if err == nil {
			out = object{"event_hex": hx(b), "id_preimage_hex": hx(pre), "event_id": hx(id[:]), "signature_hex": sig, "public_key": key(s)}
		}
	case "consent", "issuer":
		var ctx wire.ConsentContext
		decode(in["context"], &ctx)
		b := unhex(text(in, "raw_hex"))
		if op == "issuer" {
			var snap *wire.Snapshot
			decode(in["snapshot"], &snap)
			var consumed []string
			decode(in["consumed_ids"], &consumed)
			err = wire.CheckIssuerConditions(b, ctx, snap, consumed)
		} else {
			var c *wire.Consent
			c, err = wire.ReadConsent(b, ctx)
			if err == nil {
				out = object{"event_hex": hx(c.Bytes()), "event_id": c.ID(), "signature_hex": c.Signature(), "public_key": c.PublicKey(), "created_at": strconv.FormatUint(c.CreatedAt(), 10)}
			} else if c != nil {
				panic("refused consent escaped")
			}
		}
	case "issuance":
		var facts *wire.GrantFacts
		decode(in["stated_grant_facts"], &facts)
		var evidence *wire.Evidence
		decode(in["stated_evidence"], &evidence)
		var point *wire.Outpoint
		decode(in["name_output"], &point)
		args := wire.IssuanceInput{Grant: facts, IssuerAssent: unhex(text(in, "assent_hex")), RecipientConsent: unhex(text(in, "consent_hex")), NameOutput: point, Evidence: evidence, Now: number(in, "now"), Frame: wire.Frame{Script: unhex(text(in, "frame_hex")), Value: number(in, "frame_value"), OpReturnCount: int(number(in, "op_return_count"))}}
		before, _ := json.Marshal(args)
		var p *wire.Preparation
		p, err = wire.CheckIssuance(args)
		after, _ := json.Marshal(args)
		if !bytes.Equal(before, after) {
			panic("issuance mutated inputs")
		}
		if err == nil {
			d := p.Commitment()
			out = object{"preparation_hex": hx(p.Bytes()), "commitment": hx(d[:]), "frame_hex": text(in, "frame_hex")}
		} else if p != nil {
			panic("refused preparation escaped")
		}
	default:
		panic("unknown operation " + op)
	}
	if err != nil {
		out = object{}
	}
	out["code"] = code(err)
	return out
}

// The array serializer is fixture scaffolding for NIP-01's id preimage. EncodeDocument
// supplies the exact restricted encoding of an enclosing document; only its value is taken.
func canonicalArray(a []any) []byte { b := canonical(object{"a": a}, 1<<20); return b[5 : len(b)-1] }

func Generate() (result []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("generator: %v", r)
		}
	}()
	set := Set{Format: "swarma-lab-primitives/1", Scope: "no valid swarma-grant/4 vectors until B0; arithmetic and stated facts only", SpecRevision: "bd3bc80e5543d8a563343ec05abd1a5f3f67284c", PublicScalars: []int{1, 2, 3}, AuxRand: strings.Repeat("00", 32)}
	add := func(id, purpose, spec, op string, in object, want string) object {
		// Round-trip fixture inputs so evaluation sees the same JSON number types as readers.
		in = clone(in)
		out := Evaluate(op, in)
		if out["code"] != want {
			panic(fmt.Sprintf("FINDING %s (%s): lab %s, spec expectation %s", id, spec, out["code"], want))
		}
		set.Vectors = append(set.Vectors, Vector{id, purpose, "LIP-0020 " + spec, op, in, out})
		return out
	}
	genesis := strings.Repeat("11", 32)
	contract := strings.Repeat("22", 32)
	txid := strings.Repeat("33", 32)
	assentPayload := object{"type": string(wire.ContractAssent), "genesis": genesis, "contract": contract, "party": key(1)}
	add("encode-assent", "canonical specified assent payload", "W1.1-W1.6; W7.1", "encode", object{"document": assentPayload, "limit": 1024}, "ok")
	for i, doc := range []object{
		{"a": []any{true, false, object{}, []any{}, uint64(wire.MaxNumber)}, "text": "<>&/\u007f\u2028\"\\"},
		{"\U0001f600": "astral", "\ufb33": "bmp", "e\u0301": "decomposed", "é": "composed"},
	} {
		add(fmt.Sprintf("encode-restricted-%d", i), "restricted document grammar, not grant bytes", "W1.1-W1.6", "encode", object{"document": doc, "limit": 2048}, "ok")
	}
	types := []wire.Type{wire.Grant, wire.Invocation, wire.Receipt, wire.SealEndorsement, wire.ContractAssent, wire.Issuance, wire.NotaryAttestation}
	for i, typ := range types {
		doc := object{"type": string(typ)}
		add(fmt.Sprintf("arithmetic-%d", i), "registry arithmetic only; no object/schema admission", "W3.1; W4.1; W6.1; section 10 primitive stage", "primitive", object{"document": doc}, "ok")
		for _, s := range []int{1, 2, 3} {
			add(fmt.Sprintf("signature-%d-%d", i, s), "BIP340 over arithmetic typed digest, public scalar, zero aux_rand; no object admission", "W4.1; W5.1-W5.2", "signature", object{"document": doc, "public_test_scalar": s}, "ok")
		}
	}

	for _, scalar := range []int{1, 2, 3} {
		doc := clone(assentPayload)
		doc["party"] = key(scalar)
		add(fmt.Sprintf("signature-assent-%d", scalar), "deterministic signature over a specified assent payload", "W7.1; W5.1-W5.2", "signature", object{"document": doc, "public_test_scalar": scalar}, "ok")
	}
	for _, doc := range []object{{}, {"type": 1}, {"type": "swarma-grant/3"}} {
		add(fmt.Sprintf("arithmetic-type-%d", len(set.Vectors)), "unsupported type in arithmetic", "W3.1", "primitive", object{"document": doc}, "WIRE_TYPE")
	}
	// Generic canonical boundary pairs use W1's document grammar, not a made-up type schema.
	parse := func(id, raw, want, spec string, limit int) {
		add(id, "canonical refusal/boundary or precedence control", spec, "parse", object{"raw_hex": hx([]byte(raw)), "limit": limit}, want)
	}
	for _, limit := range []int{1024, 2048} {
		for _, delta := range []int{0, 1} {
			raw := `{"a":"` + strings.Repeat("a", limit-8+delta) + `"}`
			want := "ok"
			if delta == 1 {
				want = "WIRE_SIZE"
			}
			parse(fmt.Sprintf("size-%d-plus-%d", limit, delta), raw, want, "W1.1; W9.2", limit)
		}
	}
	for _, depth := range []int{16, 17} {
		raw := `{"a":` + strings.Repeat("[", depth-1) + strings.Repeat("]", depth-1) + `}`
		want := "ok"
		if depth == 17 {
			want = "WIRE_SIZE"
		}
		parse(fmt.Sprintf("depth-%d", depth), raw, want, "W1.1; W9.2", 2048)
	}

	parse("size-before-json", strings.Repeat("x", 2049), "WIRE_SIZE", "W1.1; W9.2", 2048)
	deep := strings.Repeat("[", 16)
	parse("depth-before-truncated", `{"a":`+deep, "WIRE_SIZE", "W1.1; W9.2", 2048)
	parse("syntax-before-depth", `{"a":x,"b":`+deep, "WIRE_JSON", "W1.2; W9.2", 2048)
	parse("utf8-before-depth", "{\"a\":\"\xff\",\"b\":"+deep, "WIRE_JSON", "W1.1-W1.2; W9.2", 2048)
	parse("depth-before-utf8", `{"a":`+deep+"\"\xff\"", "WIRE_SIZE", "W1.1-W1.2; W9.2", 2048)
	for _, tc := range []struct{ id, raw, want string }{
		{"json-empty", "", "WIRE_JSON"}, {"json-array", "[]", "WIRE_JSON"}, {"json-bom", "\xef\xbb\xbf{}", "WIRE_JSON"}, {"json-utf8", "{\"a\":\"\xff\"}", "WIRE_JSON"}, {"json-trailing", "{}x", "WIRE_JSON"},
		{"duplicate", `{"a":0,"a":1}`, "WIRE_DUPLICATE"}, {"duplicate-escaped", `{"a":0,"\u0061":1}`, "WIRE_DUPLICATE"},
		{"null", `{"a":null}`, "WIRE_VALUE"}, {"null-number-string", `{"a":null,"b":-1,"c":"\n"}`, "WIRE_VALUE"},
		{"number-bound", `{"a":9007199254740991}`, "ok"}, {"number-bound-plus-one", `{"a":9007199254740992}`, "WIRE_NUMBER"},
		{"number-negative", `{"a":-1}`, "WIRE_NUMBER"}, {"number-negative-zero", `{"a":-0}`, "WIRE_NUMBER"}, {"number-fraction", `{"a":1.0}`, "WIRE_NUMBER"}, {"number-exponent", `{"a":1e0}`, "WIRE_NUMBER"}, {"number-leading-zero", `{"a":01}`, "WIRE_JSON"},
		{"string-lower-bound", `{"a":" "}`, "ok"}, {"string-below-bound", `{"a":"\u001f"}`, "WIRE_STRING"}, {"string-surrogate", `{"a":"\ud800"}`, "WIRE_STRING"},
		{"canonical-space", ` {}`, "WIRE_NOT_CANONICAL"}, {"canonical-order", `{"b":1,"a":2}`, "WIRE_NOT_CANONICAL"}, {"canonical-escape", `{"a":"\u0020"}`, "WIRE_NOT_CANONICAL"},
		{"json-before-duplicate", `{"a":0,"a":1}x`, "WIRE_JSON"}, {"duplicate-before-null", `{"a":null,"a":-1}`, "WIRE_DUPLICATE"}, {"number-before-string", `{"a":-1,"b":"\n"}`, "WIRE_NUMBER"}, {"string-before-canonical", ` {"a":"\n"}`, "WIRE_STRING"},
	} {
		parse(tc.id, tc.raw, tc.want, "W1.1-W1.6; W2.2; W9.2", 2048)
	}
	for _, bound := range []uint64{4294967295, wire.MaxNumber, ^uint64(0)} {
		for _, value := range []string{"0", strconv.FormatUint(bound, 10), func() string {
			if bound == ^uint64(0) {
				return "18446744073709551616"
			}
			return strconv.FormatUint(bound+1, 10)
		}()} {
			want := "ok"
			if value != "0" && value != strconv.FormatUint(bound, 10) {
				want = "WIRE_INTEGER"
			}
			add("integer-"+strconv.FormatUint(bound, 10)+"-"+value, "exact digit parsing at bound and bound+1", "W2.3-W2.4", "integer", object{"value": value, "bound": strconv.FormatUint(bound, 10)}, want)
		}
	}
	for i, v := range []string{"", "00", "01", "-1", "+1", "1.0", "1e0", " 1", "1 ", "١"} {
		add(fmt.Sprintf("integer-grammar-%d", i), "string integer grammar refusal", "W2.3", "integer", object{"value": v, "bound": "18446744073709551615"}, "WIRE_INTEGER")
	}
	// Signature preflight boundaries are separate from full curve verification.
	p := "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
	n := "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
	decrement := func(s string) string {
		b := unhex(s)
		for i := len(b) - 1; i >= 0; i-- {
			b[i]--
			if b[i] != 255 {
				break
			}
		}
		return hx(b)
	}
	increment := func(s string) string {
		b := unhex(s)
		for i := len(b) - 1; i >= 0; i-- {
			b[i]++
			if b[i] != 0 {
				break
			}
		}
		return hx(b)
	}
	for _, length := range []int{63, 64, 65} {
		want := "ok"
		if length != 64 {
			want = "WIRE_SIGNATURE_FORM"
		}
		add(fmt.Sprintf("signature-length-%d", length), "strict raw signature length (range preflight only)", "W5.2", "signature_form", object{"signature_hex": strings.Repeat("00", length)}, want)
	}
	for _, tc := range []struct{ id, r, s, want string }{{"r-p-minus-one", decrement(p), strings.Repeat("00", 32), "ok"}, {"r-p", p, strings.Repeat("00", 32), "WIRE_SIGNATURE"}, {"r-p-plus-one", increment(p), strings.Repeat("00", 32), "WIRE_SIGNATURE"}, {"s-n-minus-one", strings.Repeat("00", 32), decrement(n), "ok"}, {"s-n", strings.Repeat("00", 32), n, "WIRE_SIGNATURE"}, {"s-n-plus-one", strings.Repeat("00", 32), increment(n), "WIRE_SIGNATURE"}} {
		add(tc.id, "field/scalar preflight boundary, not verification admission", "W5.2", "signature_form", object{"signature_hex": tc.r + tc.s}, tc.want)
	}
	for _, tc := range []struct{ id, k, want string }{{"key-valid", key(1), "ok"}, {"key-short", key(1)[:62], "WIRE_MEMBER"}, {"key-long", key(1) + "00", "WIRE_MEMBER"}, {"key-upper", strings.ToUpper(key(1)), "WIRE_MEMBER"}, {"key-nonpoint", strings.Repeat("00", 32), "WIRE_KEY"}, {"key-p", p, "WIRE_KEY"}, {"key-p-plus-one", increment(p), "WIRE_KEY"}} {
		add(tc.id, "x-only signing key form and lift_x", "W3.6", "key", object{"public_key": tc.k}, tc.want)
	}
	d := digest(canonical(assentPayload, 1024))
	validSig := sign(1, d)
	for _, tc := range []struct{ id, k, s, want string }{{"verify-valid", key(1), validSig, "ok"}, {"verify-other-key", key(2), validSig, "WIRE_SIGNATURE"}, {"verify-zero", key(1), strings.Repeat("00", 64), "WIRE_SIGNATURE"}, {"verify-signature-before-key", "bad", "00", "WIRE_SIGNATURE_FORM"}} {
		add(tc.id, "strict verification and preflight order", "W5.2; W5.5", "verify", object{"public_key": tc.k, "digest": hx(d[:]), "signature_hex": tc.s}, tc.want)
	}
	payload := canonical(assentPayload, 1024)
	signed, e := wire.EncodeSignedAssent(payload, validSig)
	if e != nil {
		panic(e)
	}
	ctx := object{"Genesis": genesis, "Contract": contract, "PartyPublicKey": key(1)}
	signedInput := object{"raw_hex": hx(signed), "expected_type": string(wire.ContractAssent), "context": ctx}
	add("assent-valid", "specified signed assent and all three hash roles", "W5.1-W5.3; W6.1-W6.4; W7.1-W7.2", "signed", signedInput, "ok")
	for _, tc := range []struct {
		id     string
		mutate func(object)
		want   string
	}{
		{"assent-reference", func(x object) { x["references"] = []string{strings.Repeat("00", 32)} }, "WIRE_ID"},
		{"assent-binding", func(x object) { x["context"].(object)["Contract"] = genesis }, "ASSENT_BINDING"},
		{"assent-party", func(x object) { x["context"].(object)["PartyPublicKey"] = key(2) }, "ASSENT_PARTY"},
		{"assent-binding-before-party", func(x object) {
			x["context"].(object)["Contract"] = genesis
			x["context"].(object)["PartyPublicKey"] = key(2)
		}, "ASSENT_BINDING"},
	} {
		in := clone(signedInput)
		tc.mutate(in)
		add(tc.id, "binding/refusal precedence on valid signed bytes", "W6.3; W7.2; W9.3", "signed", in, tc.want)
	}
	for _, tc := range []struct {
		id     string
		mutate func(object)
		want   string
	}{
		{"member-extra", func(x object) { x["extra"] = true }, "WIRE_MEMBER"}, {"member-missing", func(x object) { delete(x, "party") }, "WIRE_MEMBER"}, {"member-form", func(x object) { x["contract"] = 0 }, "WIRE_MEMBER"}, {"member-key", func(x object) { x["party"] = strings.Repeat("00", 32) }, "WIRE_KEY"}, {"type-missing", func(x object) { delete(x, "type") }, "WIRE_TYPE"}, {"type-wrong", func(x object) { x["type"] = string(wire.Grant) }, "WIRE_TYPE"},
	} {
		pl := clone(assentPayload)
		tc.mutate(pl)
		raw := canonical(object{"payload": pl, "signature": validSig}, 2048)
		add(tc.id, "closed specified assent schema before verification", "W3.1-W3.6; W9.3", "signed", object{"raw_hex": hx(raw), "expected_type": string(wire.ContractAssent)}, tc.want)
	}
	for _, length := range []int{126, 127, 128, 129, 130} {
		sig := strings.Repeat("0", length)
		want := "WIRE_SIGNATURE_FORM"
		if length == 128 {
			want = "WIRE_SIGNATURE"
		}
		raw := canonical(object{"payload": assentPayload, "signature": sig}, 2048)
		add(fmt.Sprintf("signature-text-length-%d", length), "signature text form versus failed verification", "W5.2; W9.3", "signed", object{"raw_hex": hx(raw), "expected_type": string(wire.ContractAssent)}, want)
	}
	for i, typ := range []wire.Type{wire.Grant, wire.Invocation, wire.Receipt, wire.SealEndorsement, wire.NotaryAttestation} {
		add(fmt.Sprintf("memberless-type-%d", i), "unsupported memberless type refuses even with canonical arithmetic bytes", "W3.1; section 10 primitive boundary", "signed", object{"raw_hex": hx(canonical(object{"type": string(typ)}, 2048)), "expected_type": string(typ)}, "WIRE_TYPE")
	}

	// Official BIP340 verification inputs 0-14; no secret-key or aux columns are copied.
	for _, tc := range []struct{ id, key, message, signature, want string }{
		{"0", "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9", "0000000000000000000000000000000000000000000000000000000000000000", "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0", "ok"},
		{"1", "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659", "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89", "6896bd60eeae296db48a229ff71dfe071bde413e6d43f917dc8dcf8c78de33418906d11ac976abccb20b091292bff4ea897efcb639ea871cfa95f6de339e4b0a", "ok"},
		{"2", "dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8", "7e2d58d8b3bcdf1abadec7829054f90dda9805aab56c77333024b9d0a508b75c", "5831aaeed7b44bb74e5eab94ba9d4294c49bcf2a60728d8b4c200f50dd313c1bab745879a5ad954a72c45a91c3a51d3c7adea98d82f8481e0e1e03674a6f3fb7", "ok"},
		{"3", "25d1dff95105f5253c4022f628a996ad3a0d95fbf21d468a1b33f8c160d8f517", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "7eb0509757e246f19449885651611cb965ecc1a187dd51b64fda1edc9637d5ec97582b9cb13db3933705b32ba982af5af25fd78881ebb32771fc5922efc66ea3", "ok"},
		{"4", "d69c3509bb99e412e68b0fe8544e72837dfa30746d8be2aa65975f29d22dc7b9", "4df3c3f68fcc83b27e9d42c90431a72499f17875c81a599b566c9889b9696703", "00000000000000000000003b78ce563f89a0ed9414f5aa28ad0d96d6795f9c6376afb1548af603b3eb45c9f8207dee1060cb71c04e80f593060b07d28308d7f4", "ok"},
		{"5", "eefdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34", "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89", "6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e17776969e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b", "WIRE_KEY"},
		{"6", "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659", "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89", "fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a14602975563cc27944640ac607cd107ae10923d9ef7a73c643e166be5ebeafa34b1ac553e2", "WIRE_SIGNATURE"},
		{"7", "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659", "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89", "1fa62e331edbc21c394792d2ab1100a7b432b013df3f6ff4f99fcb33e0e1515f28890b3edb6e7189b630448b515ce4f8622a954cfe545735aaea5134fccdb2bd", "WIRE_SIGNATURE"},
		{"8", "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659", "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89", "6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e177769961764b3aa9b2ffcb6ef947b6887a226e8d7c93e00c5ed0c1834ff0d0c2e6da6", "WIRE_SIGNATURE"},
		{"9", "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659", "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89", "0000000000000000000000000000000000000000000000000000000000000000123dda8328af9c23a94c1feecfd123ba4fb73476f0d594dcb65c6425bd186051", "WIRE_SIGNATURE"},
		{"10", "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659", "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89", "00000000000000000000000000000000000000000000000000000000000000017615fbaf5ae28864013c099742deadb4dba87f11ac6754f93780d5a1837cf197", "WIRE_SIGNATURE"},
		{"11", "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659", "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89", "4a298dacae57395a15d0795ddbfd1dcb564da82b0f269bc70a74f8220429ba1d69e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b", "WIRE_SIGNATURE"},
		{"12", "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659", "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89", "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f69e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b", "WIRE_SIGNATURE"},
		{"13", "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659", "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89", "6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e177769fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", "WIRE_SIGNATURE"},
		{"14", "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30", "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89", "6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e17776969e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b", "WIRE_KEY"},
	} {
		add("bip340-verify-"+tc.id, "official BIP340 verification witness; no fixture signing key imported", "W5.2; BIP340 test vector "+tc.id, "verify", object{"public_key": tc.key, "digest": tc.message, "signature_hex": tc.signature}, tc.want)
	}
	for _, reference := range []struct{ id, value, want string }{
		{"correct", hash(payload), "ok"},
		{"one-byte", func() string { b := unhex(hash(payload)); b[0] ^= 1; return hx(b) }(), "WIRE_ID"},
		{"digest", hx(d[:]), "WIRE_ID"}, {"address", hash(signed), "WIRE_ID"},
	} {
		in := clone(signedInput)
		in["references"] = []string{reference.value}
		add("assent-reference-"+reference.id, "payload id is the reference, never another hash role", "W6.1-W6.4", "signed", in, reference.want)
	}
	// Consent byte generation uses NIP-01 id, not a registry typed digest.
	tagsKey := [][2]string{{"t", "swarma-contract-consent/1"}, {"genesis", genesis}, {"contract", contract}, {"issuer", key(1)}}
	tagsName := append(append([][2]string{}, tagsKey...), [2]string{"name", "id/example"})
	makeEvent := func(id string, created uint64, tags [][2]string) object {
		return add(id, "specified consent event from public scalar 2 and zero aux_rand", "W7.3; LIP-0013 2.1 and 3.1; NIP-01", "consent_encode", object{"public_test_scalar": 2, "created_at": created, "tags": tags}, "ok")
	}
	eventKey := makeEvent("consent-encode-key", 1000, tagsKey)
	eventName := makeEvent("consent-encode-name", 1000, tagsName)
	for _, stamp := range []uint64{1, wire.MaxTimestamp} {
		event := makeEvent(fmt.Sprintf("consent-timestamp-%d", stamp), stamp, tagsKey)
		c := object{"Mode": "key", "Genesis": genesis, "Contract": contract, "IssuerPublicKey": key(1), "RequestPublicKey": key(2), "Now": stamp}
		add(fmt.Sprintf("consent-read-timestamp-%d", stamp), "inclusive inherited consent timestamp bound", "W7.3-W7.4; LIP-0013 3.1", "consent", object{"raw_hex": event["event_hex"], "context": c}, "ok")
	}
	for _, stamp := range []uint64{0, wire.MaxTimestamp + 1} {
		add(fmt.Sprintf("consent-timestamp-refuse-%d", stamp), "outside inherited timestamp range", "W7.3-W7.4; LIP-0013 3.1", "consent_encode", object{"public_test_scalar": 2, "created_at": stamp, "tags": tagsKey}, "CONSENT_SHAPE")
	}
	evidence := object{"Confirmed": true, "Height": 100, "OperationOfName": true, "LiveAtRecentBlock": true, "OwnerMatches": true, "YieldsPublicKey": key(2)}
	consentCtx := object{"Mode": "key", "Genesis": genesis, "Contract": contract, "IssuerPublicKey": key(1), "RequestPublicKey": key(2), "Now": 1000, "RecentBlockHeight": 100}
	consentKey := object{"raw_hex": eventKey["event_hex"], "context": consentCtx}
	consentName := clone(consentKey)
	consentName["raw_hex"] = eventName["event_hex"]
	cc := consentName["context"].(object)
	cc["Mode"] = "name"
	cc["RecipientName"] = "id/example"
	cc["Evidence"] = evidence
	add("consent-read-key", "consent by key from stated context", "W7.3-W7.5", "consent", consentKey, "ok")
	add("consent-read-name", "consent by name from stated evidence, no chain authentication", "W7.4; W7.6", "consent", consentName, "ok")
	consentCase := func(id, want, spec string, base object, mutate func(object)) {
		in := clone(base)
		mutate(in)
		add(id, "consent first-refusal/boundary on stated context", spec, "consent", in, want)
	}
	consentCase("consent-shape", "CONSENT_SHAPE", "W7.4 step 1", consentKey, func(x object) { x["raw_hex"] = "7b7d" })
	consentCase("consent-binding", "CONSENT_BINDING", "W7.4 step 2", consentKey, func(x object) { x["context"].(object)["Contract"] = genesis })
	consentCase("consent-key", "CONSENT_KEY", "W7.4 step 3; W7.5", consentKey, func(x object) { x["context"].(object)["RequestPublicKey"] = key(3) })
	consentCase("consent-evidence-missing", "CONSENT_EVIDENCE", "W7.6", consentName, func(x object) { delete(x["context"].(object), "Evidence") })
	for _, field := range []string{"Confirmed", "OperationOfName", "LiveAtRecentBlock", "OwnerMatches"} {
		consentCase("consent-evidence-"+field, "CONSENT_EVIDENCE", "W7.6", consentName, func(x object) { x["context"].(object)["Evidence"].(object)[field] = false })
	}
	for _, height := range []int{100, 101} {
		want := "ok"
		if height == 101 {
			want = "CONSENT_EVIDENCE"
		}
		consentCase(fmt.Sprintf("consent-evidence-height-%d", height), want, "W7.6 condition 1", consentName, func(x object) { x["context"].(object)["Evidence"].(object)["Height"] = height })
	}
	for _, spent := range []int{100, 101} {
		want := "CONSENT_EVIDENCE"
		if spent == 101 {
			want = "ok"
		}
		consentCase(fmt.Sprintf("consent-evidence-spent-%d", spent), want, "W7.6 condition 4; W7.7", consentName, func(x object) { x["context"].(object)["Evidence"].(object)["SpentAtHeight"] = spent })
	}
	consentCase("consent-name-key", "CONSENT_KEY", "W7.6 condition 5", consentName, func(x object) { x["context"].(object)["Evidence"].(object)["YieldsPublicKey"] = key(3) })
	badEvent := strings.Replace(string(unhex(text(eventKey, "event_hex"))), text(eventKey, "signature_hex"), strings.Repeat("00", 64), 1)
	consentCase("consent-signature", "CONSENT_SIGNATURE", "W7.4 step 4", consentKey, func(x object) { x["raw_hex"] = hx([]byte(badEvent)) })
	consentCase("consent-time", "CONSENT_TIME", "W7.4 step 5; W7.8", consentKey, func(x object) { x["context"].(object)["Now"] = 999 })
	consentCase("consent-verifier-no-age-limit", "ok", "W7.8", consentKey, func(x object) { x["context"].(object)["Now"] = 1000 + wire.MaxConsentAge + 1 })

	consentDefects := []struct {
		name, want string
		apply      func(object)
	}{
		{"shape", "CONSENT_SHAPE", func(x object) { x["raw_hex"] = "7b7d" }},
		{"binding", "CONSENT_BINDING", func(x object) { x["context"].(object)["Contract"] = genesis }},
		{"key", "CONSENT_KEY", func(x object) { x["context"].(object)["RequestPublicKey"] = key(3) }},
		{"signature", "CONSENT_SIGNATURE", func(x object) { x["raw_hex"] = hx([]byte(badEvent)) }},
		{"time", "CONSENT_TIME", func(x object) { x["context"].(object)["Now"] = 999 }},
	}
	for i, early := range consentDefects {
		for _, late := range consentDefects[i+1:] {
			// Apply the raw-byte shape defect last, so two independently failing steps survive.
			consentCase("consent-"+early.name+"-before-"+late.name, early.want, "W7.4 first refusal", consentKey, func(x object) { late.apply(x); early.apply(x) })
		}
	}
	consentCase("consent-signature-one-byte", "CONSENT_SIGNATURE", "W7.4 step 4", consentKey, func(x object) {
		sig := unhex(text(eventKey, "signature_hex"))
		sig[63] ^= 1
		raw := strings.Replace(string(unhex(text(eventKey, "event_hex"))), text(eventKey, "signature_hex"), hx(sig), 1)
		x["raw_hex"] = hx([]byte(raw))
	})
	// Exact consent maximum size: printable name is lengthened without inventing members.
	for _, delta := range []int{0, 1} {
		tags := append([][2]string{}, tagsName...)
		tags[4][1] = strings.Repeat("a", 2048-len(unhex(text(eventName, "event_hex")))+len("id/example")+delta)
		want := "ok"
		if delta == 1 {
			want = "CONSENT_SHAPE"
		}
		add(fmt.Sprintf("consent-size-plus-%d", delta), "consent exact 2048 and 2049 octets", "W7.3-W7.4", "consent_encode", object{"public_test_scalar": 2, "created_at": 1000, "tags": tags}, want)
	}
	for _, age := range []uint64{0, wire.MaxConsentAge, wire.MaxConsentAge + 1} {
		in := clone(consentKey)
		in["context"].(object)["Now"] = 1000 + age
		in["snapshot"] = nil
		in["consumed_ids"] = []string{}
		want := "ok"
		if age > wire.MaxConsentAge {
			want = "CONSENT_AGE"
		}
		add(fmt.Sprintf("issuer-age-%d", age), "issuer age inclusive; stated clock only", "W7.8", "issuer", in, want)
	}
	inUsed := clone(consentKey)
	inUsed["snapshot"] = nil
	inUsed["consumed_ids"] = []string{text(eventKey, "event_id")}
	add("issuer-consumed", "consumed id refuses; no durable journal claim", "W7.9", "issuer", inUsed, "CONSENT_CONSUMED")

	for _, tc := range []struct {
		id   string
		now  uint64
		used []string
		want string
	}{
		{"time-before-age-consumed", 999, []string{text(eventKey, "event_id")}, "CONSENT_TIME"},
		{"age-before-consumed", 1000 + wire.MaxConsentAge + 1, []string{text(eventKey, "event_id")}, "CONSENT_AGE"},
	} {
		in := clone(consentKey)
		in["context"].(object)["Now"] = tc.now
		in["snapshot"] = nil
		in["consumed_ids"] = tc.used
		add("issuer-"+tc.id, "issuer first refusal on supplied clock and consumed ids", "W7.8-W7.9", "issuer", in, tc.want)
	}
	// Compose only W9.4 steps 2-6. These are deliberately stated facts; no grant bytes exist here.
	var issuanceKey, issuanceName object
	for _, mode := range []string{"key", "name"} {
		c := eventKey
		var point *wire.Outpoint
		var ev *wire.Evidence
		if mode == "name" {
			c = eventName
			point = &wire.Outpoint{TxID: txid, Vout: 4294967295}
			decode(evidence, &ev)
		}
		facts := &wire.GrantFacts{Mode: wire.RecipientMode(mode), Genesis: genesis, Contract: contract, ID: strings.Repeat("44", 32), Signature: strings.Repeat("55", 64), ContentAddress: strings.Repeat("66", 32), IssuerPublicKey: key(1), PartyPublicKey: key(1), RequestPublicKey: key(2), RecipientName: "id/example", RecentBlockHeight: 100}
		parts := wire.PreparationParts{Mode: facts.Mode, Genesis: genesis, Contract: contract, GrantID: facts.ID, GrantSignature: facts.Signature, AssentParty: key(1), AssentSignature: validSig, ConsentID: text(c, "event_id"), ConsentSignature: text(c, "signature_hex"), NameOutput: point}
		prep, e := wire.BuildPreparation(parts)
		if e != nil {
			panic(e)
		}
		frame, e := wire.EncodeIssuanceFrame(prep.Commitment(), facts.ContentAddress)
		if e != nil {
			panic(e)
		}
		in := clone(object{"stated_grant_facts": facts, "stated_evidence": ev, "assent_hex": hx(signed), "consent_hex": c["event_hex"], "name_output": point, "now": 1000, "frame_hex": hx(frame), "frame_value": 0, "op_return_count": 1})
		add("issuance-stated-"+mode, "conditional preparation from stated GrantFacts, not authenticated grant bytes", "W8.1-W8.6; W9.4 steps 2-6", "issuance", in, "ok")
		add("encode-preparation-"+mode, "canonical specified unsigned preparation on stated parts", "W1.1-W1.6; W8.1", "encode", object{"document": func() object {
			var x object
			dec := json.NewDecoder(bytes.NewReader(prep.Bytes()))
			dec.UseNumber()
			if e := dec.Decode(&x); e != nil {
				panic(e)
			}
			return x
		}(), "limit": 2048}, "ok")
		add("stored-preparation-"+mode, "unsigned preparation; no authentication of its named parts", "W8.1; W9.2-W9.3", "unsigned", object{"raw_hex": hx(prep.Bytes()), "expected_type": string(wire.Issuance)}, "ok")
		if mode == "key" {
			issuanceKey = in
		} else {
			issuanceName = in
		}
	}
	issuanceCase := func(id, want string, base object, mutate func(object)) {
		in := clone(base)
		mutate(in)
		add(id, "conditional issuance refusal/boundary on stated GrantFacts", "W8.1-W8.6; W9.4", "issuance", in, want)
	}
	issuanceCase("issuance-no-facts", "WIRE_TYPE", issuanceKey, func(x object) { x["stated_grant_facts"] = nil })
	issuanceCase("issuance-mode-key-outpoint", "ISSUANCE_MODE", issuanceKey, func(x object) { x["name_output"] = object{"TxID": txid, "Vout": 0} })
	issuanceCase("issuance-mode-name-missing", "ISSUANCE_MODE", issuanceName, func(x object) { x["name_output"] = nil })
	for _, idx := range []uint64{0, 4294967295, 4294967296} {
		if idx == 4294967295 {
			continue
		}
		// Build a matching frame for the valid zero outpoint; the invalid index must refuse before anchor comparison.
		in := clone(issuanceName)
		in["name_output"].(object)["Vout"] = idx
		if idx == 0 {
			baseOut := Evaluate("issuance", issuanceName)
			var doc object
			dec := json.NewDecoder(bytes.NewReader(unhex(text(baseOut, "preparation_hex"))))
			dec.UseNumber()
			if e := dec.Decode(&doc); e != nil {
				panic(e)
			}
			doc["recipient_consent"].(object)["name_output"].(object)["vout"] = idx
			b := canonical(doc, 2048)
			h := wire.TaggedHash(string(wire.Issuance), b)
			frame, e := wire.EncodeIssuanceFrame(h, strings.Repeat("66", 32))
			if e != nil {
				panic(e)
			}
			in["frame_hex"] = hx(frame)
		}
		want := "ok"
		if idx > 4294967295 {
			want = "WIRE_INTEGER"
		}
		add(fmt.Sprintf("issuance-vout-%d", idx), "number-form outpoint index at zero, bound and bound+1", "W2.1-W2.2; W8.1", "issuance", in, want)
	}
	defects := []struct {
		name, want string
		f          func(object)
	}{
		{"mode", "ISSUANCE_MODE", func(x object) { x["name_output"] = object{"TxID": txid, "Vout": 0} }},
		{"assent", "ASSENT_PARTY", func(x object) { x["stated_grant_facts"].(object)["PartyPublicKey"] = key(3) }},
		{"consent", "CONSENT_TIME", func(x object) { x["now"] = 999 }},
		{"frame", "ISSUANCE_FRAME", func(x object) { x["frame_value"] = 1 }},
		{"commitment", "ISSUANCE_COMMITMENT", func(x object) { b := unhex(text(x, "frame_hex")); b[7] ^= 1; x["frame_hex"] = hx(b) }},
	}
	for i, a := range defects {
		issuanceCase("issuance-"+a.name, a.want, issuanceKey, a.f)
		for _, b := range defects[i+1:] {
			issuanceCase("issuance-"+a.name+"-before-"+b.name, a.want, issuanceKey, func(x object) { a.f(x); b.f(x) })
		}
	}
	for _, count := range []int{0, 2} {
		issuanceCase(fmt.Sprintf("frame-count-%d", count), "ISSUANCE_FRAME", issuanceKey, func(x object) { x["op_return_count"] = count })
	}
	for _, length := range []int{71, 73} {
		issuanceCase(fmt.Sprintf("frame-length-%d", length), "ISSUANCE_FRAME", issuanceKey, func(x object) {
			b := unhex(text(x, "frame_hex"))
			if length == 71 {
				b = b[:71]
			} else {
				b = append(b, 0)
			}
			x["frame_hex"] = hx(b)
		})
	}
	for _, offset := range []int{0, 1, 2, 3, 4, 5, 6, 39, 40} {
		issuanceCase(fmt.Sprintf("frame-byte-%d", offset), "ISSUANCE_FRAME", issuanceKey, func(x object) { b := unhex(text(x, "frame_hex")); b[offset] ^= 1; x["frame_hex"] = hx(b) })
	}
	// Inventory guard makes adding or dropping a refusal class a deliberate fixture change.
	required := []string{"WIRE_SIZE", "WIRE_JSON", "WIRE_DUPLICATE", "WIRE_VALUE", "WIRE_NUMBER", "WIRE_STRING", "WIRE_NOT_CANONICAL", "WIRE_TYPE", "WIRE_MEMBER", "WIRE_INTEGER", "WIRE_KEY", "WIRE_SIGNATURE_FORM", "WIRE_SIGNATURE", "WIRE_ID", "ASSENT_BINDING", "ASSENT_PARTY", "CONSENT_SHAPE", "CONSENT_BINDING", "CONSENT_KEY", "CONSENT_EVIDENCE", "CONSENT_SIGNATURE", "CONSENT_TIME", "CONSENT_AGE", "CONSENT_CONSUMED", "ISSUANCE_MODE", "ISSUANCE_FRAME", "ISSUANCE_COMMITMENT"}
	seen := map[string]bool{}
	ids := map[string]bool{}
	for _, v := range set.Vectors {
		if ids[v.ID] {
			panic("duplicate id " + v.ID)
		}
		ids[v.ID] = true
		seen[text(v.Output, "code")] = true
	}
	for _, c := range required {
		if !seen[c] {
			panic("missing refusal " + c)
		}
	}
	b, e := json.MarshalIndent(set, "", "  ")
	if e != nil {
		return nil, e
	}
	return append(b, '\n'), nil
}
