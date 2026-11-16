// Package vectors derives arithmetic and stated-fact fixtures from the wire lab.
// It defines no grant schema and admits no grant bytes.
package vectors

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	wire "github.com/relux-works/swarma-chain-lab/experiments/grant-v4/wire"
)

type object = map[string]any

type Vector struct {
	ID             string   `json:"id"`
	Purpose        string   `json:"purpose"`
	Spec           string   `json:"spec"`
	Operation      string   `json:"operation"`
	Input          object   `json:"input"`
	Output         object   `json:"output"`
	Basis          string   `json:"basis"`
	ValidNeighbour string   `json:"valid_neighbour,omitempty"`
	Defects        []string `json:"defects,omitempty"`
	Reason         string   `json:"reason"`
}

type Set struct {
	Format          string   `json:"format"`
	Scope           string   `json:"scope"`
	SpecRevision    string   `json:"spec_revision"`
	LabRevision     string   `json:"lab_revision"`
	LabSpecRevision string   `json:"lab_spec_revision"`
	PublicScalars   []int    `json:"public_test_scalars"`
	AuxRand         string   `json:"aux_rand"`
	Vectors         []Vector `json:"vectors"`
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

// fixtureNames adapts lab struct fields to the specification vector vocabulary.
// These stated facts do not propose serialized grant members.
var fixtureNames = map[string]string{"Genesis": "genesis", "Contract": "contract", "PartyPublicKey": "party_public_key", "Mode": "mode", "IssuerPublicKey": "issuer_public_key", "RequestPublicKey": "request_public_key", "RecipientName": "recipient_name", "RecentBlockHeight": "recent_block_height", "Now": "clock", "Evidence": "evidence", "Confirmed": "confirmed", "Height": "height", "OperationOfName": "operation_of_name", "LiveAtRecentBlock": "live_at_recent_block", "OwnerMatches": "owner_matches", "YieldsPublicKey": "yields_public_key", "SpentAtHeight": "spent_at_height", "ID": "grant_id", "Signature": "grant_signature", "ContentAddress": "content_address", "TxID": "txid", "Vout": "vout", "Name": "name", "Live": "live"}

func renameFields(x any, toFixture bool) any {
	switch v := x.(type) {
	case map[string]any:
		out := object{}
		for k, child := range v {
			name := k
			for internal, external := range fixtureNames {
				if toFixture && k == internal {
					name = external
				}
				if !toFixture && k == external {
					name = internal
				}
			}
			out[name] = renameFields(child, toFixture)
		}
		return out
	case []any:
		for i := range v {
			v[i] = renameFields(v[i], toFixture)
		}
		return v
	default:
		return x
	}
}

func decode(x any, out any) {
	x = renameFields(x, false)
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
	return renameFields(y, true).(object)
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

// publicTestKey and sign are fixture scaffolding, restricted to published test scalars.
func publicTestKey(scalar int) *btcec.PrivateKey {
	if scalar < 1 || scalar > 3 {
		panic("public test scalars 1, 2, 3 only")
	}
	b := make([]byte, 32)
	b[31] = byte(scalar)
	sk, _ := btcec.PrivKeyFromBytes(b)
	return sk
}
func key(scalar int) string {
	return hx(schnorr.SerializePubKey(publicTestKey(scalar).PubKey()))
}

// sign is a test-only deterministic signer; never use it for real key material.
func sign(scalar int, d [32]byte) string {
	sk := publicTestKey(scalar)
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
	case "memberless_signed":
		// Inspect and authenticate the actual signed fixture before testing dispatch.
		// This scaffolding does not add a schema to the wire reader.
		raw := unhex(text(in, "raw_hex"))
		var doc *wire.Document
		doc, err = wire.ParseDocument(raw, 2048)
		if err != nil {
			break
		}
		var value object
		if e := json.Unmarshal(doc.Bytes(), &value); e != nil {
			panic(e)
		}
		pl, ok := value["payload"].(object)
		if !ok || len(value) != 2 {
			err = wire.WireMember
			break
		}
		if text(pl, "type") != text(in, "expected_type") {
			err = wire.WireType
			break
		}
		b := canonical(pl, 2048)
		d := digest(b)
		err = wire.VerifyBIP340(text(in, "place_public_key"), d, unhex(text(value, "signature")))
		if err != nil {
			break
		}
		_, err = wire.ReadSigned(raw, wire.Type(text(in, "expected_type")))
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
			decode(in["consumed_event_ids"], &consumed)
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
		args := wire.IssuanceInput{Grant: facts, IssuerAssent: unhex(text(in, "assent_hex")), RecipientConsent: unhex(text(in, "consent_hex")), NameOutput: point, Evidence: evidence, Now: number(in, "clock"), Frame: wire.Frame{Script: unhex(text(in, "frame_hex")), Value: number(in, "frame_value"), OpReturnCount: int(number(in, "op_return_count"))}}
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
	set := Set{Format: "swarma-lab-primitives/1", Scope: "no valid swarma-grant/4 vectors until LIP-0020 defines its members; arithmetic and stated facts only", SpecRevision: "bd3bc80e5543d8a563343ec05abd1a5f3f67284c", LabRevision: "8a47f1a984cd93864402f7fdc09d2eba0d890b90", LabSpecRevision: "adae6e7669601f271f7d0d9cdd91ecee7d19bf02", PublicScalars: []int{1, 2, 3}, AuxRand: strings.Repeat("00", 32)}
	add := func(id, purpose, spec, op string, in object, want string) object {
		// Round-trip fixture inputs so evaluation sees the same JSON number types as readers.
		in = clone(in)
		out := Evaluate(op, in)
		if out["code"] != want {
			panic(fmt.Sprintf("FINDING %s (%s): lab %s, spec expectation %s", id, spec, out["code"], want))
		}
		set.Vectors = append(set.Vectors, Vector{ID: id, Purpose: purpose, Spec: "LIP-0020 " + spec, Operation: op, Input: in, Output: out, Basis: "spec", Reason: purpose})
		return out
	}
	genesis := strings.Repeat("11", 32)
	contract := strings.Repeat("22", 32)
	txid := strings.Repeat("33", 32)
	assentPayload := object{"type": string(wire.ContractAssent), "genesis": genesis, "contract": contract, "party": key(1)}
	add("encode-assent", "canonical specified assent payload", "W1.1-W1.6; W7.1", "encode", object{"document": assentPayload, "limit": 1024}, "ok")
	for _, tc := range []struct {
		id  string
		doc object
	}{
		{"grammar", object{"a": []any{true, false, object{}, []any{}, uint64(wire.MaxNumber)}, "text": "<>&/\u007f\u2028\"\\"}},
		{"unicode-order", object{"\U0001f600": "astral", "\ufb33": "bmp", "e\u0301": "decomposed", "é": "composed"}},
	} {
		doc := tc.doc
		add("encode-restricted-"+tc.id, "restricted document grammar, not grant bytes", "W1.1-W1.6", "encode", object{"document": doc, "limit": 2048}, "ok")
	}
	// Permanent registry witness numbers match upstream prim-type-01..07.
	// They are explicit content associations, independent of generation order.
	types := []struct {
		typ     wire.Type
		witness string
	}{{wire.Grant, "0"}, {wire.Invocation, "1"}, {wire.Receipt, "2"}, {wire.SealEndorsement, "3"}, {wire.ContractAssent, "4"}, {wire.Issuance, "5"}, {wire.NotaryAttestation, "6"}}
	for _, entry := range types {
		typ := entry.typ
		doc := object{"type": string(typ)}
		add("arithmetic-"+entry.witness, "registry arithmetic only; no object/schema admission", "W3.1; W4.1; W6.1; section 10 primitive stage", "primitive", object{"document": doc}, "ok")
		for _, s := range []int{1, 2, 3} {
			if typ == wire.Issuance {
				continue
			} // W3: nobody signs an issuance commitment.
			add(fmt.Sprintf("signature-%s-%d", entry.witness, s), "BIP340 over arithmetic typed digest, public scalar, zero aux_rand; no object admission", "W4.1; W5.1-W5.2", "signature", object{"document": doc, "public_test_scalar": s}, "ok")
		}
	}

	for _, scalar := range []int{1, 2, 3} {
		doc := clone(assentPayload)
		doc["party"] = key(scalar)
		add(fmt.Sprintf("signature-assent-%d", scalar), "deterministic signature over a specified assent payload", "W7.1; W5.1-W5.2", "signature", object{"document": doc, "public_test_scalar": scalar}, "ok")
	}
	for _, tc := range []struct {
		id  string
		doc object
	}{{"missing", object{}}, {"nonstring", object{"type": 1}}, {"grant3", object{"type": "swarma-grant/3"}}} {
		add("arithmetic-type-"+tc.id, "unsupported type in arithmetic", "W3.1", "primitive", object{"document": tc.doc}, "WIRE_TYPE")
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

	parse("parse-empty-object", `{}`, "ok", "W1.1-W1.6", 2048)
	parse("parse-zero", `{"a":0}`, "ok", "W1.1-W1.6", 2048)
	parse("parse-two-members", `{"a":2,"b":1}`, "ok", "W1.1-W1.6", 2048)
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
	for _, tc := range []struct{ id, value string }{{"empty", ""}, {"double-zero", "00"}, {"leading-zero", "01"}, {"negative", "-1"}, {"plus", "+1"}, {"fraction", "1.0"}, {"exponent", "1e0"}, {"leading-space", " 1"}, {"trailing-space", "1 "}, {"nonascii", "١"}} {
		add("integer-grammar-"+tc.id, "string integer grammar refusal", "W2.3", "integer", object{"value": tc.value, "bound": "18446744073709551615"}, "WIRE_INTEGER")
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
	ctx := object{"genesis": genesis, "contract": contract, "party_public_key": key(1)}
	signedInput := object{"raw_hex": hx(signed), "expected_type": string(wire.ContractAssent), "context": ctx}
	add("assent-valid", "specified signed assent and all three hash roles", "W5.1-W5.3; W6.1-W6.4; W7.1-W7.2", "signed", signedInput, "ok")
	for _, tc := range []struct {
		id     string
		mutate func(object)
		want   string
	}{
		{"assent-reference", func(x object) { x["references"] = []string{strings.Repeat("00", 32)} }, "WIRE_ID"},
		{"assent-binding", func(x object) { x["context"].(object)["contract"] = genesis }, "ASSENT_BINDING"},
		{"assent-party", func(x object) { x["context"].(object)["party_public_key"] = key(2) }, "ASSENT_PARTY"},
		{"assent-binding-before-party", func(x object) {
			x["context"].(object)["contract"] = genesis
			x["context"].(object)["party_public_key"] = key(2)
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
		// A matching fresh signature isolates the shape/type defect from stale signing bytes.
		tag := text(pl, "type")
		if tag == "" {
			tag = string(wire.ContractAssent)
		}
		fresh := sign(1, wire.TaggedHash(tag, canonical(pl, 2048)))
		raw = canonical(object{"payload": pl, "signature": fresh}, 2048)
		add(tc.id+"-resigned", "single schema defect with a freshly signed payload", "W3.1-W3.6; W9.3", "signed", object{"raw_hex": hx(raw), "expected_type": string(wire.ContractAssent)}, tc.want)

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
	for _, typ := range []wire.Type{wire.Grant, wire.Invocation, wire.Receipt, wire.SealEndorsement, wire.NotaryAttestation} {
		pl := object{"type": string(typ)}
		raw := canonical(object{"payload": pl, "signature": sign(1, digest(canonical(pl, 2048)))}, 2048)
		purpose, spec, want := "canonical signed arithmetic payload with verified public place key still has no member schema", "W3.1; section 10 primitive boundary", "WIRE_TYPE"
		if typ == wire.Grant {
			purpose = "canonical signed type-only grant lacks the required grant members"
			spec = "W9.1; W9.3; W11.8; spec 0.1.53 at 3bef542fc8c0a5dedeeaaa990bd7f93abe194813; vectors/LIP-0020/grant-v4.json grant-i-05 expects WIRE_MEMBER"
			want = "WIRE_MEMBER"
		}
		add("memberless-signed-"+string(typ), purpose, spec, "memberless_signed", object{"raw_hex": hx(raw), "expected_type": string(typ), "place_public_key": key(1)}, want)
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
		c := object{"mode": "key", "genesis": genesis, "contract": contract, "issuer_public_key": key(1), "request_public_key": key(2), "clock": stamp}
		add(fmt.Sprintf("consent-read-timestamp-%d", stamp), "inclusive inherited consent timestamp bound", "W7.3-W7.4; LIP-0013 3.1", "consent", object{"raw_hex": event["event_hex"], "context": c}, "ok")
	}
	for _, stamp := range []uint64{0, wire.MaxTimestamp + 1} {
		add(fmt.Sprintf("consent-timestamp-refuse-%d", stamp), "outside inherited timestamp range", "W7.3-W7.4; LIP-0013 3.1", "consent_encode", object{"public_test_scalar": 2, "created_at": stamp, "tags": tagsKey}, "CONSENT_SHAPE")
	}
	evidence := object{"confirmed": true, "height": 100, "operation_of_name": true, "live_at_recent_block": true, "owner_matches": true, "yields_public_key": key(2)}
	consentCtx := object{"mode": "key", "genesis": genesis, "contract": contract, "issuer_public_key": key(1), "request_public_key": key(2), "clock": 1000, "recent_block_height": 100}
	consentKey := object{"raw_hex": eventKey["event_hex"], "context": consentCtx}
	consentName := clone(consentKey)
	consentName["raw_hex"] = eventName["event_hex"]
	cc := consentName["context"].(object)
	cc["mode"] = "name"
	cc["recipient_name"] = "id/example"
	cc["evidence"] = evidence
	add("consent-read-key", "consent by key from stated context", "W7.3-W7.5", "consent", consentKey, "ok")
	add("consent-read-name", "consent by name from stated evidence, no chain authentication", "W7.4; W7.6", "consent", consentName, "ok")
	consentCase := func(id, want, spec string, base object, mutate func(object)) {
		in := clone(base)
		mutate(in)
		add(id, "consent first-refusal/boundary on stated context", spec, "consent", in, want)
	}
	consentCase("consent-shape", "CONSENT_SHAPE", "W7.4 step 1", consentKey, func(x object) { x["raw_hex"] = "7b7d" })
	consentCase("consent-binding", "CONSENT_BINDING", "W7.4 step 2", consentKey, func(x object) { x["context"].(object)["contract"] = genesis })
	consentCase("consent-key", "CONSENT_KEY", "W7.4 step 3; W7.5", consentKey, func(x object) { x["context"].(object)["request_public_key"] = key(3) })
	consentCase("consent-evidence-missing", "CONSENT_EVIDENCE", "W7.6", consentName, func(x object) { delete(x["context"].(object), "evidence") })
	for _, field := range []string{"confirmed", "operation_of_name", "live_at_recent_block", "owner_matches"} {
		consentCase("consent-evidence-"+field, "CONSENT_EVIDENCE", "W7.6", consentName, func(x object) { x["context"].(object)["evidence"].(object)[field] = false })
	}
	for _, height := range []int{101} {
		want := "ok"
		if height == 101 {
			want = "CONSENT_EVIDENCE"
		}
		consentCase(fmt.Sprintf("consent-evidence-height-%d", height), want, "W7.6 condition 1", consentName, func(x object) { x["context"].(object)["evidence"].(object)["height"] = height })
	}
	for _, spent := range []int{100, 101} {
		want := "CONSENT_EVIDENCE"
		if spent == 101 {
			want = "ok"
		}
		consentCase(fmt.Sprintf("consent-evidence-spent-%d", spent), want, "W7.6 condition 4; W7.7", consentName, func(x object) { x["context"].(object)["evidence"].(object)["spent_at_height"] = spent })
	}
	consentCase("consent-name-key", "CONSENT_KEY", "W7.6 condition 5", consentName, func(x object) { x["context"].(object)["evidence"].(object)["yields_public_key"] = key(3) })
	badEvent := strings.Replace(string(unhex(text(eventKey, "event_hex"))), text(eventKey, "signature_hex"), strings.Repeat("00", 64), 1)
	consentCase("consent-signature", "CONSENT_SIGNATURE", "W7.4 step 4", consentKey, func(x object) { x["raw_hex"] = hx([]byte(badEvent)) })
	consentCase("consent-time", "CONSENT_TIME", "W7.4 step 5; W7.8", consentKey, func(x object) { x["context"].(object)["clock"] = 999 })
	consentCase("consent-verifier-no-age-limit", "ok", "W7.8", consentKey, func(x object) { x["context"].(object)["clock"] = 1000 + wire.MaxConsentAge + 1 })

	consentDefects := []struct {
		name, want string
		apply      func(object)
	}{
		{"shape", "CONSENT_SHAPE", func(x object) {
			var ev object
			dec := json.NewDecoder(bytes.NewReader(unhex(text(x, "raw_hex"))))
			dec.UseNumber()
			if e := dec.Decode(&ev); e != nil {
				panic(e)
			}
			ev["content"] = "x"
			pre := canonicalArray([]any{0, ev["pubkey"], ev["created_at"], ev["kind"], ev["tags"], ev["content"]})
			id := sha256.Sum256(pre)
			ev["id"] = hx(id[:])
			if ev["sig"] != strings.Repeat("00", 64) {
				ev["sig"] = sign(2, id)
			}
			// Consent uses fixed member order rather than canonical-object key order.
			fields := []string{"id", "pubkey", "created_at", "kind", "tags", "content", "sig"}
			var parts []string
			for _, k := range fields {
				kb, _ := json.Marshal(k)
				vb, _ := json.Marshal(ev[k])
				parts = append(parts, string(kb)+":"+string(vb))
			}
			x["raw_hex"] = hx([]byte("{" + strings.Join(parts, ",") + "}"))
		}},
		{"binding", "CONSENT_BINDING", func(x object) { x["context"].(object)["contract"] = genesis }},
		{"key", "CONSENT_KEY", func(x object) { x["context"].(object)["request_public_key"] = key(3) }},
		{"signature", "CONSENT_SIGNATURE", func(x object) { x["raw_hex"] = hx([]byte(badEvent)) }},
		{"time", "CONSENT_TIME", func(x object) { x["context"].(object)["clock"] = 999 }},
	}
	for i, early := range consentDefects {
		for _, late := range consentDefects[i+1:] {
			// Preserve both independently failing stages; shape keeps a readable signed event.
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
		in["context"].(object)["clock"] = 1000 + age
		in["snapshot"] = nil
		in["consumed_event_ids"] = []string{}
		want := "ok"
		if age > wire.MaxConsentAge {
			want = "CONSENT_AGE"
		}
		add(fmt.Sprintf("issuer-age-%d", age), "issuer age inclusive; stated clock only", "W7.8", "issuer", in, want)
	}
	inUsed := clone(consentKey)
	inUsed["snapshot"] = nil
	inUsed["consumed_event_ids"] = []string{text(eventKey, "event_id")}
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
		in["context"].(object)["clock"] = tc.now
		in["snapshot"] = nil
		in["consumed_event_ids"] = tc.used
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
		in := clone(object{"stated_grant_facts": facts, "stated_evidence": ev, "assent_hex": hx(signed), "consent_hex": c["event_hex"], "name_output": point, "clock": 1000, "frame_hex": hx(frame), "frame_value": 0, "op_return_count": 1})
		add("issuance-stated-"+mode, "conditional preparation from stated facts, not authenticated grant bytes", "W8.1-W8.6; W9.4 steps 2-6", "issuance", in, "ok")
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
		add(id, "conditional issuance refusal/boundary on stated facts", "W8.1-W8.6; W9.4", "issuance", in, want)
	}
	issuanceCase("issuance-no-facts", "WIRE_TYPE", issuanceKey, func(x object) { x["stated_grant_facts"] = nil })
	issuanceCase("issuance-mode-name-missing", "ISSUANCE_MODE", issuanceName, func(x object) { x["name_output"] = nil })
	for _, idx := range []uint64{0, 4294967295, 4294967296} {
		if idx == 4294967295 {
			continue
		}
		// Build a matching frame for the valid zero outpoint; the invalid index must refuse before anchor comparison.
		in := clone(issuanceName)
		in["name_output"].(object)["vout"] = idx
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
		{"mode", "ISSUANCE_MODE", func(x object) { x["name_output"] = object{"txid": txid, "vout": 0} }},
		{"assent", "ASSENT_PARTY", func(x object) {
			pl := clone(assentPayload)
			pl["party"] = key(3)
			sig := sign(3, digest(canonical(pl, 1024)))
			x["assent_hex"] = hx(canonical(object{"payload": pl, "signature": sig}, 2048))
		}},
		{"consent", "CONSENT_TIME", func(x object) { x["clock"] = 999 }},
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
	annotate(set.Vectors)
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

// annotate records the independent contract basis and concrete neighbour delta.
// A neighbour for a memberless type is arithmetic only: there is no admitted
// signed object for that type in the pinned specification.
func annotate(rows []Vector) {
	for i := range rows {
		v := &rows[i]
		switch {
		case v.Operation == "signature_form", v.ID == "issuance-no-facts", v.ID == "issuance-vout-4294967296", v.ID == "issuer-age-before-consumed", strings.HasPrefix(v.ID, "consent-size-plus-"):
			v.Basis = "lab-choice"
		case v.ID == "arithmetic-3", strings.HasPrefix(v.ID, "signature-3-"), strings.Contains(v.ID, string(wire.SealEndorsement)):
			v.Basis = "contingent:LIP-0008-SB4/LIP-0024"
		case strings.Contains(v.ID, string(wire.NotaryAttestation)):
			v.Basis = "contingent:LIP-0014-J5/J2"
		}
		if text(v.Output, "code") == "ok" {
			continue
		}
		best := -1
		var delta []string
		for j, n := range rows {
			if text(n.Output, "code") != "ok" || n.Operation != v.Operation {
				continue
			}
			d := inputDiff(n.Input, v.Input, "")
			if best < 0 || len(d) < len(delta) {
				best = j
				delta = d
			}
		}
		if v.Operation == "memberless_signed" {
			v.ValidNeighbour = map[string]string{string(wire.Grant): "arithmetic-0", string(wire.Invocation): "arithmetic-1", string(wire.Receipt): "arithmetic-2", string(wire.SealEndorsement): "arithmetic-3", string(wire.NotaryAttestation): "arithmetic-6"}[text(v.Input, "expected_type")]
			v.Defects = []string{"type " + text(v.Input, "expected_type") + " has no accepted member schema; the signed envelope and place-key signature are otherwise valid"}
			v.Reason += "; neighbour is arithmetic only, not an admitted signed object; grant refusal changes to WIRE_MEMBER when its schema is defined"
			if text(v.Input, "expected_type") == string(wire.Grant) {
				v.Defects = []string{"payload contains only type and lacks the required W11.2 members; the signed envelope and place-key signature are otherwise valid"}
				v.Reason = v.Purpose + "; neighbour is arithmetic only, not an admitted signed object; spec grant-i-05 supersedes the former WIRE_TYPE expectation"
			}
			continue
		}
		if best < 0 {
			panic("no neighbour for " + v.ID)
		}
		v.ValidNeighbour = rows[best].ID
		v.Defects = delta

		if strings.HasPrefix(v.ID, "bip340-verify-") {
			v.Defects = []string{map[string]string{
				"5":  "public key is not on secp256k1",
				"6":  "reconstructed R has odd Y",
				"7":  "signature was made for the negated message",
				"8":  "signature s is negated",
				"9":  "sG-eP is infinity (x=0 negative witness)",
				"10": "sG-eP is infinity (x=1 negative witness)",
				"11": "signature r is not a curve X coordinate",
				"12": "signature r equals the field prime",
				"13": "signature s equals the group order",
				"14": "public key X exceeds the field prime",
			}[strings.TrimPrefix(v.ID, "bip340-verify-")]}
		}
		if strings.HasPrefix(v.ID, "signature-text-length-") {
			n := strings.TrimPrefix(v.ID, "signature-text-length-")
			v.Defects = []string{"signature text has " + n + " hex characters; required length is 128"}
			if n == "128" {
				v.Defects = []string{"all-zero 64-byte signature fails BIP340 verification"}
			}
		}
		if descriptions, ok := rawDefects[v.ID]; ok {
			v.Defects = descriptions
		}
		neighbour := ""
		if v.Operation == "parse" {
			neighbour = "parse-zero"
			switch {
			case strings.HasPrefix(v.ID, "size-1024-"):
				neighbour = "size-1024-plus-0"
			case strings.HasPrefix(v.ID, "size-2048-") || v.ID == "size-before-json":
				neighbour = "size-2048-plus-0"
			case strings.HasPrefix(v.ID, "depth-") || strings.Contains(v.ID, "-depth"):
				neighbour = "depth-16"
			case strings.HasPrefix(v.ID, "json-") || v.ID == "canonical-space":
				neighbour = "parse-empty-object"
			case strings.HasPrefix(v.ID, "string-") || v.ID == "canonical-escape":
				neighbour = "string-lower-bound"
			case v.ID == "canonical-order":
				neighbour = "parse-two-members"
			case v.ID == "number-bound-plus-one":
				neighbour = "number-bound"
			}
		}
		if v.ID == "consent-size-plus-1" {
			neighbour = "consent-size-plus-0"
			v.Defects = []string{"event size is 2049 octets, one above the laboratory API limit; name-profile verdict is not judged"}
		}
		if v.Operation == "integer" && !strings.HasPrefix(v.ID, "integer-grammar-") {
			neighbour = "integer-" + text(v.Input, "bound") + "-" + text(v.Input, "bound")
		}
		if strings.HasPrefix(v.ID, "r-p") {
			neighbour = "r-p-minus-one"
			v.Defects = []string{"signature r is at or above the field prime (preflight API observation)"}
		}
		if strings.HasPrefix(v.ID, "s-n") {
			neighbour = "s-n-minus-one"
			v.Defects = []string{"signature s is at or above the group order (preflight API observation)"}
		}
		if neighbour != "" {
			v.ValidNeighbour = neighbour
		}
		if v.ID == "consent-shape-before-signature" {
			v.Defects = append(v.Defects, "raw_hex.decoded.sig: all-zero signature fails BIP340 (compound)")
		}
		if strings.HasPrefix(v.ID, "member-") || strings.HasPrefix(v.ID, "type-") {
			if !strings.HasSuffix(v.ID, "-resigned") {
				v.Defects = append(v.Defects, "stale signature over the unmutated assent payload (compound)")
			}
		}
		if v.ID == "issuance-vout-4294967296" {
			v.Defects = append(v.Defects, "frame still commits vout 4294967295 (compound)")
		}
		v.Reason += "; defects: " + strings.Join(v.Defects, "; ")
		if len(v.Defects) > 1 {
			v.Reason += "; compound: each listed defect remains present"
		}
	}
}

func inputDiff(a, b any, path string) []string {
	if reflect.DeepEqual(a, b) {
		return nil
	}
	am, aok := a.(object)
	bm, bok := b.(object)
	if aok && bok {
		keys := map[string]bool{}
		for k := range am {
			keys[k] = true
		}
		for k := range bm {
			keys[k] = true
		}
		ordered := []string{}
		for k := range keys {
			ordered = append(ordered, k)
		}
		sort.Strings(ordered)
		var result []string
		for _, k := range ordered {
			// Re-derived identifiers/signatures support a mutation; they are not
			// additional defects. A byte-only defect is described by the fallback.
			if strings.Contains(path, ".decoded") && (k == "id" || k == "sig" || k == "signature") {
				continue
			}
			if path == "" && k == "context" && (am[k] == nil || bm[k] == nil) {
				continue
			}
			p := k
			if path != "" {
				p = path + "." + k
			}
			result = append(result, inputDiff(am[k], bm[k], p)...)
		}
		return result
	}
	if strings.HasSuffix(path, "raw_hex") || strings.HasSuffix(path, "assent_hex") || strings.HasSuffix(path, "consent_hex") {
		var av, bv any
		as, aok := a.(string)
		bs, bok := b.(string)
		if aok && bok && json.Unmarshal(unhex(as), &av) == nil && json.Unmarshal(unhex(bs), &bv) == nil {
			if delta := inputDiff(av, bv, path+".decoded"); len(delta) > 0 {
				return delta
			}
		}
	}
	if path == "" {
		path = "input"
	}
	// Avoid dumping large bytes into explanatory metadata.
	describe := func(v any) string {
		s := fmt.Sprint(v)
		if len(s) > 96 {
			return strconv.Quote(s[:64]) + fmt.Sprintf("... (%d bytes)", len(s))
		}
		return strconv.Quote(s)
	}
	return []string{path + ": " + describe(a) + " -> " + describe(b)}
}

// Raw parser failures cannot be inferred by decoding into a map: that would
// erase duplicate members, token spellings, invalid Unicode and syntax order.
var rawDefects = map[string][]string{
	"size-1024-plus-1":        {"raw document is 1025 bytes, exceeding the stated 1024-byte caller limit"},
	"size-2048-plus-1":        {"raw document is 2049 bytes, exceeding the stated 2048-byte caller limit"},
	"depth-17":                {"document has 17 containers including its root, exceeding W1.1 depth 16"},
	"size-before-json":        {"raw input has 2049 bytes at limit 2048", "raw input is not JSON"},
	"depth-before-truncated":  {"container depth 17 occurs before end of input", "document is truncated"},
	"syntax-before-depth":     {"invalid token x occurs before depth excess", "container depth exceeds 16", "document is truncated"},
	"utf8-before-depth":       {"malformed UTF-8 byte occurs before depth excess", "container depth exceeds 16", "document is truncated"},
	"depth-before-utf8":       {"container depth exceeds 16 before malformed UTF-8", "malformed UTF-8 byte", "document is truncated"},
	"json-empty":              {"no JSON document"},
	"json-array":              {"top-level array is not a document object"},
	"json-bom":                {"UTF-8 BOM precedes the document"},
	"json-utf8":               {"string contains malformed UTF-8"},
	"json-trailing":           {"trailing x after a complete object"},
	"duplicate":               {"decoded member name a appears twice"},
	"duplicate-escaped":       {"a and escaped u0061 decode to the same member name", "escaped spelling is not canonical"},
	"null":                    {"member a is null, forbidden by W1"},
	"null-number-string":      {"member a is forbidden null", "member b is a forbidden negative number", "member c contains forbidden U+000A"},
	"number-bound-plus-one":   {"number token is 9007199254740992, above W2.2's maximum"},
	"number-negative":         {"number token -1 is signed"},
	"number-negative-zero":    {"number token -0 is signed"},
	"number-fraction":         {"number token 1.0 has a fractional part"},
	"number-exponent":         {"number token 1e0 has an exponent"},
	"number-leading-zero":     {"number token 01 violates JSON grammar"},
	"string-below-bound":      {"string contains forbidden U+001F"},
	"string-surrogate":        {"string contains unpaired UTF-16 surrogate U+D800"},
	"canonical-space":         {"leading whitespace is not canonical"},
	"canonical-order":         {"members b,a are not in canonical UTF-16 order"},
	"canonical-escape":        {"U+0020 uses an unnecessary escape"},
	"json-before-duplicate":   {"trailing x violates JSON grammar", "decoded member a appears twice"},
	"duplicate-before-null":   {"decoded member a appears twice", "first a is null", "second a is a forbidden negative number"},
	"number-before-string":    {"member a is a forbidden negative number", "member b contains forbidden U+000A"},
	"string-before-canonical": {"member a contains forbidden U+000A", "leading whitespace is not canonical"},
}
