package wire

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

type vector map[string]json.RawMessage

func (v vector) str(k string) string { var s string; _ = json.Unmarshal(v[k], &s); return s }
func (v vector) octets(t *testing.T, k string) []byte {
	t.Helper()
	b, err := hex.DecodeString(v.str(k))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func decode(t *testing.T, b json.RawMessage, out any) {
	t.Helper()
	if err := json.Unmarshal(b, out); err != nil {
		t.Fatal(err)
	}
}

type vectorSet struct {
	root vector
	all  []vector
	byID map[string]vector
}

func loadVectors(t *testing.T) vectorSet {
	t.Helper()
	b, err := os.ReadFile("testdata/wire-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%x", sha256.Sum256(b)) != "0e610d1528cb07375b00459618c3f33d79b58adc3dcd9e8bbf4b41c8bdb9a636" {
		t.Fatal("pinned vector blob changed")
	}
	var root vector
	decode(t, b, &root)
	s := vectorSet{root: root, byID: map[string]vector{}}
	add := func(rows []vector) {
		for _, v := range rows {
			id := v.str("id")
			if id == "" || s.byID[id] != nil {
				t.Fatal("missing/duplicate vector id", id)
			}
			s.all = append(s.all, v)
			s.byID[id] = v
		}
	}
	for _, g := range []string{"canonical", "integers", "assents", "consent_events", "issuance"} {
		var group map[string]json.RawMessage
		decode(t, root[g], &group)
		// Fixed group order makes adjacent control execution reproducible.
		for _, name := range []string{"valid", "invalid", "compound", "bindings", "cases", "stored"} {
			if r := group[name]; r != nil {
				var rows []vector
				decode(t, r, &rows)
				add(rows)
			}
		}
	}
	for _, g := range []string{"identifiers", "issuer_checks"} {
		var rows []vector
		decode(t, root[g], &rows)
		add(rows)
	}
	var prim vector
	decode(t, root["primitives"], &prim)
	for _, g := range []string{"types", "grant_stand_in"} {
		var rows []vector
		decode(t, prim[g], &rows)
		add(rows)
	}
	for _, g := range []string{"cross", "descriptive"} {
		var v vector
		decode(t, prim[g], &v)
		add([]vector{v})
	}
	if len(s.all) != 205 {
		t.Fatalf("inventory has %d, want all 205", len(s.all))
	}
	return s
}
func wantCode(t *testing.T, err error, want string) {
	t.Helper()
	if want == "ok" || want == "sign" {
		want = ""
	}
	got := ""
	if err != nil {
		got = err.Error()
	}
	if got != want {
		t.Fatalf("refusal = %q, want %q", got, want)
	}
}
func equalBytes(t *testing.T, got, want []byte) {
	t.Helper()
	if !bytes.Equal(got, want) {
		t.Fatalf("octets differ:\n got %q\nwant %q", got, want)
	}
}
func equalHex(t *testing.T, got [32]byte, want string) {
	t.Helper()
	if hex.EncodeToString(got[:]) != want {
		t.Fatalf("hash = %x, want %s", got, want)
	}
}
func requireNoObject(t *testing.T, o any, err error) {
	t.Helper()
	if err != nil && !reflect.ValueOf(o).IsNil() {
		t.Fatal("rejection returned an object")
	}
}

// The pinned vectors exercise the seven documented stages, not whole grants
// or live nodes. Each named negative is run beside its specified valid control.
// Expected refusals come from the public fixture, never from this implementation.
func TestV4CanonicalVectors(t *testing.T) {
	s := loadVectors(t)
	for _, v := range s.all {
		t.Run(v.str("id"), func(t *testing.T) {
			if neighbour := v.str("valid_neighbour"); neighbour != "" {
				control, ok := s.byID[neighbour]
				if !ok {
					t.Fatal("missing valid control", neighbour)
				}
				if e := control.str("expect"); e != "" && e != "ok" && e != "sign" {
					t.Fatal("control is not valid", neighbour)
				}
				t.Run("valid-control", func(t *testing.T) { s.run(t, control) })
			}
			s.run(t, v)
		})
	}
}

func (s vectorSet) run(t *testing.T, v vector) {
	t.Helper()
	id, want := v.str("id"), v.str("expect")
	switch {
	case strings.HasPrefix(id, "canon-"):
		b := v.octets(t, "hex")
		d, err := ParseDocument(b, 1<<20)
		wantCode(t, err, want)
		requireNoObject(t, d, err)
		if err == nil {
			equalBytes(t, d.Bytes(), b)
			if hashHex(d.Bytes()) != v.str("sha256") {
				t.Fatal("document hash mismatch")
			}
		}
	case strings.HasPrefix(id, "int-"):
		n, err := ParseInteger(v.str("value"), ^uint64(0))
		wantCode(t, err, want)
		if err == nil && strconv.FormatUint(n, 10) != v.str("value") {
			t.Fatal("integer did not round-trip exactly")
		}
		if err != nil && n != 0 {
			t.Fatal("rejected integer escaped")
		}
	case strings.HasPrefix(id, "prim-"):
		s.runPrimitive(t, v)
	case strings.HasPrefix(id, "assent-"):
		b := v.octets(t, "signed_form_hex")
		var o *SignedObject
		var err error
		if raw := v["context"]; raw != nil {
			var c struct {
				Genesis  string `json:"genesis"`
				Contract string `json:"contract"`
				Party    string `json:"party_public_key"`
			}
			decode(t, raw, &c)
			o, err = ReadAssent(b, AssentContext{c.Genesis, c.Contract, c.Party})
		} else {
			o, err = ReadSigned(b, ContractAssent)
		}
		wantCode(t, err, want)
		requireNoObject(t, o, err)
		if err == nil {
			equalBytes(t, o.Bytes(), b)
			if x := v.str("assent_id"); x != "" && o.ID() != x {
				t.Fatal("assent id mismatch")
			}
			if x := v.str("typed_digest"); x != "" {
				equalHex(t, o.Digest(), x)
			}
			if x := v.str("content_address"); x != "" && o.ContentAddress() != x {
				t.Fatal("content address mismatch")
			}
			encoded, err := EncodeSignedAssent(o.Payload(), o.Signature())
			wantCode(t, err, "")
			equalBytes(t, encoded, b)
			p := o.payload.root
			payload, err := EncodeAssentPayload(p.get("genesis").text, p.get("contract").text, p.get("party").text)
			wantCode(t, err, "")
			equalBytes(t, payload, o.Payload())
		}
	case strings.HasPrefix(id, "id-"):
		o, err := ReadSigned(s.byID[v.str("object")].octets(t, "signed_form_hex"), ContractAssent)
		wantCode(t, err, "")
		if ref := v.str("reference"); ref != "" {
			wantCode(t, o.CheckReference(ref), want)
		} else {
			if o.ID() != v.str("identifier") || o.ContentAddress() != v.str("content_address") {
				t.Fatal("hash roles differ")
			}
			equalHex(t, o.Digest(), v.str("typed_digest"))
		}
	case strings.HasPrefix(id, "consent-"):
		ctx := s.consentContext(t, v)
		b := v.octets(t, "event_hex")
		c, err := ReadConsent(b, ctx)
		wantCode(t, err, want)
		requireNoObject(t, c, err)
		if err == nil {
			equalBytes(t, c.Bytes(), b)
			var tags [][2]string
			for _, tag := range c.root.get("tags").elements {
				tags = append(tags, [2]string{tag.elements[0].text, tag.elements[1].text})
			}
			out, err := EncodeConsentEvent(c.PublicKey(), c.CreatedAt(), tags, c.Signature())
			wantCode(t, err, "")
			equalBytes(t, out, b)
			if x := v.str("event_id"); x != "" && x != c.ID() {
				t.Fatal("event id mismatch")
			}
			if x := v.str("id_preimage"); x != "" {
				equalBytes(t, eventPreimage(c.root), []byte(x))
			}
		}
	case strings.HasPrefix(id, "issuer-"):
		ctx, snapshot, consumed := s.issuerContext(t, v)
		before, _ := json.Marshal(v)
		err := CheckIssuerConditions(v.octets(t, "event_hex"), ctx, snapshot, consumed)
		wantCode(t, err, want)
		after, _ := json.Marshal(v)
		equalBytes(t, after, before) // The wire check has no consumption or closure side effects.
	case strings.HasPrefix(id, "issuance-s-"), strings.HasPrefix(id, "issuance-c-"):
		b := v.octets(t, "preparation_hex")
		p, err := ReadUnsigned(b, Issuance)
		wantCode(t, err, want)
		requireNoObject(t, p, err)
		if err == nil {
			equalBytes(t, p.Bytes(), b)
		}
	case strings.HasPrefix(id, "issuance-"):
		parts, pointer := s.parts(t, v)
		frame := v.octets(t, "script_hex")
		// Mode-refusal vectors intentionally provide no frame: mode must win.
		p, err := CheckIssuanceAnchor(parts, pointer, Frame{Script: frame, OpReturnCount: 1})
		wantCode(t, err, want)
		requireNoObject(t, p, err)
		if err == nil {
			equalBytes(t, p.Bytes(), v.octets(t, "preparation_hex"))
			equalHex(t, p.Commitment(), v.str("commitment"))
			if pointer != v.str("pointer") {
				t.Fatal("pointer mismatch")
			}
			out, err := EncodeIssuanceFrame(p.Commitment(), pointer)
			wantCode(t, err, "")
			equalBytes(t, out, frame)
		}
	default:
		t.Fatal("unhandled vector", id)
	}
}

func (s vectorSet) runPrimitive(t *testing.T, v vector) {
	t.Helper()
	id := v.str("id")
	switch id {
	case "prim-cross-01":
		b := v.octets(t, "octets_hex")
		d, err := TypedDigest(b)
		wantCode(t, err, "")
		equalHex(t, d, v.str("under_own_type"))
		other := TaggedHash(v.str("under"), b)
		equalHex(t, other, v.str("typed_digest"))
		if d == other {
			t.Fatal("domain not bound")
		}
	case "prim-descriptive-01":
		for _, fields := range [][3]string{{"without_hex", "without_typed_digest", "without_sha256"}, {"with_member_hex", "with_member_typed_digest", "with_member_sha256"}} {
			b := v.octets(t, fields[0])
			d, err := TypedDigest(b)
			wantCode(t, err, "")
			equalHex(t, d, v.str(fields[1]))
			if hashHex(b) != v.str(fields[2]) {
				t.Fatal("descriptive member excluded")
			}
		}
	default:
		b := v.octets(t, "octets_hex")
		d, err := TypedDigest(b)
		wantCode(t, err, "")
		equalHex(t, d, v.str("typed_digest"))
		if strings.HasPrefix(id, "prim-type-") {
			equalHex(t, sha256.Sum256([]byte(v.str("type"))), v.str("tag_sha256"))
			if hex.EncodeToString([]byte(v.str("type"))) != v.str("tag_hex") || hashHex(b) != v.str("sha256") {
				t.Fatal("primitive bytes differ")
			}
		}
		if strings.HasPrefix(id, "prim-grant-") {
			raw := v.octets(t, "signature")
			wantCode(t, VerifyBIP340(v.str("public_key"), d, raw), "")
			objectID, err := PayloadID(b)
			wantCode(t, err, "")
			if objectID != v.str("identifier") || hashHex(v.octets(t, "signed_octets_hex")) != v.str("content_address") {
				t.Fatal("stand-in hash mismatch")
			}
			// These are arithmetic inputs, never valid grant payloads.
			o, err := ReadSigned(v.octets(t, "signed_octets_hex"), Grant)
			wantCode(t, err, string(WireType))
			requireNoObject(t, o, err)
		}
	}
}

// Context adapters are fixture-only: production callers must supply their own
// independently established facts, not a JSON assertion from a presenter.
type fixtureEvidence struct {
	Confirmed bool    `json:"confirmed"`
	Height    uint64  `json:"height"`
	Operation bool    `json:"operation_of_name"`
	Live      bool    `json:"live_at_recent_block"`
	Owner     bool    `json:"owner_matches"`
	Spent     *uint64 `json:"spent_at_height"`
	Key       string  `json:"yields_public_key"`
}
type fixtureContext struct {
	Mode     RecipientMode    `json:"mode"`
	Genesis  string           `json:"genesis"`
	Contract string           `json:"contract"`
	Issuer   string           `json:"issuer_public_key"`
	Request  string           `json:"request_public_key"`
	Name     string           `json:"recipient_name"`
	Recent   uint64           `json:"recent_block_height"`
	Now      uint64           `json:"now"`
	Clock    uint64           `json:"clock"`
	Evidence *fixtureEvidence `json:"evidence"`
	Consumed []string         `json:"consumed_event_ids"`
	Snapshot *struct {
		Recent uint64 `json:"recent_block_height"`
		Name   struct {
			Confirmed bool   `json:"confirmed"`
			Height    uint64 `json:"height"`
			Live      bool   `json:"live"`
			Owner     bool   `json:"owner_matches"`
			Key       string `json:"yields_public_key"`
		} `json:"name"`
	} `json:"snapshot"`
}

func (f fixtureContext) context() ConsentContext {
	ctx := ConsentContext{Mode: f.Mode, Genesis: f.Genesis, Contract: f.Contract, IssuerPublicKey: f.Issuer, RequestPublicKey: f.Request, RecipientName: f.Name, RecentBlockHeight: f.Recent, Now: f.Now}
	if f.Evidence != nil {
		e := f.Evidence
		ctx.Evidence = &Evidence{e.Confirmed, e.Height, e.Operation, e.Live, e.Owner, e.Spent, e.Key}
	}
	return ctx
}
func (s vectorSet) consentContext(t *testing.T, v vector) ConsentContext {
	t.Helper()
	var f fixtureContext
	raw := v["context"]
	if raw == nil {
		ref := "consent-c-01"
		if v.str("id") == "consent-v-02" {
			ref = "consent-c-20"
		}
		raw = s.byID[ref]["context"]
	}
	decode(t, raw, &f)
	return f.context()
}
func (s vectorSet) issuerContext(t *testing.T, v vector) (ConsentContext, *Snapshot, []string) {
	t.Helper()
	var f fixtureContext
	decode(t, v["context"], &f)
	ctx := f.context()
	ctx.Now = f.Clock
	var snap *Snapshot
	if f.Snapshot != nil {
		n := f.Snapshot.Name
		snap = &Snapshot{f.Snapshot.Recent, SnapshotName{n.Confirmed, n.Height, n.Live, n.Owner, n.Key}}
	}
	return ctx, snap, f.Consumed
}
func (s vectorSet) parts(t *testing.T, v vector) (PreparationParts, string) {
	t.Helper()
	var in struct {
		Mode       RecipientMode `json:"mode"`
		Grant      string        `json:"grant"`
		Assent     string        `json:"issuer_assent"`
		Consent    string        `json:"recipient_consent"`
		NameOutput *struct {
			TxID string `json:"txid"`
			Vout uint64 `json:"vout"`
		} `json:"name_output"`
	}
	decode(t, v["inputs"], &in)
	g, a, c := s.byID[in.Grant], s.byID[in.Assent], s.byID[in.Consent]
	if g == nil || a == nil || c == nil {
		t.Fatal("unknown arithmetic input")
	}
	ao, err := ReadSigned(a.octets(t, "signed_form_hex"), ContractAssent)
	wantCode(t, err, "")
	co, err := ReadConsent(c.octets(t, "event_hex"), s.consentContext(t, c))
	wantCode(t, err, "")
	p := ao.payload.root
	parts := PreparationParts{Mode: in.Mode, Genesis: p.get("genesis").text, Contract: p.get("contract").text, GrantID: g.str("identifier"), GrantSignature: g.str("signature"), AssentParty: p.get("party").text, AssentSignature: ao.Signature(), ConsentID: co.ID(), ConsentSignature: co.Signature()}
	if in.NameOutput != nil {
		parts.NameOutput = &Outpoint{in.NameOutput.TxID, in.NameOutput.Vout}
	}
	return parts, g.str("content_address")
}
