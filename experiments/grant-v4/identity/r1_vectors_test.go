package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

type r1FixtureLimit struct {
	Kind, Resource, Unit, Period string
	Amount                       json.Number
}
type r1FixtureRange struct {
	TxID         string `json:"txid"`
	First, Count uint64
	Script       string `json:"script_hex"`
}
type r1FixtureParent struct {
	Seal   RowOutpoint
	Pools  []r1FixtureLimit
	Groups []struct {
		Limits []r1FixtureLimit
		Ranges []r1FixtureRange
	}
}
type r1FixturePin struct {
	Name         string
	Registration RowOutpoint
	Owner        string `json:"owner_public_key"`
}
type r1FixtureRecipient struct {
	Key   *string `json:"request_public_key"`
	Name  string
	Owner string `json:"owner_public_key"`
	Class []r1FixturePin
}
type r1FixtureTemplate struct {
	Issuer    r1FixturePin
	Notaries  []string
	Recipient r1FixtureRecipient
	Certifier *string
}
type r1FixtureInput struct {
	Spent     string   `json:"spent_script_hex"`
	Unlocking string   `json:"unlocking_script_hex"`
	Witness   []string `json:"witness_hex"`
}
type r1FixtureAdmission struct {
	ID                string
	Neighbour         string `json:"passing_neighbour"`
	NegativeNeighbour string `json:"negative_neighbour"`
	Issuer            r1FixturePin
	Context           struct {
		Recent int64 `json:"recent_block_height"`
		Tip    int64 `json:"tip_height"`
	}
	Row   r1FixtureTemplate
	Child struct{ Recipient r1FixtureRecipient }
	Node  struct {
		Recipient struct {
			Script   string `json:"current_output_script_hex"`
			Creating struct {
				Operation string
				Inputs    []r1FixtureInput
			} `json:"creating_operation"`
		} `json:"recipient_name"`
		Landlords map[string]struct {
			Registration string `json:"pinned_registration"`
			History      []struct {
				ID                      string
				Height                  int64
				Prefix, Reading, Writer string
			}
			Value        string `json:"current_value"`
			Pending      bool   `json:"pending_spend_of_current_output"`
			Transactions *bool  `json:"transaction_index"`
		}
	}
	Expect map[string]any
}

func r1Hex(t *testing.T, s string) []byte {
	t.Helper()
	b, e := hex.DecodeString(s)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func r1Pin(t *testing.T, s string) Pin {
	t.Helper()
	p, e := ParsePin(s)
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func r1Landlord(t *testing.T, p r1FixturePin) LandlordPin {
	return LandlordPin{p.Name, p.Registration, r1Pin(t, p.Owner)}
}
func r1Recipient(t *testing.T, r r1FixtureRecipient) RowRecipient {
	out := RowRecipient{Key: r.Key}
	if r.Name != "" {
		out.Name = &NameRecipient{[]byte(r.Name), r1Pin(t, r.Owner)}
	}
	if r.Class != nil {
		out.Class = []LandlordPin{}
		for _, p := range r.Class {
			out.Class = append(out.Class, r1Landlord(t, p))
		}
	}
	return out
}
func r1Limits(rows []r1FixtureLimit) []RowLimit {
	var out []RowLimit
	for _, r := range rows {
		out = append(out, RowLimit{RowLimitKey{r.Kind, r.Resource, r.Unit, r.Period}, r.Amount.String()})
	}
	return out
}
func r1Parent(p r1FixtureParent) RowGroups {
	out := RowGroups{Seal: p.Seal, Pools: r1Limits(p.Pools)}
	for _, g := range p.Groups {
		group := RowGroup{Template: RowTemplate{Limits: r1Limits(g.Limits)}}
		for _, r := range g.Ranges {
			b, _ := hex.DecodeString(r.Script)
			group.Ranges = append(group.Ranges, RowRange{r.TxID, r.First, r.Count, b})
		}
		out.Groups = append(out.Groups, group)
	}
	return out
}
func r1Template(t *testing.T, v r1FixtureTemplate) RowTemplate {
	out := RowTemplate{Recipient: r1Recipient(t, v.Recipient)}
	// The upstream recipient-only fixtures omit executor facts. Supply a
	// synthetic valid executor; dedicated executor vectors exercise R8.1.
	out.Executor = RowExecutor{"service.example", "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"}
	if v.Certifier != nil {
		out.Certifier = *v.Certifier
	}
	return out
}
func r1Admission(t *testing.T, v r1FixtureAdmission) (LandlordPin, RowTemplate, Recipient, ClassObservation) {
	issuer := r1Landlord(t, v.Issuer)
	template := r1Template(t, v.Row)
	recipient := r1Recipient(t, v.Child.Recipient)
	child := Recipient{RequestKey: recipient.Key, ByName: recipient.Name}
	chain, _ := NewChain(0)
	o := ClassObservation{Tip: At(v.Context.Tip), Recent: At(v.Context.Recent), Depth: 36000, Chain: chain, ParentAdmitted: true}
	o.Recipient = ClassNameEvidence{Script: r1Hex(t, v.Node.Recipient.Script), ConfirmedAt: o.Tip, Current: CurrentOutput, Transactions: true}
	for _, in := range v.Node.Recipient.Creating.Inputs {
		item := Input{SpentScript: r1Hex(t, in.Spent), SpentConfirmedAt: At(1), Unlocking: r1Hex(t, in.Unlocking)}
		for _, w := range in.Witness {
			item.Witness = append(item.Witness, r1Hex(t, w))
		}
		o.Recipient.Inputs = append(o.Recipient.Inputs, item)
	}
	for name, l := range v.Node.Landlords {
		var binding LandlordPin
		if name == issuer.Name {
			binding = issuer
		}
		for _, p := range template.Recipient.Class {
			if p.Name == name {
				binding = p
			}
		}
		state := StatedName{Name: []byte(name), Owner: binding.Owner, Tip: o.Tip, Depth: o.Depth, Current: CurrentOutput, Transactions: l.Transactions == nil || *l.Transactions}
		for _, h := range l.History {
			prefix := PrefixUpdate
			if h.Prefix == "registration" {
				prefix = PrefixRegistration
			}
			reading := Unsupported
			if h.Reading == "controlled" {
				reading = Controlled
			}
			if h.Reading == "another key" {
				reading = AnotherKey
			}
			writer := WriterUnsupported
			if h.Writer == "written by the owner" {
				writer = WrittenByOwner
			}
			if h.Writer == "written by another" {
				writer = WrittenByAnother
			}
			state.Outputs = append(state.Outputs, StatedOutput{ID: h.ID, Height: At(h.Height), Available: true, Prefix: prefix, Name: []byte(name), Reading: reading, Writer: writer})
		}
		o.Landlords = append(o.Landlords, ClassLandlordEvidence{Binding: binding, Name: state, RegistrationID: l.Registration, Value: []byte(l.Value), PendingKnown: true, Pending: l.Pending})
	}
	return issuer, template, child, o
}

func r1Fixture(t *testing.T, file string, out any) {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + file)
	if err != nil {
		t.Fatal(err)
	}
	hashes := map[string]string{"row-fit-vectors.json": "b92eb11c26432002daa51e8c463dbdfbaf27c5bc9b8b7c444ad51016c27f4ae8", "groups-vectors.json": "46ebd308bf71332c3026320d4978e44e96e14e57a1f88aab614c47934b566c5c", "class-vectors.json": "46522ae03176f6891a83c6a834af24fb7c16dfd4825ac83a5163bfdcf872f994", "holders-vectors.json": "d7bd9ecdcd826b13a743a85b1875b8fc976c587ae37aa89a847b37b9d4152ad8"}
	sum := fmt.Sprintf("%x", sha256.Sum256(raw))
	if sum != hashes[file] {
		t.Fatalf("pinned R1 fixture differs: %s", file)
	}
	if err = json.Unmarshal(raw, out); err != nil {
		t.Fatal(err)
	}
}
func r1Record(t *testing.T, id string, result any) {
	t.Helper()
	b, e := json.Marshal(map[string]any{"id": id, "result": result})
	if e != nil {
		t.Fatal(e)
	}
	t.Log("R1_RESULT " + string(b))
}
func r1AssertEqual(t *testing.T, id string, actual, expected any) {
	t.Helper()
	a, _ := json.Marshal(actual)
	e, _ := json.Marshal(expected)
	if string(a) != string(e) {
		t.Fatalf("%s: R1 got %s, want %s", id, a, e)
	}
}
func r1Equal(t *testing.T, id string, actual, expected any) {
	t.Helper()
	r1AssertEqual(t, id, actual, expected)
	r1Record(t, id, actual)
}

type r1VectorCase struct {
	positive                     bool
	neighbour, negativeNeighbour string
	check                        func(*testing.T) any
	expect                       any
}

// A declared edge is executable in both directions. Each negative checks its
// named positive; each positive checks all negatives declaring it, plus any
// explicit negative_neighbour. Missing or same-outcome links fail the harness.
func r1RunVector(t *testing.T, id string, cases map[string]r1VectorCase) {
	t.Helper()
	current := cases[id]
	neighbours := map[string]bool{}
	if current.neighbour != "" {
		neighbours[current.neighbour] = true
	}
	if current.negativeNeighbour != "" {
		neighbours[current.negativeNeighbour] = true
	}
	if current.positive {
		for otherID, other := range cases {
			if other.neighbour == id {
				neighbours[otherID] = true
			}
		}
	}
	if !current.positive && len(neighbours) == 0 {
		t.Fatal("negative vector has no positive neighbour")
	}
	ids := make([]string, 0, len(neighbours))
	for neighbour := range neighbours {
		ids = append(ids, neighbour)
	}
	sort.Strings(ids)
	for _, neighbour := range ids {
		paired, ok := cases[neighbour]
		if !ok || paired.positive == current.positive {
			t.Fatalf("invalid neighbour %s for %s", neighbour, id)
		}
		actual := paired.check(t)
		r1AssertEqual(t, "neighbour "+neighbour, actual, paired.expect)
	}
	r1Equal(t, id, current.check(t), current.expect)
}

// Pinned vectors prove range arithmetic and selection on stated facts. They
// contain no grant octets and exercise neither coin reads nor signer custody.
func TestR1Groups(t *testing.T) {
	var f struct {
		Parents []struct {
			ID                string
			Neighbour         string `json:"valid_neighbour"`
			NegativeNeighbour string `json:"negative_neighbour"`
			Parent            r1FixtureParent
			Expect            map[string]any
		}
		Ordinals []struct {
			ID       string
			ParentOf string `json:"parent_of"`
			Ordinal  uint64
			Expect   json.RawMessage
		}
	}
	r1Fixture(t, "groups-vectors.json", &f)
	if len(f.Parents) != 26 || len(f.Ordinals) != 12 {
		t.Fatal("R1 vector inventory")
	}
	parents := map[string]RowGroups{}
	cases := map[string]r1VectorCase{}
	for _, v := range f.Parents {
		parents[v.ID] = r1Parent(v.Parent)
		cases[v.ID] = r1VectorCase{v.Expect["outcome"] == "valid", v.Neighbour, v.NegativeNeighbour, func(t *testing.T) any {
			rows, err := CheckRowGroups(R1DraftLab, parents[v.ID])
			if err != nil {
				if rows != 0 {
					t.Fatal("refused parent exposed row count")
				}
				return map[string]any{"outcome": "refused", "rule": err.Error()}
			}
			return map[string]any{"outcome": "valid", "rows": rows}
		}, v.Expect}
	}
	for _, v := range f.Parents {
		t.Run(v.ID, func(t *testing.T) { r1RunVector(t, v.ID, cases) })
	}
	for _, v := range f.Ordinals {
		t.Run(v.ID, func(t *testing.T) {
			// Ordinal fixtures declare no neighbours: ordinal 1 of the same
			// valid parent is the explicit positive for every bound rejection.
			if _, err := SelectRow(R1DraftLab, parents[v.ParentOf], 1); err != nil {
				t.Fatalf("ordinal positive control: %v", err)
			}
			row, err := SelectRow(R1DraftLab, parents[v.ParentOf], v.Ordinal)
			var actual any = map[string]any{"group": row.Group, "range": row.Range, "coin": map[string]any{"txid": row.Coin.TxID, "vout": row.Coin.Vout, "script_hex": hex.EncodeToString(row.Script)}}
			if err != nil {
				actual = err.Error()
				if !reflect.DeepEqual(row, SelectedRow{}) {
					t.Fatal("refused ordinal exposed row")
				}
			}
			var expected any
			if json.Unmarshal(v.Expect, &expected) != nil {
				t.Fatal("expect decode")
			}
			r1Equal(t, v.ID, actual, expected)
		})
	}
}

// Each refused holder value is paired with the valid neighbour in the pinned
// file. Refusals expose no partial binding; capacity rows check the exact byte
// budget, not a universal limit on arbitrary owner members.
func TestR1Holders(t *testing.T) {
	var f struct {
		Values []struct {
			ID, Value string
			Expect    struct {
				Outcome, Grant string
				Holders        []string
			}
			Neighbour         string `json:"valid_neighbour"`
			NegativeNeighbour string `json:"negative_neighbour"`
		}
		Capacity []struct {
			ID      string
			Value   string `json:"value_without_holders"`
			Most    int    `json:"most_holders"`
			Without int    `json:"bytes_without_holders"`
			With    int    `json:"bytes_with_most"`
			More    int    `json:"bytes_with_one_more"`
		}
	}
	r1Fixture(t, "holders-vectors.json", &f)
	if len(f.Values) != 28 || len(f.Capacity) != 5 {
		t.Fatal("R1 holder inventory")
	}
	cases := map[string]r1VectorCase{}
	for _, v := range f.Values {
		expected := map[string]any{"outcome": v.Expect.Outcome}
		if v.Expect.Outcome == "valid" {
			expected["grant"] = v.Expect.Grant
			expected["holders"] = v.Expect.Holders
		}
		cases[v.ID] = r1VectorCase{v.Expect.Outcome == "valid", v.Neighbour, v.NegativeNeighbour, func(t *testing.T) any {
			value, err := ReadR1Value(R1DraftLab, []byte(v.Value))
			if err != nil {
				if err != ErrR1Value || !reflect.DeepEqual(value, R1Value{}) {
					t.Fatalf("holder refusal: %v, partial=%+v", err, value)
				}
				return map[string]any{"outcome": "refused"}
			}
			pins := []string{}
			for _, pin := range value.Holders {
				pins = append(pins, pin.String())
			}
			return map[string]any{"outcome": "valid", "grant": value.Grant, "holders": pins}
		}, expected}
	}
	for _, v := range f.Values {
		t.Run(v.ID, func(t *testing.T) { r1RunVector(t, v.ID, cases) })
	}
	for _, v := range f.Capacity {
		t.Run(v.ID, func(t *testing.T) {
			base := len([]byte(v.Value))
			most, with, more, err := HoldersCapacity([]byte(v.Value))
			if err != nil || base != v.Without || most != v.Most || with != v.With || more != v.More || with > 520 || more <= 520 {
				t.Fatal("R1 capacity boundary")
			}
			r1Record(t, v.ID, map[string]any{"without": base, "most": most, "with": with, "more": more})
		})
	}
}

type r1TemplateVector struct {
	ID                string
	Neighbour         string `json:"valid_neighbour"`
	NegativeNeighbour string `json:"negative_neighbour"`
	Template          r1FixtureTemplate
	Expect            map[string]any
}

func r1ClassFixtures(t *testing.T) ([]r1TemplateVector, []r1FixtureAdmission) {
	t.Helper()
	var f struct {
		Templates  []r1TemplateVector
		Admissions []r1FixtureAdmission
	}
	r1Fixture(t, "class-vectors.json", &f)
	if len(f.Templates) != 15 || len(f.Admissions) != 50 {
		t.Fatal("R1 class inventory")
	}
	return f.Templates, f.Admissions
}

// These vectors check all four ordered class predicates, including gifted names
// and the two selected-landlord holder mirrors. Passing "required" is conditional
// on later attestation checks; placeholders are never signature qualification.
func TestR1Class(t *testing.T) {
	templates, admissions := r1ClassFixtures(t)
	cases := map[string]r1VectorCase{}
	for _, v := range templates {
		cases[v.ID] = r1VectorCase{v.Expect["outcome"] == "valid", v.Neighbour, v.NegativeNeighbour, func(t *testing.T) any {
			err := CheckRowTemplate(R1DraftLab, r1Landlord(t, v.Template.Issuer), v.Template.Notaries, r1Template(t, v.Template))
			if err != nil {
				return map[string]any{"outcome": "refused", "rule": err.Error()}
			}
			return map[string]any{"outcome": "valid"}
		}, v.Expect}
	}
	for _, v := range templates {
		t.Run(v.ID, func(t *testing.T) { r1RunVector(t, v.ID, cases) })
	}
	cases = map[string]r1VectorCase{}
	for _, v := range admissions {
		neighbour := v.Neighbour
		// The four compound-refusal fixtures have no declared neighbour.
		// class-01 is their explicit valid setup; upstream bytes stay pinned.
		if v.Expect["outcome"] != "pass" && neighbour == "" {
			neighbour = "class-01"
		}
		cases[v.ID] = r1VectorCase{v.Expect["outcome"] == "pass", neighbour, v.NegativeNeighbour, func(t *testing.T) any {
			issuer, template, child, o := r1Admission(t, v)
			result, err := CheckRowRecipient(R1DraftLab, issuer, template, child, o)
			if err != nil {
				if result != (RowRecipientResult{}) {
					t.Fatal("refusal exposed request key/policy")
				}
				return map[string]any{"outcome": err.Error()}
			}
			policy := "not read"
			if result.AttestationRequired {
				policy = "required"
			}
			return map[string]any{"outcome": "pass", "attestation": policy}
		}, v.Expect}
	}
	for _, v := range admissions {
		t.Run(v.ID, func(t *testing.T) { r1RunVector(t, v.ID, cases) })
	}

}

// The pending decisions are enabled only by the named draft profile; the
// in-force profile and unknown values cannot admit even otherwise valid facts.
func TestR1ProfileGate(t *testing.T) {
	_, fixtures := r1ClassFixtures(t)
	issuer, template, child, o := r1Admission(t, fixtures[0])
	valid := []byte(`{"swarma":{"landlord":{"grant":"` + issuer.Owner.String()[2:] + `"}}}`)
	for _, profile := range []R1Profile{0, R1InForce, 99} {
		t.Run(fmt.Sprint(profile), func(t *testing.T) {
			if v, err := ReadR1Value(profile, valid); err != ErrR1Profile || !reflect.DeepEqual(v, R1Value{}) {
				t.Fatal("R1 profile admitted a value")
			}
			if r, err := CheckRowRecipient(profile, issuer, template, child, o); err != ErrR1Profile || r != (RowRecipientResult{}) {
				t.Fatal("R1 profile admitted a child")
			}
			if err := CheckRowTemplate(profile, issuer, nil, template); err != ErrR1Profile {
				t.Fatal("R1 profile admitted a template")
			}
			if _, err := CheckRowGroups(profile, RowGroups{}); err != ErrR1Profile {
				t.Fatal("R1 profile admitted groups")
			}
		})
	}
	if _, err := ReadR1Value(R1DraftLab, valid); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckRowRecipient(R1DraftLab, issuer, template, child, o); err != nil {
		t.Fatal(err)
	}
}

// Top-level owner members are ignored; aliases/duplicates of read members and
// noncompact bindings refuse. Nostr failures remove a key, never a holder list.
func TestR1ValueBoundary(t *testing.T) {
	_, fixtures := r1ClassFixtures(t)
	issuer, _, _, _ := r1Admission(t, fixtures[0])
	key := issuer.Owner.String()[2:]
	binding := `{"landlord":{"grant":"` + key + `"}}`
	for _, prefix := range []string{``, `"owner":null,`, `"unused":1,"unused":2,`} {
		if _, err := ReadR1Value(R1DraftLab, []byte(`{`+prefix+`"swarma":`+binding+`}`)); err != nil {
			t.Fatal(err)
		}
	}
	for _, raw := range []string{
		`{"swarma":` + binding + `,"swarma":` + binding + `}`,
		`{"Swarma":` + binding + `}`, `{"swarma":` + binding + `,"NOSTR":0}`,
		`{"swarma":` + binding + `} true`, `{"swarma": ` + strings.Replace(binding, `"grant":`, `"grant": `, 1) + `}`,
		`{"swarma":{"landlord":{"grant":"` + key + `","grant":"` + key + `"}}}`,
	} {
		if _, err := ReadR1Value(R1DraftLab, []byte(raw)); err != ErrR1Value {
			t.Fatalf("R1 malformed value admitted: %s", raw)
		}
	}
}

// These local R2 vectors share the pinned class-01 observation and vary only
// row-fit facts. They test exact executor identity, all recipient modes, typed
// limit ceilings and refusal precedence before the class predicates.
func TestR1RowFitVectors(t *testing.T) {
	var file struct {
		Vectors []struct {
			ID    string
			Child struct {
				Ordinal   uint64
				Executor  RowExecutor
				Recipient r1FixtureRecipient
				Limits    []r1FixtureLimit
			}
			Expect map[string]any
		}
	}
	r1Fixture(t, "row-fit-vectors.json", &file)
	if len(file.Vectors) != 15 {
		t.Fatal("R2 vector inventory")
	}
	for _, v := range file.Vectors {
		t.Run(v.ID, func(t *testing.T) {
			parent, positive, observation := r1FullParent(t)
			if result, err := CheckR1Child(R1DraftLab, parent, positive, observation); err != nil || result.Key == "" {
				t.Fatalf("row-fit positive control: %v", err)
			}
			r := r1Recipient(t, v.Child.Recipient)
			child := R1Child{v.Child.Ordinal, v.Child.Executor, Recipient{RequestKey: r.Key, ByName: r.Name}, r1Limits(v.Child.Limits)}
			result, err := CheckR1Child(R1DraftLab, parent, child, observation)
			actual := map[string]any{"outcome": "pass"}
			if err != nil {
				actual["outcome"] = err.Error()
				if result != (RowRecipientResult{}) {
					t.Fatal("R2 refusal exposes key")
				}
			}
			r1Equal(t, v.ID, actual, v.Expect)
		})
	}
}
