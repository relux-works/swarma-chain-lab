package identity

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

type r1ProfileFixture struct {
	SpecTag    string `json:"spec_tag"`
	SpecCommit string `json:"spec_commit"`
	Profiles   []struct {
		Name  string
		Value R1Profile
	}
	Rules []struct {
		Rule   R1Rule
		Status string
	}
	Overrides map[string]json.RawMessage `json:"in_force_overrides"`
}
type profileCase struct {
	run      func(R1Profile) any
	expected any
}

func profileError(err error, ordinary any) any {
	if err == ErrR1Profile || err == ErrR1DraftRule {
		return err.Error()
	}
	return ordinary
}
func profileCases(t *testing.T) map[string]profileCase {
	t.Helper()
	cases := map[string]profileCase{}
	var groups struct {
		Parents []struct {
			ID     string
			Parent r1FixtureParent
			Expect map[string]any
		}
		Ordinals []struct {
			ID       string
			ParentOf string `json:"parent_of"`
			Ordinal  uint64
			Expect   any
		}
	}
	r1Fixture(t, "groups-vectors.json", &groups)
	parents := map[string]RowGroups{}
	for _, v := range groups.Parents {
		p := r1Parent(v.Parent)
		parents[v.ID] = p
		cases[v.ID] = profileCase{func(profile R1Profile) any {
			rows, err := CheckRowGroups(profile, p)
			if err != nil {
				if rows != 0 {
					t.Fatal("partial group result")
				}
				return profileError(err, map[string]any{"outcome": "refused", "rule": err.Error()})
			}
			return map[string]any{"outcome": "valid", "rows": rows}
		}, v.Expect}
	}
	for _, v := range groups.Ordinals {
		cases[v.ID] = profileCase{func(profile R1Profile) any {
			r, err := SelectRow(profile, parents[v.ParentOf], v.Ordinal)
			if err != nil {
				if !reflect.DeepEqual(r, SelectedRow{}) {
					t.Fatal("partial selected row")
				}
				return err.Error()
			}
			return map[string]any{"group": r.Group, "range": r.Range, "coin": map[string]any{"txid": r.Coin.TxID, "vout": r.Coin.Vout, "script_hex": hex.EncodeToString(r.Script)}}
		}, v.Expect}
	}
	templates, admissions := r1ClassFixtures(t)
	for _, v := range templates {
		cases[v.ID] = profileCase{func(profile R1Profile) any {
			err := CheckRowTemplate(profile, r1Landlord(t, v.Template.Issuer), v.Template.Notaries, r1Template(t, v.Template))
			if err != nil {
				return profileError(err, map[string]any{"outcome": "refused", "rule": err.Error()})
			}
			return map[string]any{"outcome": "valid"}
		}, v.Expect}
	}
	for _, v := range admissions {
		cases[v.ID] = profileCase{func(profile R1Profile) any {
			issuer, template, child, o := r1Admission(t, v)
			// This fixture explicitly states checkpoint 500. It is not a production
			// derivation from Recent; TestR1ExplicitCheckpoint breaks their equality.
			for i := range o.Landlords {
				o.Landlords[i].Checkpoint = At(500)
			}
			r, err := CheckRowRecipient(profile, issuer, template, child, o)
			if err != nil {
				if r != (RowRecipientResult{}) {
					t.Fatal("partial recipient result")
				}
				return profileError(err, map[string]any{"outcome": err.Error()})
			}
			policy := "required"
			if !r.AttestationRequired {
				policy = "not read"
				if profile == R1InForce051 {
					policy = "not required"
				}
			}
			return map[string]any{"outcome": "pass", "attestation": policy}
		}, v.Expect}
	}
	var holders struct {
		Values []struct {
			ID, Value string
			Expect    map[string]any
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
	r1Fixture(t, "holders-vectors.json", &holders)
	for _, v := range holders.Values {
		expected := map[string]any{}
		for k, val := range v.Expect {
			if k != "rule" {
				expected[k] = val
			}
		}
		cases[v.ID] = profileCase{func(profile R1Profile) any {
			value, err := ReadR1Value(profile, []byte(v.Value))
			if err != nil {
				if !reflect.DeepEqual(value, R1Value{}) {
					t.Fatal("partial value result")
				}
				return profileError(err, map[string]any{"outcome": "refused"})
			}
			pins := []string{}
			for _, pin := range value.Holders {
				pins = append(pins, pin.String())
			}
			return map[string]any{"outcome": "valid", "grant": value.Grant, "holders": pins}
		}, expected}
	}
	for _, v := range holders.Capacity {
		cases[v.ID] = profileCase{func(profile R1Profile) any {
			if err := RequireR1Rule(profile, R1Capacity); err != nil {
				return err.Error()
			}
			size := len([]byte(v.Value))
			most := (520 - size - 12) / 69
			return map[string]any{"without": size, "most": most, "with": size + 12 + 69*most, "more": size + 12 + 69*(most+1)}
		}, map[string]any{"without": v.Without, "most": v.Most, "with": v.With, "more": v.More}}
	}
	var fit struct {
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
	r1Fixture(t, "row-fit-vectors.json", &fit)
	for _, v := range fit.Vectors {
		cases[v.ID] = profileCase{func(profile R1Profile) any {
			p, _, _ := r1FullParent(t)
			r := r1Recipient(t, v.Child.Recipient)
			child := R1Child{v.Child.Ordinal, v.Child.Executor, Recipient{RequestKey: r.Key, ByName: r.Name}, r1Limits(v.Child.Limits)}
			err := CheckR1Fit(profile, 1, p.Rows.Groups[0].Template, child)
			if err != nil {
				return profileError(err, map[string]any{"outcome": err.Error()})
			}
			return map[string]any{"outcome": "pass"}
		}, v.Expect}
	}
	return cases
}

// Every profile crosses every original vector family and every split rule.
// Draft-only availability has a neighbouring draft positive; closed profiles
// exercise real entry points. Golden changes cite the released decision text.
func TestR1Profiles(t *testing.T) {
	raw, err := os.ReadFile("testdata/profile-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var f r1ProfileFixture
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.SpecTag != R1SpecTag || f.SpecCommit != R1SpecCommit || len(f.Profiles) != 5 || len(f.Rules) != 20 {
		t.Fatal("profile inventory/pin")
	}
	cases := profileCases(t)
	if len(cases) != 151 {
		t.Fatal("profile vector inventory")
	}
	for _, p := range f.Profiles {
		t.Run(p.Name, func(t *testing.T) {
			for _, rule := range f.Rules {
				t.Run("rule/"+string(rule.Rule), func(t *testing.T) {
					want := "available"
					if p.Value != R1DraftLab && p.Value != R1InForce051 {
						want = ErrR1Profile.Error()
					} else if p.Value == R1InForce051 && rule.Status == "DRAFT" {
						want = ErrR1DraftRule.Error()
					}
					got := "available"
					if err := RequireR1Rule(p.Value, rule.Rule); err != nil {
						got = err.Error()
					}
					r1Equal(t, "profile/"+p.Name+"/rule/"+string(rule.Rule), got, want)
				})
			}
			for id, c := range cases {
				t.Run(id, func(t *testing.T) {
					want := c.expected
					if p.Value != R1DraftLab && p.Value != R1InForce051 {
						want = ErrR1Profile.Error()
					} else if p.Value == R1InForce051 {
						if override, ok := f.Overrides[id]; ok {
							if err := json.Unmarshal(override, &want); err != nil {
								t.Fatal(err)
							}
						}
					}
					r1Equal(t, "profile/"+p.Name+"/"+id, c.run(p.Value), want)
				})
			}
		})
	}
	for _, p := range f.Profiles {
		if RequireR1Rule(p.Value, "unknown-rule") == nil {
			t.Fatal("unknown rule enabled")
		}
	}
}

// A decided class checkpoint is explicit. Changing Recent cannot replace it;
// missing/future checkpoints refuse with no key or attestation policy.
func TestR1ExplicitCheckpoint(t *testing.T) {
	_, fixtures := r1ClassFixtures(t)
	issuer, template, child, o := r1Admission(t, fixtures[0])
	for i := range o.Landlords {
		o.Landlords[i].Checkpoint = At(500)
	}
	o.Recent = At(0)
	if r, e := CheckRowRecipient(R1InForce051, issuer, template, child, o); e != nil || r.Key == "" {
		t.Fatalf("explicit checkpoint: %v", e)
	}
	for _, checkpoint := range []Height{{}, At(900)} {
		for i := range o.Landlords {
			o.Landlords[i].Checkpoint = checkpoint
		}
		if r, e := CheckRowRecipient(R1InForce051, issuer, template, child, o); e != ClassHistoryUnavailable || r != (RowRecipientResult{}) {
			t.Fatalf("missing/future checkpoint: %+v %v", r, e)
		}
	}
}

// A composed parent/child depends on the undecided atomic and selection rules;
// partial decided predicates must not be presented as whole admission.
func TestR1InForceCompositionUnavailable(t *testing.T) {
	p, c, o := r1FullParent(t)
	if CheckR1Parent(R1DraftLab, p) != nil {
		t.Fatal("draft parent positive")
	}
	if CheckR1Parent(R1InForce051, p) != ErrR1DraftRule {
		t.Fatal("atomic rule enabled")
	}
	if r, e := CheckR1Child(R1InForce051, p, c, o); e != ErrR1DraftRule || r != (RowRecipientResult{}) {
		t.Fatal("composed child enabled")
	}
}

// Selected-fact fitting supports all decided recipient modes. Wrong mode,
// identity, executor and limit facts refuse without changing caller input.
func TestR1InForceFitModes(t *testing.T) {
	p, c, _ := r1FullParent(t)
	base := p.Rows.Groups[0].Template
	key := "request-key"
	name := *c.Recipient.ByName
	for _, mode := range []string{"key", "name", "class"} {
		t.Run(mode, func(t *testing.T) {
			template := base
			child := c
			switch mode {
			case "key":
				template.Recipient = RowRecipient{Key: &key}
				child.Recipient = Recipient{RequestKey: &key}
			case "name":
				template.Recipient = RowRecipient{Name: &name}
			}
			if err := CheckR1Fit(R1InForce051, 1, template, child); err != nil {
				t.Fatal(err)
			}
			changes := []struct {
				name string
				edit func(*R1Child)
				want error
			}{
				{"ordinal", func(c *R1Child) { c.Ordinal = 0 }, ChildOrdinal},
				{"executor", func(c *R1Child) { c.Executor.Name = "another" }, ChildAgentNotAllowed},
				{"mode", func(c *R1Child) { c.Recipient = Recipient{} }, ChildGranteeNotAllowed},
				{"budget", func(c *R1Child) { c.Limits = []RowLimit{{base.Limits[0].Key, "11"}} }, ChildBudgetOver},
			}
			if mode == "key" {
				changes = append(changes, struct {
					name string
					edit func(*R1Child)
					want error
				}{"key", func(c *R1Child) { other := "another"; c.Recipient.RequestKey = &other }, ChildGranteeNotAllowed})
			}
			if mode == "name" {
				changes = append(changes, struct {
					name string
					edit func(*R1Child)
					want error
				}{"name", func(c *R1Child) { other := name; other.Name = []byte("different"); c.Recipient.ByName = &other }, ChildGranteeNotAllowed})
			}
			for _, change := range changes {
				t.Run(change.name, func(t *testing.T) {
					changed := child
					change.edit(&changed)
					before, _ := json.Marshal(struct {
						T RowTemplate
						C R1Child
					}{template, changed})
					if err := CheckR1Fit(R1InForce051, 1, template, changed); err != change.want {
						t.Fatalf("fit got %v, want %v", err, change.want)
					}
					after, _ := json.Marshal(struct {
						T RowTemplate
						C R1Child
					}{template, changed})
					if string(before) != string(after) {
						t.Fatal("fit changed input")
					}
				})
			}
		})
	}
}
