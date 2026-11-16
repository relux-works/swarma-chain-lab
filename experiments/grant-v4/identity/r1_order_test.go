package identity

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func r1FullParent(t *testing.T) (R1Parent, R1Child, ClassObservation) {
	t.Helper()
	_, fixtures := r1ClassFixtures(t)
	issuer, template, child, o := r1Admission(t, fixtures[0])
	template.Executor = RowExecutor{"service.example", issuer.Owner.String()[2:]}
	template.Limits = []RowLimit{{RowLimitKey{"model", "tokens", "token", ""}, "10"}}
	parent := R1Parent{Issuer: issuer, Notaries: []string{template.Certifier}, Rows: RowGroups{
		Seal: RowOutpoint{strings.Repeat("a", 64), 0}, Pools: append([]RowLimit(nil), template.Limits...),
		Groups: []RowGroup{{Template: template, Ranges: []RowRange{{TxID: strings.Repeat("b", 64), First: 5, Count: 1, Script: append([]byte{0, 20}, make([]byte, 20)...)}}}},
	}}
	return parent, R1Child{1, template.Executor, child, append([]RowLimit(nil), template.Limits...)}, o
}

// Each R2 predicate has a positive, a single-defect negative and every later
// defect compounded with it. Refusal precedence is checked before any state
// predicate, with no leaked key/policy and no mutation of caller input.
func TestR1ChildOrder(t *testing.T) {
	defects := []struct {
		name string
		code error
		edit func(*R1Child)
	}{
		{"ordinal", ChildOrdinal, func(c *R1Child) { c.Ordinal = 2 }},
		{"executor", ChildAgentNotAllowed, func(c *R1Child) { c.Executor.Key = strings.Repeat("0", 64) }},
		{"recipient", ChildGranteeNotAllowed, func(c *R1Child) { key := "other"; c.Recipient = Recipient{RequestKey: &key} }},
		{"budget", ChildBudgetOver, func(c *R1Child) { c.Limits[0].Amount = "11" }},
	}
	for i, first := range defects {
		for j := i; j < len(defects); j++ {
			t.Run(first.name+"-before-"+defects[j].name, func(t *testing.T) {
				p, c, o := r1FullParent(t)
				if r, e := CheckR1Child(R1DraftLab, p, c, o); e != nil || r.Key == "" || !r.AttestationRequired {
					t.Fatalf("R1 valid child: %+v %v", r, e)
				}
				first.edit(&c)
				defects[j].edit(&c)
				before, _ := json.Marshal(struct {
					P R1Parent
					C R1Child
					O ClassObservation
				}{p, c, o})
				result, err := CheckR1Child(R1DraftLab, p, c, o)
				if !errors.Is(err, first.code) || result != (RowRecipientResult{}) {
					t.Fatalf("R1 order got %+v %v, want %v", result, err, first.code)
				}
				after, _ := json.Marshal(struct {
					P R1Parent
					C R1Child
					O ClassObservation
				}{p, c, o})
				if !bytes.Equal(before, after) {
					t.Fatal("R1 refusal changed input")
				}
			})
		}
	}
	t.Run("budget-before-class", func(t *testing.T) {
		p, c, o := r1FullParent(t)
		c.Limits[0].Amount = "11"
		o.Landlords = nil
		if _, e := CheckR1Child(R1DraftLab, p, c, o); e != ChildBudgetOver {
			t.Fatalf("R1 budget order: %v", e)
		}
	})
	t.Run("executor-name", func(t *testing.T) {
		p, c, o := r1FullParent(t)
		c.Executor.Name = "other.example"
		if _, e := CheckR1Child(R1DraftLab, p, c, o); e != ChildAgentNotAllowed {
			t.Fatal(e)
		}
	})
	t.Run("new-limit", func(t *testing.T) {
		p, c, o := r1FullParent(t)
		c.Limits[0].Key.Resource = "other"
		if _, e := CheckR1Child(R1DraftLab, p, c, o); e != ChildBudgetOver {
			t.Fatal(e)
		}
	})
	t.Run("unadmitted-parent", func(t *testing.T) {
		p, c, o := r1FullParent(t)
		o.ParentAdmitted = false
		if _, e := CheckR1Child(R1DraftLab, p, c, o); e != ClassHistoryUnavailable {
			t.Fatal(e)
		}
	})
}

// J9 requires the issuer's exact name/registration/pin and no stop coin; a
// certifier's presence is determined by the parent, never by child presentation.
// The row API has no attestation bytes/callback and therefore cannot read one.
func TestR1CertifierBoundary(t *testing.T) {
	_, fixtures := r1ClassFixtures(t)
	var fixture r1FixtureAdmission
	for _, f := range fixtures {
		if f.ID == "certifier-01" {
			fixture = f
		}
	}
	issuer, template, child, o := r1Admission(t, fixture)
	result, err := CheckRowRecipient(R1DraftLab, issuer, template, child, o)
	if err != nil || result.AttestationRequired || result.Key == "" {
		t.Fatalf("R1 own row: %+v %v", result, err)
	}
	template.StopCoin = &RowOutpoint{strings.Repeat("c", 64), 0}
	if e := CheckRowTemplate(R1DraftLab, issuer, nil, template); e != R1RuleError("R10.5") {
		t.Fatalf("R1 stop coin admitted: %v", e)
	}
	template.StopCoin = nil
	template.Certifier = "id/certifier"
	result, err = CheckRowRecipient(R1DraftLab, issuer, template, child, o)
	if err != nil || !result.AttestationRequired {
		t.Fatalf("R1 certifier dropped: %+v %v", result, err)
	}
}

// Missing or incoherent class observations cannot pass. The same admitted
// name/key is returned only from the checked script; a channel-only update is
// re-read, while unavailable facts expose no key/policy and modify no input.
func TestR1ObservationBoundary(t *testing.T) {
	_, fixtures := r1ClassFixtures(t)
	for _, test := range []struct {
		name string
		edit func(*ClassObservation)
		code error
	}{
		{"missing-pending-read", func(o *ClassObservation) { o.Landlords[0].PendingKnown = false }, ClassHistoryUnavailable},
		{"different-tip", func(o *ClassObservation) { o.Landlords[0].Name.Tip = At(801) }, ClassHistoryUnavailable},
		{"different-depth", func(o *ClassObservation) { o.Landlords[0].Name.Depth = 1 }, ClassHistoryUnavailable},
		{"missing-recipient-transaction", func(o *ClassObservation) { o.Recipient.Transactions = false }, RecipientNameUnavailable},
		{"missing-recipient-height", func(o *ClassObservation) { o.Recipient.ConfirmedAt = Height{} }, RecipientNameUnavailable},
		{"bounded-walk", func(o *ClassObservation) { n := uint64(1); o.Landlords[0].Name.StepBound = &n }, ClassHistoryUnavailable},
		{"different-registration-pin", func(o *ClassObservation) { o.Landlords[0].Binding.Registration.Vout++ }, ClassHistoryUnavailable},
		{"duplicate-landlord", func(o *ClassObservation) { o.Landlords = append(o.Landlords, o.Landlords[0]) }, ClassHistoryUnavailable},
		{"no-writer-input", func(o *ClassObservation) { o.Recipient.Inputs = nil }, ClassHistoryUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			issuer, template, child, o := r1Admission(t, fixtures[0])
			if _, e := CheckRowRecipient(R1DraftLab, issuer, template, child, o); e != nil {
				t.Fatal(e)
			}
			test.edit(&o)
			before, _ := json.Marshal(o)
			result, err := CheckRowRecipient(R1DraftLab, issuer, template, child, o)
			if !errors.Is(err, test.code) || result != (RowRecipientResult{}) {
				t.Fatalf("R1 missing fact: %+v %v", result, err)
			}
			after, _ := json.Marshal(o)
			if !bytes.Equal(before, after) {
				t.Fatal("R1 changed observations")
			}
		})
	}
	t.Run("channel-from-checked-value", func(t *testing.T) {
		issuer, template, child, o := r1Admission(t, fixtures[0])
		result, e := CheckRowRecipient(R1DraftLab, issuer, template, child, o)
		if e != nil {
			t.Fatal(e)
		}
		ns, ok := ParseNameScript(o.Recipient.Script)
		if !ok {
			t.Fatal("fixture")
		}
		changed := bytes.Replace(ns.Value, []byte(result.Key), []byte(issuer.Owner.String()[2:]), 1)
		if bytes.Equal(changed, ns.Value) {
			t.Fatal("key control not applied")
		}
		o.Recipient.Script = bytes.Replace(o.Recipient.Script, ns.Value, changed, 1)
		next, e := CheckRowRecipient(R1DraftLab, issuer, template, child, o)
		if e != nil || next.Key != issuer.Owner.String()[2:] || next.Key == result.Key {
			t.Fatalf("R1 channel not re-read: %+v %v", next, e)
		}
	})
}

// Certified exact-name mode makes no landlord/class read and needs no swarma
// member. Its channel still comes from that name's owned current output.
func TestR1CertifiedExactName(t *testing.T) {
	_, fixtures := r1ClassFixtures(t)
	issuer, template, child, o := r1Admission(t, fixtures[0])
	template.Recipient = RowRecipient{Name: child.ByName}
	o.Landlords = nil
	_, ns := ReadOutput(o.Recipient.Script, child.ByName.Owner, o.Recipient.ConfirmedAt, o.Chain)
	value, _ := ReadR1Value(R1DraftLab, ns.Value)
	channelOnly := []byte(`{"nostr":"` + value.ChannelKey + `"}`)
	// Build the same update grammar with the shorter current value.
	script := []byte{0x53, byte(len(ns.Name))}
	script = append(script, ns.Name...)
	script = append(script, 0x4c, byte(len(channelOnly)))
	script = append(script, channelOnly...)
	script = append(script, 0x6d, 0x75)
	script = append(script, ns.AddressScript...)
	o.Recipient.Script = script
	result, err := CheckRowRecipient(R1DraftLab, issuer, template, child, o)
	if err != nil || result.Key != value.ChannelKey || !result.AttestationRequired {
		t.Fatalf("R1 certified name: %+v %v", result, err)
	}
	o.Recipient.Script = nil
	if result, err = CheckRowRecipient(R1DraftLab, issuer, template, child, o); err != RecipientNameUnavailable || result != (RowRecipientResult{}) {
		t.Fatalf("R1 unsupported name: %+v %v", result, err)
	}
}

// Returned scripts and swarma spans are owned copies; refused selectors return
// no row, and valid controls still pass after mutations of returned values.
func TestR1ReturnOwnership(t *testing.T) {
	p, _, _ := r1FullParent(t)
	selected, e := SelectRow(R1DraftLab, p.Rows, 1)
	if e != nil {
		t.Fatal(e)
	}
	original := bytes.Clone(p.Rows.Groups[0].Ranges[0].Script)
	selected.Script[0] ^= 255
	if !bytes.Equal(original, p.Rows.Groups[0].Ranges[0].Script) {
		t.Fatal("R1 selected script aliases input")
	}
	raw := []byte(`{"swarma":{"landlord":{"grant":"` + p.Issuer.Owner.String()[2:] + `"}}}`)
	value, e := ReadR1Value(R1DraftLab, raw)
	if e != nil {
		t.Fatal(e)
	}
	before := bytes.Clone(raw)
	value.Swarma[0] ^= 255
	if !reflect.DeepEqual(raw, before) {
		t.Fatal("R1 span aliases input")
	}
}

// Every template is validated before a parent admits any row; defects in a
// later group cannot be hidden by selecting the first group's otherwise valid child.
func TestR1ParentAtomic(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*R1Parent)
		code error
	}{
		{"later-template", func(p *R1Parent) { p.Rows.Groups[1].Template.Certifier = "id/unpinned" }, R1RuleError("R10.1")},
		{"later-executor", func(p *R1Parent) { p.Rows.Groups[1].Template.Executor.Key = "invalid" }, R1RuleError("R8.1")},
		{"later-key-and-class", func(p *R1Parent) { k := "key"; p.Rows.Groups[1].Template.Recipient.Key = &k }, R1RuleError("R9.1")},
	} {
		t.Run(test.name, func(t *testing.T) {
			p, c, o := r1FullParent(t)
			second := p.Rows.Groups[0]
			second.Ranges = append([]RowRange(nil), second.Ranges...)
			second.Ranges[0].TxID = strings.Repeat("c", 64)
			p.Rows.Groups = append(p.Rows.Groups, second)
			p.Rows.Pools[0].Amount = "20"
			if _, e := CheckR1Child(R1DraftLab, p, c, o); e != nil {
				t.Fatal(e)
			}
			test.edit(&p)
			result, e := CheckR1Child(R1DraftLab, p, c, o)
			if !errors.Is(e, test.code) || result != (RowRecipientResult{}) {
				t.Fatalf("R1 parent partial acceptance: %+v %v", result, e)
			}
		})
	}
}

// Exact integers and complete limit identities prevent a missing resource,
// period mismatch or duplicate key from acquiring an allowance by omission.
func TestR1LimitBoundaries(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*R1Parent, *R1Child)
		code error
	}{
		{"negative-parent", func(p *R1Parent, c *R1Child) { p.Rows.Groups[0].Template.Limits[0].Amount = "-1" }, R1RuleError("R8.5")},
		{"leading-zero", func(p *R1Parent, c *R1Child) { p.Rows.Pools[0].Amount = "010" }, R1RuleError("R8.5")},
		{"duplicate-pool", func(p *R1Parent, c *R1Child) { p.Rows.Pools = append(p.Rows.Pools, p.Rows.Pools[0]) }, R1RuleError("R8.5")},
		{"duplicate-row", func(p *R1Parent, c *R1Child) {
			p.Rows.Groups[0].Template.Limits = append(p.Rows.Groups[0].Template.Limits, p.Rows.Groups[0].Template.Limits[0])
		}, R1RuleError("R8.5")},
		{"duplicate-child", func(p *R1Parent, c *R1Child) { c.Limits = append(c.Limits, c.Limits[0]) }, ChildBudgetOver},
		{"negative-child", func(p *R1Parent, c *R1Child) { c.Limits[0].Amount = "-1" }, ChildBudgetOver},
		{"period", func(p *R1Parent, c *R1Child) { c.Limits[0].Key.Period = "different-period" }, ChildBudgetOver},
		{"empty-kind", func(p *R1Parent, c *R1Child) { c.Limits[0].Key.Kind = "" }, ChildBudgetOver},
	} {
		t.Run(test.name, func(t *testing.T) {
			p, c, o := r1FullParent(t)
			if _, e := CheckR1Child(R1DraftLab, p, c, o); e != nil {
				t.Fatal(e)
			}
			test.edit(&p, &c)
			r, e := CheckR1Child(R1DraftLab, p, c, o)
			if !errors.Is(e, test.code) || r != (RowRecipientResult{}) {
				t.Fatalf("R1 limit invariant: %+v %v", r, e)
			}
		})
	}
	p, c, o := r1FullParent(t)
	c.Limits[0].Amount = "0"
	if _, e := CheckR1Child(R1DraftLab, p, c, o); e != nil {
		t.Fatal(e)
	}
	c.Limits = nil
	if _, e := CheckR1Child(R1DraftLab, p, c, o); e != nil {
		t.Fatal(e)
	}
}

// Exact name and established request-key constraints compare every signed
// identity part. Key mode reads no recipient/class facts; exact certified name
// mode still proves current ownership and needs its certifier afterwards.
func TestR1RecipientModes(t *testing.T) {
	t.Run("key", func(t *testing.T) {
		p, c, o := r1FullParent(t)
		key := p.Issuer.Owner.String()[2:]
		p.Rows.Groups[0].Template.Recipient = RowRecipient{Key: &key}
		c.Recipient = Recipient{RequestKey: &key}
		o.Recipient = ClassNameEvidence{}
		o.Landlords = nil
		result, err := CheckR1Child(R1DraftLab, p, c, o)
		if err != nil || result.Key != key || !result.AttestationRequired {
			t.Fatalf("R1 key-mode control: %+v %v", result, err)
		}
		other := "other-established-key"
		c.Recipient.RequestKey = &other
		if result, err = CheckR1Child(R1DraftLab, p, c, o); err != ChildGranteeNotAllowed || result != (RowRecipientResult{}) {
			t.Fatalf("R1 key mismatch: %+v %v", result, err)
		}
	})
	for _, part := range []string{"name", "owner"} {
		t.Run("exact-"+part, func(t *testing.T) {
			p, c, o := r1FullParent(t)
			name := *c.Recipient.ByName
			p.Rows.Groups[0].Template.Recipient = RowRecipient{Name: &name}
			if _, err := CheckR1Child(R1DraftLab, p, c, o); err != nil {
				t.Fatal(err)
			}
			changed := *c.Recipient.ByName
			if part == "name" {
				changed.Name = []byte("id/other")
			} else {
				changed.Owner = p.Issuer.Owner
			}
			c.Recipient.ByName = &changed
			result, err := CheckR1Child(R1DraftLab, p, c, o)
			if err != ChildGranteeNotAllowed || result != (RowRecipientResult{}) {
				t.Fatalf("R1 exact-name binding: %+v %v", result, err)
			}
		})
	}
}
