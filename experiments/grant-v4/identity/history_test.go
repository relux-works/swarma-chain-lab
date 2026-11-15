package identity

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
)

type walkVector struct {
	ID, Rule, Claim string
	Neighbour       string `json:"valid_neighbour"`
	Context         struct {
		Recent       int64   `json:"recent_block_height"`
		Checkpoint   int64   `json:"checkpoint_height"`
		Tip          int64   `json:"tip_height"`
		Depth        int64   `json:"depth"`
		Registration string  `json:"bound_registration"`
		Swarma       string  `json:"bound_swarma"`
		Evidence     string  `json:"evidence_output"`
		Bound        *uint64 `json:"step_bound"`
		Indexed      *bool   `json:"transaction_index"`
	}
	History []struct {
		ID, Prefix, Reading, Swarma, Writer string
		Height                              int64
		Readable                            *bool
	}
	Expect json.RawMessage
}

func walkInput(t *testing.T, v walkVector) (StatedName, HistoryPredicate) {
	t.Helper()
	s := StatedName{Name: []byte("id/lip0021-issuer"), Owner: pin(t, testOwner), Tip: At(v.Context.Tip),
		Depth: v.Context.Depth, Current: CurrentOutput, Transactions: v.Context.Indexed == nil || *v.Context.Indexed,
		StepBound: v.Context.Bound}
	for _, row := range v.History {
		out := StatedOutput{ID: row.ID, Height: At(row.Height), Name: s.Name,
			Available: row.Readable == nil || *row.Readable,
			Prefix:    map[string]Prefix{"update": PrefixUpdate, "registration": PrefixRegistration}[row.Prefix],
			Reading:   map[string]Reading{"controlled": Controlled, "another key": AnotherKey}[row.Reading],
			Writer:    map[string]Writer{"written by the owner": WrittenByOwner, "written by another": WrittenByAnother}[row.Writer]}
		if row.Swarma != "none" {
			out.Swarma = []byte(row.Swarma)
		}
		s.Outputs = append(s.Outputs, out)
	}
	p := HistoryPredicate{Rule: IssuerHistory, Registration: v.Context.Registration,
		From: At(v.Context.Recent), Swarma: []byte(v.Context.Swarma)}
	if v.Rule == "notary" {
		p.Rule, p.From = NotaryHistory, At(v.Context.Checkpoint)
	}
	return s, p
}

func walkRows(t *testing.T, rule string) ([]vector, map[string]walkVector) {
	t.Helper()
	v := loadVectors(t)
	if len(v.Walks) != 56 {
		t.Fatalf("walk count %d; want 56", len(v.Walks))
	}
	var rows []vector
	index := map[string]walkVector{}
	for _, row := range v.Walks {
		if row.Rule == rule {
			rows = append(rows, vector{ID: row.ID, Claim: row.Claim, Neighbour: row.Neighbour, Expect: row.Expect})
			index[row.ID] = row
		}
	}
	return rows, index
}

func decisionResult(t *testing.T, d Decision) any {
	t.Helper()
	if d.Passes() {
		if len(d.Refusals()) != 0 {
			t.Fatal("passing decision carries refusal")
		}
		return "ok"
	}
	if len(d.Refusals()) != 1 {
		t.Fatalf("vector needs exactly one refusal: %v", d.Refusals())
	}
	return string(d.Refusals()[0])
}

func runWalkRule(t *testing.T, rule string) {
	t.Helper()
	rows, index := walkRows(t, rule)
	want := map[string]int{"issuer": 29, "recipient": 5, "consent": 12, "notary": 10}[rule]
	if len(rows) != want {
		t.Fatalf("%s count %d; want %d", rule, len(rows), want)
	}
	runVectors(t, rows, func(t *testing.T, row vector) any {
		v := index[row.ID]
		s, p := walkInput(t, v)
		switch rule {
		case "recipient":
			return decisionResult(t, CheckRecipientOwner(s))
		case "consent":
			return decisionResult(t, CheckConsentEvidence(s, At(v.Context.Recent), v.Context.Evidence))
		default:
			return decisionResult(t, CheckHistory(s, p))
		}
	})
}

// TestV4IssuerHistory proves all 29 issuer vectors, including renewal, re-registration, return, R boundaries and incomplete history; no chain read is qualified.
func TestV4IssuerHistory(t *testing.T) { runWalkRule(t, "issuer") }

// TestV4RecipientHistory proves all five current-owner verdict vectors; it intentionally makes no recipient-history closure claim.
func TestV4RecipientHistory(t *testing.T) { runWalkRule(t, "recipient") }

// TestV4ConsentHistory proves all 12 evidence-at-R vectors; it excludes consent signatures, timestamps and single-use storage.
func TestV4ConsentHistory(t *testing.T) { runWalkRule(t, "consent") }

// TestV4NotaryHistoryPredicate proves ten notary vectors and bounded cache-identity separation; no cache storage or reorg detector is implemented.
func TestV4NotaryHistoryPredicate(t *testing.T) {
	runWalkRule(t, "notary")
	t.Run("cache-rule-separation", func(t *testing.T) {
		_, rows := walkRows(t, "issuer")
		s, p := walkInput(t, rows["walk-issuer-01"])
		key, err := p.CacheKey(s, "chain-through-o4", "o4")
		if err != nil {
			t.Fatal(err)
		}
		notary := p
		notary.Rule = NotaryHistory
		nk, err := notary.CacheKey(s, "chain-through-o4", "o4")
		if err != nil || key == nk {
			t.Fatalf("issuer and notary cache keys collide: %v", err)
		}
	})
}

const testOwner = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
const oldKey = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
const newKey = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"

func recipientFixture(t *testing.T) (Recipient, StatedName) {
	t.Helper()
	// Non-id/ is deliberate: namespace prefixes grant no recipient authority.
	name := []byte("d/recipient")
	s := StatedName{Name: name, Owner: pin(t, testOwner), Tip: At(800), Depth: 36000,
		Current: CurrentOutput, Transactions: true, Outputs: []StatedOutput{{ID: "current", Height: At(700),
			Available: true, Name: name, Prefix: PrefixUpdate, Reading: Controlled, Writer: WrittenByOwner,
			Swarma: []byte("S1"), Nostr: NostrMember{Names: map[string]string{"_": newKey, "other": oldKey}}}}}
	return Recipient{ByName: &NameRecipient{Name: name, Owner: s.Owner}}, s
}

// TestV4RecipientUnion proves mode exclusion, current-channel selection and refusal before key resolution; it does not verify a request signature.
func TestV4RecipientUnion(t *testing.T) {
	r, s := recipientFixture(t)
	t.Run("any-namespace", func(t *testing.T) {
		key, err := ResolveRecipient(r, "nostr", &s)
		if err != nil || key != newKey {
			t.Fatalf("current selected channel key: %q, %v", key, err)
		}
	})
	t.Run("both-or-neither", func(t *testing.T) {
		for _, bad := range []Recipient{{}, {RequestKey: strptr(oldKey), ByName: r.ByName}} {
			if key, err := ResolveRecipient(bad, "nostr", &s); key != "" || !errors.Is(err, ErrRecipientUnion) {
				t.Fatalf("union returned key=%q err=%v", key, err)
			}
		}
	})
	t.Run("old-key-refused", func(t *testing.T) {
		if err := CheckRecipientKey(r, "nostr", newKey, &s); err != nil {
			t.Fatal(err)
		}
		if err := CheckRecipientKey(r, "nostr", oldKey, &s); !errors.Is(err, ErrRecipientKey) {
			t.Fatalf("old key got %v", err)
		}
	})
	t.Run("direct-key-no-read", func(t *testing.T) {
		key, err := ResolveRecipient(Recipient{RequestKey: strptr(oldKey)}, "nostr", nil)
		if err != nil || key != oldKey {
			t.Fatalf("direct key: %q %v", key, err)
		}
		if _, err := ResolveRecipient(Recipient{RequestKey: strptr("")}, "nostr", nil); !errors.Is(err, ErrRecipientKey) {
			t.Fatalf("empty key: %v", err)
		}
	})
	t.Run("owner-before-channel", func(t *testing.T) {
		bad := s
		bad.Outputs = append([]StatedOutput(nil), s.Outputs...)
		bad.Outputs[0].Reading, bad.Outputs[0].Nostr = AnotherKey, NostrMember{}
		if key, err := ResolveRecipient(r, "nostr", &bad); key != "" || err != RecipientNameNotHeld {
			t.Fatalf("ownership must refuse first, got %q %v", key, err)
		}
		bad.Outputs[0].Reading = Unsupported
		if _, err := ResolveRecipient(r, "nostr", &bad); err != RecipientNameUnavailable {
			t.Fatalf("unsupported ownership: %v", err)
		}
	})
	t.Run("channel-and-key-boundaries", func(t *testing.T) {
		if _, err := ResolveRecipient(r, "unknown", &s); !errors.Is(err, ErrChannel) {
			t.Fatalf("unknown channel: %v", err)
		}
		for i, member := range []NostrMember{{}, {Names: map[string]string{"other": newKey}},
			{Key: newKey, Names: map[string]string{"_": newKey}}, {Key: "invalid"}, {Key: fmt.Sprintf("%064x", 0)}} {
			bad := s
			bad.Outputs = append([]StatedOutput(nil), s.Outputs...)
			bad.Outputs[0].Nostr = member
			if key, err := ResolveRecipient(r, "nostr", &bad); key != "" || !errors.Is(err, ErrChannel) {
				t.Fatalf("member %d returned %q %v", i, key, err)
			}
		}
		s.Outputs[0].Nostr = NostrMember{Key: newKey}
		if key, err := ResolveRecipient(r, "nostr", &s); key != newKey || err != nil {
			t.Fatalf("key-string control: %q %v", key, err)
		}
	})
}

func strptr(s string) *string { return &s }

// TestV4ConsentSnapshotKey distinguishes historical consent from current request keys after rotation, with owner/evidence failures beside the valid controls.
func TestV4ConsentSnapshotKey(t *testing.T) {
	r, s := recipientFixture(t)
	evidence := s.Outputs[0]
	evidence.ID, evidence.Height, evidence.Nostr = "evidence", At(400), NostrMember{Key: oldKey}
	s.Outputs = append(s.Outputs, evidence)
	if !CheckConsentKey(s, At(500), "evidence", oldKey).Passes() || CheckRecipientKey(r, "nostr", newKey, &s) != nil {
		t.Fatal("historical consent or current request control failed")
	}
	if got := CheckConsentKey(s, At(500), "evidence", newKey); fmt.Sprint(got.Refusals()) != "[CONSENT_KEY]" {
		t.Fatalf("current key substituted at snapshot: %v", got.Refusals())
	}
	if got := CheckConsentKey(s, At(700), "evidence", oldKey); fmt.Sprint(got.Refusals()) != "[CONSENT_EVIDENCE]" {
		t.Fatalf("evidence replaced at R: %v", got.Refusals())
	}
	// Same-owner re-registration passes current admission, but cannot reach the old consent evidence.
	s.Outputs[0].Prefix, s.Outputs[0].ID = PrefixRegistration, "new-registration"
	if !CheckRecipientOwner(s).Passes() || CheckConsentEvidence(s, At(500), "evidence").Passes() {
		t.Fatal("recipient renewal and historical consent were conflated")
	}
}

// TestV4WalkMissingFacts proves explicit absence differs from missing data and malformed/bounded chains cannot pass; current expiry needs no transaction read.
func TestV4WalkMissingFacts(t *testing.T) {
	_, rows := walkRows(t, "issuer")
	base, p := walkInput(t, rows["walk-issuer-01"])
	if !CheckHistory(base, p).Passes() || (Decision{}).Passes() {
		t.Fatal("control or zero decision")
	}
	cases := []struct {
		name string
		edit func(*StatedName)
	}{
		{"zero-owner", func(s *StatedName) { s.Owner = Pin{} }},
		{"unknown-tip", func(s *StatedName) { s.Tip = Height{} }},
		{"unknown-current", func(s *StatedName) { s.Current = CurrentUnknown }},
		{"zero-depth", func(s *StatedName) { s.Depth = 0 }},
		{"empty-history", func(s *StatedName) { s.Outputs = nil }},
		{"missing-height", func(s *StatedName) { s.Outputs[1].Height = Height{} }},
		{"future-height", func(s *StatedName) { s.Outputs[0].Height = At(801) }},
		{"ascending-link", func(s *StatedName) { s.Outputs[1].Height = At(701) }},
		{"duplicate-output", func(s *StatedName) { s.Outputs[1].ID = s.Outputs[0].ID }},
		{"wrong-name", func(s *StatedName) { s.Outputs[1].Name = []byte("d/other") }},
		{"zero-bound", func(s *StatedName) { n := uint64(0); s.StepBound = &n }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := base
			s.Outputs = append([]StatedOutput(nil), base.Outputs...)
			tc.edit(&s)
			d := CheckHistory(s, p)
			if d.Passes() || fmt.Sprint(d.Refusals()) != "[ISSUER_HISTORY_UNAVAILABLE]" {
				t.Fatalf("missing/malformed fact was treated as a name verdict: %v", d.Refusals())
			}
		})
	}
	base.Current, base.Outputs, base.Transactions = NoLiveOutput, nil, false
	if got := CheckHistory(base, p); fmt.Sprint(got.Refusals()) != "[ISSUER_NAME_CHANGED]" {
		t.Fatalf("known absence: %v", got.Refusals())
	}
	if got := CheckRecipientOwner(base); fmt.Sprint(got.Refusals()) != "[RECIPIENT_NAME_NOT_HELD]" {
		t.Fatalf("known recipient absence: %v", got.Refusals())
	}
	if CheckHistory(StatedName{}, HistoryPredicate{}).Passes() || CheckRecipientOwner(StatedName{}).Passes() ||
		CheckConsentEvidence(StatedName{}, Height{}, "").Passes() {
		t.Fatal("unstated facts passed")
	}
}

// TestV4CachePredicateInputs proves R, registration, pin, member, output and active-chain identity separate saved computations; it asserts no live cache invalidation.
func TestV4CachePredicateInputs(t *testing.T) {
	_, rows := walkRows(t, "issuer")
	s, p := walkInput(t, rows["walk-issuer-01"])
	key, err := p.CacheKey(s, "chain-A", "o4")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func(*StatedName, *HistoryPredicate, *string, *string)
	}{
		{"R", func(_ *StatedName, p *HistoryPredicate, _, _ *string) { p.From = At(499) }},
		{"registration", func(_ *StatedName, p *HistoryPredicate, _, _ *string) { p.Registration = "reg-B" }},
		{"owner", func(s *StatedName, _ *HistoryPredicate, _, _ *string) { s.Owner = pin(t, "02"+oldKey) }},
		{"member", func(_ *StatedName, p *HistoryPredicate, _, _ *string) { p.Swarma = []byte("S2") }},
		{"name", func(s *StatedName, _ *HistoryPredicate, _, _ *string) { s.Name = []byte("d/other") }},
		{"chain", func(_ *StatedName, _ *HistoryPredicate, c, _ *string) { *c = "chain-B" }},
		{"output", func(_ *StatedName, _ *HistoryPredicate, _, o *string) { *o = "o3" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s2, p2, c, o := s, p, "chain-A", "o4"
			tc.edit(&s2, &p2, &c, &o)
			other, err := p2.CacheKey(s2, c, o)
			if err != nil || key == other {
				t.Fatalf("different predicate reused key: %v", err)
			}
		})
	}
	if _, err := (HistoryPredicate{}).CacheKey(s, "chain-A", "o4"); !errors.Is(err, ErrHistoryPredicate) {
		t.Fatalf("zero predicate: %v", err)
	}
	if _, err := p.CacheKey(s, "", "o4"); !errors.Is(err, ErrHistoryPredicate) {
		t.Fatalf("missing chain identity: %v", err)
	}
	if again, err := p.CacheKey(s, "chain-A", "o4"); again != key || err != nil {
		t.Fatal("identical predicate was unstable")
	}
}

// TestV4NotaryCompoundFindings preserves the draft's absence of a priority for simultaneous notary walk findings; it does not invent a first code.
func TestV4NotaryCompoundFindings(t *testing.T) {
	_, rows := walkRows(t, "notary")
	s, p := walkInput(t, rows["walk-notary-05"])
	s.Outputs[0].Reading, s.Outputs[1].Reading = AnotherKey, Unsupported
	got := CheckHistory(s, p)
	if got.Passes() || fmt.Sprint(got.Refusals()) != "[NOTARY_NAME_CHANGED NOTARY_HISTORY_UNAVAILABLE]" {
		t.Fatalf("notary finding set: %v", got.Refusals())
	}
	codes := got.Refusals()
	codes[0] = ConsentKey
	if got.Refusals()[0] != NotaryNameChanged {
		t.Fatal("caller changed the returned finding set")
	}
}

// TestV4OwnerSignedChange distinguishes a proved owner/member change from unsupported evidence and unchanged renewals; no closure is ever written.
func TestV4OwnerSignedChange(t *testing.T) {
	_, s := recipientFixture(t)
	spent := s.Outputs[0]
	if got := ReadOwnerSignedChange(spent, spent); got != ChangeUnchanged {
		t.Fatalf("renewal control: %v", got)
	}
	for _, tc := range []struct {
		name string
		edit func(*StatedOutput)
		want ChangeReading
	}{
		{"transfer", func(o *StatedOutput) { o.Reading = AnotherKey }, ChangeProved},
		{"member", func(o *StatedOutput) { o.Swarma = []byte("S2") }, ChangeProved},
		{"missing-member", func(o *StatedOutput) { o.Swarma = nil }, ChangeProved},
		{"unsupported-owner", func(o *StatedOutput) { o.Reading = Unsupported }, ChangeUnproven},
		{"unsupported-owner-changed-member", func(o *StatedOutput) { o.Reading, o.Swarma = Unsupported, []byte("S2") }, ChangeProved},
		{"unsupported-prefix", func(o *StatedOutput) { o.Prefix, o.Swarma = PrefixNone, nil }, ChangeUnproven},
		{"unsupported-writer", func(o *StatedOutput) { o.Writer, o.Reading = WriterUnsupported, AnotherKey }, ChangeUnproven},
		{"another-writer", func(o *StatedOutput) { o.Writer, o.Swarma = WrittenByAnother, nil }, ChangeUnproven},
	} {
		t.Run(tc.name, func(t *testing.T) {
			next := spent
			tc.edit(&next)
			if got := ReadOwnerSignedChange(spent, next); got != tc.want {
				t.Fatalf("change predicate got %v, want %v", got, tc.want)
			}
		})
	}
}

// TestV4WalkOctetIntegration connects script/writer checks to a stated output; it does not validate transactions or derive their input links.
func TestV4WalkOctetIntegration(t *testing.T) {
	v := loadVectors(t)
	row := v.Writers[0]
	_, inputs := writerInput(t, row)
	out := ReadStatedOutput("o", octets(t, v.Scripts[0].Script), At(700), inputs, pin(t, row.Pin), chain(t, v.Parameters.WitnessFrom))
	if out.Reading != Controlled || out.Writer != WrittenByOwner || out.Prefix != PrefixUpdate {
		t.Fatalf("octet integration control: %v %v %v", out.Reading, out.Writer, out.Prefix)
	}
	bad := ReadStatedOutput("o", []byte{0x53}, At(700), inputs, pin(t, row.Pin), chain(t, v.Parameters.WitnessFrom))
	if bad.Reading != Unsupported || bad.Writer != WriterUnsupported || bad.Prefix != PrefixNone {
		t.Fatal("malformed script created a supported output")
	}
}
