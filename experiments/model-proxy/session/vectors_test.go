package session

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

type vectorFile struct {
	Schema    string                     `json:"schema"`
	Profile   Profile                    `json:"profile"`
	Executor  Executor                   `json:"executor"`
	Base      map[string]json.RawMessage `json:"base_facts"`
	Scenarios []scenario                 `json:"scenarios"`
}
type scenario struct {
	ID    string       `json:"id"`
	Claim string       `json:"claim"`
	Rules []string     `json:"rules"`
	Steps []vectorStep `json:"steps"`
}
type vectorStep struct {
	DiscardReply bool                       `json:"discard_reply"`
	Op           string                     `json:"op"`
	Profile      *Profile                   `json:"profile"`
	Facts        map[string]json.RawMessage `json:"facts"`
	Entropy      string                     `json:"entropy"`
	TokenFrom    string                     `json:"token_from"`
	Expect       expectation                `json:"expect"`
}
type expectation struct {
	Code     Code                         `json:"code"`
	Token    bool                         `json:"token"`
	Sessions *int                         `json:"sessions"`
	Seen     *int                         `json:"seen"`
	End      map[string]uint64            `json:"end"`
	Ended    map[string]bool              `json:"ended"`
	LastKey  map[string]string            `json:"last_key"`
	Used     map[string]map[string]uint64 `json:"used"`
	Accounts map[string]uint64            `json:"accounts"`
}

func readVectors(t *testing.T) vectorFile {
	t.Helper()
	b, err := os.ReadFile("testdata/lifecycle.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectorFile
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err = d.Decode(&v); err != nil {
		t.Fatal(err)
	}
	if v.Schema != "session-lifecycle-facts/1" {
		t.Fatal("fixture schema")
	}
	return v
}
func vectorFacts(t *testing.T, base map[string]json.RawMessage, step vectorStep, tokens map[string]Token) Facts {
	t.Helper()
	m := copyMap(base)
	for k, v := range step.Facts {
		m[k] = v
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var f Facts
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err = d.Decode(&f); err != nil {
		t.Fatal(err)
	}
	if step.Entropy != "" {
		b, err := hex.DecodeString(step.Entropy)
		if err != nil || len(b) != 32 {
			t.Fatal("entropy fixture must be 32 octets")
		}
		copy(f.Random[:], b)
		f.Token = f.Random
	}
	if step.TokenFrom != "" {
		token, ok := tokens[step.TokenFrom]
		if !ok {
			t.Fatalf("fixture references missing token %s", step.TokenFrom)
		}
		f.Token = token
	}
	return f
}
func accountView(s State) map[string]uint64 {
	out := map[string]uint64{}
	for k, v := range s.accounts {
		out[fmt.Sprintf("%s:%s:%d:%s", k.Kind, k.Grant, k.Ordinal, k.Limit)] = v
	}
	return out
}

// Each vector's claim is the specific bounded property proved by its expected
// verdicts and state assertions. Fixtures are stated facts, not signed requests.
// Refused reservations must leave every grant/row/session counter unchanged.
func TestVectors(t *testing.T) {
	v := readVectors(t)
	ids := map[string]bool{}
	for _, sc := range v.Scenarios {
		if ids[sc.ID] || sc.Claim == "" || len(sc.Rules) == 0 {
			t.Fatalf("missing claim/rules or duplicate id: %s", sc.ID)
		}
		ids[sc.ID] = true
		t.Run(sc.ID, func(t *testing.T) {
			t.Log(sc.Claim)
			s := NewState(v.Executor)
			tokens := map[string]Token{}
			var plan Prepared
			for i, step := range sc.Steps {
				t.Run(fmt.Sprintf("step-%02d", i+1), func(t *testing.T) {
					f := vectorFacts(t, v.Base, step, tokens)
					p := v.Profile
					if step.Profile != nil {
						p = *step.Profile
					}
					before := clone(s)
					original := s
					var res Result
					switch step.Op {
					case "apply":
						s, res = Apply(p, s, f)
					case "check":
						s, plan, res = CheckUse(p, s, f)
					case "reserve":
						s, res = Reserve(p, s, plan, f)
					case "restart":
						s = clone(s)
						res = result(Admitted)
					case "recover":
						s = StartAnew(s, f.Now)
						res = result(Admitted)
					case "lost":
						s = Lost(s)
						res = result(Admitted)
					case "other_service":
						s = NewState(Executor{Name: "service-b", Key: "executor-b"})
						res = result(Admitted)
					default:
						t.Fatalf("unknown fixture operation: %s", step.Op)
					}
					// Reducers must never mutate any map/slice retained by their input value.
					if !reflect.DeepEqual(before, original) {
						t.Fatal("test's immutable baseline corrupted")
					}
					if res.Code != step.Expect.Code {
						t.Fatalf("verdict=%s want=%s", res.Code, step.Expect.Code)
					}
					if (res.Token != nil) != step.Expect.Token {
						t.Fatalf("token presence=%t want=%t", res.Token != nil, step.Expect.Token)
					}
					if res.Token != nil {
						if f.Op != "open" || step.Op != "apply" || *res.Token != f.Random {
							t.Fatal("token returned outside the single opening response")
						}
						r := s.sessions[f.RequestID]
						if r.Digest != tokenDigest(*res.Token) {
							t.Fatal("stored digest differs")
						}
						if !step.DiscardReply {
							tokens[f.RequestID] = *res.Token
						}
					}
					if res.Code != Admitted {
						if len(s.sessions) != len(before.sessions) || len(s.seen) != len(before.seen) {
							t.Fatal("refusal allocated a session or request identity")
						}
						if !reflect.DeepEqual(s.accounts, before.accounts) {
							t.Fatal("refusal partially debited grant/row accounts")
						}
						for id, r := range before.sessions {
							if !reflect.DeepEqual(r.Used, s.sessions[id].Used) {
								t.Fatal("refusal partially debited session account")
							}
						}
					}
					e := step.Expect
					if e.Sessions != nil && len(s.sessions) != *e.Sessions {
						t.Fatalf("session count=%d want=%d", len(s.sessions), *e.Sessions)
					}
					if e.Seen != nil && len(s.seen) != *e.Seen {
						t.Fatalf("identity count=%d want=%d", len(s.seen), *e.Seen)
					}
					for id, want := range e.End {
						if s.sessions[id].End != want {
							t.Fatalf("end of %s=%d want=%d", id, s.sessions[id].End, want)
						}
					}
					for id, want := range e.Ended {
						if s.sessions[id].Ended != want {
							t.Fatalf("ended of %s=%t want=%t", id, s.sessions[id].Ended, want)
						}
					}
					for id, want := range e.LastKey {
						if s.sessions[id].LastKey != want {
							t.Fatalf("last key of %s differs", id)
						}
					}
					for id, want := range e.Used {
						if !reflect.DeepEqual(s.sessions[id].Used, want) {
							t.Fatalf("session usage=%v want=%v", s.sessions[id].Used, want)
						}
					}
					if e.Accounts != nil && !reflect.DeepEqual(accountView(s), e.Accounts) {
						t.Fatalf("account usage=%v want=%v", accountView(s), e.Accounts)
					}
				})
				if t.Failed() {
					break
				}
			}
		})
	}
}

// The default profile blocks all state transitions; the draft vocabulary has
// exactly eleven codes in the specification's printed order.
func TestProfileGate(t *testing.T) {
	s := NewState(Executor{Name: "service-a", Key: "executor-a"})
	f := Facts{WriteOK: true}
	next, r := Apply("", s, f)
	if r.Code != "PROFILE_DISABLED" || !reflect.DeepEqual(s, next) {
		t.Fatal("default profile admitted or changed state")
	}
	want := "SESSION_CHANNEL SESSION_REPLAY SESSION_BINDING SESSION_WINDOW SESSION_LIMITS SESSION_UNKNOWN SESSION_TOKEN SESSION_PEER SESSION_ENDED SESSION_COMMAND SESSION_LIMIT_OVER"
	got := []string{}
	for _, c := range Refusals() {
		got = append(got, string(c))
	}
	if strings.Join(got, " ") != want {
		t.Fatal("refusal vocabulary order")
	}
}

// A real random draw has 32 octets. State and Prepared recursively contain no
// Token field, and only the opening reply discloses the fixture token. An intact
// restart, replay and extension cannot disclose it. No real token is logged.
func TestTokenCustody(t *testing.T) {
	token, err := DrawToken()
	if err != nil || len(token) != 32 {
		t.Fatal("secure random draw failed")
	}
	for _, typ := range []reflect.Type{reflect.TypeOf(State{}), reflect.TypeOf(Prepared{})} {
		assertNoTokenType(t, typ, map[reflect.Type]bool{})
	}
	if fmt.Sprintf("%v %#v", token, token) != "[session token] [session token]" {
		t.Fatal("token formatting is not redacted")
	}
	v := readVectors(t)
	f := vectorFacts(t, v.Base, vectorStep{Entropy: strings.Repeat("11", 32)}, nil)
	s := NewState(v.Executor)
	next, r := Apply(Draft, s, f)
	if r.Code != Admitted || r.Token == nil || next.sessions[f.RequestID].Digest != tokenDigest(f.Random) {
		t.Fatal("opening digest/token contract")
	}
	assertNoPlaintext(t, reflect.ValueOf(next), f.Random)
	if len(s.sessions) != 0 || len(s.seen) != 0 {
		t.Fatal("open mutated input")
	}
	_, again := Apply(Draft, next, f)
	if again.Code != Replay || again.Token != nil {
		t.Fatal("token returned twice")
	}
	f.Op = "extend"
	f.RequestID = "extension"
	f.SessionID = "open-a"
	ext, r := Apply(Draft, next, f)
	if r.Code != Admitted || r.Token != nil || ext.sessions["open-a"].Digest != next.sessions["open-a"].Digest {
		t.Fatal("extension changed or returned token")
	}
	// Inputs and outputs must not share mutable authority, limits or usage maps.
	f.Path[0] = "changed"
	f.GrantLimits["requests"] = 999
	if next.sessions["open-a"].Path[0] != "grant-a" || next.sessions["open-a"].GrantLimits["requests"] != 20 {
		t.Fatal("facts aliased retained session")
	}
}
func assertNoTokenType(t *testing.T, typ reflect.Type, seen map[reflect.Type]bool) {
	t.Helper()
	if seen[typ] {
		return
	}
	seen[typ] = true
	if typ == reflect.TypeOf(Token{}) {
		t.Fatalf("stored plaintext token type in %s", typ)
	}
	switch typ.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Array:
		assertNoTokenType(t, typ.Elem(), seen)
	case reflect.Map:
		assertNoTokenType(t, typ.Key(), seen)
		assertNoTokenType(t, typ.Elem(), seen)
	case reflect.Struct:
		for i := 0; i < typ.NumField(); i++ {
			assertNoTokenType(t, typ.Field(i).Type, seen)
		}
	}
}

// Every case named in §9 is represented, and every service T-rule has named
// vector evidence. Key-holder rules are explicitly external; K cases demonstrate
// the service's inability to enforce origins and the limits of peer binding.
func TestCaseAndRuleCoverage(t *testing.T) {
	v := readVectors(t)
	ids := map[string]bool{}
	rules := map[string]bool{}
	for _, sc := range v.Scenarios {
		ids[sc.ID] = true
		for _, r := range sc.Rules {
			rules[r] = true
		}
	}
	for i := 1; i <= 24; i++ {
		if !ids[fmt.Sprintf("S13-%d", i)] {
			t.Fatalf("missing S13-%d", i)
		}
	}
	for i := 1; i <= 4; i++ {
		if !ids[fmt.Sprintf("S13-K%d", i)] {
			t.Fatalf("missing S13-K%d", i)
		}
	}
	for sec, n := range map[int]int{1: 3, 2: 7, 3: 5, 4: 7, 5: 8, 6: 4, 8: 4} {
		for i := 1; i <= n; i++ {
			r := fmt.Sprintf("T%d.%d", sec, i)
			if !rules[r] {
				t.Fatalf("missing rule %s", r)
			}
		}
	}
	names := make([]string, 0, len(ids))
	for id := range ids {
		names = append(names, id)
	}
	sort.Strings(names)
	t.Logf("%d named scenarios", len(names))
}

// The retained state contains neither raw nor hex-encoded fixture token bytes,
// including if a future change stores a token under an unrelated field type.
func assertNoPlaintext(t *testing.T, v reflect.Value, token Token) {
	t.Helper()
	switch v.Kind() {
	case reflect.String:
		if v.String() == hex.EncodeToString(token[:]) || v.String() == string(token[:]) {
			t.Fatal("plaintext token retained in string")
		}
	case reflect.Array, reflect.Slice:
		if v.Len() == 32 && v.Type().Elem().Kind() == reflect.Uint8 {
			equal := true
			for i := 0; i < 32; i++ {
				equal = equal && byte(v.Index(i).Uint()) == token[i]
			}
			if equal {
				t.Fatal("plaintext token retained in octets")
			}
		}
		for i := 0; i < v.Len(); i++ {
			assertNoPlaintext(t, v.Index(i), token)
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			assertNoPlaintext(t, v.Field(i), token)
		}
	case reflect.Map:
		iter := v.MapRange()
		for iter.Next() {
			assertNoPlaintext(t, iter.Key(), token)
			assertNoPlaintext(t, iter.Value(), token)
		}
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			assertNoPlaintext(t, v.Elem(), token)
		}
	}
}

// Concurrent forks of one input value do not share mutable session/account maps.
// Each fork independently charges one request; this is purity, not shared-ledger
// serialization or a claim that independent forks enforce a common budget.
func TestConcurrentBranches(t *testing.T) {
	v := readVectors(t)
	f := vectorFacts(t, v.Base, vectorStep{Entropy: strings.Repeat("11", 32)}, nil)
	s, r := Apply(Draft, NewState(v.Executor), f)
	if r.Code != Admitted {
		t.Fatal(r.Code)
	}
	f.Op = "use"
	f.Token = *r.Token
	results := make(chan State, 16)
	for i := 0; i < 16; i++ {
		go func() {
			next, res := Apply(Draft, s, f)
			if res.Code != Admitted {
				results <- State{}
				return
			}
			results <- next
		}()
	}
	for i := 0; i < 16; i++ {
		next := <-results
		if next.sessions["open-a"].Used["requests"] != 1 {
			t.Fatal("fork did not reserve exactly once")
		}
	}
	if len(s.accounts) != 0 || len(s.sessions["open-a"].Used) != 0 || s.next != 0 {
		t.Fatal("concurrent forks mutated input")
	}
}
