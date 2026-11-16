// Package session models the proposed LIP-0028 lifecycle from stated facts.
// It performs no observation, signature verification, persistence or transport.
package session

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net/netip"
	"slices"
)

// Profile has no enabled default. Draft is an explicit experimental selection.
type Profile string

const Draft Profile = "DRAFT-LIP-0028-v0.1.49"

type Code string

const (
	Admitted       Code = "ADMITTED"
	Channel        Code = "SESSION_CHANNEL"
	Replay         Code = "SESSION_REPLAY"
	BindingInvalid Code = "SESSION_BINDING"
	Window         Code = "SESSION_WINDOW"
	Limits         Code = "SESSION_LIMITS"
	Unknown        Code = "SESSION_UNKNOWN"
	TokenUnknown   Code = "SESSION_TOKEN"
	PeerMismatch   Code = "SESSION_PEER"
	Ended          Code = "SESSION_ENDED"
	Command        Code = "SESSION_COMMAND"
	LimitOver      Code = "SESSION_LIMIT_OVER"
)

// Refusals is the vocabulary in §8's printed order; each operation has its own pipeline.
func Refusals() []Code {
	return []Code{Channel, Replay, BindingInvalid, Window, Limits, Unknown, TokenUnknown, PeerMismatch, Ended, Command, LimitOver}
}

// Token is ephemeral. Only its digest enters State. A scalar pointer keeps
// fmt's method-bypassing bad-verb reflection from reaching the secret bytes.
// A pointer to an array is insufficient: fmt may dereference it at depth zero.
// Like codec.Secret, copies share immutable private storage.
type Token struct{ value *string }

func newToken(raw [32]byte) Token {
	if raw == [32]byte{} {
		return Token{}
	}
	value := string(raw[:])
	return Token{value: &value}
}

func tokenBytes(t Token) (raw [32]byte) {
	if t.value != nil {
		copy(raw[:], *t.value)
	}
	return raw
}

// Format ignores every verb and flag, including numeric/hex array formatting.
func (Token) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, "[session token]") }
func (Token) MarshalJSON() ([]byte, error) { return []byte(`"[session token]"`), nil }
func (Token) MarshalText() ([]byte, error) { return []byte("[session token]"), nil }

// RevealForOpen is the sole explicit plaintext output boundary. Use it only to
// deliver the successful opening result once; never for logs or serialization.
// Apply enforces one-time issuance, not erasure of copies held by the caller.
func (t Token) RevealForOpen() [32]byte { return tokenBytes(t) }

func (Token) String() string   { return "[session token]" }
func (Token) GoString() string { return "[session token]" }

// DrawToken is the only effectful helper. The reducer receives its result as a fact.
func DrawToken() (Token, error) {
	var raw [32]byte
	_, err := rand.Read(raw[:])
	return newToken(raw), err
}
func tokenDigest(t Token) [32]byte {
	raw := tokenBytes(t)
	return sha256.Sum256(raw[:])
}

type Executor struct{ Name, Key string }
type Binding struct {
	Kind    string
	UID     uint32
	Address string
}
type Limit struct {
	Key    string
	Amount uint64
	Kind   string
}
type Row struct {
	Parent  string
	Ordinal uint64
}

// Check is an already verified upstream fact, not a request assertion.
// Refusal preserves an upstream verdict; an absent fact fails with a model label.
type Check struct {
	OK      bool
	Refusal Code
}
type Verification struct{ Names, Recipient, Observation, Path, Resources Check }
type Closure struct {
	Grant     string
	Validated bool
}

// Facts is a logical laboratory input, NOT a wire request or proof format.
// Now is the final service-clock reading at this transition. PeerVerified means
// the binding came from the connection, never from the request body.
type Facts struct {
	Action                                 string // Logical action class, not an assigned wire command.
	Op                                     string
	RequestID, SessionID                   string
	Path                                   []string
	Executor                               Executor
	Row                                    *Row
	Binding, Peer                          Binding
	PeerVerified                           bool
	Channel                                string
	Now, Iat, Exp, End                     uint64
	Key                                    string
	Checks                                 Verification
	Limits                                 []Limit
	GrantLimits, RowLimits, OperatorLimits map[string]uint64
	Spend                                  []Limit
	Token                                  Token
	Random                                 Token // The opening token itself, not a derived seed; also redacts.
	RandomReady                            bool
	Closures                               []Closure
	FinalObservation                       bool
	WriteOK                                bool
}

type record struct {
	ID                             string
	Path                           []string
	Executor                       Executor
	Row                            *Row
	Binding                        Binding
	End                            uint64
	Ended                          bool
	LastKey                        string
	Digest                         [32]byte
	Limits, GrantLimits, RowLimits map[string]uint64
	Used                           map[string]uint64
}
type accountKey struct {
	Kind, Grant string
	Ordinal     uint64
	Limit       string
}

// State is an immutable value to callers: reducers copy all maps before writes.
// This is abstract journal content, not an encoding or persistence implementation.
type State struct {
	executor     Executor
	sessions     map[string]record
	seen         map[string]bool
	closed       map[string]bool
	accounts     map[accountKey]uint64
	reservations map[uint64]bool
	next         uint64
	ready        bool
	fenced       bool
	fence        uint64
	marked       bool
	mark         uint64
}

// NewState states an intact empty journal for one independently pinned executor.
func NewState(executor Executor) State {
	return State{executor: executor, sessions: map[string]record{}, seen: map[string]bool{}, closed: map[string]bool{}, accounts: map[accountKey]uint64{}, reservations: map[uint64]bool{}, ready: true}
}

// Lost states journal unavailability. No transition may infer an empty journal.
func Lost(s State) State { s.ready = false; return s }

// StartAnew states an attended recovery with fenced writers. Grant accounts and
// recorded closures are supplied unchanged; their actual recovery is external.
func StartAnew(s State, fencedAt uint64) State {
	s = clone(s)
	s.sessions = map[string]record{}
	s.seen = map[string]bool{}
	s.ready = true
	s.fenced = true
	s.fence = max(s.fence, fencedAt)
	s.mark = max(s.mark, s.fence)
	s.marked = true
	return s
}

type Result struct {
	Code  Code
	Token *Token
}

func result(c Code) Result { return Result{Code: c} }
func copyMap[K comparable, V any](m map[K]V) map[K]V {
	n := make(map[K]V, len(m))
	for k, v := range m {
		n[k] = v
	}
	return n
}
func clone(s State) State {
	s.sessions = copyMap(s.sessions)
	s.seen = copyMap(s.seen)
	s.closed = copyMap(s.closed)
	s.accounts = copyMap(s.accounts)
	s.reservations = copyMap(s.reservations)
	for k, r := range s.sessions {
		r.Path = slices.Clone(r.Path)
		r.Limits = copyMap(r.Limits)
		r.GrantLimits = copyMap(r.GrantLimits)
		r.RowLimits = copyMap(r.RowLimits)
		r.Used = copyMap(r.Used)
		if r.Row != nil {
			row := *r.Row
			r.Row = &row
		}
		s.sessions[k] = r
	}
	return s
}
func gate(p Profile, s State) Code {
	if p != Draft {
		return "PROFILE_DISABLED"
	}
	if !s.ready {
		return "JOURNAL_UNAVAILABLE"
	}
	return Admitted
}

// commit publishes a candidate only after a completed write. Refusals keep
// their admission code; a failed write publishes neither state nor a token.
func commit(input, candidate State, f Facts, res Result) (State, Result) {
	if !f.WriteOK {
		if res.Code == Admitted {
			return input, result("JOURNAL_WRITE")
		}
		return input, res
	}
	return candidate, res
}
func secure(c string) bool { return c == "local" || c == "private-authenticated" }
func validBinding(b Binding) bool {
	switch b.Kind {
	case "uid":
		return b.Address == ""
	case "address":
		a, err := netip.ParseAddr(b.Address)
		return err == nil && a.Zone() == "" && a.String() == b.Address && b.UID == 0
	}
	return false
}
func peerMatches(f Facts, b Binding) bool {
	return f.PeerVerified && validBinding(f.Peer) && f.Peer == b && ((b.Kind == "uid" && f.Channel == "local") || (b.Kind == "address" && f.Channel == "private-authenticated"))
}
func validWindow(now, end uint64) bool { return end > now && end-now <= 3600 }
func passed(c Check, fallback Code) Code {
	if c.OK {
		return Admitted
	}
	if c.Refusal != "" {
		return c.Refusal
	}
	return fallback
}
func validPath(path []string) bool {
	if len(path) < 1 || len(path) > 2 {
		return false
	}
	return path[0] != "" && path[len(path)-1] != "" && (len(path) == 1 || path[0] != path[1])
}
func closedPath(s State, path []string) bool {
	for _, g := range path {
		if s.closed[g] {
			return true
		}
	}
	return false
}
func recordClosure(s *State, c Closure) {
	s.closed[c.Grant] = true
	for id, r := range s.sessions {
		if slices.Contains(r.Path, c.Grant) {
			r.Ended = true
			s.sessions[id] = r
		}
	}
}

// verify follows the upstream admission order using explicit successful facts.
// A validated closure remains recorded even when the discovering request refuses.
func verify(s *State, f Facts, r *record, signed bool) Code {
	if c := passed(f.Checks.Names, "NAME_FACTS"); c != Admitted {
		return c
	}
	if c := passed(f.Checks.Recipient, "KEY_FACTS"); c != Admitted {
		return c
	}
	if f.Key == "" || (r != nil && f.Key != r.LastKey) {
		return "KEY_FACTS"
	}
	if signed && (f.RequestID == "" || f.Iat > f.Now || f.Exp <= f.Now || f.Exp <= f.Iat) {
		return "INVOCATION_TIME"
	}
	if c := passed(f.Checks.Observation, "OBSERVATION_FACTS"); c != Admitted {
		return c
	}
	if s.marked && f.Now < s.mark {
		return "OBSERVATION_CLOCK"
	}
	if !f.FinalObservation {
		return "OBSERVATION_VOID"
	}
	for _, c := range f.Closures {
		if c.Validated && c.Grant != "" {
			recordClosure(s, c)
		}
	}
	if !validPath(f.Path) || f.Executor != s.executor || f.Executor.Name == "" || f.Executor.Key == "" {
		return "AUTHORITY_FACTS"
	}
	if r != nil && (!slices.Equal(f.Path, r.Path) || f.Executor != r.Executor) {
		return "AUTHORITY_FACTS"
	}
	if closedPath(*s, f.Path) {
		return "GRANT_CLOSED"
	}
	if c := passed(f.Checks.Path, "AUTHORITY_FACTS"); c != Admitted {
		return c
	}
	return passed(f.Checks.Resources, "RESOURCE_FACTS")
}
func replay(s State, f Facts) bool { return s.seen[f.RequestID] || (s.fenced && f.Iat <= s.fence) }
func live(s *State, id string, now uint64) bool {
	r := s.sessions[id]
	if r.Ended {
		return false
	}
	if now >= r.End {
		r.Ended = true
		s.sessions[id] = r
		return false
	}
	return true
}
func mark(s *State, now uint64) { s.mark = max(s.mark, now); s.marked = true }
func validLimits(f Facts) bool {
	seen := map[string]bool{}
	for _, l := range f.Limits {
		cap, ok := f.GrantLimits[l.Key]
		if l.Key == "" || l.Kind != "cumulative" || seen[l.Key] || !ok || l.Amount > cap {
			return false
		}
		if ceiling, set := f.OperatorLimits[l.Key]; set && l.Amount > ceiling {
			return false
		}
		seen[l.Key] = true
	}
	return true
}

// Apply computes one atomic abstract transition. Its input is never modified.
// A successful open is the only transition whose result can carry a token.
func Apply(p Profile, input State, f Facts) (State, Result) {
	if c := gate(p, input); c != Admitted {
		return input, result(c)
	}
	if f.Op == "use" {
		s, plan, res := prepareUse(p, input, f)
		if res.Code != Admitted {
			return commit(input, s, f, res)
		}
		next, res := Reserve(p, s, plan, f)
		return commit(input, next, f, res)
	}
	s := clone(input)
	if f.Op == "closure" {
		for _, c := range f.Closures {
			if !c.Validated || c.Grant == "" {
				return input, result("SEAL_UNVALIDATED")
			}
		}
		if len(f.Closures) == 0 {
			return input, result("SEAL_UNVALIDATED")
		}
		for _, c := range f.Closures {
			recordClosure(&s, c)
		}
		return commit(input, s, f, result(Admitted))
	}
	if f.Op != "open" && f.Op != "extend" && f.Op != "close" {
		return input, result("OPERATION_UNSUPPORTED")
	}
	if f.Op == "open" && !secure(f.Channel) {
		return input, result(Channel)
	}
	if c := verify(&s, f, nil, true); c != Admitted {
		return commit(input, s, f, result(c))
	}
	if replay(s, f) {
		return commit(input, s, f, result(Replay))
	}
	if f.Op == "open" {
		if !validBinding(f.Binding) {
			return commit(input, s, f, result(BindingInvalid))
		}
		if !validWindow(f.Now, f.End) {
			return commit(input, s, f, result(Window))
		}
		if !validLimits(f) {
			return commit(input, s, f, result(Limits))
		}
		if f.Row != nil && (len(f.Path) != 2 || f.Row.Parent != f.Path[0]) {
			return commit(input, s, f, result("AUTHORITY_FACTS"))
		}
		if len(f.Path) == 2 && f.Row == nil {
			return commit(input, s, f, result("AUTHORITY_FACTS"))
		}
		if !f.RandomReady {
			return commit(input, s, f, result("ENTROPY_UNAVAILABLE"))
		}
		digest := tokenDigest(f.Random)
		for _, r := range s.sessions {
			if r.Digest == digest {
				return commit(input, s, f, result("ENTROPY_COLLISION"))
			}
		}
		limits := map[string]uint64{}
		for _, l := range f.Limits {
			limits[l.Key] = l.Amount
		}
		r := record{ID: f.RequestID, Path: slices.Clone(f.Path), Executor: f.Executor, Binding: f.Binding, End: f.End, LastKey: f.Key, Digest: digest, Limits: limits, GrantLimits: copyMap(f.GrantLimits), RowLimits: copyMap(f.RowLimits), Used: map[string]uint64{}}
		if f.Row != nil {
			row := *f.Row
			r.Row = &row
		}
		s.sessions[r.ID] = r
		s.seen[f.RequestID] = true
		mark(&s, f.Now)
		token := f.Random
		return commit(input, s, f, Result{Code: Admitted, Token: &token})
	}
	r, ok := s.sessions[f.SessionID]
	if !ok || !slices.Equal(r.Path, f.Path) || r.Executor != f.Executor {
		return commit(input, s, f, result(Unknown))
	}
	if f.Op == "extend" {
		if !live(&s, r.ID, f.Now) {
			return commit(input, s, f, result(Ended))
		}
		if !validWindow(f.Now, f.End) {
			return commit(input, s, f, result(Window))
		}
		r.End = max(r.End, f.End)
		r.LastKey = f.Key
	} else {
		r.Ended = true
	}
	s.sessions[r.ID] = r
	s.seen[f.RequestID] = true
	mark(&s, f.Now)
	return commit(input, s, f, result(Admitted))
}

// Prepared is a checked request, not a reservation. It carries no plaintext token.
// Its fields are private so callers cannot manufacture a successful check.
type Prepared struct {
	valid   bool
	serial  uint64
	session string
	digest  [32]byte
	key     string
	now     uint64
	spend   []Limit
}

func CheckUse(p Profile, input State, f Facts) (State, Prepared, Result) {
	s, plan, res := prepareUse(p, input, f)
	next, res := commit(input, s, f, res)
	if res.Code != Admitted {
		return next, Prepared{}, res
	}
	return next, plan, res
}

// prepareUse stages an identity without publishing it. Apply combines this with
// Reserve in one commit; standalone CheckUse commits its preparation separately.
func prepareUse(p Profile, input State, f Facts) (State, Prepared, Result) {
	fail := func(s State, c Code) (State, Prepared, Result) { return s, Prepared{}, result(c) }
	if c := gate(p, input); c != Admitted {
		return fail(input, c)
	}
	if !secure(f.Channel) {
		return fail(input, Channel)
	}
	digest := tokenDigest(f.Token)
	id := ""
	for k, r := range input.sessions {
		if r.Digest == digest {
			id = k
			break
		}
	}
	if id == "" {
		return fail(input, TokenUnknown)
	}
	r := input.sessions[id]
	if !peerMatches(f, r.Binding) {
		return fail(input, PeerMismatch)
	}
	s := clone(input)
	if !live(&s, id, f.Now) {
		return fail(s, Ended)
	}
	if f.Action == "open" || f.Action == "extend" || f.Action == "close" {
		return fail(s, Command)
	}
	if f.Op != "use" {
		return fail(s, "OPERATION_UNSUPPORTED")
	}
	if c := verify(&s, f, &r, false); c != Admitted {
		return fail(s, c)
	}
	if s.next == ^uint64(0) {
		return fail(s, "IDENTITY_EXHAUSTED")
	}
	plan := Prepared{valid: true, serial: s.next, session: id, digest: digest, key: r.LastKey, now: f.Now, spend: slices.Clone(f.Spend)}
	s.next++
	return s, plan, result(Admitted)
}

// Reserve is the atomic write boundary. It re-reads the current session end,
// then closures, and checks all own/row/session accounts before any debit.
func Reserve(p Profile, input State, plan Prepared, f Facts) (State, Result) {
	if c := gate(p, input); c != Admitted {
		return input, result(c)
	}
	if !plan.valid || input.reservations[plan.serial] || plan.serial >= input.next {
		return input, result("REQUEST_REPLAY")
	}
	r, ok := input.sessions[plan.session]
	if !ok || r.Digest != plan.digest {
		return input, result(TokenUnknown)
	}
	s := clone(input)
	if !f.FinalObservation {
		return commit(input, s, f, result("OBSERVATION_VOID"))
	}
	if f.Now < plan.now || (s.marked && f.Now < s.mark) {
		return commit(input, s, f, result("OBSERVATION_CLOCK"))
	}
	if !live(&s, r.ID, f.Now) {
		return commit(input, s, f, result(Ended))
	}
	if closedPath(s, r.Path) {
		return commit(input, s, f, result("GRANT_CLOSED"))
	}
	if r.LastKey != plan.key {
		return commit(input, s, f, result("KEY_FACTS"))
	}
	// Accumulate in scratch maps: a late failing key leaves all accounts unchanged.
	accounts := copyMap(s.accounts)
	used := copyMap(r.Used)
	for _, l := range plan.spend {
		if l.Key == "" || l.Kind != "cumulative" {
			return commit(input, s, f, result("RESOURCE_FACTS"))
		}
		own := accountKey{Kind: "own", Grant: r.Path[len(r.Path)-1], Limit: l.Key}
		if !fits(accounts[own], l.Amount, r.GrantLimits[l.Key]) {
			return commit(input, s, f, result("OWN_LIMIT_OVER"))
		}
		accounts[own] += l.Amount
		if r.Row != nil {
			row := accountKey{Kind: "row", Grant: r.Row.Parent, Ordinal: r.Row.Ordinal, Limit: l.Key}
			if !fits(accounts[row], l.Amount, r.RowLimits[l.Key]) {
				return commit(input, s, f, result("ROW_CAP_OVER"))
			}
			accounts[row] += l.Amount
		}
		if !fits(used[l.Key], l.Amount, r.Limits[l.Key]) {
			return commit(input, s, f, result(LimitOver))
		}
		used[l.Key] += l.Amount
	}
	s.accounts = accounts
	r.Used = used
	s.sessions[r.ID] = r
	s.reservations[plan.serial] = true
	mark(&s, f.Now)
	return commit(input, s, f, result(Admitted))
}
func fits(used, amount, ceiling uint64) bool { return used <= ceiling && amount <= ceiling-used }

// String exposes only counts, never credentials or authority identifiers.
func (s State) String() string { return fmt.Sprintf("session state: %d sessions", len(s.sessions)) }
