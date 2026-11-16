package trustcontract

// This file is a copy of experiments/notary-checker at chain-lab base
// 8a47f1a984cd93864402f7fdc09d2eba0d890b90: ParseContract from contract.go
// (sha256 d588697ea03b40bdc6d549ebb3b5d2ecd6064dabbb2a775aa9b1b2b66d93591d),
// the helpers it calls from encoding.go
// (sha256 304113dcf9070f2726f9779442669a9f4e0c071fb3212a383a3f6323f48982a1)
// and the contract types from types.go. The copy differs from the source in
// three ways only: the names ParseV2 and V2, a refusal returned as its code
// string instead of an error, and the shared constants of v1.go. A copy was
// chosen over an import because a new requirement edge between two modules
// of this repository changes the published module graph, and over a shared
// module because that would change the notary's sources and release hash.
// TestNotaryCopyMatchesSource fails when either source file changes, so the
// copy is then read again; TestNotaryCorpusAgrees runs the notary's own
// committed vectors through this copy.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// Point is a transaction output, as in a notary registration.
type Point struct {
	TxID string `json:"txid"`
	Vout uint32 `json:"vout"`
}

// V2 is the fifteen-member contract of profile /2 in LIP-0014 order.
type V2 struct {
	Profile         string          `json:"profile"`
	Network         string          `json:"network"`
	LandlordName    string          `json:"landlord_name"`
	AgentName       string          `json:"agent_name"`
	GranteeKey      string          `json:"grantee_key"`
	Actions         []string        `json:"actions"`
	Repos           []string        `json:"repos"`
	SpendBudget     int64           `json:"spend_budget"`
	NotBefore       int64           `json:"not_before"`
	NotAfter        int64           `json:"not_after"`
	ScopeTextSHA256 string          `json:"scope_text_sha256"`
	ParentGrantID   string          `json:"parent_grant_id"`
	Ordinal         int64           `json:"ordinal"`
	Delegate        json.RawMessage `json:"delegate"`
	Note            string          `json:"note"`
}

// Delegate is the right of re-delegation of LIP-0014 section 2.
type Delegate struct {
	Depth      int64    `json:"depth"`
	Actions    []string `json:"actions"`
	Budget     int64    `json:"budget"`
	Slots      []Row    `json:"slots"`
	Notaries   []Notary `json:"notaries"`
	Checkpoint string   `json:"checkpoint"`
}

// Row is one slot of a delegate.
type Row struct {
	Executor string `json:"executor"`
	Grantee  string `json:"grantee"`
	Cap      int64  `json:"cap"`
	Notary   string `json:"notary"`
}

// Notary is one designated notary of a delegate.
type Notary struct {
	Name         string `json:"name"`
	Registration Point  `json:"registration"`
	Owner        string `json:"owner"`
}

var integer = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
var nameRE = regexp.MustCompile(`^id/[a-z0-9_.-]{1,252}$`)
var repoRE = regexp.MustCompile(`^https://[a-z0-9.-]+/[A-Za-z0-9_./-]+$`)

func canonical(v any) []byte {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if e.Encode(v) != nil {
		return nil
	}
	return bytes.TrimSuffix(b.Bytes(), []byte{'\n'})
}
func ishex(s string, n int) bool {
	if len(s) != n || strings.ToLower(s) != s {
		return false
	}
	_, e := hex.DecodeString(s)
	return e == nil
}
func key(s string) bool {
	if !ishex(s, 64) {
		return false
	}
	b, _ := hex.DecodeString(s)
	_, e := schnorr.ParsePubKey(b)
	return e == nil
}
func owner(s string) bool {
	if !ishex(s, 66) || (s[:2] != "02" && s[:2] != "03") {
		return false
	}
	b, _ := hex.DecodeString(s)
	_, e := btcec.ParsePubKey(b)
	return e == nil
}

// lexical enforces canonical spellings at every depth before semantic rules.
// Object order and duplicate members are preserved for typed shape comparison.
func lexical(raw []byte, limit int) bool {
	if len(raw) == 0 || len(raw) > limit {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var out bytes.Buffer
	var value func() bool
	value = func() bool {
		t, e := d.Token()
		if e != nil {
			return false
		}
		switch v := t.(type) {
		case json.Delim:
			if v != '{' && v != '[' {
				return false
			}
			out.WriteByte(byte(v))
			first := true
			for d.More() {
				if !first {
					out.WriteByte(',')
				}
				first = false
				if v == '{' {
					k, e := d.Token()
					s, ok := k.(string)
					if e != nil || !ok || !ascii(s) {
						return false
					}
					out.Write(canonical(s))
					out.WriteByte(':')
				}
				if !value() {
					return false
				}
			}
			close, e := d.Token()
			if e != nil || (v == '{' && close != json.Delim('}')) || (v == '[' && close != json.Delim(']')) {
				return false
			}
			out.WriteByte(byte(close.(json.Delim)))
		case string:
			if !ascii(v) {
				return false
			}
			out.Write(canonical(v))
		case json.Number:
			if !integer.MatchString(string(v)) {
				return false
			}
			if _, e := strconv.ParseInt(string(v), 10, 64); e != nil {
				return false
			}
			out.WriteString(string(v))
		default:
			return false
		}
		return true
	}
	if !value() {
		return false
	}
	_, e := d.Token()
	return e == io.EOF && bytes.Equal(out.Bytes(), raw)
}
func ascii(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 32 || s[i] > 126 {
			return false
		}
	}
	return true
}
func decode(raw []byte, out any, limit int) bool {
	if !lexical(raw, limit) {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	return d.Decode(out) == nil && bytes.Equal(canonical(out), raw)
}
func sorted(s []string) bool {
	if s == nil {
		return false
	}
	for i := 1; i < len(s); i++ {
		if s[i-1] >= s[i] {
			return false
		}
	}
	return true
}
func contains(s []string, k string) bool {
	for _, v := range s {
		if v == k {
			return true
		}
	}
	return false
}
func subset(a, b []string) bool {
	for _, v := range a {
		if !contains(b, v) {
			return false
		}
	}
	return true
}
func repository(s string) bool {
	if len(s) > 200 || !repoRE.MatchString(s) {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(s, "https://"), "/")
	labels := strings.Split(parts[0], ".")
	if len(labels) < 2 {
		return false
	}
	for _, v := range labels {
		if len(v) < 1 || len(v) > 63 || v[0] == '-' || v[len(v)-1] == '-' {
			return false
		}
	}
	for _, v := range parts[1:] {
		if v == "" || v == "." || v == ".." {
			return false
		}
	}
	return true
}

// ParseV2 applies LIP-0014 section 3.1 in its specified refusal order to the
// fifteen-member profile /2 and returns the first refusal code, or "" for a
// valid contract. It still judges a depth-1 delegate in full, as the notary
// does; refusing delegation is the caller's rule, not this parser's.
func ParseV2(raw []byte) (V2, Delegate, string) {
	var c V2
	var d Delegate
	fail := func(s string) (V2, Delegate, string) { return c, d, s }
	if !decode(raw, &c, 8192) {
		return fail("CONTRACT_ENCODING")
	} // rule 1
	if c.Profile != ProfileV2 {
		return fail("CONTRACT_PROFILE")
	}
	if (c.Network != "main" && c.Network != "regtest") || !nameRE.MatchString(c.LandlordName) || !nameRE.MatchString(c.AgentName) || c.AgentName == c.LandlordName || !key(c.GranteeKey) || c.NotAfter <= c.NotBefore || c.NotAfter > MaxTime || (c.ScopeTextSHA256 != "" && !ishex(c.ScopeTextSHA256, 64)) {
		return fail("CONTRACT_FIELD")
	}
	if len(c.Actions) == 0 || !sorted(c.Actions) || !subset(c.Actions, []string{"instruct", "land", "review", "spend"}) {
		return fail("CONTRACT_ACTIONS")
	}
	if !sorted(c.Repos) || len(c.Repos) > 16 || ((len(c.Repos) > 0) != contains(c.Actions, "land")) {
		return fail("CONTRACT_REPOS")
	}
	for _, s := range c.Repos {
		if !repository(s) {
			return fail("CONTRACT_REPOS")
		}
	}
	if c.SpendBudget > MaxMoney || ((c.SpendBudget > 0) != contains(c.Actions, "spend")) {
		return fail("CONTRACT_BUDGET")
	}
	if len(c.Note) > 280 {
		return fail("CONTRACT_NOTE")
	}
	if c.Ordinal > 16 || (c.ParentGrantID != "" && !ishex(c.ParentGrantID, 64)) || ((c.ParentGrantID == "") != (c.Ordinal == 0)) {
		return fail("CONTRACT_PARENT")
	}
	// Rule 8 reads depth only when it is the first member with integer value.
	decoder := json.NewDecoder(bytes.NewReader(c.Delegate))
	first, _ := decoder.Token()
	if first == json.Delim('{') {
		member, _ := decoder.Token()
		if member == "depth" {
			var depth int64
			if decoder.Decode(&depth) == nil && c.ParentGrantID != "" && depth != 0 {
				return fail("CONTRACT_PARENT")
			}
		}
	}
	// Rule 9 step 1 judges the delegate header, not its nested row semantics.
	var head struct {
		Depth      int64             `json:"depth"`
		Actions    []json.RawMessage `json:"actions"`
		Budget     int64             `json:"budget"`
		Slots      []json.RawMessage `json:"slots"`
		Notaries   []json.RawMessage `json:"notaries"`
		Checkpoint string            `json:"checkpoint"`
	}
	if !decode(c.Delegate, &head, 8192) {
		return fail("CONTRACT_DELEGATE")
	}
	if head.Depth == 1 && len(head.Notaries) == 0 {
		return fail("DELEGATE_NO_NOTARY")
	}
	if !decode(c.Delegate, &d, 8192) {
		return fail("CONTRACT_DELEGATE")
	}
	if d.Depth == 0 {
		if len(d.Actions) != 0 || d.Budget != 0 || len(d.Slots) != 0 || len(d.Notaries) != 0 || d.Checkpoint != "" {
			return fail("CONTRACT_DELEGATE")
		}
		return c, d, ""
	}
	if d.Depth != 1 || len(d.Actions) == 0 || !sorted(d.Actions) || !subset(d.Actions, c.Actions) || d.Budget > MaxMoney || ((d.Budget > 0) != contains(d.Actions, "spend")) || len(d.Slots) < 1 || len(d.Slots) > 16 || len(d.Notaries) < 1 || len(d.Notaries) > 4 || !ishex(d.Checkpoint, 64) {
		return fail("CONTRACT_DELEGATE")
	}
	for i, n := range d.Notaries {
		if !nameRE.MatchString(n.Name) || !ishex(n.Registration.TxID, 64) || !owner(n.Owner) || (i > 0 && d.Notaries[i-1].Name >= n.Name) {
			return fail("CONTRACT_DELEGATE")
		}
	}
	var total int64
	for _, r := range d.Slots {
		found := false
		for _, n := range d.Notaries {
			if r.Notary == n.Name {
				found = true
			}
		}
		if !nameRE.MatchString(r.Executor) || r.Executor == c.LandlordName || !key(r.Grantee) || r.Cap > MaxMoney || !found {
			return fail("CONTRACT_DELEGATE")
		}
		total += r.Cap // At most 16 * MaxMoney, strictly within int64.
	}
	if total > d.Budget {
		return fail("CONTRACT_DELEGATE")
	}
	// D12 is unconditional for profile /2; there is no spend-profile switch.
	if contains(d.Actions, "spend") {
		return fail("CONTRACT_DELEGATE")
	}
	return c, d, ""
}
