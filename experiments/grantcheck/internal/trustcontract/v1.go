// Package trustcontract decodes the two trust-contract profiles that a Grant
// v3 can commit to through contract_sha256, and binds a decoded contract to
// the grant fields:
//
//   - swarma-trust-contract/1, LIP-0013 section 2 (v1.go). That file is a port
//     of swarma-link-spec tools/trustcheck/contract.go at commit
//     bd3bc80e5543d8a563343ec05abd1a5f3f67284c (v0.1.51). The tool is
//     `package main` and cannot be imported.
//   - swarma-trust-contract/2, LIP-0014 section 3.1 (v2.go). That file is a
//     copy of experiments/notary-checker contract.go and of the helpers it
//     needs from encoding.go and types.go.
//
// The package reads no network, node, clock or key file. It verifies no
// signature and gives no authority: a caller still needs a live grant check.
package trustcontract

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// Constants of the trust-contract profiles (LIP-0013 section 2, LIP-0014
// section 3).
const (
	ProfileV1        = "swarma-trust-contract/1"
	ProfileV2        = "swarma-trust-contract/2"
	ConsentTagValue  = "swarma-rental-consent-v1"
	PrivacyLabel     = "swarma-trust-privacy-v1"
	BookingSuffix    = "booking"
	MaxContractBytes = 8192
	MaxNoteBytes     = 280
	MaxRepos         = 16
	MaxRepoBytes     = 200
	MaxMoney         = int64(21000000) * 100000000
	MaxTime          = int64(253402300799)
)

// V1 is the preimage of the v3 contract_sha256 for a trust grant of profile
// /1. The struct field order is the canonical field order.
type V1 struct {
	Profile      string   `json:"profile"`
	Network      string   `json:"network"`
	LandlordName string   `json:"landlord_name"`
	AgentName    string   `json:"agent_name"`
	GranteeKey   string   `json:"grantee_key"`
	Actions      []string `json:"actions"`
	Repos        []string `json:"repos"`
	SpendBudget  int64    `json:"spend_budget"`
	NotBefore    int64    `json:"not_before"`
	NotAfter     int64    `json:"not_after"`
	Note         string   `json:"note"`
}

// actionScope maps each profile action to the v3 scope entry it requires;
// an empty string means the action has no v3 carrier.
var actionScope = map[string]string{
	"instruct": "",
	"land":     "repository.push",
	"review":   "",
	"spend":    "pay",
}

// compact encodes v as compact JSON without HTML escaping, the encoder
// configuration LIP-0013 section 2.1 names for contract bytes. The source
// panics on an encoder error; this port returns nil, which equals no input.
func compact(v any) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
}

func sha256Hex(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func isDigest(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == s
}

func isPubkey(s string) bool {
	if !isDigest(s) {
		return false
	}
	b, _ := hex.DecodeString(s)
	_, err := schnorr.ParsePubKey(b)
	return err == nil
}

// isStation mirrors chain-lab rental station(): "id/" plus 1..252 bytes of
// [a-z0-9._-].
func isStation(s string) bool {
	if !strings.HasPrefix(s, "id/") || len(s) <= 3 || len(s) > 255 {
		return false
	}
	for _, c := range []byte(s[3:]) {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

func isPrintableASCII(s string) bool {
	for _, c := range []byte(s) {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// strictlyAscending reports byte-wise ascending order without duplicates.
func strictlyAscending(s []string) bool {
	for i := 1; i < len(s); i++ {
		if s[i-1] >= s[i] {
			return false
		}
	}
	return true
}

// isRepoURL implements the LIP-0013 repository grammar:
// "https://" host path, host = 2+ lowercase DNS labels, path = 1+ segments
// of [A-Za-z0-9._-], no port, userinfo, query, fragment or trailing slash.
func isRepoURL(s string) bool {
	if len(s) > MaxRepoBytes || !strings.HasPrefix(s, "https://") {
		return false
	}
	rest := s[len("https://"):]
	slash := strings.IndexByte(rest, '/')
	if slash <= 0 {
		return false
	}
	host, path := rest[:slash], rest[slash+1:]
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if len(l) < 1 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, c := range []byte(l) {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	for _, seg := range strings.Split(path, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
		for _, c := range []byte(seg) {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
				return false
			}
		}
	}
	return true
}

// lexicallyCanonical applies the section 2.1 rules that re-encoding equality
// does not decide: no integer carries a sign, and every string value, note
// included, is printable ASCII (0x20 to 0x7E) after unescaping, so the only
// escapes the canonical bytes can contain are \" and \\.
func lexicallyCanonical(c V1) bool {
	if c.SpendBudget < 0 || c.NotBefore < 0 || c.NotAfter < 0 {
		return false
	}
	strs := append([]string{c.Profile, c.Network, c.LandlordName, c.AgentName, c.GranteeKey, c.Note}, c.Actions...)
	for _, s := range append(strs, c.Repos...) {
		if !isPrintableASCII(s) {
			return false
		}
	}
	return true
}

// ParseV1 applies LIP-0013 section 2.3 in its fixed order and returns the
// first refusal code, or "" for a valid contract.
func ParseV1(raw []byte) (V1, string) {
	var c V1
	if len(raw) == 0 || len(raw) > MaxContractBytes {
		return c, "CONTRACT_ENCODING"
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, "CONTRACT_ENCODING"
	}
	// Exact canonical bytes: field set, order, duplicates, whitespace, number
	// and string spelling are decided by re-encoding equality; the sign and
	// the character repertoire by lexicallyCanonical. Rule 1 owns every
	// lexical property, so later rules see only canonical values.
	if c.Actions == nil || c.Repos == nil || !bytes.Equal(compact(c), raw) || !lexicallyCanonical(c) {
		return c, "CONTRACT_ENCODING"
	}
	if c.Profile != ProfileV1 {
		return c, "CONTRACT_PROFILE"
	}
	if (c.Network != "main" && c.Network != "regtest") ||
		!isStation(c.LandlordName) || !isStation(c.AgentName) || c.LandlordName == c.AgentName ||
		!isPubkey(c.GranteeKey) ||
		c.NotAfter <= c.NotBefore || c.NotAfter > MaxTime {
		return c, "CONTRACT_FIELD"
	}
	if len(c.Actions) == 0 || !strictlyAscending(c.Actions) {
		return c, "CONTRACT_ACTIONS"
	}
	for _, a := range c.Actions {
		if _, ok := actionScope[a]; !ok {
			return c, "CONTRACT_ACTIONS"
		}
	}
	land := slices.Contains(c.Actions, "land")
	if land != (len(c.Repos) > 0) || len(c.Repos) > MaxRepos || !strictlyAscending(c.Repos) {
		return c, "CONTRACT_REPOS"
	}
	for _, r := range c.Repos {
		if !isRepoURL(r) {
			return c, "CONTRACT_REPOS"
		}
	}
	spend := slices.Contains(c.Actions, "spend")
	if spend != (c.SpendBudget > 0) || c.SpendBudget > MaxMoney {
		return c, "CONTRACT_BUDGET"
	}
	if len(c.Note) > MaxNoteBytes {
		return c, "CONTRACT_NOTE"
	}
	return c, ""
}

// V3Scope derives the v3 grant scope from contract actions (LIP-0013 section
// 2.2): sorted, never nil.
func V3Scope(actions []string) []string {
	scope := []string{}
	for _, a := range actions {
		if s := actionScope[a]; s != "" {
			scope = append(scope, s)
		}
	}
	slices.Sort(scope)
	return scope
}

// ConsentTags returns the four consent-event tags in their v3 order
// (LIP-0013 section 2.4).
func ConsentTags(raw []byte) [][]string {
	return [][]string{
		{"t", ConsentTagValue},
		{"contract", sha256Hex(raw)},
		{"booking", sha256Hex(append(append([]byte{}, raw...), BookingSuffix...))},
		{"privacy", sha256Hex([]byte(PrivacyLabel))},
	}
}
