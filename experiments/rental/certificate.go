// Package rental implements experimental landlord grants and legacy profiles. It
// exports scope as data; it never authorizes an effect from conversation text.
package rental

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/bip340"
)

const MaxMoney int64 = 21000000 * 100000000

type Point struct {
	TxID string `json:"txid"`
	Vout uint32 `json:"vout"`
}
type Certificate struct {
	Version        int      `json:"version"`
	Network        string   `json:"network"`
	Genesis        string   `json:"genesis"`
	StationName    string   `json:"station_name"`
	AgentPubkey    string   `json:"agent_pubkey"`
	IssuerPubkey   string   `json:"issuer_pubkey"`
	GranteePubkey  string   `json:"grantee_pubkey"`
	ContractSHA256 string   `json:"contract_sha256"`
	Scope          []string `json:"scope"`
	NotBefore      int64    `json:"not_before"`
	NotAfter       int64    `json:"not_after"`
	Seal           Point    `json:"seal"`
	BudgetSat      int64    `json:"budget_sat"`
}
type Envelope struct {
	Certificate Certificate `json:"certificate"`
	Signature   string      `json:"signature"`
}

func bad(s string) error { return errors.New(s) }
func digest(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == s
}
func pubkey(s string) bool {
	if !digest(s) {
		return false
	}
	b, _ := hex.DecodeString(s)
	_, e := schnorr.ParsePubKey(b)
	return e == nil
}
func station(s string) bool {
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
func validScope(s []string) bool {
	return validProfileScope(s, false)
}
func validGrantScope(s []string) bool {
	return validProfileScope(s, true)
}
func validProfileScope(s []string, names bool) bool {
	max := 5
	if names {
		max = 6
	}
	if s == nil || len(s) > max || !sort.StringsAreSorted(s) {
		return false
	}
	for i, v := range s {
		if i > 0 && s[i-1] == v {
			return false
		}
		switch v {
		case "deliver", "pay", "publish", "repository.push", "secret.release":
		case "names.register":
			if !names {
				return false
			}
		default:
			return false
		}
	}
	return true
}
func (c Certificate) Validate() error {
	if c.Version != 1 || !su.NetworkPinned(c.Network, c.Genesis) {
		return bad("CERTIFICATE_NETWORK")
	}
	if !station(c.StationName) {
		return bad("CERTIFICATE_STATION")
	}
	if !pubkey(c.AgentPubkey) || !pubkey(c.IssuerPubkey) || !pubkey(c.GranteePubkey) {
		return bad("CERTIFICATE_KEY")
	}
	if !digest(c.ContractSHA256) || !digest(c.Seal.TxID) {
		return bad("CERTIFICATE_HASH")
	}
	if !validScope(c.Scope) {
		return bad("CERTIFICATE_SCOPE")
	}
	if c.NotBefore < 0 || c.NotAfter <= c.NotBefore || c.NotAfter > 253402300799 {
		return bad("CERTIFICATE_TIME")
	}
	if c.BudgetSat < 0 || c.BudgetSat > MaxMoney {
		return bad("CERTIFICATE_BUDGET")
	}
	return nil
}
func canonical(raw []byte, out any) error {
	if len(raw) == 0 || len(raw) > 16384 || su.StrictInput(raw, out) != nil {
		return bad("CANONICAL_ENCODING")
	}
	b, e := json.Marshal(out)
	if e != nil || !bytes.Equal(raw, b) {
		return bad("CANONICAL_ENCODING")
	}
	return nil
}
func (c Certificate) Canonical() ([]byte, error) {
	if e := c.Validate(); e != nil {
		return nil, e
	}
	return json.Marshal(c)
}

// ParseEnvelope checks exact bytes and mathematical signature validity. Caller
// must separately bind the issuer to trusted policy; a self-signed object is
// not by itself authority. No private-key API is exposed by this package.
func ParseEnvelope(raw []byte) (Envelope, error) {
	var e Envelope
	if err := canonical(raw, &e); err != nil {
		return e, err
	}
	unsigned, err := e.Certificate.Canonical()
	if err != nil {
		return e, err
	}
	if !VerifySignature(e.Certificate.IssuerPubkey, su.Hash(unsigned), e.Signature) {
		return e, bad("ISSUER_SIGNATURE")
	}
	return e, nil
}
func VerifySignature(key, hash, signature string) bool {
	if !digest(key) || !digest(hash) || len(signature) != 128 {
		return false
	}
	kb, _ := hex.DecodeString(key)
	pk, e := schnorr.ParsePubKey(kb)
	if e != nil {
		return false
	}
	sb, e := hex.DecodeString(signature)
	if e != nil || hex.EncodeToString(sb) != signature {
		return false
	}
	sig, e := bip340.ParseBIP340Strict(sb)
	if e != nil {
		return false
	}
	h, _ := hex.DecodeString(hash)
	return sig.Verify(h, pk)
}
func Hash(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }

type ActiveValue struct {
	Swarma struct {
		Issuer      string `json:"rental_issuer_pubkey"`
		Certificate string `json:"rental_certificate_sha256"`
		Seal        Point  `json:"rental_seal"`
	} `json:"swarma"`
}

func NameValue(c Certificate, id string) (string, error) {
	if c.Validate() != nil || !digest(id) {
		return "", bad("NAME_VALUE")
	}
	var v ActiveValue
	v.Swarma.Issuer = c.IssuerPubkey
	v.Swarma.Certificate = id
	v.Swarma.Seal = c.Seal
	b, _ := json.Marshal(v)
	if len(b) > 520 {
		return "", bad("NAME_VALUE")
	}
	return string(b), nil
}
func IdleValue(issuer string) (string, error) {
	if !pubkey(issuer) {
		return "", bad("ISSUER_KEY")
	}
	return `{"swarma":{"rental_issuer_pubkey":"` + issuer + `"}}`, nil
}
