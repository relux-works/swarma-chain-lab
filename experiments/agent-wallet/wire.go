// Package wallet implements a grant-checked wallet client and isolated service.
package wallet

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

const MaxMoney int64 = 21000000 * 100000000
const RequestKind = 8184
const NameDeposit int64 = 1000000
const DefaultNameBudget int64 = 3000000
const MaxFee int64 = 1000000

func fail(code string) error { return errors.New(code) }
func Hash(b []byte) string   { return su.Hash(b) }
func hexN(s string, n int) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == n && hex.EncodeToString(b) == s
}
func canonical(v any) []byte {
	b, e := json.Marshal(v)
	if e != nil {
		panic("internal JSON encoding")
	}
	return b
}

// Exact JSON bytes keep signed request and contract commitments unambiguous.
// Shared W3 decoding additionally rejects duplicate names and spelling aliases.
func strict(b []byte, v any) error {
	if len(b) == 0 || len(b) > 65536 || su.StrictInput(b, v) != nil || !bytes.Equal(b, canonical(v)) {
		return fail("INPUT_CANONICAL")
	}
	return nil
}
func ascii(s string, max int) bool {
	if len(s) > max {
		return false
	}
	for _, b := range []byte(s) {
		if b < 32 || b > 126 {
			return false
		}
	}
	return true
}
func addressScript(address string) ([]byte, error) {
	return addressScriptForNetwork(address, "regtest", su.RegtestGenesis)
}

func addressScriptForNetwork(address, network, genesis string) ([]byte, error) {
	if !su.NetworkPinned(network, genesis) {
		return nil, fail("NETWORK_PIN")
	}
	params := chaincfg.RegressionNetParams
	code := "ADDRESS_REGTEST"
	if network == "main" {
		params = chaincfg.MainNetParams
		params.PubKeyHashAddrID, params.ScriptHashAddrID, params.PrivateKeyID = 52, 13, 180
		params.Bech32HRPSegwit = "nc"
		code = "ADDRESS_MAIN"
	}
	a, e := btcutil.DecodeAddress(address, &params)
	if e != nil || !a.IsForNet(&params) || a.EncodeAddress() != address {
		return nil, fail(code)
	}
	if _, ok := a.(*btcutil.AddressPubKeyHash); !ok {
		return nil, fail("ADDRESS_P2PKH_ONLY")
	}
	s, e := txscript.PayToAddrScript(a)
	if e != nil {
		return nil, fail("ADDRESS_SCRIPT")
	}
	return s, nil
}

type Event struct {
	ID        string     `json:"id"`
	Pubkey    string     `json:"pubkey"`
	CreatedAt int64      `json:"created_at"`
	Kind      int        `json:"kind"`
	Tags      [][]string `json:"tags"`
	Content   string     `json:"content"`
	Sig       string     `json:"sig"`
}
type Request struct {
	Version  int    `json:"version"`
	GrantID  string `json:"grant_id"`
	Action   string `json:"action"`
	Nonce    string `json:"nonce"`
	Address  string `json:"address"`
	Amount   int64  `json:"amount_sat"`
	FeeLimit int64  `json:"fee_limit_sat"`
	Name     string `json:"name"`
	Value    string `json:"value"`
}
type SignedRequest struct {
	Event   Event
	Request Request
	Raw     []byte
}

func (e Event) Digest() string {
	return Hash(canonical([]any{0, e.Pubkey, e.CreatedAt, e.Kind, e.Tags, e.Content}))
}
func ParseRequest(raw []byte) (SignedRequest, error) {
	var s SignedRequest
	if len(raw) > 8192 || strict(raw, &s.Event) != nil {
		return s, fail("REQUEST_SCHEMA")
	}
	e := s.Event
	if e.Kind != RequestKind || e.CreatedAt <= 0 || e.Tags == nil || len(e.Tags) != 0 || !hexN(e.ID, 32) || !hexN(e.Pubkey, 32) || !hexN(e.Sig, 64) {
		return s, fail("REQUEST_SCHEMA")
	}
	if e.ID != e.Digest() {
		return s, fail("REQUEST_ID")
	}
	pb, _ := hex.DecodeString(e.Pubkey)
	pk, pe := schnorr.ParsePubKey(pb)
	sb, _ := hex.DecodeString(e.Sig)
	sig, se := schnorr.ParseSignature(sb)
	id, _ := hex.DecodeString(e.ID)
	if pe != nil || se != nil || !sig.Verify(id, pk) {
		return s, fail("REQUEST_SIGNATURE")
	}
	if strict([]byte(e.Content), &s.Request) != nil {
		return s, fail("REQUEST_CONTENT")
	}
	r := s.Request
	if r.Version != 1 || !hexN(r.GrantID, 32) || !hexN(r.Nonce, 32) || r.FeeLimit < 1 || r.FeeLimit > MaxFee {
		return s, fail("REQUEST_FIELDS")
	}
	if _, err := addressScript(r.Address); err != nil {
		return s, err
	}
	switch r.Action {
	case "pay":
		if r.Amount <= 0 || r.Amount > MaxMoney || r.Name != "" || r.Value != "" {
			return s, fail("REQUEST_PAY")
		}
	case "names.register":
		if r.Amount != 0 || !validName(r.Name) || !ascii(r.Value, 520) {
			return s, fail("REQUEST_NAME")
		}
	default:
		return s, fail("REQUEST_ACTION")
	}
	s.Raw = append([]byte{}, raw...)
	return s, nil
}
func validName(s string) bool {
	if len(s) < 3 || len(s) > 255 || !ascii(s, 255) || strings.ContainsAny(s, " \t\\") {
		return false
	}
	return strings.HasPrefix(s, "d/") || strings.HasPrefix(s, "id/")
}

// Terms are an exact canonical contract committed by the issuer-signed grant.
// They can narrow the grant budget, never create additional spending authority.
type Terms struct {
	Version    int      `json:"version"`
	Recipients []string `json:"recipients"`
	SpendCap   int64    `json:"spend_cap_sat"`
	NameCap    int64    `json:"name_cap_sat"`
	NameCount  int      `json:"name_count"`
}

func ParseTerms(raw []byte, total int64) (Terms, error) {
	return parseTermsForNetwork(raw, total, "regtest", su.RegtestGenesis)
}

func parseTermsForNetwork(raw []byte, total int64, network, genesis string) (Terms, error) {
	var t Terms
	if strict(raw, &t) != nil || t.Version != 1 || t.Recipients == nil || len(t.Recipients) > 32 || !slices.IsSorted(t.Recipients) {
		return t, fail("CONTRACT_SCHEMA")
	}
	if total < 0 || total > MaxMoney || t.SpendCap < 0 || t.NameCap < 0 || t.SpendCap > total || t.NameCap > total-t.SpendCap || t.NameCount < 0 || t.NameCount > 3 {
		return t, fail("CONTRACT_BUDGET")
	}
	for i, a := range t.Recipients {
		if _, e := addressScriptForNetwork(a, network, genesis); e != nil {
			return t, e
		}
		if i > 0 && a == t.Recipients[i-1] {
			return t, fail("CONTRACT_RECIPIENTS")
		}
	}
	return t, nil
}
