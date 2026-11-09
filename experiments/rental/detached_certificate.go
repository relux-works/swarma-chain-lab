package rental

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"golang.org/x/crypto/ripemd160"
)

// DetachedCertificate is the version-2 signed LIP-0003 payload. Optional
// budget is integer satoshis; absence means zero, never unlimited authority.
type DetachedCertificate struct {
	Version        int      `json:"version"`
	Network        string   `json:"network"`
	Genesis        string   `json:"genesis"`
	AgentName      string   `json:"agent_name"`
	IssuerKey      string   `json:"issuer_key"`
	GranteeKey     string   `json:"grantee_key"`
	GranteeName    string   `json:"grantee_name,omitempty"`
	ContractSHA256 string   `json:"contract_sha256"`
	Scope          []string `json:"scope"`
	NotBefore      int64    `json:"not_before"`
	NotAfter       int64    `json:"not_after"`
	Seal           Point    `json:"seal"`
	Budget         *int64   `json:"budget,omitempty"`
}
type DetachedEnvelope struct {
	Certificate DetachedCertificate `json:"certificate"`
	Signature   string              `json:"signature"`
}

func (c DetachedCertificate) Validate() error {
	if c.Version != 2 || !su.NetworkPinned(c.Network, c.Genesis) {
		return bad("DETACHED_NETWORK")
	}
	if !station(c.AgentName) || (c.GranteeName != "" && !station(c.GranteeName)) {
		return bad("DETACHED_NAME")
	}
	if !pubkey(c.IssuerKey) || !pubkey(c.GranteeKey) {
		return bad("DETACHED_KEY")
	}
	if !digest(c.ContractSHA256) || !digest(c.Seal.TxID) {
		return bad("DETACHED_HASH")
	}
	if !validScope(c.Scope) {
		return bad("DETACHED_SCOPE")
	}
	if c.NotBefore < 0 || c.NotAfter <= c.NotBefore || c.NotAfter > 253402300799 {
		return bad("DETACHED_TIME")
	}
	if c.Budget != nil && (*c.Budget < 0 || *c.Budget > MaxMoney) {
		return bad("DETACHED_BUDGET")
	}
	return nil
}
func (c DetachedCertificate) Canonical() ([]byte, error) {
	if e := c.Validate(); e != nil {
		return nil, e
	}
	return json.Marshal(c)
}
func (c DetachedCertificate) BudgetSat() int64 {
	if c.Budget == nil {
		return 0
	}
	return *c.Budget
}
func ParseDetachedEnvelope(raw []byte) (DetachedEnvelope, error) {
	var env DetachedEnvelope
	if e := canonical(raw, &env); e != nil {
		return env, e
	}
	b, e := env.Certificate.Canonical()
	if e != nil {
		return env, e
	}
	if !VerifySignature(env.Certificate.IssuerKey, Hash(b), env.Signature) {
		return env, bad("ISSUER_SIGNATURE")
	}
	return env, nil
}

// GrantSealScript binds revocation custody to the even-y compressed point of
// the grant x-only key. An ECDSA spender must use the corresponding normalized
// secret. This profile deliberately reuses that key across BIP-340 and ECDSA.
func GrantSealScript(issuer string) (string, error) {
	if !pubkey(issuer) {
		return "", bad("DETACHED_KEY")
	}
	pk, e := schnorr.ParsePubKey(mustDecodeKey(issuer))
	if e != nil {
		return "", bad("DETACHED_KEY")
	}
	compressed := pk.SerializeCompressed()
	if compressed[0] != 2 {
		return "", bad("DETACHED_KEY")
	}
	h := sha256.Sum256(compressed)
	r := ripemd160.New()
	_, _ = r.Write(h[:])
	script := append([]byte{0x76, 0xa9, 20}, r.Sum(nil)...)
	script = append(script, 0x88, 0xac)
	return hex.EncodeToString(script), nil
}
func mustDecodeKey(s string) []byte { b, _ := hex.DecodeString(s); return b }
