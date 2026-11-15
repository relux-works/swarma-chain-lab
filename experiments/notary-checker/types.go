// Package notarycheck computes an offline depth-1 notary decision and an
// unsigned attestation candidate. It neither issues nor signs anything.
package notarycheck

import "encoding/json"

const SpecCommit = "2012ac9155568af80d610bdf9b7683881a46e5cb"
const MaxMoney int64 = 2100000000000000
const MaxTime int64 = 253402300799

// MaxAttestationBytes is the complete canonical attestation limit inherited
// from LIP-0013 section 2.1 by LIP-0014 section 6.1, excluding its signature envelope.
const MaxAttestationBytes = 8192

type Point struct {
	TxID string `json:"txid"`
	Vout uint32 `json:"vout"`
}
type Event struct {
	ID        string     `json:"id"`
	Pubkey    string     `json:"pubkey"`
	CreatedAt int64      `json:"created_at"`
	Kind      int64      `json:"kind"`
	Tags      [][]string `json:"tags"`
	Content   string     `json:"content"`
	Sig       string     `json:"sig"`
}
type Consent struct {
	ContractSHA256 string `json:"contract_sha256"`
	ConsentEvent   Event  `json:"consent_event"`
	LandlordSig    string `json:"landlord_sig"`
}
type Grant struct {
	Version        int64    `json:"version"`
	Network        string   `json:"network"`
	Genesis        string   `json:"genesis"`
	AgentName      string   `json:"agent_name"`
	LandlordName   string   `json:"landlord_name"`
	IssuerKey      string   `json:"issuer_key"`
	GranteeKey     string   `json:"grantee_key"`
	GranteeName    string   `json:"grantee_name,omitempty"`
	ContractSHA256 string   `json:"contract_sha256"`
	Scope          []string `json:"scope"`
	NotBefore      int64    `json:"not_before"`
	NotAfter       int64    `json:"not_after"`
	Seal           Point    `json:"seal"`
	Budget         *int64   `json:"budget,omitempty"`
	Consent        Consent  `json:"consent"`
}
type SignedGrant struct {
	Grant     Grant  `json:"grant"`
	Signature string `json:"signature"`
}
type Presentation struct {
	SignedGrant SignedGrant `json:"signed_grant"`
	Issuance    PointTx     `json:"issuance"`
}
type PointTx struct {
	TxID string `json:"txid"`
}
type Contract struct {
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
type Delegate struct {
	Depth      int64    `json:"depth"`
	Actions    []string `json:"actions"`
	Budget     int64    `json:"budget"`
	Slots      []Row    `json:"slots"`
	Notaries   []Notary `json:"notaries"`
	Checkpoint string   `json:"checkpoint"`
}
type Row struct {
	Executor string `json:"executor"`
	Grantee  string `json:"grantee"`
	Cap      int64  `json:"cap"`
	Notary   string `json:"notary"`
}
type Notary struct {
	Name         string `json:"name"`
	Registration Point  `json:"registration"`
	Owner        string `json:"owner"`
}

// Policy is trusted local configuration, NOT a protocol object or chain proof.
// The caller must authenticate affiliations and default-mode consent out of band.
// The explicit MVP mode resolves named registrations/current grant keys through
// NameSource and additionally verifies both owners' policy signatures.
// Binding both IDs prevents accidental use of a policy for a different bundle.
type Policy struct {
	ParentGrantID  string         `json:"parent_grant_id"`
	ChildGrantID   string         `json:"child_grant_id"`
	IssuerOwner    string         `json:"issuer_owner"`
	DelegatorOwner string         `json:"delegator_owner"`
	NotaryName     string         `json:"notary_name"`
	NotaryOwner    string         `json:"notary_owner"`
	AgreedBy       []string       `json:"agreed_by"`
	Mode           string         `json:"mode,omitempty"`
	ModeApprovals  []ModeApproval `json:"mode_approvals,omitempty"`
}

// ModeApproval is a local deployment-policy signature, never a protocol object.
type ModeApproval struct {
	Owner        string `json:"owner"`
	Name         string `json:"name"`
	Registration Point  `json:"registration"`
	Signature    string `json:"signature"`
}
type Seal struct {
	TxID   string `json:"txid"`
	Vout   uint32 `json:"vout"`
	Script string `json:"script"`
}

// Statement supplies explicit claims for the unsigned candidate. No claim is
// turned into a node observation by this library.
type Statement struct {
	NotarySeal Seal   `json:"notary_seal"`
	TipHeight  int64  `json:"tip_height"`
	TipHash    string `json:"tip_hash"`
}
type Attestation struct {
	Profile              string `json:"profile"`
	Kind                 string `json:"kind"`
	Network              string `json:"network"`
	Genesis              string `json:"genesis"`
	LandlordName         string `json:"landlord_name"`
	NotaryName           string `json:"notary_name"`
	NotaryKey            string `json:"notary_key"`
	ParentGrantID        string `json:"parent_grant_id"`
	ParentContractSHA256 string `json:"parent_contract_sha256"`
	ChildGrantID         string `json:"child_grant_id"`
	ChildContractSHA256  string `json:"child_contract_sha256"`
	Ordinal              int64  `json:"ordinal"`
	Textual              string `json:"textual"`
	Mechanical           string `json:"mechanical"`
	NotarySeal           Seal   `json:"notary_seal"`
	TipHeight            int64  `json:"tip_height"`
	TipHash              string `json:"tip_hash"`
	AttestedAt           int64  `json:"attested_at"`
}
type Input struct {
	Parent, Child                           []byte // exact canonical v3 presentations
	ParentContract, ChildContract           []byte
	Request, Policy, NotaryValue, Statement []byte
	ParentText, ChildText                   []byte
	At                                      int64
	Names                                   NameSource // explicit chain-view dependency; nil refuses MVP
}
type Result struct {
	Attestation []byte
	Digest      string // SHA-256("swarma-notary-v1" || Attestation), NOT attestation_id
}
type Refusal string

func (r Refusal) Error() string { return string(r) }
func refuse(code string) error  { return Refusal(code) }
