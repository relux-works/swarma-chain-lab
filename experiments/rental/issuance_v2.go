package rental

import (
	"bytes"
	"context"
	paymentchain "github.com/relux-works/swarma-chain-lab/experiments/payment-chain"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"slices"
	"time"
)

// V2 wire types are independently decoded here. Legacy v1 remains frozen.
type ContractV2 struct {
	Version        int                `json:"version"`
	BookingID      string             `json:"booking_id"`
	RenterPubkey   string             `json:"renter_pubkey"`
	RenterName     string             `json:"renter_name"`
	AgentPubkey    string             `json:"agent_pubkey"`
	StationName    string             `json:"station_name"`
	NotBefore      int64              `json:"not_before"`
	NotAfter       int64              `json:"not_after"`
	Allowed        []string           `json:"allowed"`
	Forbidden      []string           `json:"forbidden"`
	BudgetSat      int64              `json:"budget_sat"`
	TemplateID     string             `json:"template_id"`
	TemplateSHA256 string             `json:"template_sha256"`
	ProfileID      string             `json:"profile_id"`
	ProfileVersion string             `json:"profile_version"`
	ProfileSHA256  string             `json:"profile_sha256"`
	Payment        paymentchain.Terms `json:"payment"`
	PaymentPolicy  string             `json:"payment_policy"`
	PrivacySHA256  string             `json:"privacy_sha256"`
}

type IssuanceRequestV2 struct {
	Version          int      `json:"version"`
	BookingID        string   `json:"booking_id"`
	StationName      string   `json:"station_name"`
	AgentPubkey      string   `json:"agent_pubkey"`
	RenterPubkey     string   `json:"renter_pubkey"`
	ContractSHA256   string   `json:"contract_sha256"`
	Scope            []string `json:"scope"`
	BudgetSat        int64    `json:"budget_sat"`
	NotBefore        int64    `json:"not_before"`
	NotAfter         int64    `json:"not_after"`
	PaymentPolicy    string   `json:"payment_policy"`
	PaymentCoin      string   `json:"payment_coin"`
	PaymentNetwork   string   `json:"payment_network"`
	PaymentGenesis   string   `json:"payment_genesis"`
	PaymentTxID      string   `json:"payment_txid"`
	PaymentVout      uint32   `json:"payment_vout"`
	PaymentHeight    int64    `json:"payment_height"`
	PaymentBlockHash string   `json:"payment_block_hash"`
	ObservedTipHash  string   `json:"observed_tip_hash"`
	PackageEventID   string   `json:"package_event_id"`
}

type PackageV2 struct {
	Version           int        `json:"version"`
	Contract          ContractV2 `json:"contract"`
	Consent           Event      `json:"consent"`
	ProviderPubkey    string     `json:"provider_pubkey"`
	ProviderSignature string     `json:"provider_signature"`
	PrivacyAckAt      int64      `json:"privacy_ack_at"`
	PrivacySHA256     string     `json:"privacy_sha256"`
	HoldCreatedAt     int64      `json:"hold_created_at"`
	HoldExpiresAt     int64      `json:"hold_expires_at"`
}

type PaymentAdmissionPolicy struct {
	MaxRateAgeSeconds int64               `json:"max_rate_age_seconds"`
	MinConfirmations  int64               `json:"min_confirmations"`
	Limits            paymentchain.Limits `json:"limits"`
}
type IssuerPolicyV2 struct {
	IssuerPolicy
	PaymentPolicies map[string]PaymentAdmissionPolicy `json:"payment_policies"`
}

func VerifyIssuancePackageV2(p IssuerPolicyV2, request, event []byte, now int64) (IssuanceRequestV2, PackageV2, error) {
	var r IssuanceRequestV2
	var publication Event
	var pack PackageV2
	fail := func(code string) (IssuanceRequestV2, PackageV2, error) { return r, pack, bad(code) }
	if p.Policy.validate() != nil || !pubkey(p.ProviderPubkey) {
		return fail("ISSUER_POLICY")
	}
	if canonical(request, &r) != nil || r.Version != 2 || !digest(r.BookingID) || !digest(r.PaymentTxID) || !digest(r.ObservedTipHash) || !digest(r.PackageEventID) || !digest(r.ContractSHA256) || !validGrantScope(r.Scope) {
		return fail("ISSUANCE_REQUEST")
	}
	if r.StationName != p.Policy.StationName || r.AgentPubkey != p.Policy.AgentPubkey || !pubkey(r.RenterPubkey) || r.BudgetSat < 0 || r.BudgetSat > MaxMoney || r.NotBefore < 1 || r.NotAfter <= r.NotBefore || r.NotAfter-r.NotBefore > 3600 || now >= r.NotAfter {
		return fail("ISSUANCE_BINDING")
	}
	if (r.PaymentPolicy != "advance" && r.PaymentPolicy != "start_now") || r.PaymentHeight < 1 || (r.PaymentHeight > 0 && !digest(r.PaymentBlockHash)) {
		return fail("PAYMENT_OBSERVATION")
	}
	// M3 emits unescaped printable-ASCII JSON for NIP-01 interoperability.
	if len(event) > 16384 || su.StrictInput(event, &publication) != nil || !bytes.Equal(event, eventBytes(publication)) || !eventValid(publication, now) || publication.ID != r.PackageEventID || publication.Pubkey != p.ProviderPubkey || publication.Kind != 8182 {
		return fail("PACKAGE_EVENT")
	}
	content := []byte(publication.Content)
	if su.StrictInput(content, &pack) != nil || !bytes.Equal(content, eventBytes(pack)) || pack.Version != 1 || pack.ProviderPubkey != p.ProviderPubkey {
		return fail("PACKAGE_ENCODING")
	}
	c := pack.Contract
	if pack.HoldCreatedAt < 1 || pack.HoldExpiresAt <= pack.HoldCreatedAt || pack.HoldExpiresAt-pack.HoldCreatedAt > 1800 || now < pack.HoldCreatedAt || pack.PrivacyAckAt != pack.HoldCreatedAt {
		return fail("HOLD_BINDING")
	}
	if now >= pack.HoldExpiresAt {
		return fail("hold_expired_at_admission")
	}
	hash := Hash(eventBytes(c))
	if c.Version != 2 || hash != r.ContractSHA256 || !VerifySignature(p.ProviderPubkey, hash, pack.ProviderSignature) {
		return fail("PROVIDER_SIGNATURE")
	}
	if c.BookingID != r.BookingID || c.RenterPubkey != r.RenterPubkey || c.AgentPubkey != r.AgentPubkey || c.StationName != r.StationName || c.NotBefore != r.NotBefore || c.NotAfter != r.NotAfter || c.BudgetSat != r.BudgetSat || c.PaymentPolicy != r.PaymentPolicy || !slices.Equal(c.Allowed, r.Scope) || r.PaymentCoin != c.Payment.Coin || r.PaymentNetwork != c.Payment.Network || r.PaymentGenesis != c.Payment.Genesis {
		return fail("PACKAGE_REQUEST_BINDING")
	}
	// Existing M3 contracts partition five actions. The additive action is
	// denied when absent; its explicit presence requires all six actions.
	actions := 5
	if slices.Contains(c.Allowed, "names.register") || slices.Contains(c.Forbidden, "names.register") {
		actions = 6
	}
	if !validGrantScope(c.Allowed) || !validGrantScope(c.Forbidden) || len(c.Allowed)+len(c.Forbidden) != actions {
		return fail("CONTRACT_SCOPE")
	}
	for _, v := range c.Allowed {
		if slices.Contains(c.Forbidden, v) {
			return fail("CONTRACT_SCOPE")
		}
	}
	if !digest(c.TemplateSHA256) || !digest(c.ProfileSHA256) || !digest(c.PrivacySHA256) || c.TemplateID == "" || c.ProfileID == "" || c.ProfileVersion == "" {
		return fail("CONTRACT_FIELDS")
	}
	paymentPolicy, ok := p.PaymentPolicies[c.Payment.Coin]
	if !ok {
		return fail("PAYMENT_POLICY")
	}
	if e := c.Payment.ValidateAt(pack.HoldCreatedAt, paymentPolicy.MaxRateAgeSeconds, paymentPolicy.MinConfirmations); e != nil {
		return fail(e.Error())
	}
	consent := pack.Consent
	if !eventValid(consent, now) || consent.Pubkey != c.RenterPubkey || consent.Kind != 8181 || consent.Content != "" || consent.CreatedAt < pack.HoldCreatedAt || consent.CreatedAt >= pack.HoldExpiresAt || consent.CreatedAt >= c.NotAfter || !sameJSON(consent.Tags, [][]string{{"t", "swarma-rental-consent-v1"}, {"contract", hash}, {"booking", c.BookingID}, {"privacy", c.PrivacySHA256}}) {
		return fail("RENTER_CONSENT")
	}
	if pack.PrivacySHA256 != c.PrivacySHA256 || pack.PrivacyAckAt < 1 || pack.PrivacyAckAt > consent.CreatedAt || publication.CreatedAt < consent.CreatedAt || !sameJSON(publication.Tags, [][]string{{"t", "swarma-rental-package-v1"}, {"contract", hash}, {"booking", c.BookingID}, {"e", consent.ID}}) {
		return fail("PACKAGE_PRIVACY_BINDING")
	}
	return r, pack, nil
}

// AdmissionV2 carries explicitly denominated payment evidence. It does not
// authorize a signature, journal write, node mutation or external effect.
type AdmissionV2 struct {
	Verdict        string                  `json:"verdict"`
	Reason         string                  `json:"reason"`
	BookingID      string                  `json:"booking_id"`
	ContractSHA256 string                  `json:"contract_sha256"`
	Coin           string                  `json:"coin"`
	Network        string                  `json:"network"`
	Genesis        string                  `json:"genesis"`
	CheckedAt      int64                   `json:"checked_at"`
	Observation    *paymentchain.Admission `json:"observation,omitempty"`
}

func AdmitIssuanceV2(ctx context.Context, paymentNodes map[string]su.Node, p IssuerPolicyV2, request, event []byte, now int64) (a AdmissionV2) {
	started := time.Now()
	a = AdmissionV2{Verdict: "refused", CheckedAt: now}
	r, pack, e := VerifyIssuancePackageV2(p, request, event, now)
	if e != nil {
		a.Reason = e.Error()
		return
	}
	a.BookingID = r.BookingID
	a.ContractSHA256 = r.ContractSHA256
	a.Coin = pack.Contract.Payment.Coin
	a.Network = pack.Contract.Payment.Network
	a.Genesis = pack.Contract.Payment.Genesis
	node := paymentNodes[a.Coin]
	if node == nil {
		a.Reason = "PAYMENT_NODE_UNAVAILABLE"
		return
	}
	policy := p.PaymentPolicies[a.Coin]
	claim := paymentchain.Payment{TxID: r.PaymentTxID, Vout: r.PaymentVout, Height: r.PaymentHeight, BlockHash: r.PaymentBlockHash}
	evidence, e := paymentchain.Admit(ctx, node, policy.Limits, pack.Contract.Payment, claim, pack.HoldCreatedAt, pack.HoldExpiresAt, policy.MaxRateAgeSeconds, policy.MinConfirmations, now)
	if e != nil {
		a.Reason = e.Error()
		return
	}
	current := now + int64(time.Since(started)/time.Second)
	if current >= pack.HoldExpiresAt {
		a.Reason = "hold_expired_at_admission"
		return
	}
	if current >= r.NotAfter {
		a.Reason = "ISSUANCE_BINDING"
		return
	}
	a.Verdict = "admit"
	a.Reason = "PAYMENT_AND_PACKAGE_CURRENT"
	a.Observation = &evidence
	return
}
