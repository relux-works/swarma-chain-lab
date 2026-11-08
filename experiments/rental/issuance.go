package rental

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"slices"
	"time"

	su "relux.works/swarma-chain-lab/experiments/single-use"
)

// These wire types implement the agreed M3 FORMAT-PROPOSAL v1. They contain
// public statements, never a wallet or signing authority.
type IssuanceRequest struct {
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
	PaymentTxID      string   `json:"payment_txid"`
	PaymentVout      uint32   `json:"payment_vout"`
	PaymentHeight    int64    `json:"payment_height"`
	PaymentBlockHash string   `json:"payment_block_hash"`
	ObservedTipHash  string   `json:"observed_tip_hash"`
	PackageEventID   string   `json:"package_event_id"`
}
type Contract struct {
	Version         int      `json:"version"`
	BookingID       string   `json:"booking_id"`
	RenterPubkey    string   `json:"renter_pubkey"`
	RenterName      string   `json:"renter_name"`
	AgentPubkey     string   `json:"agent_pubkey"`
	StationName     string   `json:"station_name"`
	NotBefore       int64    `json:"not_before"`
	NotAfter        int64    `json:"not_after"`
	Allowed         []string `json:"allowed"`
	Forbidden       []string `json:"forbidden"`
	BudgetSat       int64    `json:"budget_sat"`
	TemplateID      string   `json:"template_id"`
	TemplateSHA256  string   `json:"template_sha256"`
	ProfileID       string   `json:"profile_id"`
	ProfileVersion  string   `json:"profile_version"`
	ProfileSHA256   string   `json:"profile_sha256"`
	PriceUSDCents   int64    `json:"price_usd_cents"`
	USDMicrosPerNMC int64    `json:"usd_micros_per_nmc"`
	RateAsOf        int64    `json:"rate_as_of"`
	PriceNMCSat     int64    `json:"price_nmc_sat"`
	PaymentPolicy   string   `json:"payment_policy"`
	PaymentAddress  string   `json:"payment_address"`
	PrivacySHA256   string   `json:"privacy_sha256"`
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
type Package struct {
	Version           int      `json:"version"`
	Contract          Contract `json:"contract"`
	Consent           Event    `json:"consent"`
	ProviderPubkey    string   `json:"provider_pubkey"`
	ProviderSignature string   `json:"provider_signature"`
	PrivacyAckAt      int64    `json:"privacy_ack_at"`
	PrivacySHA256     string   `json:"privacy_sha256"`
	HoldCreatedAt     int64    `json:"hold_created_at"`
	HoldExpiresAt     int64    `json:"hold_expires_at"`
}
type IssuerPolicy struct {
	Policy         Policy `json:"policy"`
	ProviderPubkey string `json:"provider_pubkey"`
}

func eventBytes(v any) []byte {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	_ = e.Encode(v)
	return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
}
func eventValid(e Event, now int64) bool {
	if e.CreatedAt < 1 || e.CreatedAt > now || e.Kind < 0 || e.Kind > 65535 || e.Tags == nil || len(e.Tags) > 16 || len(e.Content) > 12000 {
		return false
	}
	if !eventASCII(e) {
		return false
	}
	b := eventBytes([]any{0, e.Pubkey, e.CreatedAt, e.Kind, e.Tags, e.Content})
	return e.ID == Hash(b) && VerifySignature(e.Pubkey, e.ID, e.Sig)
}
func eventASCII(e Event) bool {
	printable := func(s string) bool {
		for _, c := range []byte(s) {
			if c < 32 || c > 126 {
				return false
			}
		}
		return true
	}
	if !printable(e.Content) {
		return false
	}
	for _, tag := range e.Tags {
		if len(tag) < 1 || len(tag) > 3 {
			return false
		}
		for _, s := range tag {
			if len(s) > 512 || !printable(s) {
				return false
			}
		}
	}
	return true
}
func sameJSON(a, b any) bool { return bytes.Equal(eventBytes(a), eventBytes(b)) }

// VerifyIssuancePackage is offline authentication/binding only. It deliberately
// makes no claim that payment or a relay acknowledgement is current.
func VerifyIssuancePackage(p IssuerPolicy, request, event []byte, now int64) (IssuanceRequest, Package, error) {
	var r IssuanceRequest
	var publication Event
	var pack Package
	fail := func(code string) (IssuanceRequest, Package, error) { return r, pack, bad(code) }
	if p.Policy.validate() != nil || !pubkey(p.ProviderPubkey) {
		return fail("ISSUER_POLICY")
	}
	if canonical(request, &r) != nil || r.Version != 1 || !digest(r.BookingID) || !digest(r.PaymentTxID) || !digest(r.ObservedTipHash) || !digest(r.PackageEventID) || !digest(r.ContractSHA256) || !validScope(r.Scope) {
		return fail("ISSUANCE_REQUEST")
	}
	if r.StationName != p.Policy.StationName || r.AgentPubkey != p.Policy.AgentPubkey || !pubkey(r.RenterPubkey) || r.BudgetSat < 0 || r.BudgetSat > MaxMoney || r.NotBefore < 1 || r.NotAfter <= r.NotBefore || r.NotAfter-r.NotBefore > 3600 || now >= r.NotAfter {
		return fail("ISSUANCE_BINDING")
	}
	if (r.PaymentPolicy != "advance" && r.PaymentPolicy != "start_now") || r.PaymentHeight < 0 || (r.PaymentHeight == 0 && r.PaymentBlockHash != "") || (r.PaymentHeight > 0 && !digest(r.PaymentBlockHash)) {
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
	if pack.HoldCreatedAt < 1 || pack.HoldExpiresAt <= pack.HoldCreatedAt || now < pack.HoldCreatedAt || pack.PrivacyAckAt != pack.HoldCreatedAt {
		return fail("HOLD_BINDING")
	}
	if now >= pack.HoldExpiresAt {
		return fail("hold_expired_at_admission")
	}
	hash := Hash(eventBytes(c))
	if c.Version != 1 || hash != r.ContractSHA256 || !VerifySignature(p.ProviderPubkey, hash, pack.ProviderSignature) {
		return fail("PROVIDER_SIGNATURE")
	}
	if c.BookingID != r.BookingID || c.RenterPubkey != r.RenterPubkey || c.AgentPubkey != r.AgentPubkey || c.StationName != r.StationName || c.NotBefore != r.NotBefore || c.NotAfter != r.NotAfter || c.BudgetSat != r.BudgetSat || c.PaymentPolicy != r.PaymentPolicy || !slices.Equal(c.Allowed, r.Scope) {
		return fail("PACKAGE_REQUEST_BINDING")
	}
	if !validScope(c.Allowed) || !validScope(c.Forbidden) || len(c.Allowed)+len(c.Forbidden) != 5 {
		return fail("CONTRACT_SCOPE")
	}
	for _, v := range c.Allowed {
		if slices.Contains(c.Forbidden, v) {
			return fail("CONTRACT_SCOPE")
		}
	}
	if !digest(c.TemplateSHA256) || !digest(c.ProfileSHA256) || !digest(c.PrivacySHA256) || c.TemplateID == "" || c.ProfileID == "" || c.ProfileVersion == "" || c.PriceNMCSat <= 0 || c.PriceNMCSat > MaxMoney || len(c.PaymentAddress) < 26 || len(c.PaymentAddress) > 40 {
		return fail("CONTRACT_FIELDS")
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

type Admission struct {
	Verdict        string `json:"verdict"`
	Reason         string `json:"reason"`
	BookingID      string `json:"booking_id"`
	ContractSHA256 string `json:"contract_sha256"`
	Payment        Point  `json:"payment"`
	TipHash        string `json:"tip_hash"`
	Calls          int    `json:"calls"`
	CheckedAt      int64  `json:"checked_at"`
}

// AdmitIssuance is a fresh read-only gate for the future signer, never a
// transferable approval. A request's historical payment fields do not replace
// current own-node evidence. No journal, plan, signature or broadcast is emitted.
func AdmitIssuance(ctx context.Context, node su.Node, p IssuerPolicy, request, event []byte, now int64) (a Admission) {
	started := time.Now()
	a = Admission{Verdict: "refused", CheckedAt: now}
	refuse := func(e error) Admission { a.Reason = e.Error(); return a }
	r, pack, e := VerifyIssuancePackage(p, request, event, now)
	if e != nil {
		return refuse(e)
	}
	a.BookingID = r.BookingID
	a.ContractSHA256 = r.ContractSHA256
	a.Payment = Point{r.PaymentTxID, r.PaymentVout}
	if node == nil {
		return refuse(bad("NODE_UNAVAILABLE"))
	}
	o := su.NewReadObservation(ctx, node)
	defer o.Close()
	defer func() { a.Calls = o.Calls() }()
	if e = o.Start(p.Policy.Network, p.Policy.Genesis); e != nil {
		return refuse(e)
	}
	a.TipHash = o.Tip().Best
	for i := 0; i < 2; i++ {
		v, tx, e := o.PaymentTransaction(r.PaymentTxID)
		if e != nil {
			return refuse(e)
		}
		if uint64(r.PaymentVout) >= uint64(len(tx.Outputs)) {
			return refuse(bad("PAYMENT_OUTPUT"))
		}
		output := tx.Outputs[r.PaymentVout]
		projected := v.Vout[r.PaymentVout]
		if output.Value != pack.Contract.PriceNMCSat || !p2pkh(hex.EncodeToString(output.Script)) || projected.Script.Address != pack.Contract.PaymentAddress {
			return refuse(bad("PAYMENT_BINDING"))
		}
		if v.Block == "" || v.Confirmations <= 0 {
			return refuse(bad("payment_unconfirmed"))
		}
		if _, e = o.Confirmed(v); e != nil {
			return refuse(e)
		}
	}
	if e = o.Stable(); e != nil {
		return refuse(e)
	}
	current := now + int64(time.Since(started)/time.Second)
	if current >= pack.HoldExpiresAt {
		return refuse(bad("hold_expired_at_admission"))
	}
	if current >= pack.Contract.NotAfter {
		return refuse(bad("ISSUANCE_BINDING"))
	}
	a.Verdict = "admit"
	a.Reason = "PAYMENT_AND_PACKAGE_CURRENT"
	return a
}
