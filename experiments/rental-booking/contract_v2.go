package booking

import paymentchain "relux.works/swarma-chain-lab/experiments/payment-chain"

// ContractV2 binds payment currency independently of the NMC execution budget.
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

func (c ContractV2) Bytes() []byte { return canonical(c) }
func (c ContractV2) Hash() string  { return Hash(c.Bytes()) }
func (c ContractV2) Validate() error {
	if c.Version != 2 || !hexSize(c.BookingID, 32) || !pubkey(c.RenterPubkey) || !pubkey(c.AgentPubkey) || !stationName(c.StationName) || c.RenterName != "" && !identifier(c.RenterName) {
		return refuse("CONTRACT_IDENTITY")
	}
	if c.NotBefore <= 0 || c.NotAfter <= c.NotBefore || c.NotAfter-c.NotBefore > 3600 {
		return refuse("CONTRACT_SLOT")
	}
	if !actionPartition(c.Allowed, c.Forbidden) || c.BudgetSat < 0 || c.BudgetSat > 21000000*100000000 {
		return refuse("CONTRACT_SCOPE")
	}
	if !identifier(c.TemplateID) || !identifier(c.ProfileID) || !identifier(c.ProfileVersion) || !hexSize(c.TemplateSHA256, 32) || !hexSize(c.ProfileSHA256, 32) || c.PrivacySHA256 != Hash([]byte(PrivacyNotice)) {
		return refuse("CONTRACT_PINS")
	}
	if e := c.Payment.ValidateAt(c.Payment.RateAsOf, c.Payment.MaxRateAgeSeconds, 1); e != nil {
		return e
	}
	if c.PaymentPolicy != "advance" && c.PaymentPolicy != "start_now" {
		return refuse("PAYMENT_POLICY")
	}
	return nil
}
