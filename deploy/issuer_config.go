package deploy

import "strings"

const regtestGenesis = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
const mainGenesis = "000000000062b72c5e2ceb45fbc8587e807c155b0da735e6483dfba2f0a9c770"
const maxMoney int64 = 21000000 * 100000000

type issuerCaps struct {
	FeePerTx    int64 `json:"fee_per_tx"`
	CountHour   int   `json:"count_hour"`
	CountDay    int   `json:"count_day"`
	BudgetHour  int64 `json:"budget_hour"`
	BudgetDay   int64 `json:"budget_day"`
	RefillCount int   `json:"refill_count"`
	SealValue   int64 `json:"seal_value"`
	RefillValue int64 `json:"refill_value"`
	LowWater    int   `json:"low_water"`
}
type paymentLimits struct {
	MaxBlocks  int64 `json:"max_blocks"`
	MaxMempool int   `json:"max_mempool"`
	MaxCalls   int   `json:"max_calls"`
	MaxBytes   int   `json:"max_bytes"`
}
type paymentPolicy struct {
	MaxRateAgeSeconds int64         `json:"max_rate_age_seconds"`
	MinConfirmations  int64         `json:"min_confirmations"`
	Limits            paymentLimits `json:"limits"`
}
type issuerPoint struct {
	TxID string `json:"txid"`
	Vout uint32 `json:"vout"`
}
type issuerPolicy struct {
	ConstructionProfile string        `json:"construction_profile"`
	FeeRate             int64         `json:"fee_rate,omitempty"`
	Network             string        `json:"network"`
	Genesis             string        `json:"genesis"`
	IssuerPubkey        string        `json:"issuer_pubkey"`
	AgentPubkey         string        `json:"agent_pubkey"`
	StationName         string        `json:"station_name"`
	StationScript       string        `json:"station_script"`
	StateDir            string        `json:"state_dir"`
	AgentName           string        `json:"agent_name,omitempty"`
	SealScript          string        `json:"seal_script,omitempty"`
	LandlordName        string        `json:"landlord_name,omitempty"`
	KnownPoolSeals      []issuerPoint `json:"known_pool_seals,omitempty"`
	FundingScript       string        `json:"funding_script,omitempty"`
}
type issuerConfig struct {
	PaymentRouteFiles map[string]string `json:"payment_route_files,omitempty"`
	Config            struct {
		Spending        *spendingCaps            `json:"spending,omitempty"`
		PresentationDir string                   `json:"presentation_dir,omitempty"`
		Profile         string                   `json:"profile"`
		PaymentPolicies map[string]paymentPolicy `json:"payment_policies,omitempty"`
		Policy          struct {
			Policy         issuerPolicy `json:"policy"`
			ProviderPubkey string       `json:"provider_pubkey"`
		} `json:"policy"`
		StateDir              string     `json:"state_dir"`
		GrantKeyPath          string     `json:"grant_key_path"`
		FundingKeyPath        string     `json:"funding_key_path"`
		HistoricalSealScripts []string   `json:"historical_seal_scripts,omitempty"`
		Caps                  issuerCaps `json:"caps"`
	} `json:"config"`
	ReadRouteFile       string `json:"read_route_file"`
	BroadcastRouteFile  string `json:"broadcast_route_file"`
	BookingOutbox       string `json:"booking_outbox"`
	OperatorOutbox      string `json:"operator_outbox,omitempty"`
	StoreURL            string `json:"store_url"`
	StoreLandlordReader string `json:"store_landlord_reader"`
	StoreAgentReader    string `json:"store_agent_reader"`
	IntervalSeconds     int    `json:"interval_seconds"`
	Inventory           []struct {
		Point    issuerPoint `json:"point"`
		ValueSat int64       `json:"value_sat"`
		Script   string      `json:"script"`
		Role     string      `json:"role"`
	} `json:"inventory,omitempty"`
}

func p2pkhScript(s string) bool {
	return exactHex(s, 25) && strings.HasPrefix(s, "76a914") && strings.HasSuffix(s, "88ac")
}
func identityName(s string) bool {
	return strings.HasPrefix(s, "id/") && len(s) > 3 && len(s) <= 255 && !strings.ContainsAny(s, " \t\r\n\x00")
}
func validateIssuer(raw []byte) error {
	var f issuerConfig
	if e := serviceDecode(raw, &f, false); e != nil {
		return e
	}
	c, p := f.Config, f.Config.Policy.Policy
	if p.ConstructionProfile != "W" {
		return ErrPolicy
	}
	if c.Profile != "v2" || c.StateDir != "/var/lib/swarma-issuer/ledger" || p.StateDir != "/var/lib/swarma-issuer/issuance" || c.PresentationDir != "/var/lib/swarma-issuer/presentations" || c.GrantKeyPath != "/etc/swarma/issuer/grant.key" || c.FundingKeyPath != "/etc/swarma/issuer/funding.key" || f.ReadRouteFile != "/etc/swarma/issuer/read-route.json" || f.BroadcastRouteFile != "/etc/swarma/issuer/broadcast-route.json" || f.BookingOutbox != "/var/lib/swarma-issuer/intake/booking" || f.OperatorOutbox != "/var/lib/swarma-issuer/intake/operator" || f.IntervalSeconds < 1 || f.IntervalSeconds > 3600 {
		return ErrPolicy
	}
	if !deploymentNetwork(p.Network, p.Genesis) || p.Genesis == "" {
		return ErrNetwork
	}
	if p.Network == "main" && (c.Spending == nil || !c.Spending.valid() || p.FeeRate < 1 || p.FeeRate > 1000) {
		return ErrPolicy
	}
	if c.Spending != nil && !c.Spending.valid() {
		return ErrPolicy
	}
	if !digestPin(p.IssuerPubkey) || !digestPin(p.AgentPubkey) || !digestPin(c.Policy.ProviderPubkey) || !identityName(p.AgentName) || !identityName(p.LandlordName) || p.AgentName == p.LandlordName || !identityName(p.StationName) || !p2pkhScript(p.StationScript) || !p2pkhScript(p.SealScript) || !(exactHex(p.FundingScript, 22) && strings.HasPrefix(p.FundingScript, "0014")) || p.FundingScript == p.SealScript {
		return ErrPolicy
	}
	// Public structural validation cannot establish a curve point, key-script
	// derivation, inventory ownership, node pins or a live signed contract.
	if f.StoreURL != "http://127.0.0.1:8091" || !digestPin(f.StoreLandlordReader) || !digestPin(f.StoreAgentReader) {
		return ErrPolicy
	}
	caps := c.Caps
	if caps.FeePerTx < 1 || caps.FeePerTx > maxMoney || caps.CountHour < 1 || caps.CountDay < caps.CountHour || caps.CountDay > 64 || caps.BudgetHour < 1 || caps.BudgetDay < caps.BudgetHour || caps.BudgetDay > maxMoney || caps.RefillCount < 1 || caps.RefillCount > 16 || caps.SealValue < 100000 || caps.SealValue > maxMoney/int64(caps.RefillCount) || caps.RefillValue < caps.SealValue*int64(caps.RefillCount) || caps.RefillValue > maxMoney || caps.LowWater < 1 || caps.LowWater > caps.RefillCount {
		return ErrPolicy
	}
	if len(c.PaymentPolicies) < 1 || len(c.PaymentPolicies) > 3 || len(f.PaymentRouteFiles) != len(c.PaymentPolicies) {
		return ErrPolicy
	}
	for coin, policy := range c.PaymentPolicies {
		if p.Network == "main" && coin != "nmc" {
			return ErrPolicy
		}
		if coin != "btc" && coin != "ltc" && coin != "nmc" {
			return ErrPolicy
		}
		l := policy.Limits
		if f.PaymentRouteFiles[coin] != "/etc/swarma/issuer/payment-"+coin+".json" || policy.MinConfirmations < 1 || policy.MaxRateAgeSeconds < 1 || l.MaxBlocks < 1 || l.MaxBlocks > 2016 || l.MaxMempool < 1 || l.MaxMempool > 100000 || l.MaxCalls < 1 || l.MaxCalls > 200000 || l.MaxBytes < 1 || l.MaxBytes > 512<<20 {
			return ErrPolicy
		}
	}
	if len(c.HistoricalSealScripts) > 64 || len(p.KnownPoolSeals) > 64 || len(f.Inventory) > 64 {
		return ErrPolicy
	}
	for _, s := range c.HistoricalSealScripts {
		if !p2pkhScript(s) || s == p.FundingScript {
			return ErrPolicy
		}
	}
	for _, point := range p.KnownPoolSeals {
		if !digestPin(point.TxID) {
			return ErrPolicy
		}
	}
	seen := map[issuerPoint]bool{}
	var enrolled int64
	for _, in := range f.Inventory {
		if !digestPin(in.Point.TxID) || in.ValueSat < 1 || in.ValueSat > maxMoney || seen[in.Point] {
			return ErrPolicy
		}
		seen[in.Point] = true
		if in.ValueSat > maxMoney-enrolled {
			return ErrPolicy
		}
		enrolled += in.ValueSat
		if in.Role == "seal" {
			if in.Script != p.SealScript {
				return ErrPolicy
			}
		} else if in.Role == "funding" {
			if in.Script != p.FundingScript {
				return ErrPolicy
			}
		} else {
			return ErrPolicy
		}
	}
	if c.Spending != nil && enrolled > c.Spending.EnrolledHot {
		return ErrPolicy
	}
	return nil
}

type spendingCaps struct {
	MovedPerTx  int64 `json:"moved_per_tx"`
	MovedDay    int64 `json:"moved_day"`
	EnrolledHot int64 `json:"enrolled_hot"`
}

func (c spendingCaps) valid() bool {
	return c.MovedPerTx > 0 && c.MovedDay >= c.MovedPerTx && c.MovedDay <= maxMoney && c.EnrolledHot > 0 && c.EnrolledHot <= maxMoney
}
