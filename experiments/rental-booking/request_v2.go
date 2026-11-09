package booking

import (
	paymentchain "github.com/relux-works/swarma-chain-lab/experiments/payment-chain"
	"slices"
)

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

// Validate binds every request field to the authenticated contract and package.
// Historical payment fields are lookup hints, never proof of current payment.
func (r IssuanceRequestV2) Validate(c ContractV2, packageEventID string) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if r.Version != 2 || r.Scope == nil || !hexSize(r.PaymentTxID, 32) || !hexSize(r.ObservedTipHash, 32) || !hexSize(packageEventID, 32) || r.PackageEventID != packageEventID || r.PaymentHeight < 1 || !hexSize(r.PaymentBlockHash, 32) {
		return refuse("ISSUANCE_REQUEST")
	}
	if r.BookingID != c.BookingID || r.ContractSHA256 != c.Hash() || r.StationName != c.StationName || r.AgentPubkey != c.AgentPubkey || r.RenterPubkey != c.RenterPubkey || !slices.Equal(r.Scope, c.Allowed) || r.BudgetSat != c.BudgetSat || r.NotBefore != c.NotBefore || r.NotAfter != c.NotAfter || r.PaymentPolicy != c.PaymentPolicy || r.PaymentCoin != c.Payment.Coin || r.PaymentNetwork != c.Payment.Network || r.PaymentGenesis != c.Payment.Genesis {
		return refuse("PACKAGE_REQUEST_BINDING")
	}
	return nil
}

func NewIssuanceRequestV2(c ContractV2, payment paymentchain.Payment, tip paymentchain.Tip, packageEventID string) (IssuanceRequestV2, error) {
	r := IssuanceRequestV2{Version: 2, BookingID: c.BookingID, StationName: c.StationName, AgentPubkey: c.AgentPubkey, RenterPubkey: c.RenterPubkey, ContractSHA256: c.Hash(), Scope: append([]string{}, c.Allowed...), BudgetSat: c.BudgetSat, NotBefore: c.NotBefore, NotAfter: c.NotAfter, PaymentPolicy: c.PaymentPolicy, PaymentCoin: c.Payment.Coin, PaymentNetwork: c.Payment.Network, PaymentGenesis: c.Payment.Genesis, PaymentTxID: payment.TxID, PaymentVout: payment.Vout, PaymentHeight: payment.Height, PaymentBlockHash: payment.BlockHash, ObservedTipHash: tip.Hash, PackageEventID: packageEventID}
	if err := r.Validate(c, packageEventID); err != nil {
		return IssuanceRequestV2{}, err
	}
	if payment.ValueAtoms < c.Payment.AmountAtoms || payment.Height > tip.Height || tip.Height-payment.Height+1 < c.Payment.MinConfirmations {
		return IssuanceRequestV2{}, refuse("PAYMENT_INELIGIBLE")
	}
	return r, nil
}
